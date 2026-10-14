#include "network_log.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <core/constants.h>

static FILE *open_private(const char *path, size_t *size)
{
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_uid != geteuid() || fchmod(fd, 0600)) {
        close(fd);
        return NULL;
    }
    *size = (size_t)st.st_size;
    FILE *file = fdopen(fd, "a");
    if (!file) close(fd);
    return file;
}

static int write_line(struct network_log *log, const char *line)
{
    size_t len = strlen(line);
    if (!log->file) goto error;
    if (log->size + len > log->max_bytes) {
        char backup[sizeof(log->path) + 3];
        snprintf(backup, sizeof(backup), "%s.1", log->path);
        if (rename(log->path, backup)) goto error;
        fclose(log->file);
        log->file = open_private(log->path, &log->size);
        if (!log->file) goto error;
    }
    if (fputs(line, log->file) == EOF || fflush(log->file)) goto error;
    log->size += len;
    if (log->console) fputs(line, stdout);
    return 0;
error:
    /* One diagnostic per failure episode, rather than one per packet. */
    if (!log->write_errors)
        fprintf(stderr, "[-] Network log write/rotation failed; check disk and permissions\n");
    log->write_errors++;
    return -1;
}

static void timestamp(long long ns, char *out, size_t size)
{
    time_t seconds = ns / 1000000000LL;
    struct tm utc;
    gmtime_r(&seconds, &utc);
    strftime(out, size, "%Y-%m-%dT%H:%M:%SZ", &utc);
}

int network_log_init(struct network_log *log, const char *path,
                     unsigned window_sec, size_t max_bytes, int console)
{
    memset(log, 0, sizeof(*log));
    if (!path || strlen(path) >= sizeof(log->path) || !window_sec || max_bytes < 4096)
        return -1;
    snprintf(log->path, sizeof(log->path), "%s", path);
    log->window_sec = window_sec;
    log->max_bytes = max_bytes;
    log->console = console;
    struct timespec real, mono;
    clock_gettime(CLOCK_REALTIME, &real);
    clock_gettime(CLOCK_MONOTONIC, &mono);
    log->clock_offset_ns = (real.tv_sec - mono.tv_sec) * 1000000000LL + real.tv_nsec - mono.tv_nsec;
    log->file = open_private(path, &log->size);
    return log->file ? 0 : -1;
}

static const char *reason_name(unsigned reason)
{
    switch (reason) {
    case REASON_POLICY: return "policy";
    case REASON_DEFAULT_POLICY: return "default_policy";
    case REASON_INVALID_STATE: return "invalid_state";
    case REASON_MALFORMED: return "malformed";
    default: return "state";
    }
}

static void emit_entry(struct network_log *log, struct network_log_entry *entry)
{
    if (!entry->count) return;
    const struct packet_event *e = &entry->event;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN], first[32], last[32], line[1024];
    inet_ntop(AF_INET, &e->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &e->dst_ip, dst, sizeof(dst));
    timestamp((long long)e->timestamp_ns + log->clock_offset_ns, first, sizeof(first));
    timestamp((long long)entry->last_ns + log->clock_offset_ns, last, sizeof(last));
    snprintf(line, sizeof(line),
        "{\"type\":\"network\",\"severity\":\"info\",\"first_seen\":\"%s\",\"last_seen\":\"%s\","
        "\"first_monotonic_ns\":%llu,\"last_monotonic_ns\":%llu,"
        "\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,"
        "\"protocol\":%u,\"direction\":\"%s\",\"ifindex\":%u,\"action\":\"%s\","
        "\"reason\":\"%s\",\"rule_id\":%u,\"conn_state\":%u,\"tcp_flags\":%u,"
        "\"new_flow\":%s,\"event_count\":%llu,\"observed_bytes\":%llu}\n",
        first, last, (unsigned long long)e->timestamp_ns, (unsigned long long)entry->last_ns,
        src, dst, ntohs(e->src_port), ntohs(e->dst_port), e->proto,
        e->direction == DIR_INGRESS ? "in" : e->direction == DIR_EGRESS ? "out" : "unknown",
        e->ifindex, e->action == ACTION_DROP ? "drop" : "allow", reason_name(e->reason),
        e->rule_id, e->conn_state, e->tcp_flags, e->new_flow ? "true" : "false",
        (unsigned long long)entry->count, (unsigned long long)entry->bytes);
    write_line(log, line);
    memset(entry, 0, sizeof(*entry));
}

static int same_key(const struct packet_event *a, const struct packet_event *b)
{
    return a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
        a->src_port == b->src_port && a->dst_port == b->dst_port &&
        a->proto == b->proto && a->direction == b->direction &&
        a->ifindex == b->ifindex && a->action == b->action &&
        a->reason == b->reason && a->rule_id == b->rule_id &&
        a->conn_state == b->conn_state && a->tcp_flags == b->tcp_flags &&
        a->new_flow == b->new_flow;
}

void network_log_record(struct network_log *log, const struct packet_event *evt)
{
    log->received++;
    unsigned hash = evt->src_ip ^ (evt->dst_ip * 16777619u) ^
        ((unsigned)evt->src_port << 16) ^ evt->dst_port ^ evt->ifindex ^ evt->proto;
    hash ^= hash >> 16;
    struct network_log_entry *entry = &log->entries[hash % NETWORK_LOG_BUCKETS];
    if (entry->count && (!same_key(&entry->event, evt) ||
        (evt->timestamp_ns > entry->event.timestamp_ns &&
         evt->timestamp_ns - entry->event.timestamp_ns >= (__u64)log->window_sec * 1000000000ULL))) {
        if (!same_key(&entry->event, evt)) log->evictions++;
        emit_entry(log, entry);
    }
    if (!entry->count) entry->event = *evt;
    entry->count++;
    entry->bytes += evt->pkt_len;
    if (evt->timestamp_ns > entry->last_ns) entry->last_ns = evt->timestamp_ns;
    if (evt->timestamp_ns < entry->event.timestamp_ns) entry->event.timestamp_ns = evt->timestamp_ns;
}

void network_log_flush(struct network_log *log)
{
    for (unsigned i = 0; i < NETWORK_LOG_BUCKETS; i++) emit_entry(log, &log->entries[i]);
}

void network_log_health(struct network_log *log, __u64 kernel_lost, int stats_available)
{
    char now[32], line[512];
    timestamp((long long)time(NULL) * 1000000000LL, now, sizeof(now));
    snprintf(line, sizeof(line),
        "{\"type\":\"telemetry_health\",\"timestamp\":\"%s\",\"events_received\":%llu,"
        "\"invalid_events\":%llu,\"aggregation_evictions\":%llu,\"write_errors\":%llu,"
        "\"kernel_events_lost\":%llu,\"kernel_stats_available\":%s}\n", now,
        (unsigned long long)log->received, (unsigned long long)log->invalid,
        (unsigned long long)log->evictions, (unsigned long long)log->write_errors,
        (unsigned long long)kernel_lost, stats_available ? "true" : "false");
    write_line(log, line);
}

void network_log_close(struct network_log *log)
{
    if (!log->file) return;
    network_log_flush(log);
    fclose(log->file);
    log->file = NULL;
}
