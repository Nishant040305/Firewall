#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include "conntrack_mgr.h"
#include "../utils/ip_utils.h"

static const char *state_to_str(enum conn_state st)
{
    switch (st) {
    case CONN_STATE_NEW:         return "NEW";
    case CONN_STATE_SYN_SENT:    return "SYN_SENT";
    case CONN_STATE_SYN_RECV:    return "SYN_RECV";
    case CONN_STATE_ESTABLISHED: return "ESTABLISHED";
    case CONN_STATE_FIN_WAIT:    return "FIN_WAIT";
    case CONN_STATE_CLOSE_WAIT:  return "CLOSE_WAIT";
    case CONN_STATE_CLOSED:      return "CLOSED";
    case CONN_STATE_UDP_ACTIVE:  return "UDP_ACTIVE";
    case CONN_STATE_ICMP_ACTIVE: return "ICMP_ACTIVE";
    default:                     return "UNKNOWN";
    }
}

static int conntrack_mgr_list_table(int map_fd, const char *label)
{
    if (map_fd < 0) return 0;

    printf("\n  [ %s ]\n", label);
    printf("  %-6s | %-21s | %-21s | %-12s | %-12s | %-12s\n",
           "PROTO", "SOURCE (IP:PORT)", "DESTINATION (IP:PORT)", "STATE", "PKTS (FWD/REV)", "BYTES (FWD/REV)");
    printf("  ----------------------------------------------------------------------------------------\n");

    struct flow_key key, next_key;
    const struct flow_key *previous = NULL;
    memset(&key, 0, sizeof(key));
    int count = 0;

    while (bpf_map_get_next_key(map_fd, previous, &next_key) == 0) {
        struct flow_entry entry;
        if (bpf_map_lookup_elem(map_fd, &next_key, &entry) == 0) {
            count++;
            char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
            char src_str[64], dst_str[64];
            address_to_str(next_key.family, next_key.src_ip, &next_key.src_ip6, src_ip, sizeof(src_ip));
            address_to_str(next_key.family, next_key.dst_ip, &next_key.dst_ip6, dst_ip, sizeof(dst_ip));

            __u16 sport = ntohs(next_key.src_port);
            __u16 dport = ntohs(next_key.dst_port);

            snprintf(src_str, sizeof(src_str), next_key.family == FW_AF_INET6 ? "[%s]:%u" : "%s:%u", src_ip, sport);
            snprintf(dst_str, sizeof(dst_str), next_key.family == FW_AF_INET6 ? "[%s]:%u" : "%s:%u", dst_ip, dport);

            const char *proto_str = (next_key.proto == IPPROTO_TCP)  ? "TCP"  :
                                    (next_key.proto == IPPROTO_UDP)  ? "UDP"  :
                                    (next_key.proto == IPPROTO_ICMP) ? "ICMP" :
                                    (next_key.proto == IPPROTO_ICMPV6) ? "ICMPv6" : "OTHER";

            char pkts_str[20];
            char bytes_str[20];
            snprintf(pkts_str, sizeof(pkts_str), "%llu/%llu",
                     (unsigned long long)entry.packets_forward, (unsigned long long)entry.packets_reverse);
            snprintf(bytes_str, sizeof(bytes_str), "%llu/%llu",
                     (unsigned long long)entry.bytes_forward, (unsigned long long)entry.bytes_reverse);

            printf("  %-6s | %-21s | %-21s | %-12s | %-12s | %-12s\n",
                   proto_str, src_str, dst_str, state_to_str(entry.state), pkts_str, bytes_str);
        }
        key = next_key;
        previous = &key;
    }

    if (count == 0) {
        printf("    (Table is empty.)\n");
    }
    return count;
}

int conntrack_mgr_list(int map_fd)
{
    return conntrack_mgr_list_dual(map_fd, -1);
}

int conntrack_mgr_list_dual(int estab_map_fd, int syn_map_fd)
{
    printf("========================================================================================\n");
    printf("                   DUAL-MAP STATEFUL CONNECTION TRACKING TABLES (Step 9)                \n");
    printf("========================================================================================\n");

    int total = 0;
    if (estab_map_fd >= 0) {
        total += conntrack_mgr_list_table(estab_map_fd, "ESTABLISHED / ACTIVE FLOWS (Fast Path Hash Table)");
    }
    if (syn_map_fd >= 0) {
        total += conntrack_mgr_list_table(syn_map_fd, "HALF-OPEN SYN FLOWS (Shield LRU Table)");
    }

    printf("\n========================================================================================\n");
    printf("[+] Total active state entries across all tables: %d\n\n", total);
    return 0;
}

static int conntrack_mgr_flush_single(int map_fd)
{
    if (map_fd < 0) return 0;

    struct flow_key key, next_key;
    memset(&key, 0, sizeof(key));
    int count = 0;

    while (bpf_map_get_next_key(map_fd, NULL, &next_key) == 0) {
        if (bpf_map_delete_elem(map_fd, &next_key)) return -1;
        count++;
    }
    return count;
}

int conntrack_mgr_flush(int map_fd)
{
    return conntrack_mgr_flush_dual(map_fd, -1);
}

int conntrack_mgr_flush_dual(int estab_map_fd, int syn_map_fd)
{
    int count = conntrack_mgr_flush_single(estab_map_fd);
    if (syn_map_fd >= 0) {
        count += conntrack_mgr_flush_single(syn_map_fd);
    }
    printf("[+] Flushed %d connection tracking entries across tables.\n", count);
    return 0;
}

static int conntrack_mgr_gc_sweep_single(int map_fd)
{
    if (map_fd < 0) return 0;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    __u64 now_ns = (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    struct flow_key key, next_key;
    memset(&key, 0, sizeof(key));
    int evicted = 0;

    #define MAX_BATCH_EVICT 1024
    struct flow_key evict_keys[MAX_BATCH_EVICT];
    int batch_count = 0;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        struct flow_entry entry;
        if (bpf_map_lookup_elem(map_fd, &next_key, &entry) == 0) {
            if (entry.state == CONN_STATE_CLOSED ||
                (now_ns > entry.last_seen_ns && (now_ns - entry.last_seen_ns > entry.timeout_ns))) {
                if (batch_count < MAX_BATCH_EVICT) {
                    evict_keys[batch_count++] = next_key;
                }
            }
        }
        key = next_key;
    }

    for (int i = 0; i < batch_count; i++) {
        if (bpf_map_delete_elem(map_fd, &evict_keys[i]) == 0) {
            evicted++;
        }
    }

    return evicted;
}

int conntrack_mgr_gc_sweep(int map_fd)
{
    return conntrack_mgr_gc_sweep_dual(map_fd, -1);
}

int conntrack_mgr_gc_sweep_dual(int estab_map_fd, int syn_map_fd)
{
    int evicted = conntrack_mgr_gc_sweep_single(estab_map_fd);
    if (syn_map_fd >= 0) {
        evicted += conntrack_mgr_gc_sweep_single(syn_map_fd);
    }
    return evicted;
}

static pthread_t g_gc_thread;
static volatile int g_gc_running = 0;
static int g_gc_estab_fd = -1;
static int g_gc_syn_fd = -1;
static int g_gc_interval_sec = 1;

static void *conntrack_gc_worker(void *arg)
{
    while (g_gc_running) {
        sleep(g_gc_interval_sec);
        if (!g_gc_running) break;
        conntrack_mgr_gc_sweep_dual(g_gc_estab_fd, g_gc_syn_fd);
    }
    return NULL;
}

int conntrack_mgr_start_gc(int estab_map_fd, int syn_map_fd, int interval_sec)
{
    if (estab_map_fd < 0 && syn_map_fd < 0) return -1;
    if (g_gc_running) return 0;

    g_gc_estab_fd = estab_map_fd;
    g_gc_syn_fd = syn_map_fd;
    g_gc_interval_sec = interval_sec > 0 ? interval_sec : 1;
    g_gc_running = 1;

    if (pthread_create(&g_gc_thread, NULL, conntrack_gc_worker, NULL) != 0) {
        g_gc_running = 0;
        return -1;
    }
    return 0;
}

void conntrack_mgr_stop_gc(void)
{
    if (!g_gc_running) return;
    g_gc_running = 0;
    pthread_join(g_gc_thread, NULL);
}
