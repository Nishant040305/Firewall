#ifndef NETWORK_LOG_H
#define NETWORK_LOG_H

#include <stdio.h>
#include <core/types.h>

#define NETWORK_LOG_BUCKETS 2048

struct network_log_entry {
    struct packet_event event;
    __u64 count, bytes, last_ns;
};

struct network_log {
    FILE *file;
    char path[512];
    size_t size, max_bytes;
    unsigned window_sec;
    int console;
    long long clock_offset_ns;
    __u64 received, invalid, evictions, write_errors;
    struct network_log_entry entries[NETWORK_LOG_BUCKETS];
};

int network_log_init(struct network_log *log, const char *path,
                     unsigned window_sec, size_t max_bytes, int console);
void network_log_record(struct network_log *log, const struct packet_event *evt);
void network_log_flush(struct network_log *log);
void network_log_health(struct network_log *log, __u64 kernel_lost, int stats_available);
void network_log_close(struct network_log *log);

#endif
