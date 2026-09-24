#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <core/constants.h>
#include <core/conntrack.h>

#define DEFAULT_MAP_PIN MAP_PIN_CONNTRACK

static uint64_t get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int count_entries(int map_fd)
{
    struct flow_key key = {0}, next_key = {0};
    int count = 0;
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        count++;
        key = next_key;
    }
    return count;
}

int clear_entries(int map_fd)
{
    struct flow_key key = {0}, next_key = {0};
    int count = 0;
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        bpf_map_delete_elem(map_fd, &next_key);
        count++;
        key = next_key;
    }
    return count;
}

int populate_entries(int map_fd, int target_count)
{
    uint64_t now = get_time_ns();
    uint64_t t_start = get_time_ns();
    int success = 0;
    int failed = 0;

    for (int i = 1; i <= target_count; i++) {
        struct flow_key key;
        memset(&key, 0, sizeof(key));
        key.src_ip = htonl((10 << 24) | (10 << 16) | (1 << 8) | (100 + (i % 150)));
        key.dst_ip = htonl((10 << 24) | (10 << 16) | (2 << 8) | 10);
        key.src_port = htons((uint16_t)(10000 + (i % 55000)));
        key.dst_port = htons(80);
        key.proto = IPPROTO_TCP;

        struct flow_entry entry = {
            .state = CONN_STATE_ESTABLISHED,
            .flags_seen = 0x12, /* SYN-ACK */
            .created_ns = now,
            .last_seen_ns = now,
            .packets_forward = 10,
            .packets_reverse = 10,
            .bytes_forward = 1500,
            .bytes_reverse = 1500,
            .timeout_ns = TCP_ESTABLISHED_TIMEOUT_NS,
        };

        if (bpf_map_update_elem(map_fd, &key, &entry, BPF_ANY) == 0) {
            success++;
        } else {
            failed++;
        }
    }

    uint64_t t_end = get_time_ns();
    double elapsed_s = (double)(t_end - t_start) / 1e9;
    double rate = (elapsed_s > 0) ? (success / elapsed_s) : 0;
    int current_total = count_entries(map_fd);

    printf("{\"action\":\"populate\",\"requested\":%d,\"inserted\":%d,\"failed\":%d,\"current_total\":%d,\"elapsed_sec\":%.6f,\"insert_rate_per_sec\":%.1f}\n",
           target_count, success, failed, current_total, elapsed_s, rate);
    return success;
}

int test_overflow(int map_fd, int target_count)
{
    fprintf(stderr, "[*] Testing state table behavior past capacity (Attempting %d insertions)...\n", target_count);
    return populate_entries(map_fd, target_count);
}

int benchmark_lookups(int map_fd, int num_lookups, int rounds)
{
    if (rounds <= 0) rounds = 5;

    /* Sample existing keys */
    struct flow_key *keys = malloc(sizeof(struct flow_key) * num_lookups);
    if (!keys) return -1;

    struct flow_key k = {0}, next_k = {0};
    int key_count = 0;

    while (key_count < num_lookups && bpf_map_get_next_key(map_fd, &k, &next_k) == 0) {
        keys[key_count++] = next_k;
        k = next_k;
    }

    if (key_count == 0) {
        printf("{\"action\":\"lookup_bench\",\"error\":\"table_empty\"}\n");
        free(keys);
        return 0;
    }

    struct flow_entry val;

    /* 1. CPU & TLB Cache Warmup (2,000 lookups not timed) */
    for (int w = 0; w < 2000; w++) {
        bpf_map_lookup_elem(map_fd, &keys[w % key_count], &val);
    }

    /* 2. Run timed rounds to compute mean, min, max, stddev */
    double round_avg[rounds];
    double total_sum = 0.0;
    double min_ns = 1e9;
    double max_ns = 0.0;
    int total_hits = 0;

    for (int r = 0; r < rounds; r++) {
        uint64_t t_start = get_time_ns();
        int hits = 0;
        for (int i = 0; i < num_lookups; i++) {
            int idx = (i + r * 101) % key_count;
            if (bpf_map_lookup_elem(map_fd, &keys[idx], &val) == 0) {
                hits++;
            }
        }
        uint64_t t_end = get_time_ns();
        double r_avg = (double)(t_end - t_start) / (double)num_lookups;
        round_avg[r] = r_avg;
        total_sum += r_avg;
        total_hits += hits;

        if (r_avg < min_ns) min_ns = r_avg;
        if (r_avg > max_ns) max_ns = r_avg;
    }

    double mean_ns = total_sum / (double)rounds;
    double var_sum = 0.0;
    for (int r = 0; r < rounds; r++) {
        double diff = round_avg[r] - mean_ns;
        var_sum += diff * diff;
    }
    double stddev_ns = sqrt(var_sum / (double)rounds);

    printf("{\"action\":\"lookup_bench\",\"rounds\":%d,\"lookups_per_round\":%d,\"key_pool\":%d,\"hits\":%d,\"mean_ns\":%.2f,\"min_ns\":%.2f,\"max_ns\":%.2f,\"stddev_ns\":%.2f,\"note\":\"userspace_syscall_bpf_map_lookup_elem\"}\n",
           rounds, num_lookups, key_count, total_hits, mean_ns, min_ns, max_ns, stddev_ns);

    free(keys);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <count|clear|populate <N>|overflow <N>|lookup <M> [rounds]> [map_pin_path]\n", argv[0]);
        return 1;
    }

    const char *map_path = DEFAULT_MAP_PIN;
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "{\"error\":\"failed_to_open_map\",\"path\":\"%s\",\"errno\":%d}\n", map_path, errno);
        return 1;
    }

    if (strcmp(argv[1], "count") == 0) {
        int c = count_entries(map_fd);
        printf("{\"action\":\"count\",\"entries\":%d}\n", c);
    } else if (strcmp(argv[1], "clear") == 0) {
        int c = clear_entries(map_fd);
        printf("{\"action\":\"clear\",\"flushed\":%d}\n", c);
    } else if (strcmp(argv[1], "populate") == 0) {
        int target = (argc >= 3) ? atoi(argv[2]) : 1000;
        populate_entries(map_fd, target);
    } else if (strcmp(argv[1], "overflow") == 0) {
        int target = (argc >= 3) ? atoi(argv[2]) : 70000;
        test_overflow(map_fd, target);
    } else if (strcmp(argv[1], "lookup") == 0) {
        int lookups = (argc >= 3) ? atoi(argv[2]) : 10000;
        int rounds = (argc >= 4) ? atoi(argv[3]) : 5;
        benchmark_lookups(map_fd, lookups, rounds);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        close(map_fd);
        return 1;
    }

    close(map_fd);
    return 0;
}
