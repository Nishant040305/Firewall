#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "event_bus.h"

static int ringbuf_sample_handler(void *ctx, void *data, size_t data_sz)
{
    struct event_bus *bus = ctx;
    if (data_sz != sizeof(struct packet_event)) {
        bus->log.invalid++;
        return 0;
    }
    network_log_record(&bus->log, data);
    return 0;
}

int event_bus_init(struct event_bus *bus, int ringbuf_fd, int stats_map_fd,
                   const struct firewall_config *cfg)
{
    memset(bus, 0, sizeof(*bus));
    bus->stats_map_fd = stats_map_fd;
    if (network_log_init(&bus->log, cfg->telemetry.path,
        cfg->telemetry.aggregate_window_sec, (size_t)cfg->telemetry.max_file_mb * 1024 * 1024,
        cfg->telemetry.console_events) < 0) {
        fprintf(stderr, "[-] Cannot open private network log '%s'\n", cfg->telemetry.path);
        return -1;
    }

    if (ringbuf_fd >= 0) {
        bus->rb = ring_buffer__new(ringbuf_fd, ringbuf_sample_handler, bus, NULL);
        if (!bus->rb) {
            fprintf(stderr, "[-] Failed to initialize BPF RingBuffer in EventBus\n");
            network_log_close(&bus->log);
            return -1;
        }
    }

    if (!bus->rb) {
        network_log_close(&bus->log);
        return -1;
    }
    return 0;
}

void event_bus_flush(struct event_bus *bus)
{
    network_log_flush(&bus->log);
    int ncpus = libbpf_num_possible_cpus();
    __u64 lost = 0;
    int available = 0;
    if (ncpus > 0) {
        __u64 values[ncpus];
        __u32 key = STAT_EVENTS_LOST;
        if (bus->stats_map_fd >= 0 && bpf_map_lookup_elem(bus->stats_map_fd, &key, values) == 0) {
            available = 1;
            for (int i = 0; i < ncpus; i++) lost += values[i];
        }
    }
    network_log_health(&bus->log, lost, available);
}

int event_bus_poll(struct event_bus *bus, int timeout_ms)
{
    if (!bus->rb) return -1;
    return ring_buffer__poll(bus->rb, timeout_ms);
}

void event_bus_collect_stats(struct event_bus *bus)
{
    if (bus->stats_map_fd < 0) return;

    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) ncpus = 1;

    __u64 cpu_values[ncpus];
    __u64 totals[STAT_MAX_COUNTERS] = {0};

    for (__u32 key = 0; key < STAT_MAX_COUNTERS; key++) {
        memset(cpu_values, 0, sizeof(cpu_values));
        if (bpf_map_lookup_elem(bus->stats_map_fd, &key, cpu_values) == 0) {
            for (int i = 0; i < ncpus; i++) {
                totals[key] += cpu_values[i];
            }
        }
    }

    printf("\n[STATS] Total: %llu (IN: %llu, OUT: %llu) | TCP: %llu | UDP: %llu | ICMP: %llu | Other: %llu\n",
           (unsigned long long)totals[STAT_TOTAL_PACKETS],
           (unsigned long long)totals[STAT_INGRESS_PACKETS],
           (unsigned long long)totals[STAT_EGRESS_PACKETS],
           (unsigned long long)totals[STAT_TCP_PACKETS],
           (unsigned long long)totals[STAT_UDP_PACKETS],
           (unsigned long long)totals[STAT_ICMP_PACKETS],
           (unsigned long long)totals[STAT_OTHER_PACKETS]);
    fflush(stdout);
}

void event_bus_cleanup(struct event_bus *bus)
{
    if (bus->rb) ring_buffer__consume(bus->rb);
    event_bus_flush(bus);
    network_log_close(&bus->log);
    if (bus->rb) {
        ring_buffer__free(bus->rb);
        bus->rb = NULL;
    }
}
