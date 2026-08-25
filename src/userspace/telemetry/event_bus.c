#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "event_bus.h"
#include "../protocols/protocol_registry.h"
#include "../utils/ip_utils.h"

static int ringbuf_sample_handler(void *ctx, void *data, size_t data_sz)
{
    const struct packet_event *evt = (const struct packet_event *)data;
    char buf[256];
    const struct protocol_adapter *adapter = protocol_registry_get(evt->proto);
    if (adapter && adapter->format_event) {
        adapter->format_event(evt, buf, sizeof(buf));
        printf("%s\n", buf);
    } else {
        char src[32], dst[32];
        ip_to_str(evt->src_ip, src, sizeof(src));
        ip_to_str(evt->dst_ip, dst, sizeof(dst));
        printf("[PACKET] Proto %u | %s -> %s (%u bytes)\n", evt->proto, src, dst, evt->pkt_len);
    }
    return 0;
}

int event_bus_init(struct event_bus *bus, int ringbuf_fd, int stats_map_fd)
{
    memset(bus, 0, sizeof(*bus));
    bus->stats_map_fd = stats_map_fd;

    if (ringbuf_fd >= 0) {
        bus->rb = ring_buffer__new(ringbuf_fd, ringbuf_sample_handler, bus, NULL);
        if (!bus->rb) {
            fprintf(stderr, "[-] Failed to initialize BPF RingBuffer in EventBus\n");
            return -1;
        }
    }

    return 0;
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

    printf("\n[STATS] Total: %llu | TCP: %llu | UDP: %llu | ICMP: %llu | Other: %llu\n",
           (unsigned long long)totals[STAT_TOTAL_PACKETS],
           (unsigned long long)totals[STAT_TCP_PACKETS],
           (unsigned long long)totals[STAT_UDP_PACKETS],
           (unsigned long long)totals[STAT_ICMP_PACKETS],
           (unsigned long long)totals[STAT_OTHER_PACKETS]);
    fflush(stdout);
}

void event_bus_cleanup(struct event_bus *bus)
{
    if (bus->rb) {
        ring_buffer__free(bus->rb);
        bus->rb = NULL;
    }
}
