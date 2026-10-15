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
    if (data_sz != sizeof(*evt)) return 0;
    char buf[256];
    const struct protocol_adapter *adapter = protocol_registry_get(evt->proto);
    if (adapter && adapter->format_event) {
        adapter->format_event(evt, buf, sizeof(buf));
        printf("%s\n", buf);
    } else {
        char src[46], dst[46];
        address_to_str(evt->family, evt->src_ip, &evt->src_ip6, src, sizeof(src));
        address_to_str(evt->family, evt->dst_ip, &evt->dst_ip6, dst, sizeof(dst));
        const char *dir_str = (evt->direction == DIR_INGRESS) ? "IN " :
                              (evt->direction == DIR_EGRESS)  ? "OUT" : "---";
        printf("[PACKET] %s | Proto %u | %s -> %s (%u bytes) | Time(ns): ext=%u hash=%u lkp=%u upd=%u tot=%u\n",
               dir_str, evt->proto, src, dst, evt->pkt_len,
               evt->time_extract_ns, evt->time_hash_ns,
               evt->time_lookup_ns, evt->time_update_ns, evt->time_total_ns);
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
    if (bus->rb) {
        ring_buffer__free(bus->rb);
        bus->rb = NULL;
    }
}
