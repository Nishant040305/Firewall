#include "event_bus.h"
#include "../utils/ip_utils.h"
#include <arpa/inet.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <stdio.h>

static int record(void *context, void *data, size_t size)
{
    (void)context;
    if (size != sizeof(struct packet_event)) return 0;
    const struct packet_event *e = data;
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    address_to_str(e->family, e->src_ip, &e->src_ip6, src, sizeof(src));
    address_to_str(e->family, e->dst_ip, &e->dst_ip6, dst, sizeof(dst));
    printf("[%s] %s | proto=%u %s:%u -> %s:%u state=%u bytes=%u\n",
           e->action == ACTION_PASS ? "ALLOW" : "DROP",
           e->direction == DIR_EGRESS ? "OUT" : "IN", e->proto,
           src, ntohs(e->src_port), dst, ntohs(e->dst_port), e->conn_state, e->pkt_len);
    return 0;
}

int event_bus_init(struct event_bus *bus, int ringbuf_fd, int stats_fd,
                   const struct firewall_config *cfg)
{
    (void)cfg;
    memset(bus, 0, sizeof(*bus));
    bus->stats_map_fd = stats_fd;
    bus->rb = ring_buffer__new(ringbuf_fd, record, bus, NULL);
    return bus->rb ? 0 : -1;
}
int event_bus_poll(struct event_bus *bus, int timeout)
{
    return ring_buffer__poll(bus->rb, timeout);
}
void event_bus_cleanup(struct event_bus *bus)
{
    if (bus->rb) ring_buffer__free(bus->rb);
    bus->rb = NULL;
}
