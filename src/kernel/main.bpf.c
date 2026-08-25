#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

#include <core/types.h>
#include <core/constants.h>
#include <core/stats.h>

#include "core/context.bpf.h"
#include "core/maps.bpf.h"
#include "core/helpers.bpf.h"

#include "protocols/proto_eth.bpf.h"
#include "protocols/proto_ipv4.bpf.h"
#include "protocols/proto_tcp.bpf.h"
#include "protocols/proto_udp.bpf.h"
#include "protocols/proto_icmp.bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* Minimalist Stateless 5-Tuple Parser & Pass Pipeline */
SEC("xdp")
int xdp_firewall_prog(struct xdp_md *ctx)
{
    struct pkt_ctx pkt;

    /* 1. Context initialization */
    if (pkt_ctx_init(&pkt, ctx) < 0) {
        return XDP_PASS;
    }

    /* 2. L2: Ethernet Parsing */
    if (parse_eth(&pkt) < 0) {
        return XDP_PASS;
    }

    /* Pass non-IPv4 traffic (e.g. ARP, IPv6) directly */
    if (pkt.eth_proto != ETH_P_IP) {
        return XDP_PASS;
    }

    /* 3. L3: IPv4 Parsing */
    if (parse_ipv4(&pkt) < 0) {
        return XDP_PASS;
    }

    inc_stat(STAT_TOTAL_PACKETS);

    /* 4. L4: Protocol Parsing & 5-Tuple Extraction */
    switch (pkt.proto) {
    case IPPROTO_TCP:
        if (parse_tcp(&pkt) == 0) {
            inc_stat(STAT_TCP_PACKETS);
            emit_packet_event(&pkt);
        }
        break;
    case IPPROTO_UDP:
        if (parse_udp(&pkt) == 0) {
            inc_stat(STAT_UDP_PACKETS);
            emit_packet_event(&pkt);
        }
        break;
    case IPPROTO_ICMP:
        if (parse_icmp(&pkt) == 0) {
            inc_stat(STAT_ICMP_PACKETS);
            emit_packet_event(&pkt);
        }
        break;
    default:
        inc_stat(STAT_OTHER_PACKETS);
        emit_packet_event(&pkt);
        break;
    }

    /* Always pass traffic */
    return XDP_PASS;
}
