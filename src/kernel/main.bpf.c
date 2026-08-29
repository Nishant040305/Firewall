#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
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

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

char LICENSE[] SEC("license") = "GPL";

/* Shared 5-Tuple Parser & Telemetry Pipeline */
static __always_inline int process_packet(struct pkt_ctx *pkt)
{
    /* 1. L2: Ethernet Parsing */
    if (parse_eth(pkt) < 0) {
        return 0;
    }

    /* Pass non-IPv4 traffic (e.g. ARP, IPv6) directly */
    if (pkt->eth_proto != ETH_P_IP) {
        return 0;
    }

    /* 2. L3: IPv4 Parsing */
    if (parse_ipv4(pkt) < 0) {
        return 0;
    }

    inc_stat(STAT_TOTAL_PACKETS);
    if (pkt->direction == DIR_INGRESS) {
        inc_stat(STAT_INGRESS_PACKETS);
    } else if (pkt->direction == DIR_EGRESS) {
        inc_stat(STAT_EGRESS_PACKETS);
    }

    /* 3. L4: Protocol Parsing & 5-Tuple Extraction */
    switch (pkt->proto) {
    case IPPROTO_TCP:
        if (parse_tcp(pkt) == 0) {
            inc_stat(STAT_TCP_PACKETS);
            emit_packet_event(pkt);
        }
        break;
    case IPPROTO_UDP:
        if (parse_udp(pkt) == 0) {
            inc_stat(STAT_UDP_PACKETS);
            emit_packet_event(pkt);
        }
        break;
    case IPPROTO_ICMP:
        if (parse_icmp(pkt) == 0) {
            inc_stat(STAT_ICMP_PACKETS);
            emit_packet_event(pkt);
        }
        break;
    default:
        inc_stat(STAT_OTHER_PACKETS);
        emit_packet_event(pkt);
        break;
    }

    return 0;
}

/* XDP Program: Ingress Traffic */
SEC("xdp")
int xdp_firewall_prog(struct xdp_md *ctx)
{
    struct pkt_ctx pkt;

    if (pkt_ctx_init_xdp(&pkt, ctx) < 0) {
        return XDP_PASS;
    }

    process_packet(&pkt);
    return XDP_PASS;
}

/* TC Program: Ingress Traffic */
SEC("tc")
int tc_ingress_prog(struct __sk_buff *skb)
{
    struct pkt_ctx pkt;

    if (pkt_ctx_init_skb(&pkt, skb, DIR_INGRESS) < 0) {
        return TC_ACT_OK;
    }

    process_packet(&pkt);
    return TC_ACT_OK;
}

/* TC Program: Egress Traffic */
SEC("tc")
int tc_egress_prog(struct __sk_buff *skb)
{
    struct pkt_ctx pkt;

    if (pkt_ctx_init_skb(&pkt, skb, DIR_EGRESS) < 0) {
        return TC_ACT_OK;
    }

    process_packet(&pkt);
    return TC_ACT_OK;
}
