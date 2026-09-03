#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <core/types.h>
#include <core/constants.h>
#include <core/stats.h>
#include <core/rules.h>
#include <core/conntrack.h>

#include "core/context.bpf.h"
#include "core/maps.bpf.h"
#include "core/helpers.bpf.h"
#include "core/rules.bpf.h"
#include "core/conntrack.bpf.h"

#include "protocols/proto_eth.bpf.h"
#include "protocols/proto_ipv4.bpf.h"
#include "protocols/proto_tcp.bpf.h"
#include "protocols/proto_udp.bpf.h"
#include "protocols/proto_icmp.bpf.h"

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

char LICENSE[] SEC("license") = "GPL";

/* Shared 5-Tuple Stateful Decision Pipeline */
static __always_inline int process_packet(struct pkt_ctx *pkt)
{
    /* 1. L2: Ethernet Parsing */
    if (parse_eth(pkt) < 0) {
        return ACTION_PASS;
    }

    /* Pass non-IPv4 traffic (e.g. ARP, IPv6 Neighbor Discovery) directly */
    if (pkt->eth_proto != ETH_P_IP) {
        return ACTION_PASS;
    }

    /* 2. L3: IPv4 Parsing */
    if (parse_ipv4(pkt) < 0) {
        inc_stat(STAT_DROPPED_MALFORMED);
        return ACTION_DROP;
    }

    inc_stat(STAT_TOTAL_PACKETS);
    if (pkt->direction == DIR_INGRESS) {
        inc_stat(STAT_INGRESS_PACKETS);
    } else if (pkt->direction == DIR_EGRESS) {
        inc_stat(STAT_EGRESS_PACKETS);
    }

    __u64 now = bpf_ktime_get_ns();
    int decision = ACTION_PASS;

    /* 3. L4: Protocol Parsing & Stateful Engine (Steps 6, 7, 9) */
    switch (pkt->proto) {
    case IPPROTO_TCP:
        if (parse_tcp(pkt) < 0) {
            inc_stat(STAT_DROPPED_MALFORMED);
            decision = ACTION_DROP;
        } else {
            inc_stat(STAT_TCP_PACKETS);
            decision = process_tcp_state(pkt, now);
        }
        break;
    case IPPROTO_UDP:
        if (parse_udp(pkt) < 0) {
            inc_stat(STAT_DROPPED_MALFORMED);
            decision = ACTION_DROP;
        } else {
            inc_stat(STAT_UDP_PACKETS);
            decision = process_udp_state(pkt, now);
        }
        break;
    case IPPROTO_ICMP:
        if (parse_icmp(pkt) < 0) {
            inc_stat(STAT_DROPPED_MALFORMED);
            decision = ACTION_DROP;
        } else {
            inc_stat(STAT_ICMP_PACKETS);
            decision = process_icmp_state(pkt, now);
        }
        break;
    default:
        inc_stat(STAT_OTHER_PACKETS);
        decision = evaluate_rules(pkt);
        pkt->action = decision;
        break;
    }

    /* 4. Update Statistics & Emit Telemetry Event */
    if (decision == ACTION_PASS) {
        inc_stat(STAT_ALLOWED_PACKETS);
    } else {
        inc_stat(STAT_DROPPED_PACKETS);
    }

    emit_packet_event(pkt);
    return decision;
}

/* XDP Program: Ingress Traffic (Step 5) */
SEC("xdp")
int xdp_firewall_prog(struct xdp_md *ctx)
{
    struct pkt_ctx pkt;

    if (pkt_ctx_init_xdp(&pkt, ctx) < 0) {
        return XDP_PASS;
    }

    int decision = process_packet(&pkt);
    if (decision == ACTION_DROP) {
        return XDP_DROP;
    }
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

    int decision = process_packet(&pkt);
    if (decision == ACTION_DROP) {
        return TC_ACT_SHOT;
    }
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

    int decision = process_packet(&pkt);
    if (decision == ACTION_DROP) {
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}
