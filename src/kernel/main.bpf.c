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
#include "protocols/proto_ipv6.bpf.h"
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
    __u64 t_start = bpf_ktime_get_ns();

    /* 1. L2: Ethernet Parsing */
    if (parse_eth(pkt) < 0) {
        pkt->time_extract_ns = (__u32)(bpf_ktime_get_ns() - t_start);
        pkt->time_total_ns = pkt->time_extract_ns;
        record_step_time(STEP_EXTRACTION, pkt->time_extract_ns);
        record_step_time(STEP_TOTAL_PIPELINE, pkt->time_total_ns);
        return ACTION_PASS;
    }

    /* ARP and other non-IP traffic remain outside IP policy. */
    if (pkt->eth_proto != ETH_P_IP && pkt->eth_proto != ETH_P_IPV6) {
        pkt->time_extract_ns = (__u32)(bpf_ktime_get_ns() - t_start);
        pkt->time_total_ns = pkt->time_extract_ns;
        record_step_time(STEP_EXTRACTION, pkt->time_extract_ns);
        record_step_time(STEP_TOTAL_PIPELINE, pkt->time_total_ns);
        return ACTION_PASS;
    }

    /* 2. L3: IPv4 Parsing */
    if ((pkt->eth_proto == ETH_P_IPV6 ? parse_ipv6(pkt) : parse_ipv4(pkt)) < 0) {
        pkt->time_extract_ns = (__u32)(bpf_ktime_get_ns() - t_start);
        __u64 t_stat_start = bpf_ktime_get_ns();
        inc_stat(STAT_DROPPED_MALFORMED);
        __u64 t_stat_end = bpf_ktime_get_ns();
        pkt->time_update_ns = (__u32)(t_stat_end - t_stat_start);
        pkt->time_total_ns = (__u32)(t_stat_end - t_start);
        record_step_time(STEP_EXTRACTION, pkt->time_extract_ns);
        record_step_time(STEP_UPDATE_STATS, pkt->time_update_ns);
        record_step_time(STEP_UPDATE_TOTAL, pkt->time_update_ns);
        record_step_time(STEP_TOTAL_PIPELINE, pkt->time_total_ns);
        return ACTION_DROP;
    }

    __u64 t_stat_start = bpf_ktime_get_ns();
    inc_stat(STAT_TOTAL_PACKETS);
    if (pkt->direction == DIR_INGRESS) {
        inc_stat(STAT_INGRESS_PACKETS);
    } else if (pkt->direction == DIR_EGRESS) {
        inc_stat(STAT_EGRESS_PACKETS);
    }
    __u64 t_stat_end = bpf_ktime_get_ns();
    __u64 stat_dur = t_stat_end - t_stat_start;
    record_step_time(STEP_UPDATE_STATS, stat_dur);
    pkt->time_update_ns += (__u32)stat_dur;

    __u64 now = t_stat_end;
    int decision = ACTION_PASS;

    /* 3. L4: Protocol Parsing & Extraction + Stateful Engine (Steps 6, 7, 9) */
    switch (pkt->proto) {
    case IPPROTO_TCP:
        if (parse_tcp(pkt) < 0) {
            pkt->time_extract_ns = (__u32)(bpf_ktime_get_ns() - t_start);
            record_step_time(STEP_EXTRACTION, pkt->time_extract_ns);
            inc_stat(STAT_DROPPED_MALFORMED);
            decision = ACTION_DROP;
        } else {
            pkt->time_extract_ns = (__u32)(bpf_ktime_get_ns() - t_start);
            record_step_time(STEP_EXTRACTION, pkt->time_extract_ns);
            inc_stat(STAT_TCP_PACKETS);
            decision = process_tcp_state(pkt, now);
        }
        break;
    case IPPROTO_UDP:
        if (parse_udp(pkt) < 0) {
            pkt->time_extract_ns = (__u32)(bpf_ktime_get_ns() - t_start);
            record_step_time(STEP_EXTRACTION, pkt->time_extract_ns);
            inc_stat(STAT_DROPPED_MALFORMED);
            decision = ACTION_DROP;
        } else {
            pkt->time_extract_ns = (__u32)(bpf_ktime_get_ns() - t_start);
            record_step_time(STEP_EXTRACTION, pkt->time_extract_ns);
            inc_stat(STAT_UDP_PACKETS);
            decision = process_udp_state(pkt, now);
        }
        break;
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        if (parse_icmp(pkt) < 0) {
            pkt->time_extract_ns = (__u32)(bpf_ktime_get_ns() - t_start);
            record_step_time(STEP_EXTRACTION, pkt->time_extract_ns);
            inc_stat(STAT_DROPPED_MALFORMED);
            decision = ACTION_DROP;
        } else {
            pkt->time_extract_ns = (__u32)(bpf_ktime_get_ns() - t_start);
            record_step_time(STEP_EXTRACTION, pkt->time_extract_ns);
            inc_stat(STAT_ICMP_PACKETS);
            now = bpf_ktime_get_ns();
            if (valid_neighbor_discovery(pkt))
                decision = ACTION_PASS;
            else if (pkt->proto == IPPROTO_ICMPV6 && pkt->icmp_type != 128 && pkt->icmp_type != 129)
                decision = evaluate_rules(pkt);
            else
                decision = process_icmp_state(pkt, now);
        }
        break;
    default:
        pkt->time_extract_ns = (__u32)(bpf_ktime_get_ns() - t_start);
        record_step_time(STEP_EXTRACTION, pkt->time_extract_ns);
        inc_stat(STAT_OTHER_PACKETS);
        __u64 t_rule_start = bpf_ktime_get_ns();
        decision = evaluate_rules(pkt);
        __u64 t_rule_end = bpf_ktime_get_ns();
        pkt->time_lookup_ns = (__u32)(t_rule_end - t_rule_start);
        record_step_time(STEP_LOOKUP_RULES, pkt->time_lookup_ns);
        record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);
        pkt->action = decision;
        break;
    }

    /* 4. Update Statistics & Emit Telemetry Event */
    __u64 t_dec_stat_start = bpf_ktime_get_ns();
    if (decision == ACTION_PASS) {
        inc_stat(STAT_ALLOWED_PACKETS);
    } else {
        inc_stat(STAT_DROPPED_PACKETS);
    }
    __u64 t_dec_stat_end = bpf_ktime_get_ns();
    __u64 dec_stat_dur = t_dec_stat_end - t_dec_stat_start;
    record_step_time(STEP_UPDATE_STATS, dec_stat_dur);
    pkt->time_update_ns += (__u32)dec_stat_dur;

#ifndef MINIMAL_OBSERVABILITY
    pkt->action = decision;
    /* Only emit ringbuffer events for drops and state transitions to eliminate bulk data lock contention */
    if (decision == ACTION_DROP ||
        pkt->conn_state == CONN_STATE_SYN_SENT ||
        pkt->conn_state == CONN_STATE_SYN_RECV ||
        pkt->conn_state == CONN_STATE_CLOSED ||
        pkt->conn_state == CONN_STATE_FIN_WAIT ||
        pkt->conn_state == CONN_STATE_NEW ||
        (pkt->proto == IPPROTO_TCP && (pkt->tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST)))) {
        __u64 t_rb_start = bpf_ktime_get_ns();
        pkt->time_total_ns = (__u32)(t_rb_start - t_start);
        emit_packet_event(pkt);
        __u64 t_rb_end = bpf_ktime_get_ns();
        __u64 rb_dur = t_rb_end - t_rb_start;
        record_step_time(STEP_UPDATE_RINGBUF, rb_dur);
        pkt->time_update_ns += (__u32)rb_dur;
    }
#endif

    record_step_time(STEP_UPDATE_TOTAL, pkt->time_update_ns);
    __u64 t_end = bpf_ktime_get_ns();
    pkt->time_total_ns = (__u32)(t_end - t_start);
    record_step_time(STEP_TOTAL_PIPELINE, pkt->time_total_ns);

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
