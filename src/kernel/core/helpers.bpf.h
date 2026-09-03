#ifndef __CORE_HELPERS_BPF_H__
#define __CORE_HELPERS_BPF_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <core/types.h>
#include "context.bpf.h"
#include "maps.bpf.h"

/* Increment per-CPU stats counter safely */
static __always_inline void inc_stat(__u32 counter_key)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &counter_key);
    if (val) {
        *val += 1;
    }
}

/* Construct forward 5-tuple flow key */
static __always_inline void make_flow_key(const struct pkt_ctx *pkt, struct flow_key *key)
{
    key->src_ip = pkt->src_ip;
    key->dst_ip = pkt->dst_ip;
    key->src_port = pkt->src_port;
    key->dst_port = pkt->dst_port;
    key->proto = pkt->proto;
    key->pad[0] = 0;
    key->pad[1] = 0;
    key->pad[2] = 0;
}

/* Construct reverse 5-tuple flow key */
static __always_inline void make_reverse_flow_key(const struct pkt_ctx *pkt, struct flow_key *key)
{
    key->src_ip = pkt->dst_ip;
    key->dst_ip = pkt->src_ip;
    key->src_port = pkt->dst_port;
    key->dst_port = pkt->src_port;
    key->proto = pkt->proto;
    key->pad[0] = 0;
    key->pad[1] = 0;
    key->pad[2] = 0;
}

/* Emit 5-tuple packet event to Userspace RingBuffer */
static __always_inline void emit_packet_event(const struct pkt_ctx *pkt)
{
    struct packet_event *evt;

    evt = bpf_ringbuf_reserve(&events_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->src_ip = pkt->src_ip;
    evt->dst_ip = pkt->dst_ip;
    evt->src_port = pkt->src_port;
    evt->dst_port = pkt->dst_port;
    evt->proto = pkt->proto;
    evt->direction = pkt->direction;
    evt->action = pkt->action;
    evt->conn_state = pkt->conn_state;
    evt->rule_id = pkt->rule_id;
    evt->pkt_len = pkt->pkt_len;
    evt->tcp_flags = pkt->tcp_flags;
    evt->pad[0] = 0;
    evt->pad[1] = 0;
    evt->pad[2] = 0;

    bpf_ringbuf_submit(evt, 0);
}

#endif /* __CORE_HELPERS_BPF_H__ */
