#ifndef __CORE_HELPERS_BPF_H__
#define __CORE_HELPERS_BPF_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
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
    evt->pad[0] = 0;
    evt->pad[1] = 0;
    evt->pad[2] = 0;
    evt->pkt_len = pkt->pkt_len;

    bpf_ringbuf_submit(evt, 0);
}

#endif /* __CORE_HELPERS_BPF_H__ */
