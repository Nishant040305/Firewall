#ifndef __CORE_HELPERS_BPF_H__
#define __CORE_HELPERS_BPF_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <core/types.h>
#include "context.bpf.h"
#include "maps.bpf.h"
#include "timing.bpf.h"

#ifdef NO_OBSERVABILITY
#define inc_stat(counter_key) do {} while (0)
#else
/* Increment per-CPU stats counter safely */
static __always_inline void inc_stat(__u32 counter_key)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &counter_key);
    if (val) {
        *val += 1;
    }
}
#endif

/* Compare every address/family word; hash collisions must never authorize flows. */
static __always_inline int flow_keys_equal(const struct flow_key *a, const struct flow_key *b)
{
    const __u32 *w1 = (const __u32 *)a;
    const __u32 *w2 = (const __u32 *)b;
    int equal = 1;
    #pragma unroll
    for (int i = 0; i < sizeof(*a) / sizeof(__u32); i++)
        equal &= w1[i] == w2[i];
    return equal;
}

/* Fast 5-Tuple hash calculation */
static __always_inline __u32 calc_flow_hash(const struct flow_key *key)
{
#if FW_TIMING
    __u64 start = bpf_ktime_get_ns();
#endif
    __u32 h = key->src_ip ^ key->dst_ip;
    #pragma unroll
    for (int i = 0; i < 4; i++)
        h = (h * 16777619u) ^ key->src_ip6.words[i] ^ key->dst_ip6.words[i];
    h ^= key->family;
    h ^= ((__u32)key->src_port << 16) | key->dst_port;
    h ^= key->proto;
    h = (h ^ (h >> 16)) * 0x45d9f3b;
    h = (h ^ (h >> 16)) * 0x45d9f3b;
    h = h ^ (h >> 16);
#if FW_TIMING
    record_step_time(STEP_HASH_CAL, bpf_ktime_get_ns() - start);
#endif
    return h;
}

/* Construct forward 5-tuple flow key (direct struct copy from pre-populated pkt->flow) */
static __always_inline void make_flow_key(const struct pkt_ctx *pkt, struct flow_key *key)
{
    *key = pkt->flow;
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
    key->src_ip6 = pkt->dst_ip6;
    key->dst_ip6 = pkt->src_ip6;
    key->family = pkt->family;
    __builtin_memset(key->family_pad, 0, sizeof(key->family_pad));
}

/* Emit 5-tuple packet event to Userspace RingBuffer */
#ifndef MINIMAL_OBSERVABILITY
static __always_inline void emit_packet_event(const struct pkt_ctx *pkt)
{
    struct packet_event *evt;

    evt = bpf_ringbuf_reserve(&events_ringbuf, sizeof(*evt), 0);
    if (!evt) {
        inc_stat(STAT_EVENTS_LOST);
        return;
    }

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
    evt->reason = pkt->reason;
    evt->new_flow = pkt->new_flow;
    evt->pad = 0;
    evt->ifindex = pkt->ifindex;
    evt->src_ip6 = pkt->src_ip6;
    evt->dst_ip6 = pkt->dst_ip6;
    evt->family = pkt->family;
    __builtin_memset(evt->family_pad, 0, sizeof(evt->family_pad));

    bpf_ringbuf_submit(evt, 0);
}
#endif

#endif /* __CORE_HELPERS_BPF_H__ */
