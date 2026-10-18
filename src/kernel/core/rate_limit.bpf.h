#ifndef __CORE_RATE_LIMIT_BPF_H__
#define __CORE_RATE_LIMIT_BPF_H__

#include <core/rate_limit.h>
#include "context.bpf.h"
#include "maps.bpf.h"
#include "helpers.bpf.h"

static __always_inline int syn_rate_allow(struct pkt_ctx *pkt, __u64 now)
{
    if (pkt->direction != DIR_INGRESS)
        return 1;
    __u32 scope = pkt->ifindex;
    struct syn_rate_config *stored = bpf_map_lookup_elem(&syn_rate_config, &scope);
    if (!stored)
        return 1; /* No protection selected for this interface. */
    struct syn_rate_config cfg = *stored;
    int allowed;
    if (cfg.aggregate_enabled) {
        struct rate_bucket *total = bpf_map_lookup_elem(&syn_rate_total, &scope);
        if (!total) {
            inc_stat(STAT_RATE_MAP_FULL);
            goto drop;
        }
        bpf_spin_lock(&total->lock);
        allowed = rate_bucket_take(total, now, cfg.aggregate_rate, cfg.aggregate_burst);
        bpf_spin_unlock(&total->lock);
        if (!allowed) {
            inc_stat(STAT_RATE_AGGREGATE_DROP);
            goto drop;
        }
    }

    struct rate_source_key key = {.ifindex = scope, .family = pkt->family};
    if (pkt->family == FW_AF_INET6)
        __builtin_memcpy(key.address, pkt->src_ip6.words, sizeof(key.address));
    else
        key.address[0] = pkt->src_ip;
    struct rate_bucket *source = bpf_map_lookup_elem(&syn_rate_sources, &key);
    if (!source) {
        struct rate_bucket initial = {
            .last_refill_ns = now,
            .credit = (__u64)cfg.source_burst * RATE_CREDIT_PER_PACKET,
        };
        /* A racing CPU must not reset an existing source's budget. */
        bpf_map_update_elem(&syn_rate_sources, &key, &initial, BPF_NOEXIST);
        source = bpf_map_lookup_elem(&syn_rate_sources, &key);
        if (!source) {
            inc_stat(STAT_RATE_MAP_FULL);
            goto drop;
        }
    }
    bpf_spin_lock(&source->lock);
    allowed = rate_bucket_take(source, now, cfg.source_rate, cfg.source_burst);
    bpf_spin_unlock(&source->lock);
    if (allowed)
        return 1;
    inc_stat(STAT_RATE_SOURCE_DROP);
drop:
    pkt->reason = REASON_RATE_LIMIT;
    return 0;
}

#endif
