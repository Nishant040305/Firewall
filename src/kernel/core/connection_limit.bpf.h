#ifndef __CORE_CONNECTION_LIMIT_BPF_H__
#define __CORE_CONNECTION_LIMIT_BPF_H__
#include <core/connection_limit.h>
#include "context.bpf.h"
#include "maps.bpf.h"
#include "helpers.bpf.h"

/* Accumulate differences rather than branching on each tuple word. */
static __always_inline int connection_flow_equal(const struct flow_key *a, const struct flow_key *b)
{
    volatile __u32 difference = 0;
    #ifdef __clang__
    #pragma unroll
    #endif
    for (__u32 i = 0; i < sizeof(*a) / sizeof(__u32); i++) {
        __u32 left, right;
        __builtin_memcpy(&left, (const char *)a + i * sizeof(__u32), sizeof(left));
        __builtin_memcpy(&right, (const char *)b + i * sizeof(__u32), sizeof(right));
        difference |= left ^ right;
    }
    return difference == 0;
}

static __always_inline void connection_source_key(const struct flow_key *flow,
                                                  struct connection_source *key)
{
    *key = (struct connection_source){.family = flow->family};
    if (flow->family == FW_AF_INET6)
        __builtin_memcpy(key->address, flow->src_ip6.words, sizeof(key->address));
    else
        key->address[0] = flow->src_ip;
}

static __always_inline int connection_slot_live(const struct connection_slot *slot, __u64 now)
{
    return slot->timeout_ns && now <= slot->expires_ns;
}

/* Caller holds the source lock. No helpers inside critical sections. */
static __always_inline int connection_find_slot(struct connection_source_slots *source,
                                                 const struct flow_key *flow, __u64 now)
{
    #ifdef __clang__
    #pragma clang loop unroll(disable)
    #endif
    for (__u32 i = 0; i < CONN_LIMIT_SLOTS; i++)
        if (connection_slot_live(&source->slots[i], now) &&
            connection_flow_equal(&source->slots[i].flow, flow)) return i;
    return -1;
}

static __always_inline void connection_cache_hint(const struct flow_key *flow,
                                                   const struct connection_hint *hint)
{
    bpf_map_update_elem(&conn_limit_hint, flow, hint, BPF_ANY);
}

/* Admission happens after SYN policy checks, before conntrack allocation.
 * Source-slot admission/counting is atomic across CPUs and independent of LRU CT. */
static __always_inline int connection_limit_admit(struct pkt_ctx *pkt, __u64 now)
{
    if (!pkt) return 0;
    if (pkt->direction != DIR_INGRESS) return 1;
    __u32 scope = pkt->ifindex;
    __u32 *configured = bpf_map_lookup_elem(&conn_limit_cfg, &scope);
    if (!configured) return 1;
    __u32 limit = *configured;
    if (!limit || limit > CONN_LIMIT_SLOTS) goto denied;
    struct connection_hint hint = {0};
    connection_source_key(&pkt->flow, &hint.source);
    struct connection_source_slots *source = bpf_map_lookup_elem(&conn_limit_src, &hint.source);
    if (!source) {
        __u32 zero = 0;
        struct connection_zero_template *empty = bpf_map_lookup_elem(&conn_limit_zero, &zero);
        if (!empty) goto full;
        bpf_map_update_elem(&conn_limit_src, &hint.source, empty, BPF_NOEXIST);
        source = bpf_map_lookup_elem(&conn_limit_src, &hint.source);
        if (!source) goto full;
    }
    int found = -1, free_slot = -1;
    volatile __u64 occupied = 0;
    bpf_spin_lock(&source->lock);
    found = connection_find_slot(source, &pkt->flow, now);
    if (found < 0) {
        #ifdef __clang__
        #pragma clang loop unroll(disable)
        #endif
        for (__u32 i = 0; i < CONN_LIMIT_SLOTS; i++) {
            struct connection_slot *slot = &source->slots[i];
            /* Monotonic deadlines are less than 2^63 ns apart. Arithmetic
             * avoids per-slot verifier branches; unused deadline zero is past. */
            __u64 active = 1 ^ ((slot->expires_ns - now) >> 63);
            occupied |= active << i;
        }
        __u64 available = (~occupied) & ((1ULL << CONN_LIMIT_SLOTS) - 1);
        if (available) {
            free_slot = 0;
            if (!(available & 0xffffffffULL)) { free_slot += 32; available >>= 32; }
            if (!(available & 0xffffULL)) { free_slot += 16; available >>= 16; }
            if (!(available & 0xffULL)) { free_slot += 8; available >>= 8; }
            if (!(available & 0xfULL)) { free_slot += 4; available >>= 4; }
            if (!(available & 3ULL)) { free_slot += 2; available >>= 2; }
            if (!(available & 1ULL)) free_slot++;
        }
    }
    __u64 bits = occupied;
    bits -= (bits >> 1) & 0x5555555555555555ULL;
    bits = (bits & 0x3333333333333333ULL) + ((bits >> 2) & 0x3333333333333333ULL);
    bits = (bits + (bits >> 4)) & 0x0f0f0f0f0f0f0f0fULL;
    __u32 live = (bits * 0x0101010101010101ULL) >> 56;
    if (found >= 0) {
        /* Retransmission is not a new connection; match CT idle refresh. */
        hint.slot = found;
        struct connection_slot *slot = &source->slots[hint.slot & (CONN_LIMIT_SLOTS - 1)];
        if (now > slot->last_seen_ns) slot->last_seen_ns = now;
        slot->expires_ns = slot->last_seen_ns + slot->timeout_ns;
    } else if (live < limit && free_slot >= 0) {
        hint.slot = free_slot;
        struct connection_slot *slot = &source->slots[hint.slot & (CONN_LIMIT_SLOTS - 1)];
        slot->flow = pkt->flow;
        slot->last_seen_ns = now;
        slot->timeout_ns = TCP_SYN_TIMEOUT_NS;
        slot->expires_ns = now + TCP_SYN_TIMEOUT_NS;
        found = free_slot;
    }
    bpf_spin_unlock(&source->lock);
    if (found < 0) goto denied;
    connection_cache_hint(&pkt->flow, &hint);
    /* Reverse hint is populated on the first accepted response. */
    return 1;
full:
    inc_stat(STAT_CONN_LIMIT_MAP_FULL);
    pkt->reason = REASON_CONN_LIMIT;
    return 0;
denied:
    inc_stat(STAT_CONN_LIMIT_DROP);
    pkt->reason = REASON_CONN_LIMIT;
    return 0;
}

/* Renew accepted activity in either direction, including flow-cache hits.
 * Hint entries are always verified against the full tuple before use. */
__noinline void connection_limit_touch(struct pkt_ctx *pkt, __u64 now)
{
    if (!pkt) return;
    __u32 zero = 0;
    __u32 *enabled = bpf_map_lookup_elem(&conn_limit_on, &zero);
    if (!enabled || !*enabled) return;
    if ((pkt->tcp_flags & 0x02) && !(pkt->tcp_flags & 0x10)) return;
    struct connection_scratch *scratch = bpf_map_lookup_elem(&conn_limit_tmp, &zero);
    if (!scratch) return;
    const struct flow_key *forward = &pkt->flow;
    struct flow_key *reverse = &scratch->reverse;
    make_reverse_flow_key(pkt, reverse);
    struct connection_hint *hint = &scratch->hint;
    *hint = (struct connection_hint){0};
    struct connection_hint *cached = bpf_map_lookup_elem(&conn_limit_hint, forward);
    int found = -1;
    struct connection_source_slots *source = NULL;
    if (cached) {
        *hint = *cached;
        source = bpf_map_lookup_elem(&conn_limit_src, &hint->source);
        if (source && hint->slot < CONN_LIMIT_SLOTS) {
            bpf_spin_lock(&source->lock);
            struct connection_slot *slot = &source->slots[hint->slot & (CONN_LIMIT_SLOTS - 1)];
            if (slot->timeout_ns && (connection_flow_equal(&slot->flow, forward) ||
                                    connection_flow_equal(&slot->flow, reverse))) found = hint->slot;
            bpf_spin_unlock(&source->lock);
        }
    }
    if (found < 0) {
        connection_source_key(forward, &hint->source);
        source = bpf_map_lookup_elem(&conn_limit_src, &hint->source);
        if (source) {
            bpf_spin_lock(&source->lock);
            found = connection_find_slot(source, forward, now);
            bpf_spin_unlock(&source->lock);
        }
        if (found < 0) {
            connection_source_key(reverse, &hint->source);
            source = bpf_map_lookup_elem(&conn_limit_src, &hint->source);
            if (source) {
                bpf_spin_lock(&source->lock);
                found = connection_find_slot(source, reverse, now);
                bpf_spin_unlock(&source->lock);
            }
        }
        if (found < 0) return;
        hint->slot = found;
        connection_cache_hint(forward, hint);
        connection_cache_hint(reverse, hint);
    }
    if (!source || hint->slot >= CONN_LIMIT_SLOTS) return;
    bpf_spin_lock(&source->lock);
    struct connection_slot *slot = &source->slots[hint->slot & (CONN_LIMIT_SLOTS - 1)];
    /* Slot may have been reused after the earlier lookup. */
    if (slot->timeout_ns && (connection_flow_equal(&slot->flow, forward) ||
                             connection_flow_equal(&slot->flow, reverse))) {
        if (now > slot->last_seen_ns) slot->last_seen_ns = now;
        if (pkt->tcp_flags & (0x01 | 0x04))
            slot->timeout_ns = TCP_CLOSE_TIMEOUT_NS;
        else if (pkt->conn_state == CONN_STATE_ESTABLISHED &&
                 slot->timeout_ns != TCP_CLOSE_TIMEOUT_NS)
            slot->timeout_ns = TCP_ESTABLISHED_TIMEOUT_NS;
        slot->expires_ns = slot->last_seen_ns + slot->timeout_ns;
    }
    bpf_spin_unlock(&source->lock);
}
#endif
