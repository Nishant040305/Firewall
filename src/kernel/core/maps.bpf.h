#ifndef __CORE_MAPS_BPF_H__
#define __CORE_MAPS_BPF_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <core/types.h>
#include <core/constants.h>
#include <core/stats.h>
#include <core/rules.h>
#include <core/conntrack.h>
#if FW_CONN_LIMIT
#include <core/connection_limit.h>
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); /* Selected ingress interface. */
    __type(value, __u32); /* Maximum concurrent TCP connections per source. */
    __uint(max_entries, 16);
} conn_limit_cfg SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} conn_limit_on SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct connection_source);
    __type(value, struct connection_source_slots);
    __uint(max_entries, CONN_LIMIT_SOURCES);
} conn_limit_src SEC(".maps");
/* This is only an accelerator; source slots are authoritative after eviction. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct connection_hint);
    __uint(max_entries, CONN_LIMIT_HINTS);
} conn_limit_hint SEC(".maps");
/* Preallocated all-zero template avoids placing a large value on the BPF stack. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct connection_zero_template);
    __uint(max_entries, 1);
} conn_limit_zero SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct connection_scratch);
    __uint(max_entries, 1);
} conn_limit_tmp SEC(".maps");
#endif
#if FW_ANTI_SPOOF
#include <core/anti_spoof.h>
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, ANTI_SPOOF_MAX_SCOPES);
} anti_spoof_scopes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct anti_spoof_key);
    __type(value, __u32);
    __uint(max_entries, ANTI_SPOOF_MAX_PREFIXES);
} anti_spoof_prefix SEC(".maps");
#endif
#if FW_RATE_LIMIT
#include <core/rate_limit.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct syn_rate_config);
    __uint(max_entries, RATE_SCOPE_ENTRIES);
} syn_rate_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct rate_bucket);
    __uint(max_entries, RATE_SCOPE_ENTRIES);
} syn_rate_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rate_source_key);
    __type(value, struct rate_bucket);
    __uint(max_entries, RATE_SOURCE_ENTRIES);
} syn_rate_sources SEC(".maps");
#endif

/* Per-CPU Statistics for High-Throughput */
#ifndef NO_OBSERVABILITY
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_MAX_COUNTERS);
} stats_map SEC(".maps");
#endif

/* Ring Buffer for Real-Time 5-Tuple Event Streaming to Userspace */
#ifndef MINIMAL_OBSERVABILITY
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_EVENT_SIZE);
} events_ringbuf SEC(".maps");
#endif

/* Dynamic Firewall Rule Table (Step 8) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct fw_rule);
    __uint(max_entries, MAX_RULE_ENTRIES);
} rules_map SEC(".maps");

/* Stateful Connection Tracking Table (Step 9) - LRU Hash prevents exhaustion */
struct {
#if FW_ENGINE == FW_ENGINE_DUALMAP
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
#endif
    __type(key, struct flow_key);
    __type(value, struct flow_entry);
    __uint(max_entries, MAX_FLOW_ENTRIES);
#if FW_ENGINE != FW_ENGINE_DUALMAP
    __uint(map_flags, BPF_F_NO_COMMON_LRU);
#endif
} conntrack_map SEC(".maps");

/* L1 Per-CPU Direct-Indexed Flow Cache for O(1) Fast-Path Conntrack Bypass */
#if FW_ENGINE == FW_ENGINE_FASTCACHE
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct flow_cache_entry);
    __uint(max_entries, FLOW_CACHE_ENTRIES);
} flow_cache_map SEC(".maps");
#endif

#if FW_ENGINE == FW_ENGINE_DUALMAP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_entry);
    __uint(max_entries, MAX_SYN_FLOW_ENTRIES);
    __uint(map_flags, BPF_F_NO_COMMON_LRU);
} ct_syn_map SEC(".maps");
#endif

#if FW_TIMING
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct step_metric);
    __uint(max_entries, STEP_MAX_OPS);
} perf_map SEC(".maps");
#endif

#endif /* __CORE_MAPS_BPF_H__ */
