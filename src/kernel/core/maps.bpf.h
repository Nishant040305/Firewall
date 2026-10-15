#ifndef __CORE_MAPS_BPF_H__
#define __CORE_MAPS_BPF_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <core/types.h>
#include <core/constants.h>
#include <core/stats.h>
#include <core/rules.h>
#include <core/conntrack.h>

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
