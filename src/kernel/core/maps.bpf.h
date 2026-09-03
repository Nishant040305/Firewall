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
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_MAX_COUNTERS);
} stats_map SEC(".maps");

/* Ring Buffer for Real-Time 5-Tuple Event Streaming to Userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_EVENT_SIZE);
} events_ringbuf SEC(".maps");

/* Dynamic Firewall Rule Table (Step 8) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct fw_rule);
    __uint(max_entries, MAX_RULE_ENTRIES);
} rules_map SEC(".maps");

/* Stateful Connection Tracking Table (Step 9) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_entry);
    __uint(max_entries, MAX_FLOW_ENTRIES);
} conntrack_map SEC(".maps");

#endif /* __CORE_MAPS_BPF_H__ */
