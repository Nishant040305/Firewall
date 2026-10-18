#ifndef __ENGINE_DISPATCH_BPF_H__
#define __ENGINE_DISPATCH_BPF_H__

#include "timing.bpf.h"
#if FW_CONN_LIMIT
#include "connection_limit.bpf.h"
#endif

/* Instrument only the selected engine. With FW_TIMING=0 none of these
 * timestamps or metric updates exist in the translation unit. */
#if FW_TIMING
#if FW_ENGINE == FW_ENGINE_FASTCACHE
#define FW_LOOKUP_STEP(map) ((void *)(map) == (void *)&flow_cache_map ? STEP_LOOKUP_CACHE : STEP_LOOKUP_CONNTRACK)
#else
#define FW_LOOKUP_STEP(map) STEP_LOOKUP_CONNTRACK
#endif
#define bpf_map_lookup_elem(map, key) ({ \
    __u64 start_ = bpf_ktime_get_ns(); \
    void *result_ = bpf_map_lookup_elem(map, key); \
    __u64 ns_ = bpf_ktime_get_ns() - start_; \
    record_step_time(FW_LOOKUP_STEP(map), ns_); \
    pkt->time_lookup_ns += ns_; \
    result_; \
})
#define bpf_map_update_elem(map, key, value, flags) ({ \
    __u64 start_ = bpf_ktime_get_ns(); \
    long result_ = bpf_map_update_elem(map, key, value, flags); \
    __u64 ns_ = bpf_ktime_get_ns() - start_; \
    record_step_time(STEP_UPDATE_CONNTRACK, ns_); \
    pkt->time_update_ns += ns_; \
    result_; \
})
#define bpf_map_delete_elem(map, key) ({ \
    __u64 start_ = bpf_ktime_get_ns(); \
    long result_ = bpf_map_delete_elem(map, key); \
    __u64 ns_ = bpf_ktime_get_ns() - start_; \
    record_step_time(STEP_UPDATE_CONNTRACK, ns_); \
    pkt->time_update_ns += ns_; \
    result_; \
})
#endif

/* One engine, selected by the preprocessor; no runtime dispatch. */
#if FW_ENGINE == FW_ENGINE_DUALMAP
#include "../engines/single.bpf.h"
#include "../engines/dualmap.bpf.h"
#else
#include "../engines/single.bpf.h"
#endif

#if FW_TIMING
#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef bpf_map_delete_elem
#undef FW_LOOKUP_STEP
#endif

#endif
