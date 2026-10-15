#ifndef __TIMING_BPF_H__
#define __TIMING_BPF_H__

#if FW_TIMING
static __always_inline void record_step_time(__u32 step, __u64 ns)
{
    struct step_metric *m = bpf_map_lookup_elem(&perf_map, &step);
    if (!m) return;
    m->total_time_ns += ns;
    m->count++;
    if (!m->min_time_ns || ns < m->min_time_ns) m->min_time_ns = ns;
    if (ns > m->max_time_ns) m->max_time_ns = ns;
}
#endif

#endif
