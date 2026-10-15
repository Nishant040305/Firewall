#include "perf_mgr.h"
#include <core/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static const char *names[STEP_MAX_OPS] = {
    "extraction", "hash", "cache_lookup", "conntrack_lookup", "rule_lookup",
    "lookup_total", "conntrack_update", "stats_update", "ringbuf_update",
    "update_total", "pipeline_total",
};

int perf_mgr_show(int fd, int json)
{
    int cpus = libbpf_num_possible_cpus();
    if (fd < 0 || cpus <= 0) return -1;
    struct step_metric *values = calloc(cpus, sizeof(*values));
    if (!values) return -1;
    if (json) puts("{");
    int result = 0;
    for (__u32 step = 0; step < STEP_MAX_OPS; step++) {
        if (bpf_map_lookup_elem(fd, &step, values)) { result = -1; break; }
        __u64 count = 0, total = 0, min = 0, max = 0;
        for (int cpu = 0; cpu < cpus; cpu++) {
            const struct step_metric *m = &values[cpu];
            count += m->count;
            total += m->total_time_ns;
            if (m->count && (!min || m->min_time_ns < min)) min = m->min_time_ns;
            if (m->max_time_ns > max) max = m->max_time_ns;
        }
        double average = count ? (double)total / count : 0;
        if (json)
            printf("  \"%s\":{\"count\":%llu,\"avg_ns\":%.2f,\"min_ns\":%llu,\"max_ns\":%llu}%s\n",
                   names[step], (unsigned long long)count, average,
                   (unsigned long long)min, (unsigned long long)max,
                   step + 1 == STEP_MAX_OPS ? "" : ",");
        else
            printf("%-20s count=%llu avg=%.2f ns min=%llu max=%llu\n", names[step],
                   (unsigned long long)count, average, (unsigned long long)min, (unsigned long long)max);
    }
    if (json) puts("}");
    free(values);
    return result;
}

int perf_mgr_reset(int fd)
{
    int cpus = libbpf_num_possible_cpus();
    if (fd < 0 || cpus <= 0) return -1;
    struct step_metric *zero = calloc(cpus, sizeof(*zero));
    if (!zero) return -1;
    int result = 0;
    for (__u32 step = 0; step < STEP_MAX_OPS; step++)
        if (bpf_map_update_elem(fd, &step, zero, BPF_ANY)) { result = -1; break; }
    free(zero);
    return result;
}
