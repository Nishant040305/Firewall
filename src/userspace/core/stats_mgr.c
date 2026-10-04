#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "stats_mgr.h"

struct step_metric_summary {
    __u64 total_time_ns;
    __u64 count;
    __u64 min_time_ns;
    __u64 max_time_ns;
    double avg_ns;
};

static const char *step_names[STEP_MAX_OPS] = {
    [STEP_EXTRACTION]       = "1. Header Extraction (L2/L3/L4)",
    [STEP_HASH_CAL]         = "2. Flow Key & Hash Calculation",
    [STEP_LOOKUP_CACHE]     = "3. L1 Flow Cache Lookup",
    [STEP_LOOKUP_CONNTRACK] = "4. Conntrack Table Lookup",
    [STEP_LOOKUP_RULES]     = "5. Dynamic Rule Engine Evaluation",
    [STEP_LOOKUP_TOTAL]     = "-> Total Lookup Stage",
    [STEP_UPDATE_CONNTRACK] = "6. Conntrack State Update / Insert",
    [STEP_UPDATE_STATS]     = "7. Statistics Map Increment",
    [STEP_UPDATE_RINGBUF]   = "8. Telemetry RingBuffer Submission",
    [STEP_UPDATE_TOTAL]     = "-> Total Update Stage",
    [STEP_TOTAL_PIPELINE]   = "★ Total Dataplane Pipeline",
};

static void collect_perf_summaries(int perf_map_fd, struct step_metric_summary *summaries, int ncpus)
{
    struct step_metric cpu_metrics[ncpus];

    for (__u32 op = 0; op < STEP_MAX_OPS; op++) {
        memset(cpu_metrics, 0, sizeof(cpu_metrics));
        __u64 min_ns = (__u64)-1;
        __u64 max_ns = 0;
        __u64 tot_ns = 0;
        __u64 cnt = 0;

        if (bpf_map_lookup_elem(perf_map_fd, &op, cpu_metrics) == 0) {
            for (int c = 0; c < ncpus; c++) {
                tot_ns += cpu_metrics[c].total_time_ns;
                cnt += cpu_metrics[c].count;
                if (cpu_metrics[c].count > 0 && cpu_metrics[c].min_time_ns > 0) {
                    if (cpu_metrics[c].min_time_ns < min_ns) {
                        min_ns = cpu_metrics[c].min_time_ns;
                    }
                }
                if (cpu_metrics[c].max_time_ns > max_ns) {
                    max_ns = cpu_metrics[c].max_time_ns;
                }
            }
        }

        summaries[op].total_time_ns = tot_ns;
        summaries[op].count = cnt;
        summaries[op].min_time_ns = (min_ns == (__u64)-1) ? 0 : min_ns;
        summaries[op].max_time_ns = max_ns;
        summaries[op].avg_ns = (cnt > 0) ? ((double)tot_ns / (double)cnt) : 0.0;
    }
}

int perf_mgr_write_stream(FILE *fp, int perf_map_fd, int json_format)
{
    if (!fp) fp = stdout;
    if (perf_map_fd < 0) {
        if (json_format) {
            fprintf(fp, "{\"error\":\"perf_map_not_found\"}\n");
        } else {
            fprintf(stderr, "[-] Error: Performance & Latency Telemetry map not available.\n");
        }
        return -1;
    }

    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) ncpus = 1;

    struct step_metric_summary summaries[STEP_MAX_OPS];
    memset(summaries, 0, sizeof(summaries));
    collect_perf_summaries(perf_map_fd, summaries, ncpus);

    double peak_mpps = (summaries[STEP_TOTAL_PIPELINE].avg_ns > 0) ? (1000.0 / summaries[STEP_TOTAL_PIPELINE].avg_ns) : 0.0;

    if (json_format) {
        fprintf(fp, "{\n");
        fprintf(fp, "  \"timing_analysis\": {\n");
        fprintf(fp, "    \"extraction\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_EXTRACTION].count, summaries[STEP_EXTRACTION].avg_ns,
               (unsigned long long)summaries[STEP_EXTRACTION].min_time_ns, (unsigned long long)summaries[STEP_EXTRACTION].max_time_ns,
               (double)summaries[STEP_EXTRACTION].total_time_ns / 1e6);
        fprintf(fp, "    \"hash_calculation\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_HASH_CAL].count, summaries[STEP_HASH_CAL].avg_ns,
               (unsigned long long)summaries[STEP_HASH_CAL].min_time_ns, (unsigned long long)summaries[STEP_HASH_CAL].max_time_ns,
               (double)summaries[STEP_HASH_CAL].total_time_ns / 1e6);
        fprintf(fp, "    \"flow_cache_lookup\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_LOOKUP_CACHE].count, summaries[STEP_LOOKUP_CACHE].avg_ns,
               (unsigned long long)summaries[STEP_LOOKUP_CACHE].min_time_ns, (unsigned long long)summaries[STEP_LOOKUP_CACHE].max_time_ns,
               (double)summaries[STEP_LOOKUP_CACHE].total_time_ns / 1e6);
        fprintf(fp, "    \"conntrack_lookup\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_LOOKUP_CONNTRACK].count, summaries[STEP_LOOKUP_CONNTRACK].avg_ns,
               (unsigned long long)summaries[STEP_LOOKUP_CONNTRACK].min_time_ns, (unsigned long long)summaries[STEP_LOOKUP_CONNTRACK].max_time_ns,
               (double)summaries[STEP_LOOKUP_CONNTRACK].total_time_ns / 1e6);
        fprintf(fp, "    \"rules_lookup\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_LOOKUP_RULES].count, summaries[STEP_LOOKUP_RULES].avg_ns,
               (unsigned long long)summaries[STEP_LOOKUP_RULES].min_time_ns, (unsigned long long)summaries[STEP_LOOKUP_RULES].max_time_ns,
               (double)summaries[STEP_LOOKUP_RULES].total_time_ns / 1e6);
        fprintf(fp, "    \"lookup_total\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_LOOKUP_TOTAL].count, summaries[STEP_LOOKUP_TOTAL].avg_ns,
               (unsigned long long)summaries[STEP_LOOKUP_TOTAL].min_time_ns, (unsigned long long)summaries[STEP_LOOKUP_TOTAL].max_time_ns,
               (double)summaries[STEP_LOOKUP_TOTAL].total_time_ns / 1e6);
        fprintf(fp, "    \"conntrack_update\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_UPDATE_CONNTRACK].count, summaries[STEP_UPDATE_CONNTRACK].avg_ns,
               (unsigned long long)summaries[STEP_UPDATE_CONNTRACK].min_time_ns, (unsigned long long)summaries[STEP_UPDATE_CONNTRACK].max_time_ns,
               (double)summaries[STEP_UPDATE_CONNTRACK].total_time_ns / 1e6);
        fprintf(fp, "    \"stats_update\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_UPDATE_STATS].count, summaries[STEP_UPDATE_STATS].avg_ns,
               (unsigned long long)summaries[STEP_UPDATE_STATS].min_time_ns, (unsigned long long)summaries[STEP_UPDATE_STATS].max_time_ns,
               (double)summaries[STEP_UPDATE_STATS].total_time_ns / 1e6);
        fprintf(fp, "    \"ringbuf_update\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_UPDATE_RINGBUF].count, summaries[STEP_UPDATE_RINGBUF].avg_ns,
               (unsigned long long)summaries[STEP_UPDATE_RINGBUF].min_time_ns, (unsigned long long)summaries[STEP_UPDATE_RINGBUF].max_time_ns,
               (double)summaries[STEP_UPDATE_RINGBUF].total_time_ns / 1e6);
        fprintf(fp, "    \"update_total\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_UPDATE_TOTAL].count, summaries[STEP_UPDATE_TOTAL].avg_ns,
               (unsigned long long)summaries[STEP_UPDATE_TOTAL].min_time_ns, (unsigned long long)summaries[STEP_UPDATE_TOTAL].max_time_ns,
               (double)summaries[STEP_UPDATE_TOTAL].total_time_ns / 1e6);
        fprintf(fp, "    \"pipeline_total\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_TOTAL_PIPELINE].count, summaries[STEP_TOTAL_PIPELINE].avg_ns,
               (unsigned long long)summaries[STEP_TOTAL_PIPELINE].min_time_ns, (unsigned long long)summaries[STEP_TOTAL_PIPELINE].max_time_ns,
               (double)summaries[STEP_TOTAL_PIPELINE].total_time_ns / 1e6);
        fprintf(fp, "    \"peak_mpps_single_core\": %.2f\n", peak_mpps);
        fprintf(fp, "  }\n");
        fprintf(fp, "}\n");
        return 0;
    }

    fprintf(fp, "====================================================================================================\n");
    fprintf(fp, "                  FIREWALL COMPONENT & OPERATION TIMING ANALYSIS (Step 11)                          \n");
    fprintf(fp, "====================================================================================================\n");
    fprintf(fp, "  %-36s | %13s | %10s | %10s | %10s | %10s\n",
           "Operation / Component", "Packets", "Avg (ns)", "Min (ns)", "Max (ns)", "Total (ms)");
    fprintf(fp, "-------------------------------------+---------------+------------+------------+------------+-----------\n");

    for (__u32 op = 0; op < STEP_MAX_OPS; op++) {
        if (op == STEP_TOTAL_PIPELINE) {
            fprintf(fp, "-------------------------------------+---------------+------------+------------+------------+-----------\n");
        }
        fprintf(fp, "  %-35s | %13llu | %10.2f | %10llu | %10llu | %10.3f\n",
               step_names[op],
               (unsigned long long)summaries[op].count,
               summaries[op].avg_ns,
               (unsigned long long)summaries[op].min_time_ns,
               (unsigned long long)summaries[op].max_time_ns,
               (double)summaries[op].total_time_ns / 1e6);
    }

    fprintf(fp, "====================================================================================================\n");
    fprintf(fp, "  Estimated Single-Core Peak Throughput: %.2f Mpps (%.2f ns / packet)\n",
           peak_mpps, summaries[STEP_TOTAL_PIPELINE].avg_ns);
    fprintf(fp, "====================================================================================================\n\n");

    return 0;
}

int perf_mgr_show(int perf_map_fd, int json_format)
{
    return perf_mgr_write_stream(stdout, perf_map_fd, json_format);
}

int perf_mgr_reset(int perf_map_fd)
{
    if (perf_map_fd < 0) return -1;

    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) ncpus = 1;

    struct step_metric zeroes[ncpus];
    memset(zeroes, 0, sizeof(zeroes));

    for (__u32 key = 0; key < STEP_MAX_OPS; key++) {
        bpf_map_update_elem(perf_map_fd, &key, zeroes, BPF_ANY);
    }

    printf("[+] Firewall performance & latency telemetry metrics reset to zero.\n");
    return 0;
}

int stats_mgr_write_stream(FILE *fp, int map_fd, int perf_map_fd, int json_format)
{
    if (!fp) fp = stdout;
    if (map_fd < 0) return -1;

    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) ncpus = 1;

    __u64 cpu_values[ncpus];
    __u64 totals[STAT_MAX_COUNTERS] = {0};

    for (__u32 key = 0; key < STAT_MAX_COUNTERS; key++) {
        memset(cpu_values, 0, sizeof(cpu_values));
        if (bpf_map_lookup_elem(map_fd, &key, cpu_values) == 0) {
            for (int i = 0; i < ncpus; i++) {
                totals[key] += cpu_values[i];
            }
        }
    }

    struct step_metric_summary summaries[STEP_MAX_OPS];
    memset(summaries, 0, sizeof(summaries));
    if (perf_map_fd >= 0) {
        collect_perf_summaries(perf_map_fd, summaries, ncpus);
    }
    double peak_mpps = (summaries[STEP_TOTAL_PIPELINE].avg_ns > 0) ? (1000.0 / summaries[STEP_TOTAL_PIPELINE].avg_ns) : 0.0;

    if (json_format) {
        fprintf(fp, "{\n");
        fprintf(fp, "  \"total_packets\": %llu,\n", (unsigned long long)totals[STAT_TOTAL_PACKETS]);
        fprintf(fp, "  \"ingress_packets\": %llu,\n", (unsigned long long)totals[STAT_INGRESS_PACKETS]);
        fprintf(fp, "  \"egress_packets\": %llu,\n", (unsigned long long)totals[STAT_EGRESS_PACKETS]);
        fprintf(fp, "  \"allowed_packets\": %llu,\n", (unsigned long long)totals[STAT_ALLOWED_PACKETS]);
        fprintf(fp, "  \"dropped_packets\": %llu,\n", (unsigned long long)totals[STAT_DROPPED_PACKETS]);
        fprintf(fp, "  \"tcp_packets\": %llu,\n", (unsigned long long)totals[STAT_TCP_PACKETS]);
        fprintf(fp, "  \"udp_packets\": %llu,\n", (unsigned long long)totals[STAT_UDP_PACKETS]);
        fprintf(fp, "  \"icmp_packets\": %llu,\n", (unsigned long long)totals[STAT_ICMP_PACKETS]);
        fprintf(fp, "  \"other_packets\": %llu,\n", (unsigned long long)totals[STAT_OTHER_PACKETS]);
        fprintf(fp, "  \"dropped_unsolicited\": %llu,\n", (unsigned long long)totals[STAT_DROPPED_UNSOLICITED]);
        fprintf(fp, "  \"dropped_rule\": %llu,\n", (unsigned long long)totals[STAT_DROPPED_RULE]);
        fprintf(fp, "  \"dropped_malformed\": %llu,\n", (unsigned long long)totals[STAT_DROPPED_MALFORMED]);
        fprintf(fp, "  \"connections_new\": %llu,\n", (unsigned long long)totals[STAT_CONN_NEW]);
        fprintf(fp, "  \"connections_established\": %llu,\n", (unsigned long long)totals[STAT_CONN_ESTABLISHED]);
        fprintf(fp, "  \"connections_closed\": %llu,\n", (unsigned long long)totals[STAT_CONN_CLOSED]);
        fprintf(fp, "  \"connections_timeout\": %llu,\n", (unsigned long long)totals[STAT_CONN_TIMEOUT]);
        __u64 cache_hits = totals[STAT_CACHE_HITS];
        __u64 cache_misses = totals[STAT_CACHE_MISSES];
        __u64 total_cache_lookups = cache_hits + cache_misses;
        double hit_ratio = (total_cache_lookups > 0) ? ((double)cache_hits * 100.0 / (double)total_cache_lookups) : 0.0;
        fprintf(fp, "  \"cache_hits\": %llu,\n", (unsigned long long)cache_hits);
        fprintf(fp, "  \"cache_misses\": %llu,\n", (unsigned long long)cache_misses);
        fprintf(fp, "  \"cache_hit_ratio_pct\": %.2f,\n", hit_ratio);
        fprintf(fp, "  \"timing_analysis\": {\n");
        fprintf(fp, "    \"extraction\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_EXTRACTION].count, summaries[STEP_EXTRACTION].avg_ns,
               (unsigned long long)summaries[STEP_EXTRACTION].min_time_ns, (unsigned long long)summaries[STEP_EXTRACTION].max_time_ns,
               (double)summaries[STEP_EXTRACTION].total_time_ns / 1e6);
        fprintf(fp, "    \"hash_calculation\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_HASH_CAL].count, summaries[STEP_HASH_CAL].avg_ns,
               (unsigned long long)summaries[STEP_HASH_CAL].min_time_ns, (unsigned long long)summaries[STEP_HASH_CAL].max_time_ns,
               (double)summaries[STEP_HASH_CAL].total_time_ns / 1e6);
        fprintf(fp, "    \"flow_cache_lookup\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_LOOKUP_CACHE].count, summaries[STEP_LOOKUP_CACHE].avg_ns,
               (unsigned long long)summaries[STEP_LOOKUP_CACHE].min_time_ns, (unsigned long long)summaries[STEP_LOOKUP_CACHE].max_time_ns,
               (double)summaries[STEP_LOOKUP_CACHE].total_time_ns / 1e6);
        fprintf(fp, "    \"conntrack_lookup\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_LOOKUP_CONNTRACK].count, summaries[STEP_LOOKUP_CONNTRACK].avg_ns,
               (unsigned long long)summaries[STEP_LOOKUP_CONNTRACK].min_time_ns, (unsigned long long)summaries[STEP_LOOKUP_CONNTRACK].max_time_ns,
               (double)summaries[STEP_LOOKUP_CONNTRACK].total_time_ns / 1e6);
        fprintf(fp, "    \"rules_lookup\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_LOOKUP_RULES].count, summaries[STEP_LOOKUP_RULES].avg_ns,
               (unsigned long long)summaries[STEP_LOOKUP_RULES].min_time_ns, (unsigned long long)summaries[STEP_LOOKUP_RULES].max_time_ns,
               (double)summaries[STEP_LOOKUP_RULES].total_time_ns / 1e6);
        fprintf(fp, "    \"lookup_total\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_LOOKUP_TOTAL].count, summaries[STEP_LOOKUP_TOTAL].avg_ns,
               (unsigned long long)summaries[STEP_LOOKUP_TOTAL].min_time_ns, (unsigned long long)summaries[STEP_LOOKUP_TOTAL].max_time_ns,
               (double)summaries[STEP_LOOKUP_TOTAL].total_time_ns / 1e6);
        fprintf(fp, "    \"conntrack_update\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_UPDATE_CONNTRACK].count, summaries[STEP_UPDATE_CONNTRACK].avg_ns,
               (unsigned long long)summaries[STEP_UPDATE_CONNTRACK].min_time_ns, (unsigned long long)summaries[STEP_UPDATE_CONNTRACK].max_time_ns,
               (double)summaries[STEP_UPDATE_CONNTRACK].total_time_ns / 1e6);
        fprintf(fp, "    \"stats_update\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_UPDATE_STATS].count, summaries[STEP_UPDATE_STATS].avg_ns,
               (unsigned long long)summaries[STEP_UPDATE_STATS].min_time_ns, (unsigned long long)summaries[STEP_UPDATE_STATS].max_time_ns,
               (double)summaries[STEP_UPDATE_STATS].total_time_ns / 1e6);
        fprintf(fp, "    \"ringbuf_update\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_UPDATE_RINGBUF].count, summaries[STEP_UPDATE_RINGBUF].avg_ns,
               (unsigned long long)summaries[STEP_UPDATE_RINGBUF].min_time_ns, (unsigned long long)summaries[STEP_UPDATE_RINGBUF].max_time_ns,
               (double)summaries[STEP_UPDATE_RINGBUF].total_time_ns / 1e6);
        fprintf(fp, "    \"update_total\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_UPDATE_TOTAL].count, summaries[STEP_UPDATE_TOTAL].avg_ns,
               (unsigned long long)summaries[STEP_UPDATE_TOTAL].min_time_ns, (unsigned long long)summaries[STEP_UPDATE_TOTAL].max_time_ns,
               (double)summaries[STEP_UPDATE_TOTAL].total_time_ns / 1e6);
        fprintf(fp, "    \"pipeline_total\": { \"count\": %llu, \"avg_ns\": %.2f, \"min_ns\": %llu, \"max_ns\": %llu, \"total_ms\": %.3f },\n",
               (unsigned long long)summaries[STEP_TOTAL_PIPELINE].count, summaries[STEP_TOTAL_PIPELINE].avg_ns,
               (unsigned long long)summaries[STEP_TOTAL_PIPELINE].min_time_ns, (unsigned long long)summaries[STEP_TOTAL_PIPELINE].max_time_ns,
               (double)summaries[STEP_TOTAL_PIPELINE].total_time_ns / 1e6);
        fprintf(fp, "    \"peak_mpps_single_core\": %.2f\n", peak_mpps);
        fprintf(fp, "  }\n");
        fprintf(fp, "}\n");
        return 0;
    }

    fprintf(fp, "========================================================================================\n");
    fprintf(fp, "                           FIREWALL TELEMETRY & STATISTICS (Step 11)                    \n");
    fprintf(fp, "========================================================================================\n");
    fprintf(fp, "  [ PACKET COUNTERS ]\n");
    fprintf(fp, "    - Total Received:       %llu (Ingress: %llu, Egress: %llu)\n",
           (unsigned long long)totals[STAT_TOTAL_PACKETS],
           (unsigned long long)totals[STAT_INGRESS_PACKETS],
           (unsigned long long)totals[STAT_EGRESS_PACKETS]);
    fprintf(fp, "    - Allowed (Passed):     %llu\n", (unsigned long long)totals[STAT_ALLOWED_PACKETS]);
    fprintf(fp, "    - Dropped (Blocked):    %llu\n", (unsigned long long)totals[STAT_DROPPED_PACKETS]);
    fprintf(fp, "\n  [ PROTOCOL BREAKDOWN ]\n");
    fprintf(fp, "    - TCP:                  %llu\n", (unsigned long long)totals[STAT_TCP_PACKETS]);
    fprintf(fp, "    - UDP:                  %llu\n", (unsigned long long)totals[STAT_UDP_PACKETS]);
    fprintf(fp, "    - ICMP:                 %llu\n", (unsigned long long)totals[STAT_ICMP_PACKETS]);
    fprintf(fp, "    - Other:                %llu\n", (unsigned long long)totals[STAT_OTHER_PACKETS]);
    fprintf(fp, "\n  [ ENFORCEMENT BREAKDOWN ]\n");
    fprintf(fp, "    - Dropped by Policy:    %llu\n", (unsigned long long)totals[STAT_DROPPED_RULE]);
    fprintf(fp, "    - Dropped Unsolicited:  %llu (Out-of-state / Invalid)\n", (unsigned long long)totals[STAT_DROPPED_UNSOLICITED]);
    fprintf(fp, "    - Dropped Malformed:    %llu\n", (unsigned long long)totals[STAT_DROPPED_MALFORMED]);
    fprintf(fp, "\n  [ STATEFUL CONNECTION LIFECYCLE ]\n");
    fprintf(fp, "    - New Flows Initiated:  %llu\n", (unsigned long long)totals[STAT_CONN_NEW]);
    fprintf(fp, "    - Fully Established:    %llu\n", (unsigned long long)totals[STAT_CONN_ESTABLISHED]);
    fprintf(fp, "    - Closed / Reset:       %llu\n", (unsigned long long)totals[STAT_CONN_CLOSED]);
    fprintf(fp, "    - Expired / Timed Out:  %llu\n", (unsigned long long)totals[STAT_CONN_TIMEOUT]);
    __u64 cache_hits = totals[STAT_CACHE_HITS];
    __u64 cache_misses = totals[STAT_CACHE_MISSES];
    __u64 total_cache_lookups = cache_hits + cache_misses;
    double hit_ratio = (total_cache_lookups > 0) ? ((double)cache_hits * 100.0 / (double)total_cache_lookups) : 0.0;
    fprintf(fp, "\n  [ L1 PER-CPU FLOW CACHE ]\n");
    fprintf(fp, "    - Cache Hits:           %llu (%.2f%%)\n", (unsigned long long)cache_hits, hit_ratio);
    fprintf(fp, "    - Cache Misses:         %llu\n", (unsigned long long)cache_misses);
    fprintf(fp, "    - Total Cache Lookups:  %llu\n", (unsigned long long)total_cache_lookups);
    fprintf(fp, "========================================================================================\n\n");

    if (perf_map_fd >= 0) {
        perf_mgr_write_stream(fp, perf_map_fd, 0);
    }

    return 0;
}

int stats_mgr_show(int map_fd, int perf_map_fd, int json_format)
{
    return stats_mgr_write_stream(stdout, map_fd, perf_map_fd, json_format);
}

int stats_mgr_log_to_file(int map_fd, int perf_map_fd, const char *filepath, int json_format)
{
    if (!filepath || map_fd < 0) return -1;

    /* Strip leading/trailing quotes or spaces if present */
    char clean_path[512];
    const char *p = filepath;
    while (*p == ' ' || *p == '"' || *p == '\'') p++;
    snprintf(clean_path, sizeof(clean_path), "%s", p);
    size_t len = strlen(clean_path);
    while (len > 0 && (clean_path[len - 1] == ' ' || clean_path[len - 1] == '"' || clean_path[len - 1] == '\'')) {
        clean_path[len - 1] = '\0';
        len--;
    }

    /* Auto-create parent directory if path contains slashes */
    char *slash = strrchr(clean_path, '/');
    if (slash) {
        char dir[512];
        size_t dlen = slash - clean_path;
        if (dlen < sizeof(dir)) {
            strncpy(dir, clean_path, dlen);
            dir[dlen] = '\0';
            char tmp[512];
            snprintf(tmp, sizeof(tmp), "%s", dir);
            for (char *c = tmp + 1; *c; c++) {
                if (*c == '/') {
                    *c = '\0';
                    mkdir(tmp, 0755);
                    *c = '/';
                }
            }
            mkdir(tmp, 0755);
        }
    }

    FILE *fp = fopen(clean_path, "a");
    if (!fp) {
        fprintf(stderr, "[-] Warning: Failed to open telemetry log file '%s': %s\n", clean_path, strerror(errno));
        return -1;
    }

    time_t now = time(NULL);
    char time_str[64];
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

    if (json_format) {
        int ncpus = libbpf_num_possible_cpus();
        if (ncpus <= 0) ncpus = 1;

        __u64 cpu_values[ncpus];
        __u64 totals[STAT_MAX_COUNTERS] = {0};

        for (__u32 key = 0; key < STAT_MAX_COUNTERS; key++) {
            memset(cpu_values, 0, sizeof(cpu_values));
            if (bpf_map_lookup_elem(map_fd, &key, cpu_values) == 0) {
                for (int i = 0; i < ncpus; i++) {
                    totals[key] += cpu_values[i];
                }
            }
        }

        struct step_metric_summary summaries[STEP_MAX_OPS];
        memset(summaries, 0, sizeof(summaries));
        if (perf_map_fd >= 0) {
            collect_perf_summaries(perf_map_fd, summaries, ncpus);
        }
        double peak_mpps = (summaries[STEP_TOTAL_PIPELINE].avg_ns > 0) ? (1000.0 / summaries[STEP_TOTAL_PIPELINE].avg_ns) : 0.0;

        __u64 cache_hits = totals[STAT_CACHE_HITS];
        __u64 cache_misses = totals[STAT_CACHE_MISSES];
        __u64 total_cache_lookups = cache_hits + cache_misses;
        double hit_ratio = (total_cache_lookups > 0) ? ((double)cache_hits * 100.0 / (double)total_cache_lookups) : 0.0;

        fprintf(fp, "{\"timestamp\":\"%s\",\"total_pkts\":%llu,\"allowed\":%llu,\"dropped\":%llu,\"tcp\":%llu,\"udp\":%llu,\"icmp\":%llu,\"conn_est\":%llu,\"cache_hits\":%llu,\"cache_misses\":%llu,\"cache_hit_ratio_pct\":%.2f,\"lat_extract_ns\":%.2f,\"lat_hash_ns\":%.2f,\"lat_cache_ns\":%.2f,\"lat_ct_lkp_ns\":%.2f,\"lat_rules_ns\":%.2f,\"lat_ct_upd_ns\":%.2f,\"lat_stats_ns\":%.2f,\"lat_tot_ns\":%.2f,\"peak_mpps\":%.2f}\n",
                time_str,
                (unsigned long long)totals[STAT_TOTAL_PACKETS],
                (unsigned long long)totals[STAT_ALLOWED_PACKETS],
                (unsigned long long)totals[STAT_DROPPED_PACKETS],
                (unsigned long long)totals[STAT_TCP_PACKETS],
                (unsigned long long)totals[STAT_UDP_PACKETS],
                (unsigned long long)totals[STAT_ICMP_PACKETS],
                (unsigned long long)totals[STAT_CONN_ESTABLISHED],
                (unsigned long long)cache_hits,
                (unsigned long long)cache_misses,
                hit_ratio,
                summaries[STEP_EXTRACTION].avg_ns,
                summaries[STEP_HASH_CAL].avg_ns,
                summaries[STEP_LOOKUP_CACHE].avg_ns,
                summaries[STEP_LOOKUP_CONNTRACK].avg_ns,
                summaries[STEP_LOOKUP_RULES].avg_ns,
                summaries[STEP_UPDATE_CONNTRACK].avg_ns,
                summaries[STEP_UPDATE_STATS].avg_ns,
                summaries[STEP_TOTAL_PIPELINE].avg_ns,
                peak_mpps);
    } else {
        fprintf(fp, "========================================================================================\n");
        fprintf(fp, "  TELEMETRY SNAPSHOT [%s]\n", time_str);
        fprintf(fp, "========================================================================================\n");
        stats_mgr_write_stream(fp, map_fd, perf_map_fd, 0);
    }

    fflush(fp);
    fclose(fp);
    return 0;
}

int stats_mgr_reset(int map_fd, int perf_map_fd)
{
    if (map_fd >= 0) {
        int ncpus = libbpf_num_possible_cpus();
        if (ncpus <= 0) ncpus = 1;

        __u64 zeroes[ncpus];
        memset(zeroes, 0, sizeof(zeroes));

        for (__u32 key = 0; key < STAT_MAX_COUNTERS; key++) {
            bpf_map_update_elem(map_fd, &key, zeroes, BPF_ANY);
        }
        printf("[+] All firewall statistics counters reset to zero.\n");
    }

    if (perf_map_fd >= 0) {
        perf_mgr_reset(perf_map_fd);
    }

    return 0;
}
