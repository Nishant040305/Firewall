#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "stats_mgr.h"

int stats_mgr_show(int map_fd, int json_format)
{
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

    if (json_format) {
        printf("{\n");
        printf("  \"total_packets\": %llu,\n", (unsigned long long)totals[STAT_TOTAL_PACKETS]);
        printf("  \"ingress_packets\": %llu,\n", (unsigned long long)totals[STAT_INGRESS_PACKETS]);
        printf("  \"egress_packets\": %llu,\n", (unsigned long long)totals[STAT_EGRESS_PACKETS]);
        printf("  \"allowed_packets\": %llu,\n", (unsigned long long)totals[STAT_ALLOWED_PACKETS]);
        printf("  \"dropped_packets\": %llu,\n", (unsigned long long)totals[STAT_DROPPED_PACKETS]);
        printf("  \"tcp_packets\": %llu,\n", (unsigned long long)totals[STAT_TCP_PACKETS]);
        printf("  \"udp_packets\": %llu,\n", (unsigned long long)totals[STAT_UDP_PACKETS]);
        printf("  \"icmp_packets\": %llu,\n", (unsigned long long)totals[STAT_ICMP_PACKETS]);
        printf("  \"other_packets\": %llu,\n", (unsigned long long)totals[STAT_OTHER_PACKETS]);
        printf("  \"dropped_unsolicited\": %llu,\n", (unsigned long long)totals[STAT_DROPPED_UNSOLICITED]);
        printf("  \"dropped_rule\": %llu,\n", (unsigned long long)totals[STAT_DROPPED_RULE]);
        printf("  \"dropped_malformed\": %llu,\n", (unsigned long long)totals[STAT_DROPPED_MALFORMED]);
        printf("  \"connections_new\": %llu,\n", (unsigned long long)totals[STAT_CONN_NEW]);
        printf("  \"connections_established\": %llu,\n", (unsigned long long)totals[STAT_CONN_ESTABLISHED]);
        printf("  \"connections_closed\": %llu,\n", (unsigned long long)totals[STAT_CONN_CLOSED]);
        printf("  \"connections_timeout\": %llu\n", (unsigned long long)totals[STAT_CONN_TIMEOUT]);
        printf("}\n");
        return 0;
    }

    printf("========================================================================================\n");
    printf("                           FIREWALL TELEMETRY & STATISTICS (Step 11)                    \n");
    printf("========================================================================================\n");
    printf("  [ PACKET COUNTERS ]\n");
    printf("    - Total Received:       %llu (Ingress: %llu, Egress: %llu)\n",
           (unsigned long long)totals[STAT_TOTAL_PACKETS],
           (unsigned long long)totals[STAT_INGRESS_PACKETS],
           (unsigned long long)totals[STAT_EGRESS_PACKETS]);
    printf("    - Allowed (Passed):     %llu\n", (unsigned long long)totals[STAT_ALLOWED_PACKETS]);
    printf("    - Dropped (Blocked):    %llu\n", (unsigned long long)totals[STAT_DROPPED_PACKETS]);
    printf("\n  [ PROTOCOL BREAKDOWN ]\n");
    printf("    - TCP:                  %llu\n", (unsigned long long)totals[STAT_TCP_PACKETS]);
    printf("    - UDP:                  %llu\n", (unsigned long long)totals[STAT_UDP_PACKETS]);
    printf("    - ICMP:                 %llu\n", (unsigned long long)totals[STAT_ICMP_PACKETS]);
    printf("    - Other:                %llu\n", (unsigned long long)totals[STAT_OTHER_PACKETS]);
    printf("\n  [ ENFORCEMENT BREAKDOWN ]\n");
    printf("    - Dropped by Policy:    %llu\n", (unsigned long long)totals[STAT_DROPPED_RULE]);
    printf("    - Dropped Unsolicited:  %llu (Out-of-state / Invalid)\n", (unsigned long long)totals[STAT_DROPPED_UNSOLICITED]);
    printf("    - Dropped Malformed:    %llu\n", (unsigned long long)totals[STAT_DROPPED_MALFORMED]);
    printf("\n  [ STATEFUL CONNECTION LIFECYCLE ]\n");
    printf("    - New Flows Initiated:  %llu\n", (unsigned long long)totals[STAT_CONN_NEW]);
    printf("    - Fully Established:    %llu\n", (unsigned long long)totals[STAT_CONN_ESTABLISHED]);
    printf("    - Closed / Reset:       %llu\n", (unsigned long long)totals[STAT_CONN_CLOSED]);
    printf("    - Expired / Timed Out:  %llu\n", (unsigned long long)totals[STAT_CONN_TIMEOUT]);
    printf("========================================================================================\n\n");

    return 0;
}

int stats_mgr_reset(int map_fd)
{
    if (map_fd < 0) return -1;

    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) ncpus = 1;

    __u64 zeroes[ncpus];
    memset(zeroes, 0, sizeof(zeroes));

    for (__u32 key = 0; key < STAT_MAX_COUNTERS; key++) {
        bpf_map_update_elem(map_fd, &key, zeroes, BPF_ANY);
    }

    printf("[+] All firewall statistics counters reset to zero.\n");
    return 0;
}
