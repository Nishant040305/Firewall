#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <bpf/bpf.h>
#include "conntrack_mgr.h"
#include "../utils/ip_utils.h"

static const char *state_to_str(enum conn_state st)
{
    switch (st) {
    case CONN_STATE_NEW:         return "NEW";
    case CONN_STATE_SYN_SENT:    return "SYN_SENT";
    case CONN_STATE_SYN_RECV:    return "SYN_RECV";
    case CONN_STATE_ESTABLISHED: return "ESTABLISHED";
    case CONN_STATE_FIN_WAIT:    return "FIN_WAIT";
    case CONN_STATE_CLOSE_WAIT:  return "CLOSE_WAIT";
    case CONN_STATE_CLOSED:      return "CLOSED";
    case CONN_STATE_UDP_ACTIVE:  return "UDP_ACTIVE";
    case CONN_STATE_ICMP_ACTIVE: return "ICMP_ACTIVE";
    default:                     return "UNKNOWN";
    }
}

int conntrack_mgr_list(int map_fd)
{
    if (map_fd < 0) return -1;

    printf("========================================================================================\n");
    printf("                       STATEFUL CONNECTION TRACKING TABLE (Step 9)                      \n");
    printf("========================================================================================\n");
    printf("%-6s | %-21s | %-21s | %-12s | %-12s | %-12s\n",
           "PROTO", "SOURCE (IP:PORT)", "DESTINATION (IP:PORT)", "STATE", "PKTS (FWD/REV)", "BYTES (FWD/REV)");
    printf("----------------------------------------------------------------------------------------\n");

    struct flow_key key, next_key;
    memset(&key, 0, sizeof(key));
    int count = 0;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        struct flow_entry entry;
        if (bpf_map_lookup_elem(map_fd, &next_key, &entry) == 0) {
            count++;
            char src_ip[20], dst_ip[20];
            char src_str[24], dst_str[24];
            ip_to_str(next_key.src_ip, src_ip, sizeof(src_ip));
            ip_to_str(next_key.dst_ip, dst_ip, sizeof(dst_ip));

            __u16 sport = ntohs(next_key.src_port);
            __u16 dport = ntohs(next_key.dst_port);

            snprintf(src_str, sizeof(src_str), "%s:%u", src_ip, sport);
            snprintf(dst_str, sizeof(dst_str), "%s:%u", dst_ip, dport);

            const char *proto_str = (next_key.proto == IPPROTO_TCP)  ? "TCP"  :
                                    (next_key.proto == IPPROTO_UDP)  ? "UDP"  :
                                    (next_key.proto == IPPROTO_ICMP) ? "ICMP" : "OTHER";

            char pkts_str[20];
            char bytes_str[20];
            snprintf(pkts_str, sizeof(pkts_str), "%llu/%llu",
                     (unsigned long long)entry.packets_forward, (unsigned long long)entry.packets_reverse);
            snprintf(bytes_str, sizeof(bytes_str), "%llu/%llu",
                     (unsigned long long)entry.bytes_forward, (unsigned long long)entry.bytes_reverse);

            printf("%-6s | %-21s | %-21s | %-12s | %-12s | %-12s\n",
                   proto_str, src_str, dst_str, state_to_str(entry.state), pkts_str, bytes_str);
        }
        key = next_key;
    }

    if (count == 0) {
        printf("  (No active connections in state table.)\n");
    }
    printf("========================================================================================\n");
    printf("[+] Total active state entries: %d\n\n", count);
    return 0;
}

int conntrack_mgr_flush(int map_fd)
{
    if (map_fd < 0) return -1;

    struct flow_key key, next_key;
    memset(&key, 0, sizeof(key));
    int count = 0;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        bpf_map_delete_elem(map_fd, &next_key);
        count++;
        key = next_key;
    }

    printf("[+] Flushed %d connection tracking entries.\n", count);
    return 0;
}
