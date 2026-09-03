#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <errno.h>
#include <bpf/bpf.h>
#include "rules_mgr.h"
#include "../utils/ip_utils.h"

int rules_mgr_add(int map_fd, const struct fw_rule *rule, __u32 *out_index)
{
    if (map_fd < 0) return -1;

    /* Find next free slot in array */
    for (__u32 i = 0; i < MAX_RULE_ENTRIES; i++) {
        struct fw_rule existing;
        if (bpf_map_lookup_elem(map_fd, &i, &existing) == 0) {
            if (!(existing.flags & RULE_FLAG_ACTIVE)) {
                if (bpf_map_update_elem(map_fd, &i, rule, BPF_ANY) < 0) {
                    fprintf(stderr, "[-] Failed to insert rule at slot %u: %s\n", i, strerror(errno));
                    return -1;
                }
                if (out_index) *out_index = i;
                return 0;
            }
        }
    }

    fprintf(stderr, "[-] Error: Rule table is full (max: %d)\n", MAX_RULE_ENTRIES);
    return -1;
}

int rules_mgr_del(int map_fd, __u32 index)
{
    if (map_fd < 0 || index >= MAX_RULE_ENTRIES) return -1;

    struct fw_rule empty;
    memset(&empty, 0, sizeof(empty));
    return bpf_map_update_elem(map_fd, &index, &empty, BPF_ANY);
}

int rules_mgr_list(int map_fd)
{
    if (map_fd < 0) return -1;

    printf("========================================================================================\n");
    printf("                               ACTIVE FIREWALL RULES (Step 8)                           \n");
    printf("========================================================================================\n");
    printf("%-4s | %-6s | %-6s | %-18s | %-18s | %-10s | %-8s | %-15s\n",
           "ID", "ACTION", "PROTO", "SOURCE IP/MASK", "DEST IP/MASK", "PORTS", "HITS", "DESC");
    printf("----------------------------------------------------------------------------------------\n");

    int active_count = 0;
    for (__u32 i = 0; i < MAX_RULE_ENTRIES; i++) {
        struct fw_rule r;
        if (bpf_map_lookup_elem(map_fd, &i, &r) == 0 && (r.flags & RULE_FLAG_ACTIVE)) {
            active_count++;
            const char *act = (r.action == ACTION_PASS) ? "ALLOW" :
                              (r.action == ACTION_DROP) ? "DROP"  : "REJECT";

            const char *proto_str = "ANY";
            if (r.flags & RULE_FLAG_PROTO) {
                if (r.proto == PROTO_TCP) proto_str = "TCP";
                else if (r.proto == PROTO_UDP) proto_str = "UDP";
                else if (r.proto == PROTO_ICMP) proto_str = "ICMP";
            }

            char src_buf[32] = "ANY";
            if (r.flags & RULE_FLAG_SRC_IP) {
                char ip[20];
                ip_to_str(r.src_ip, ip, sizeof(ip));
                snprintf(src_buf, sizeof(src_buf), "%s", ip);
            }

            char dst_buf[32] = "ANY";
            if (r.flags & RULE_FLAG_DST_IP) {
                char ip[20];
                ip_to_str(r.dst_ip, ip, sizeof(ip));
                snprintf(dst_buf, sizeof(dst_buf), "%s", ip);
            }

            char port_buf[24] = "ANY";
            if (r.flags & RULE_FLAG_DST_PORT) {
                if (r.dst_port_min == r.dst_port_max) {
                    snprintf(port_buf, sizeof(port_buf), "d:%u", r.dst_port_min);
                } else {
                    snprintf(port_buf, sizeof(port_buf), "d:%u-%u", r.dst_port_min, r.dst_port_max);
                }
            }

            printf("%-4u | %-6s | %-6s | %-18s | %-18s | %-10s | %-8llu | %-15s\n",
                   i + 1, act, proto_str, src_buf, dst_buf, port_buf,
                   (unsigned long long)r.hit_count,
                   strlen(r.description) > 0 ? r.description : "-");
        }
    }

    if (active_count == 0) {
        printf("  (No active rules configured. Default policy applies.)\n");
    }
    printf("========================================================================================\n\n");
    return 0;
}

int rules_mgr_flush(int map_fd)
{
    if (map_fd < 0) return -1;
    struct fw_rule empty;
    memset(&empty, 0, sizeof(empty));
    for (__u32 i = 0; i < MAX_RULE_ENTRIES; i++) {
        bpf_map_update_elem(map_fd, &i, &empty, BPF_ANY);
    }
    printf("[+] All firewall rules flushed.\n");
    return 0;
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    if (*s == 0) return s;
    char *end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = 0;
        end--;
    }
    return s;
}

int rules_mgr_load_file(int map_fd, const char *filepath)
{
    if (map_fd < 0 || !filepath) return -1;

    FILE *f = fopen(filepath, "r");
    if (!f) {
        fprintf(stderr, "[-] Failed to open rules file '%s': %s\n", filepath, strerror(errno));
        return -1;
    }

    char line[256];
    struct fw_rule current_rule;
    memset(&current_rule, 0, sizeof(current_rule));
    int in_rule = 0;
    int rules_loaded = 0;

    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (*p == '#' || *p == '\0') continue;

        if (strncmp(p, "- rule:", 7) == 0 || strncmp(p, "- name:", 7) == 0) {
            if (in_rule && (current_rule.flags & RULE_FLAG_ACTIVE)) {
                rules_mgr_add(map_fd, &current_rule, NULL);
                rules_loaded++;
                memset(&current_rule, 0, sizeof(current_rule));
            }
            in_rule = 1;
            current_rule.flags |= RULE_FLAG_ACTIVE;
            current_rule.action = ACTION_PASS;
            char *colon = strchr(p, ':');
            if (colon) {
                snprintf(current_rule.description, sizeof(current_rule.description), "%s", trim(colon + 1));
            }
            continue;
        }

        char *colon = strchr(p, ':');
        if (!colon) continue;
        *colon = '\0';
        char *key = trim(p);
        char *val = trim(colon + 1);

        if (strcmp(key, "action") == 0) {
            if (strcasecmp(val, "allow") == 0 || strcasecmp(val, "pass") == 0) {
                current_rule.action = ACTION_PASS;
            } else {
                current_rule.action = ACTION_DROP;
            }
        } else if (strcmp(key, "proto") == 0 || strcmp(key, "protocol") == 0) {
            current_rule.flags |= RULE_FLAG_PROTO;
            if (strcasecmp(val, "tcp") == 0) current_rule.proto = PROTO_TCP;
            else if (strcasecmp(val, "udp") == 0) current_rule.proto = PROTO_UDP;
            else if (strcasecmp(val, "icmp") == 0) current_rule.proto = PROTO_ICMP;
            else current_rule.proto = PROTO_ANY;
        } else if (strcmp(key, "src_ip") == 0 || strcmp(key, "src") == 0) {
            if (strcmp(val, "any") != 0 && strcmp(val, "0.0.0.0/0") != 0) {
                current_rule.flags |= RULE_FLAG_SRC_IP;
                current_rule.src_ip = inet_addr(val);
                current_rule.src_mask = 0xFFFFFFFF;
            }
        } else if (strcmp(key, "dst_ip") == 0 || strcmp(key, "dst") == 0) {
            if (strcmp(val, "any") != 0 && strcmp(val, "0.0.0.0/0") != 0) {
                current_rule.flags |= RULE_FLAG_DST_IP;
                current_rule.dst_ip = inet_addr(val);
                current_rule.dst_mask = 0xFFFFFFFF;
            }
        } else if (strcmp(key, "dport") == 0 || strcmp(key, "dst_port") == 0 || strcmp(key, "port") == 0) {
            if (strcmp(val, "any") != 0) {
                current_rule.flags |= RULE_FLAG_DST_PORT;
                char *dash = strchr(val, '-');
                if (dash) {
                    *dash = '\0';
                    current_rule.dst_port_min = atoi(val);
                    current_rule.dst_port_max = atoi(dash + 1);
                } else {
                    current_rule.dst_port_min = atoi(val);
                    current_rule.dst_port_max = atoi(val);
                }
            }
        } else if (strcmp(key, "desc") == 0 || strcmp(key, "description") == 0) {
            snprintf(current_rule.description, sizeof(current_rule.description), "%s", val);
        }
    }

    if (in_rule && (current_rule.flags & RULE_FLAG_ACTIVE)) {
        rules_mgr_add(map_fd, &current_rule, NULL);
        rules_loaded++;
    }

    fclose(f);
    printf("[+] Loaded %d rule(s) from '%s'.\n", rules_loaded, filepath);
    return rules_loaded;
}
