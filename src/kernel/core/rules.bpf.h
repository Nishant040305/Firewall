#ifndef __CORE_RULES_BPF_H__
#define __CORE_RULES_BPF_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <core/types.h>
#include <core/constants.h>
#include <core/rules.h>
#include "context.bpf.h"
#include "maps.bpf.h"

/* Evaluate Dynamic Firewall Rules against Packet 5-Tuple (Step 8) */
static __always_inline int evaluate_rules(struct pkt_ctx *pkt)
{
    __u16 sport = bpf_ntohs(pkt->src_port);
    __u16 dport = bpf_ntohs(pkt->dst_port);

    #pragma unroll
    for (__u32 i = 0; i < 32; i++) {
        __u32 key = i;
        struct fw_rule *rule = bpf_map_lookup_elem(&rules_map, &key);
        if (!rule) {
            break;
        }

        /* Check if rule is active */
        if (!(rule->flags & RULE_FLAG_ACTIVE)) {
            continue;
        }

        /* Check Protocol Match */
        if ((rule->flags & RULE_FLAG_PROTO) && rule->proto != PROTO_ANY) {
            if (rule->proto != pkt->proto) {
                continue;
            }
        }

        /* Check Source IP / CIDR Subnet */
        if (rule->flags & RULE_FLAG_SRC_IP) {
            if ((pkt->src_ip & rule->src_mask) != (rule->src_ip & rule->src_mask)) {
                continue;
            }
        }

        /* Check Destination IP / CIDR Subnet */
        if (rule->flags & RULE_FLAG_DST_IP) {
            if ((pkt->dst_ip & rule->dst_mask) != (rule->dst_ip & rule->dst_mask)) {
                continue;
            }
        }

        /* Check Source Port Range */
        if (rule->flags & RULE_FLAG_SRC_PORT) {
            if (sport < rule->src_port_min || sport > rule->src_port_max) {
                continue;
            }
        }

        /* Check Destination Port Range */
        if (rule->flags & RULE_FLAG_DST_PORT) {
            if (dport < rule->dst_port_min || dport > rule->dst_port_max) {
                continue;
            }
        }

        /* Rule Matched! Record hit stats and return action */
        rule->hit_count += 1;
        rule->byte_count += pkt->pkt_len;
        pkt->rule_id = i + 1;
        return rule->action;
    }

    /* Default Policy: DROP if not explicitly allowed by rule */
    return ACTION_DROP;
}

#endif /* __CORE_RULES_BPF_H__ */
