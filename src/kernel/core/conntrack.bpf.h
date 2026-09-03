#ifndef __CORE_CONNTRACK_BPF_H__
#define __CORE_CONNTRACK_BPF_H__

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <core/types.h>
#include <core/constants.h>
#include <core/conntrack.h>
#include <core/stats.h>
#include "context.bpf.h"
#include "maps.bpf.h"
#include "helpers.bpf.h"
#include "rules.bpf.h"

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

/* Process TCP state machine (Step 9) */
static __always_inline int process_tcp_state(struct pkt_ctx *pkt, __u64 now)
{
    struct flow_key fwd_key, rev_key;
    make_flow_key(pkt, &fwd_key);
    make_reverse_flow_key(pkt, &rev_key);

    __u8 flags = pkt->tcp_flags;
    struct flow_entry *entry = bpf_map_lookup_elem(&conntrack_map, &fwd_key);

    /* 1. TCP SYN (Initial connection request) */
    if ((flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK)) {
        /* Evaluate policy rules */
        int rule_action = evaluate_rules(pkt);
        if (rule_action != ACTION_PASS) {
            inc_stat(STAT_DROPPED_RULE);
            pkt->action = ACTION_DROP;
            pkt->conn_state = CONN_STATE_INVALID;
            return ACTION_DROP;
        }

        /* Create forward flow entry */
        struct flow_entry new_entry = {
            .state = CONN_STATE_SYN_SENT,
            .flags_seen = flags,
            .created_ns = now,
            .last_seen_ns = now,
            .packets_forward = 1,
            .packets_reverse = 0,
            .bytes_forward = pkt->pkt_len,
            .bytes_reverse = 0,
            .timeout_ns = TCP_SYN_TIMEOUT_NS,
        };
        bpf_map_update_elem(&conntrack_map, &fwd_key, &new_entry, BPF_ANY);

        /* Create reverse flow entry awaiting SYN-ACK */
        struct flow_entry rev_entry = {
            .state = CONN_STATE_SYN_SENT,
            .flags_seen = 0,
            .created_ns = now,
            .last_seen_ns = now,
            .packets_forward = 0,
            .packets_reverse = 0,
            .bytes_forward = 0,
            .bytes_reverse = 0,
            .timeout_ns = TCP_SYN_TIMEOUT_NS,
        };
        bpf_map_update_elem(&conntrack_map, &rev_key, &rev_entry, BPF_ANY);

        inc_stat(STAT_CONN_NEW);
        pkt->action = ACTION_PASS;
        pkt->conn_state = CONN_STATE_SYN_SENT;
        return ACTION_PASS;
    }

    /* 2. Check for existing connection */
    if (entry) {
        /* Check timeout */
        if (now - entry->last_seen_ns > entry->timeout_ns) {
            inc_stat(STAT_CONN_TIMEOUT);
            bpf_map_delete_elem(&conntrack_map, &fwd_key);
            bpf_map_delete_elem(&conntrack_map, &rev_key);
            inc_stat(STAT_DROPPED_UNSOLICITED);
            pkt->action = ACTION_DROP;
            pkt->conn_state = CONN_STATE_INVALID;
            return ACTION_DROP;
        }

        /* TCP SYN-ACK Response from Server */
        if ((flags & TCP_FLAG_SYN) && (flags & TCP_FLAG_ACK)) {
            entry->state = CONN_STATE_SYN_RECV;
            entry->last_seen_ns = now;
            entry->packets_reverse += 1;
            entry->bytes_reverse += pkt->pkt_len;
            entry->flags_seen |= flags;
            entry->timeout_ns = TCP_SYN_TIMEOUT_NS;

            /* Also update corresponding forward entry */
            struct flow_entry *fwd_ent = bpf_map_lookup_elem(&conntrack_map, &rev_key);
            if (fwd_ent) {
                fwd_ent->state = CONN_STATE_SYN_RECV;
                fwd_ent->last_seen_ns = now;
            }

            pkt->action = ACTION_PASS;
            pkt->conn_state = CONN_STATE_SYN_RECV;
            return ACTION_PASS;
        }

        /* TCP ACK or Data packet */
        if (flags & TCP_FLAG_ACK) {
            if (entry->state == CONN_STATE_SYN_RECV || entry->state == CONN_STATE_SYN_SENT) {
                entry->state = CONN_STATE_ESTABLISHED;
                entry->timeout_ns = TCP_ESTABLISHED_TIMEOUT_NS;
                inc_stat(STAT_CONN_ESTABLISHED);

                struct flow_entry *peer_ent = bpf_map_lookup_elem(&conntrack_map, &rev_key);
                if (peer_ent) {
                    peer_ent->state = CONN_STATE_ESTABLISHED;
                    peer_ent->timeout_ns = TCP_ESTABLISHED_TIMEOUT_NS;
                }
            }

            entry->last_seen_ns = now;
            entry->packets_forward += 1;
            entry->bytes_forward += pkt->pkt_len;
            entry->flags_seen |= flags;

            /* Handle connection termination (FIN / RST) */
            if (flags & TCP_FLAG_RST) {
                entry->state = CONN_STATE_CLOSED;
                entry->timeout_ns = TCP_CLOSE_TIMEOUT_NS;
                inc_stat(STAT_CONN_CLOSED);
            } else if (flags & TCP_FLAG_FIN) {
                entry->state = CONN_STATE_FIN_WAIT;
                entry->timeout_ns = TCP_CLOSE_TIMEOUT_NS;
            }

            pkt->action = ACTION_PASS;
            pkt->conn_state = entry->state;
            return ACTION_PASS;
        }

        /* Handle standalone RST or FIN */
        if (flags & (TCP_FLAG_RST | TCP_FLAG_FIN)) {
            entry->last_seen_ns = now;
            entry->state = (flags & TCP_FLAG_RST) ? CONN_STATE_CLOSED : CONN_STATE_FIN_WAIT;
            entry->timeout_ns = TCP_CLOSE_TIMEOUT_NS;
            pkt->action = ACTION_PASS;
            pkt->conn_state = entry->state;
            return ACTION_PASS;
        }

        /* Other valid packets on established flow */
        if (entry->state == CONN_STATE_ESTABLISHED) {
            entry->last_seen_ns = now;
            entry->packets_forward += 1;
            entry->bytes_forward += pkt->pkt_len;
            pkt->action = ACTION_PASS;
            pkt->conn_state = CONN_STATE_ESTABLISHED;
            return ACTION_PASS;
        }
    }

    /* 3. Unsolicited non-SYN packet with no state in conntrack -> DROP (Step 14 Test Case 4) */
    inc_stat(STAT_DROPPED_UNSOLICITED);
    pkt->action = ACTION_DROP;
    pkt->conn_state = CONN_STATE_INVALID;
    return ACTION_DROP;
}

/* Process UDP pseudo-connection state (Step 9) */
static __always_inline int process_udp_state(struct pkt_ctx *pkt, __u64 now)
{
    struct flow_key fwd_key, rev_key;
    make_flow_key(pkt, &fwd_key);
    make_reverse_flow_key(pkt, &rev_key);

    struct flow_entry *entry = bpf_map_lookup_elem(&conntrack_map, &fwd_key);
    if (entry) {
        if (now - entry->last_seen_ns <= entry->timeout_ns) {
            entry->last_seen_ns = now;
            entry->packets_forward += 1;
            entry->bytes_forward += pkt->pkt_len;
            pkt->action = ACTION_PASS;
            pkt->conn_state = CONN_STATE_UDP_ACTIVE;
            return ACTION_PASS;
        }
        /* Expired */
        bpf_map_delete_elem(&conntrack_map, &fwd_key);
        bpf_map_delete_elem(&conntrack_map, &rev_key);
    }

    /* Evaluate rules for new UDP flow */
    int rule_action = evaluate_rules(pkt);
    if (rule_action != ACTION_PASS) {
        inc_stat(STAT_DROPPED_RULE);
        pkt->action = ACTION_DROP;
        pkt->conn_state = CONN_STATE_INVALID;
        return ACTION_DROP;
    }

    /* Create forward and reverse UDP state entries */
    struct flow_entry new_fwd = {
        .state = CONN_STATE_UDP_ACTIVE,
        .flags_seen = 0,
        .created_ns = now,
        .last_seen_ns = now,
        .packets_forward = 1,
        .packets_reverse = 0,
        .bytes_forward = pkt->pkt_len,
        .bytes_reverse = 0,
        .timeout_ns = UDP_TIMEOUT_NS,
    };
    bpf_map_update_elem(&conntrack_map, &fwd_key, &new_fwd, BPF_ANY);

    struct flow_entry new_rev = {
        .state = CONN_STATE_UDP_ACTIVE,
        .flags_seen = 0,
        .created_ns = now,
        .last_seen_ns = now,
        .packets_forward = 0,
        .packets_reverse = 0,
        .bytes_forward = 0,
        .bytes_reverse = 0,
        .timeout_ns = UDP_TIMEOUT_NS,
    };
    bpf_map_update_elem(&conntrack_map, &rev_key, &new_rev, BPF_ANY);

    inc_stat(STAT_CONN_NEW);
    pkt->action = ACTION_PASS;
    pkt->conn_state = CONN_STATE_UDP_ACTIVE;
    return ACTION_PASS;
}

/* Process ICMP Echo session state (Step 9) */
static __always_inline int process_icmp_state(struct pkt_ctx *pkt, __u64 now)
{
    struct flow_key fwd_key, rev_key;
    make_flow_key(pkt, &fwd_key);
    make_reverse_flow_key(pkt, &rev_key);

    struct flow_entry *entry = bpf_map_lookup_elem(&conntrack_map, &fwd_key);
    if (entry) {
        if (now - entry->last_seen_ns <= entry->timeout_ns) {
            entry->last_seen_ns = now;
            entry->packets_forward += 1;
            entry->bytes_forward += pkt->pkt_len;
            pkt->action = ACTION_PASS;
            pkt->conn_state = CONN_STATE_ICMP_ACTIVE;
            return ACTION_PASS;
        }
        bpf_map_delete_elem(&conntrack_map, &fwd_key);
        bpf_map_delete_elem(&conntrack_map, &rev_key);
    }

    /* Evaluate rules for new ICMP flow */
    int rule_action = evaluate_rules(pkt);
    if (rule_action != ACTION_PASS) {
        inc_stat(STAT_DROPPED_RULE);
        pkt->action = ACTION_DROP;
        pkt->conn_state = CONN_STATE_INVALID;
        return ACTION_DROP;
    }

    struct flow_entry new_fwd = {
        .state = CONN_STATE_ICMP_ACTIVE,
        .flags_seen = 0,
        .created_ns = now,
        .last_seen_ns = now,
        .packets_forward = 1,
        .packets_reverse = 0,
        .bytes_forward = pkt->pkt_len,
        .bytes_reverse = 0,
        .timeout_ns = ICMP_TIMEOUT_NS,
    };
    bpf_map_update_elem(&conntrack_map, &fwd_key, &new_fwd, BPF_ANY);

    struct flow_entry new_rev = {
        .state = CONN_STATE_ICMP_ACTIVE,
        .flags_seen = 0,
        .created_ns = now,
        .last_seen_ns = now,
        .packets_forward = 0,
        .packets_reverse = 0,
        .bytes_forward = 0,
        .bytes_reverse = 0,
        .timeout_ns = ICMP_TIMEOUT_NS,
    };
    bpf_map_update_elem(&conntrack_map, &rev_key, &new_rev, BPF_ANY);

    inc_stat(STAT_CONN_NEW);
    pkt->action = ACTION_PASS;
    pkt->conn_state = CONN_STATE_ICMP_ACTIVE;
    return ACTION_PASS;
}

#endif /* __CORE_CONNTRACK_BPF_H__ */
