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

/* Process TCP state machine (Step 9) - Dual-Map Architecture (Cilium-Style Split Table) */
static __always_inline int process_tcp_state(struct pkt_ctx *pkt, __u64 now)
{
    /* Step: 5-Tuple Key Extraction & Hash Calculation */
    __u64 t_hash_start = bpf_ktime_get_ns();
    struct flow_key fwd_key, rev_key;
    make_flow_key(pkt, &fwd_key);
    make_reverse_flow_key(pkt, &rev_key);
    calc_flow_hash(&fwd_key);
    __u64 t_hash_end = bpf_ktime_get_ns();
    pkt->time_hash_ns = (__u32)(t_hash_end - t_hash_start);
    record_step_time(STEP_HASH_CAL, pkt->time_hash_ns);

    __u8 flags = pkt->tcp_flags;

    /* 1. TCP SYN (Initial connection request from client or SYN flood) */
    if ((flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK)) {
        /* Step: Dynamic Rule Engine Lookup */
        __u64 t_rule_start = bpf_ktime_get_ns();
        int rule_action = evaluate_rules(pkt);
        __u64 t_rule_end = bpf_ktime_get_ns();
        __u64 rule_lookup_ns = t_rule_end - t_rule_start;
        record_step_time(STEP_LOOKUP_RULES, rule_lookup_ns);

        /* Step: Established Table Lookup (check for retransmitted SYN) */
        __u64 t_ct_start = bpf_ktime_get_ns();
        struct flow_entry *estab_existing = bpf_map_lookup_elem(&conntrack_map, &fwd_key);
        __u64 t_ct_end = bpf_ktime_get_ns();
        __u64 ct_lookup_ns = t_ct_end - t_ct_start;
        record_step_time(STEP_LOOKUP_CONNTRACK, ct_lookup_ns);

        pkt->time_lookup_ns = (__u32)(rule_lookup_ns + ct_lookup_ns);
        record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);

        if (rule_action != ACTION_PASS) {
            inc_stat(STAT_DROPPED_RULE);
            pkt->action = ACTION_DROP;
            pkt->conn_state = CONN_STATE_INVALID;
            return ACTION_DROP;
        }

        if (estab_existing) {
            estab_existing->last_seen_ns = now;
            pkt->action = ACTION_PASS;
            pkt->conn_state = estab_existing->state;
            return ACTION_PASS;
        }

        /* Step: State Table Update — Store half-open state in ct_syn_map */
        __u64 t_upd_start = bpf_ktime_get_ns();
        struct flow_entry new_syn = {
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
        bpf_map_update_elem(&ct_syn_map, &fwd_key, &new_syn, BPF_ANY);

        /* Create reverse half-open entry awaiting SYN-ACK */
        struct flow_entry rev_syn = {
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
        bpf_map_update_elem(&ct_syn_map, &rev_key, &rev_syn, BPF_ANY);
        __u64 t_upd_end = bpf_ktime_get_ns();
        __u64 upd_ns = t_upd_end - t_upd_start;
        record_step_time(STEP_UPDATE_CONNTRACK, upd_ns);
        pkt->time_update_ns += (__u32)upd_ns;

        inc_stat(STAT_CONN_NEW);
        pkt->action = ACTION_PASS;
        pkt->conn_state = CONN_STATE_SYN_SENT;
        return ACTION_PASS;
    }

    /* 2. Fast Path: Lookup in Established Table (conntrack_map) */
    __u64 t_ct_start = bpf_ktime_get_ns();
    struct flow_entry *entry = bpf_map_lookup_elem(&conntrack_map, &fwd_key);
    __u64 t_ct_end = bpf_ktime_get_ns();
    __u64 ct_lookup_ns = t_ct_end - t_ct_start;
    record_step_time(STEP_LOOKUP_CONNTRACK, ct_lookup_ns);

    if (entry) {
        /* Check timeout */
        if (now > entry->last_seen_ns && (now - entry->last_seen_ns > entry->timeout_ns)) {
            inc_stat(STAT_CONN_TIMEOUT);
            __u64 t_del_start = bpf_ktime_get_ns();
            bpf_map_delete_elem(&conntrack_map, &fwd_key);
            bpf_map_delete_elem(&conntrack_map, &rev_key);
            __u64 t_del_end = bpf_ktime_get_ns();
            __u64 del_ns = t_del_end - t_del_start;
            record_step_time(STEP_UPDATE_CONNTRACK, del_ns);
            pkt->time_update_ns += (__u32)del_ns;

            pkt->time_lookup_ns = (__u32)ct_lookup_ns;
            record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);
            inc_stat(STAT_DROPPED_UNSOLICITED);
            pkt->action = ACTION_DROP;
            pkt->conn_state = CONN_STATE_INVALID;
            return ACTION_DROP;
        }

        /* TCP ACK or Data packet */
        if (flags & TCP_FLAG_ACK) {
            __u64 t_upd_start = bpf_ktime_get_ns();
            if (entry->state == CONN_STATE_ESTABLISHED) {
                /* Hot data path: only write if refresh interval elapsed (lazy refresh) */
                if (now > entry->last_seen_ns &&
                    (now - entry->last_seen_ns) > CONNTRACK_REFRESH_INTERVAL_NS) {
                    entry->last_seen_ns = now;
                    entry->timeout_ns = TCP_ESTABLISHED_TIMEOUT_NS;
                    entry->packets_forward += 1;
                    entry->bytes_forward += pkt->pkt_len;
                }
            }

            /* Handle connection termination (FIN / RST) */
            if (flags & TCP_FLAG_RST) {
                entry->state = CONN_STATE_CLOSED;
                entry->timeout_ns = TCP_CLOSE_TIMEOUT_NS;
                entry->last_seen_ns = now;
                inc_stat(STAT_CONN_CLOSED);
            } else if (flags & TCP_FLAG_FIN) {
                entry->state = CONN_STATE_FIN_WAIT;
                entry->timeout_ns = TCP_CLOSE_TIMEOUT_NS;
                entry->last_seen_ns = now;
            }
            __u64 t_upd_end = bpf_ktime_get_ns();
            __u64 upd_ns = t_upd_end - t_upd_start;
            record_step_time(STEP_UPDATE_CONNTRACK, upd_ns);
            pkt->time_update_ns += (__u32)upd_ns;

            pkt->time_lookup_ns = (__u32)ct_lookup_ns;
            record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);
            pkt->action = ACTION_PASS;
            pkt->conn_state = entry->state;
            return ACTION_PASS;
        }

        /* Handle standalone RST or FIN */
        if (flags & (TCP_FLAG_RST | TCP_FLAG_FIN)) {
            __u64 t_upd_start = bpf_ktime_get_ns();
            if (now > entry->last_seen_ns) {
                entry->last_seen_ns = now;
            }
            entry->state = (flags & TCP_FLAG_RST) ? CONN_STATE_CLOSED : CONN_STATE_FIN_WAIT;
            entry->timeout_ns = TCP_CLOSE_TIMEOUT_NS;
            __u64 t_upd_end = bpf_ktime_get_ns();
            __u64 upd_ns = t_upd_end - t_upd_start;
            record_step_time(STEP_UPDATE_CONNTRACK, upd_ns);
            pkt->time_update_ns += (__u32)upd_ns;

            pkt->time_lookup_ns = (__u32)ct_lookup_ns;
            record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);
            pkt->action = ACTION_PASS;
            pkt->conn_state = entry->state;
            return ACTION_PASS;
        }

        /* Other valid packets on established flow */
        if (entry->state == CONN_STATE_ESTABLISHED) {
            __u64 t_upd_start = bpf_ktime_get_ns();
            if (now > entry->last_seen_ns &&
                (now - entry->last_seen_ns) > CONNTRACK_REFRESH_INTERVAL_NS) {
                entry->last_seen_ns = now;
                entry->timeout_ns = TCP_ESTABLISHED_TIMEOUT_NS;
                entry->packets_forward += 1;
                entry->bytes_forward += pkt->pkt_len;
            }
            __u64 t_upd_end = bpf_ktime_get_ns();
            __u64 upd_ns = t_upd_end - t_upd_start;
            record_step_time(STEP_UPDATE_CONNTRACK, upd_ns);
            pkt->time_update_ns += (__u32)upd_ns;

            pkt->time_lookup_ns = (__u32)ct_lookup_ns;
            record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);
            pkt->action = ACTION_PASS;
            pkt->conn_state = CONN_STATE_ESTABLISHED;
            return ACTION_PASS;
        }
    }

    /* 3. Slow Path: Check Half-Open SYN Table (ct_syn_map) */
    __u64 t_syn_start = bpf_ktime_get_ns();
    struct flow_entry *syn_entry = bpf_map_lookup_elem(&ct_syn_map, &fwd_key);
    __u64 t_syn_end = bpf_ktime_get_ns();
    __u64 syn_lookup_ns = t_syn_end - t_syn_start;
    /* Record syn-map lookup time as a separate CONNTRACK lookup for visibility */
    record_step_time(STEP_LOOKUP_CONNTRACK, syn_lookup_ns);

    if (syn_entry) {
        /* Check timeout */
        if (now > syn_entry->last_seen_ns && (now - syn_entry->last_seen_ns > syn_entry->timeout_ns)) {
            inc_stat(STAT_CONN_TIMEOUT);
            __u64 t_del_start = bpf_ktime_get_ns();
            bpf_map_delete_elem(&ct_syn_map, &fwd_key);
            bpf_map_delete_elem(&ct_syn_map, &rev_key);
            __u64 t_del_end = bpf_ktime_get_ns();
            __u64 del_ns = t_del_end - t_del_start;
            record_step_time(STEP_UPDATE_CONNTRACK, del_ns);
            pkt->time_update_ns += (__u32)del_ns;

            pkt->time_lookup_ns = (__u32)(ct_lookup_ns + syn_lookup_ns);
            record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);
            inc_stat(STAT_DROPPED_UNSOLICITED);
            pkt->action = ACTION_DROP;
            pkt->conn_state = CONN_STATE_INVALID;
            return ACTION_DROP;
        }

        /* TCP SYN-ACK Response from Server */
        if ((flags & TCP_FLAG_SYN) && (flags & TCP_FLAG_ACK)) {
            __u64 t_upd_start = bpf_ktime_get_ns();
            syn_entry->state = CONN_STATE_SYN_RECV;
            if (now > syn_entry->last_seen_ns) {
                syn_entry->last_seen_ns = now;
            }
            syn_entry->packets_reverse += 1;
            syn_entry->bytes_reverse += pkt->pkt_len;
            syn_entry->flags_seen |= flags;
            syn_entry->timeout_ns = TCP_SYN_TIMEOUT_NS;
            __u64 t_upd_end = bpf_ktime_get_ns();
            __u64 upd_ns = t_upd_end - t_upd_start;
            record_step_time(STEP_UPDATE_CONNTRACK, upd_ns);
            pkt->time_update_ns += (__u32)upd_ns;

            pkt->time_lookup_ns = (__u32)(ct_lookup_ns + syn_lookup_ns);
            record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);
            pkt->action = ACTION_PASS;
            pkt->conn_state = CONN_STATE_SYN_RECV;
            return ACTION_PASS;
        }

        /* TCP ACK: Handshake complete -> Promote connection into established table */
        if (flags & TCP_FLAG_ACK) {
            __u64 t_upd_start = bpf_ktime_get_ns();
            struct flow_entry estab_fwd = {
                .state = CONN_STATE_ESTABLISHED,
                .flags_seen = syn_entry->flags_seen | flags,
                .created_ns = syn_entry->created_ns,
                .last_seen_ns = now,
                .packets_forward = syn_entry->packets_forward + 1,
                .packets_reverse = syn_entry->packets_reverse,
                .bytes_forward = syn_entry->bytes_forward + pkt->pkt_len,
                .bytes_reverse = syn_entry->bytes_reverse,
                .timeout_ns = TCP_ESTABLISHED_TIMEOUT_NS,
            };
            bpf_map_update_elem(&conntrack_map, &fwd_key, &estab_fwd, BPF_ANY);

            struct flow_entry estab_rev = {
                .state = CONN_STATE_ESTABLISHED,
                .flags_seen = 0,
                .created_ns = syn_entry->created_ns,
                .last_seen_ns = now,
                .packets_forward = syn_entry->packets_reverse,
                .packets_reverse = syn_entry->packets_forward + 1,
                .bytes_forward = syn_entry->bytes_reverse,
                .bytes_reverse = syn_entry->bytes_forward + pkt->pkt_len,
                .timeout_ns = TCP_ESTABLISHED_TIMEOUT_NS,
            };
            bpf_map_update_elem(&conntrack_map, &rev_key, &estab_rev, BPF_ANY);

            /* Evict from half-open table */
            bpf_map_delete_elem(&ct_syn_map, &fwd_key);
            bpf_map_delete_elem(&ct_syn_map, &rev_key);
            __u64 t_upd_end = bpf_ktime_get_ns();
            __u64 upd_ns = t_upd_end - t_upd_start;
            record_step_time(STEP_UPDATE_CONNTRACK, upd_ns);
            pkt->time_update_ns += (__u32)upd_ns;

            pkt->time_lookup_ns = (__u32)(ct_lookup_ns + syn_lookup_ns);
            record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);
            inc_stat(STAT_CONN_ESTABLISHED);
            pkt->action = ACTION_PASS;
            pkt->conn_state = CONN_STATE_ESTABLISHED;
            return ACTION_PASS;
        }

        /* RST on half-open flow */
        if (flags & TCP_FLAG_RST) {
            __u64 t_upd_start = bpf_ktime_get_ns();
            bpf_map_delete_elem(&ct_syn_map, &fwd_key);
            bpf_map_delete_elem(&ct_syn_map, &rev_key);
            __u64 t_upd_end = bpf_ktime_get_ns();
            __u64 upd_ns = t_upd_end - t_upd_start;
            record_step_time(STEP_UPDATE_CONNTRACK, upd_ns);
            pkt->time_update_ns += (__u32)upd_ns;

            pkt->time_lookup_ns = (__u32)(ct_lookup_ns + syn_lookup_ns);
            record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);
            inc_stat(STAT_CONN_CLOSED);
            pkt->action = ACTION_PASS;
            pkt->conn_state = CONN_STATE_CLOSED;
            return ACTION_PASS;
        }
    }

    /* 4. Unsolicited non-SYN packet with no state in either table -> DROP */
    pkt->time_lookup_ns = (__u32)(ct_lookup_ns + syn_lookup_ns);
    record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);
    inc_stat(STAT_DROPPED_UNSOLICITED);
    pkt->action = ACTION_DROP;
    pkt->conn_state = CONN_STATE_INVALID;
    return ACTION_DROP;
}

/* Process UDP pseudo-connection state (Step 9) */
static __always_inline int process_udp_state(struct pkt_ctx *pkt, __u64 now)
{
    /* Step: 5-Tuple Key Extraction & Hash Calculation */
    __u64 t_hash_start = bpf_ktime_get_ns();
    struct flow_key fwd_key, rev_key;
    make_flow_key(pkt, &fwd_key);
    make_reverse_flow_key(pkt, &rev_key);
    calc_flow_hash(&fwd_key);
    __u64 t_hash_end = bpf_ktime_get_ns();
    pkt->time_hash_ns = (__u32)(t_hash_end - t_hash_start);
    record_step_time(STEP_HASH_CAL, pkt->time_hash_ns);

    /* Step: Conntrack State Table Lookup */
    __u64 t_ct_start = bpf_ktime_get_ns();
    struct flow_entry *entry = bpf_map_lookup_elem(&conntrack_map, &fwd_key);
    __u64 t_ct_end = bpf_ktime_get_ns();
    __u64 ct_lookup_ns = t_ct_end - t_ct_start;
    record_step_time(STEP_LOOKUP_CONNTRACK, ct_lookup_ns);

    if (entry) {
        if (now <= entry->last_seen_ns || (now - entry->last_seen_ns <= entry->timeout_ns)) {
            /* Lazy refresh: only write if interval elapsed */
            __u64 t_upd_start = bpf_ktime_get_ns();
            if (now > entry->last_seen_ns &&
                (now - entry->last_seen_ns) > CONNTRACK_REFRESH_INTERVAL_NS) {
                entry->last_seen_ns = now;
                entry->packets_forward += 1;
                entry->bytes_forward += pkt->pkt_len;
            }
            __u64 t_upd_end = bpf_ktime_get_ns();
            __u64 upd_ns = t_upd_end - t_upd_start;
            record_step_time(STEP_UPDATE_CONNTRACK, upd_ns);
            pkt->time_update_ns += (__u32)upd_ns;

            pkt->time_lookup_ns = (__u32)ct_lookup_ns;
            record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);
            pkt->action = ACTION_PASS;
            pkt->conn_state = CONN_STATE_UDP_ACTIVE;
            return ACTION_PASS;
        }
        /* Expired */
        __u64 t_del_start = bpf_ktime_get_ns();
        bpf_map_delete_elem(&conntrack_map, &fwd_key);
        bpf_map_delete_elem(&conntrack_map, &rev_key);
        __u64 t_del_end = bpf_ktime_get_ns();
        __u64 del_ns = t_del_end - t_del_start;
        record_step_time(STEP_UPDATE_CONNTRACK, del_ns);
        pkt->time_update_ns += (__u32)del_ns;
    }

    /* Step: Dynamic Rule Engine Lookup */
    __u64 t_rule_start = bpf_ktime_get_ns();
    int rule_action = evaluate_rules(pkt);
    __u64 t_rule_end = bpf_ktime_get_ns();
    __u64 rule_lookup_ns = t_rule_end - t_rule_start;
    record_step_time(STEP_LOOKUP_RULES, rule_lookup_ns);

    if (rule_action != ACTION_PASS) {
        inc_stat(STAT_DROPPED_RULE);
        pkt->time_lookup_ns = (__u32)(ct_lookup_ns + rule_lookup_ns);
        record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);
        pkt->action = ACTION_DROP;
        pkt->conn_state = CONN_STATE_INVALID;
        return ACTION_DROP;
    }

    /* Create forward and reverse UDP state entries */
    __u64 t_upd_start = bpf_ktime_get_ns();
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
    __u64 t_upd_end = bpf_ktime_get_ns();
    __u64 upd_ns = t_upd_end - t_upd_start;
    record_step_time(STEP_UPDATE_CONNTRACK, upd_ns);
    pkt->time_update_ns += (__u32)upd_ns;

    pkt->time_lookup_ns = (__u32)(ct_lookup_ns + rule_lookup_ns);
    record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);
    inc_stat(STAT_CONN_NEW);
    pkt->action = ACTION_PASS;
    pkt->conn_state = CONN_STATE_UDP_ACTIVE;
    return ACTION_PASS;
}

/* Process ICMP Echo session state (Step 9) */
static __always_inline int process_icmp_state(struct pkt_ctx *pkt, __u64 now)
{
    /* Step: 5-Tuple Key Extraction & Hash Calculation */
    __u64 t_hash_start = bpf_ktime_get_ns();
    struct flow_key fwd_key, rev_key;
    make_flow_key(pkt, &fwd_key);
    make_reverse_flow_key(pkt, &rev_key);
    calc_flow_hash(&fwd_key);
    __u64 t_hash_end = bpf_ktime_get_ns();
    pkt->time_hash_ns = (__u32)(t_hash_end - t_hash_start);
    record_step_time(STEP_HASH_CAL, pkt->time_hash_ns);

    /* Step: Conntrack State Table Lookup */
    __u64 t_ct_start = bpf_ktime_get_ns();
    struct flow_entry *entry = bpf_map_lookup_elem(&conntrack_map, &fwd_key);
    __u64 t_ct_end = bpf_ktime_get_ns();
    __u64 ct_lookup_ns = t_ct_end - t_ct_start;
    record_step_time(STEP_LOOKUP_CONNTRACK, ct_lookup_ns);

    if (entry) {
        if (now <= entry->last_seen_ns || (now - entry->last_seen_ns <= entry->timeout_ns)) {
            /* Lazy refresh: only write if interval elapsed */
            __u64 t_upd_start = bpf_ktime_get_ns();
            if (now > entry->last_seen_ns &&
                (now - entry->last_seen_ns) > CONNTRACK_REFRESH_INTERVAL_NS) {
                entry->last_seen_ns = now;
                entry->packets_forward += 1;
                entry->bytes_forward += pkt->pkt_len;
            }
            __u64 t_upd_end = bpf_ktime_get_ns();
            __u64 upd_ns = t_upd_end - t_upd_start;
            record_step_time(STEP_UPDATE_CONNTRACK, upd_ns);
            pkt->time_update_ns += (__u32)upd_ns;

            pkt->time_lookup_ns = (__u32)ct_lookup_ns;
            record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);
            pkt->action = ACTION_PASS;
            pkt->conn_state = CONN_STATE_ICMP_ACTIVE;
            return ACTION_PASS;
        }
        __u64 t_del_start = bpf_ktime_get_ns();
        bpf_map_delete_elem(&conntrack_map, &fwd_key);
        bpf_map_delete_elem(&conntrack_map, &rev_key);
        __u64 t_del_end = bpf_ktime_get_ns();
        __u64 del_ns = t_del_end - t_del_start;
        record_step_time(STEP_UPDATE_CONNTRACK, del_ns);
        pkt->time_update_ns += (__u32)del_ns;
    }

    /* Step: Dynamic Rule Engine Lookup */
    __u64 t_rule_start = bpf_ktime_get_ns();
    int rule_action = evaluate_rules(pkt);
    __u64 t_rule_end = bpf_ktime_get_ns();
    __u64 rule_lookup_ns = t_rule_end - t_rule_start;
    record_step_time(STEP_LOOKUP_RULES, rule_lookup_ns);

    if (rule_action != ACTION_PASS) {
        inc_stat(STAT_DROPPED_RULE);
        pkt->time_lookup_ns = (__u32)(ct_lookup_ns + rule_lookup_ns);
        record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);
        pkt->action = ACTION_DROP;
        pkt->conn_state = CONN_STATE_INVALID;
        return ACTION_DROP;
    }

    __u64 t_upd_start = bpf_ktime_get_ns();
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
    __u64 t_upd_end = bpf_ktime_get_ns();
    __u64 upd_ns = t_upd_end - t_upd_start;
    record_step_time(STEP_UPDATE_CONNTRACK, upd_ns);
    pkt->time_update_ns += (__u32)upd_ns;

    pkt->time_lookup_ns = (__u32)(ct_lookup_ns + rule_lookup_ns);
    record_step_time(STEP_LOOKUP_TOTAL, pkt->time_lookup_ns);
    inc_stat(STAT_CONN_NEW);
    pkt->action = ACTION_PASS;
    pkt->conn_state = CONN_STATE_ICMP_ACTIVE;
    return ACTION_PASS;
}

#endif /* __CORE_CONNTRACK_BPF_H__ */
