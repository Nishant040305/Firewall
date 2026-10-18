#ifndef __DUALMAP_TCP_BPF_H__
#define __DUALMAP_TCP_BPF_H__

/* Only TCP placement differs from the single-map engine. UDP and ICMP use
 * the shared implementations. Half-open flows cannot evict established ones. */
static __always_inline int process_tcp_state(struct pkt_ctx *pkt, __u64 now)
{
    const struct flow_key *key = &pkt->flow;
    struct flow_key reverse;
    make_reverse_flow_key(pkt, &reverse);
    __u8 flags = pkt->tcp_flags;

    if ((flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK)) {
        if (evaluate_rules(pkt) != ACTION_PASS) {
            inc_stat(STAT_DROPPED_RULE);
            return ACTION_DROP;
        }
#if FW_CONN_LIMIT
        if (!connection_limit_admit(pkt, now))
            return ACTION_DROP;
#endif
        struct flow_entry *existing = bpf_map_lookup_elem(&conntrack_map, key);
        if (existing && (now <= existing->last_seen_ns ||
            now - existing->last_seen_ns <= existing->timeout_ns)) {
            existing->last_seen_ns = now;
            pkt->conn_state = existing->state;
            return ACTION_PASS;
        }
        struct flow_entry forward = {
            .state = CONN_STATE_SYN_SENT, .flags_seen = flags,
            .created_ns = now, .last_seen_ns = now,
            .packets_forward = 1, .bytes_forward = pkt->pkt_len,
            .timeout_ns = TCP_SYN_TIMEOUT_NS,
        };
        struct flow_entry backward = forward;
        backward.flags_seen = 0;
        backward.packets_forward = 0;
        backward.bytes_forward = 0;
        if (bpf_map_update_elem(&ct_syn_map, key, &forward, BPF_ANY) ||
            bpf_map_update_elem(&ct_syn_map, &reverse, &backward, BPF_ANY)) {
            bpf_map_delete_elem(&ct_syn_map, key);
            bpf_map_delete_elem(&ct_syn_map, &reverse);
            return ACTION_DROP;
        }
        inc_stat(STAT_CONN_NEW);
        pkt->new_flow = 1;
        pkt->conn_state = CONN_STATE_SYN_SENT;
        return ACTION_PASS;
    }

    struct flow_entry *entry = bpf_map_lookup_elem(&conntrack_map, key);
    if (entry) {
        if (now > entry->last_seen_ns && now - entry->last_seen_ns > entry->timeout_ns) {
            bpf_map_delete_elem(&conntrack_map, key);
            bpf_map_delete_elem(&conntrack_map, &reverse);
            inc_stat(STAT_CONN_TIMEOUT);
            goto unsolicited;
        }
        if (flags & (TCP_FLAG_RST | TCP_FLAG_FIN)) {
            entry->state = flags & TCP_FLAG_RST ? CONN_STATE_CLOSED : CONN_STATE_FIN_WAIT;
            entry->last_seen_ns = now;
            entry->timeout_ns = TCP_CLOSE_TIMEOUT_NS;
            if (flags & TCP_FLAG_RST) inc_stat(STAT_CONN_CLOSED);
        } else if (entry->state == CONN_STATE_ESTABLISHED) {
            if (now > entry->last_seen_ns &&
                now - entry->last_seen_ns > CONNTRACK_REFRESH_INTERVAL_NS) {
                entry->last_seen_ns = now;
                entry->packets_forward++;
                entry->bytes_forward += pkt->pkt_len;
            }
        } else if (!(flags & TCP_FLAG_ACK)) {
            goto unsolicited;
        }
        pkt->conn_state = entry->state;
        return ACTION_PASS;
    }

    struct flow_entry *syn = bpf_map_lookup_elem(&ct_syn_map, key);
    if (!syn) goto unsolicited;
    if (now > syn->last_seen_ns && now - syn->last_seen_ns > syn->timeout_ns) {
        bpf_map_delete_elem(&ct_syn_map, key);
        bpf_map_delete_elem(&ct_syn_map, &reverse);
        inc_stat(STAT_CONN_TIMEOUT);
        goto unsolicited;
    }
    if ((flags & TCP_FLAG_SYN) && (flags & TCP_FLAG_ACK)) {
        syn->state = CONN_STATE_SYN_RECV;
        syn->last_seen_ns = now;
        syn->packets_reverse++;
        syn->bytes_reverse += pkt->pkt_len;
        syn->flags_seen |= flags;
        pkt->conn_state = CONN_STATE_SYN_RECV;
        return ACTION_PASS;
    }
    if (flags & TCP_FLAG_ACK) {
        struct flow_entry forward = *syn;
        forward.state = CONN_STATE_ESTABLISHED;
        forward.flags_seen |= flags;
        forward.last_seen_ns = now;
        forward.timeout_ns = TCP_ESTABLISHED_TIMEOUT_NS;
        forward.packets_forward++;
        forward.bytes_forward += pkt->pkt_len;
        struct flow_entry backward = forward;
        backward.packets_forward = forward.packets_reverse;
        backward.packets_reverse = forward.packets_forward;
        backward.bytes_forward = forward.bytes_reverse;
        backward.bytes_reverse = forward.bytes_forward;
        if (bpf_map_update_elem(&conntrack_map, key, &forward, BPF_ANY) ||
            bpf_map_update_elem(&conntrack_map, &reverse, &backward, BPF_ANY)) {
            bpf_map_delete_elem(&conntrack_map, key);
            bpf_map_delete_elem(&conntrack_map, &reverse);
            return ACTION_DROP;
        }
        bpf_map_delete_elem(&ct_syn_map, key);
        bpf_map_delete_elem(&ct_syn_map, &reverse);
        inc_stat(STAT_CONN_ESTABLISHED);
        pkt->conn_state = CONN_STATE_ESTABLISHED;
        return ACTION_PASS;
    }
    if (flags & TCP_FLAG_RST) {
        bpf_map_delete_elem(&ct_syn_map, key);
        bpf_map_delete_elem(&ct_syn_map, &reverse);
        inc_stat(STAT_CONN_CLOSED);
        pkt->conn_state = CONN_STATE_CLOSED;
        return ACTION_PASS;
    }
unsolicited:
    inc_stat(STAT_DROPPED_UNSOLICITED);
    pkt->reason = REASON_INVALID_STATE;
    return ACTION_DROP;
}

#endif
