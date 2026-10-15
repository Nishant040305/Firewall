#include <stdio.h>
#include <arpa/inet.h>
#include <core/constants.h>
#include "protocol_adapter.h"
#include "../utils/ip_utils.h"
#include "../utils/format_utils.h"

static void udp_format_event(const struct packet_event *evt, char *buf, size_t len)
{
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    address_to_str(evt->family, evt->src_ip, &evt->src_ip6, src, sizeof(src));
    address_to_str(evt->family, evt->dst_ip, &evt->dst_ip6, dst, sizeof(dst));

    const char *dir_str = (evt->direction == DIR_INGRESS) ? "IN " :
                          (evt->direction == DIR_EGRESS)  ? "OUT" : "---";
    const char *act_str = (evt->action == ACTION_PASS) ? "ALLOW" : "DROP ";

    snprintf(buf, len, "[%s] %s | UDP  | %s:%-5u -> %s:%-5u | State: %u (%u bytes) | Time(ns): ext=%u hash=%u lkp=%u upd=%u tot=%u",
             act_str, dir_str,
             src, ntohs(evt->src_port),
             dst, ntohs(evt->dst_port),
             evt->conn_state,
             evt->pkt_len,
             evt->time_extract_ns, evt->time_hash_ns,
             evt->time_lookup_ns, evt->time_update_ns, evt->time_total_ns);
}

const struct protocol_adapter udp_adapter = {
    .name = "UDP",
    .proto_num = PROTO_UDP,
    .format_event = udp_format_event,
};
