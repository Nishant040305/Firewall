#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <core/constants.h>
#include "protocol_adapter.h"
#include "../utils/ip_utils.h"
#include "../utils/format_utils.h"

static void tcp_format_event(const struct packet_event *evt, char *buf, size_t len)
{
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    ip_to_str(evt->src_ip, src, sizeof(src));
    ip_to_str(evt->dst_ip, dst, sizeof(dst));

    const char *dir_str = (evt->direction == DIR_INGRESS) ? "IN " :
                          (evt->direction == DIR_EGRESS)  ? "OUT" : "---";
    const char *act_str = (evt->action == ACTION_PASS) ? "ALLOW" : "DROP ";

    char flags_str[32] = "";
    if (evt->tcp_flags & 0x02) strcat(flags_str, "SYN ");
    if (evt->tcp_flags & 0x10) strcat(flags_str, "ACK ");
    if (evt->tcp_flags & 0x01) strcat(flags_str, "FIN ");
    if (evt->tcp_flags & 0x04) strcat(flags_str, "RST ");
    if (evt->tcp_flags & 0x08) strcat(flags_str, "PSH ");
    if (strlen(flags_str) == 0) strcpy(flags_str, "--- ");

    snprintf(buf, len, "[%s] %s | TCP  | %s:%-5u -> %s:%-5u | Flags: %-8s | State: %u (%u bytes)",
             act_str, dir_str,
             src, ntohs(evt->src_port),
             dst, ntohs(evt->dst_port),
             flags_str, evt->conn_state,
             evt->pkt_len);
}

const struct protocol_adapter tcp_adapter = {
    .name = "TCP",
    .proto_num = PROTO_TCP,
    .format_event = tcp_format_event,
};
