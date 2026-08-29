#include <stdio.h>
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

    snprintf(buf, len, "[PACKET] %s | TCP  | %s:%-5u -> %s:%-5u (%u bytes)",
             dir_str,
             src, ntohs(evt->src_port),
             dst, ntohs(evt->dst_port),
             evt->pkt_len);
}

const struct protocol_adapter tcp_adapter = {
    .name = "TCP",
    .proto_num = PROTO_TCP,
    .format_event = tcp_format_event,
};
