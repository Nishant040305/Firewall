#include <stdio.h>
#include <arpa/inet.h>
#include <core/constants.h>
#include "protocol_adapter.h"
#include "../utils/ip_utils.h"
#include "../utils/format_utils.h"

static void udp_format_event(const struct packet_event *evt, char *buf, size_t len)
{
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    ip_to_str(evt->src_ip, src, sizeof(src));
    ip_to_str(evt->dst_ip, dst, sizeof(dst));

    snprintf(buf, len, "[PACKET] UDP  | %s:%-5u -> %s:%-5u (%u bytes)",
             src, ntohs(evt->src_port),
             dst, ntohs(evt->dst_port),
             evt->pkt_len);
}

const struct protocol_adapter udp_adapter = {
    .name = "UDP",
    .proto_num = PROTO_UDP,
    .format_event = udp_format_event,
};
