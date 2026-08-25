#include <stdio.h>
#include <arpa/inet.h>
#include <core/constants.h>
#include "protocol_adapter.h"
#include "../utils/ip_utils.h"
#include "../utils/format_utils.h"

static void icmp_format_event(const struct packet_event *evt, char *buf, size_t len)
{
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    ip_to_str(evt->src_ip, src, sizeof(src));
    ip_to_str(evt->dst_ip, dst, sizeof(dst));

    snprintf(buf, len, "[PACKET] ICMP | %s -> %s (%u bytes)",
             src, dst, evt->pkt_len);
}

const struct protocol_adapter icmp_adapter = {
    .name = "ICMP",
    .proto_num = PROTO_ICMP,
    .format_event = icmp_format_event,
};
