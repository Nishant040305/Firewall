#include "format_utils.h"

const char *proto_to_str(__u8 proto)
{
    switch (proto) {
    case PROTO_TCP:  return "TCP";
    case PROTO_UDP:  return "UDP";
    case PROTO_ICMP: return "ICMP";
    default:         return "OTHER";
    }
}
