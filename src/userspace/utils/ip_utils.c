#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "ip_utils.h"

void ip_to_str(__u32 ip, char *buf, size_t buf_len)
{
    struct in_addr addr;
    addr.s_addr = ip;
    if (!inet_ntop(AF_INET, &addr, buf, buf_len)) {
        snprintf(buf, buf_len, "0.0.0.0");
    }
}

int parse_ip(const char *ip_str, __u32 *out_ip)
{
    if (!ip_str || !out_ip) return -1;
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        return -1;
    }
    *out_ip = addr.s_addr;
    return 0;
}

void address_to_str(__u8 family, __u32 ip, const struct ip6_addr *ip6,
                    char *buf, size_t size)
{
    if (family == FW_AF_INET6) {
        if (!inet_ntop(AF_INET6, ip6, buf, size)) snprintf(buf, size, "::");
    } else {
        ip_to_str(ip, buf, size);
    }
}

int rule_set_family(struct fw_rule *rule, const char *text)
{
    __u8 family;
    if (!strcmp(text, "ipv4") || !strcmp(text, "4")) family = FW_AF_INET;
    else if (!strcmp(text, "ipv6") || !strcmp(text, "6")) family = FW_AF_INET6;
    else if (!strcmp(text, "any")) family = FW_AF_ANY;
    else return -1;
    if (rule->family && family != rule->family) return -1;
    rule->family = family;
    return 0;
}

int rule_set_address(struct fw_rule *rule, const char *text, int source)
{
    if (!strcmp(text, "any")) return 0;
    char addr[INET6_ADDRSTRLEN + 5];
    if (strlen(text) >= sizeof(addr)) return -1;
    strcpy(addr, text);
    char *slash = strchr(addr, '/');
    unsigned family = strchr(addr, ':') ? FW_AF_INET6 : FW_AF_INET;
    unsigned bits = family == FW_AF_INET6 ? 128 : 32;
    if (slash) {
        *slash++ = 0;
        char *end;
        long value = strtol(slash, &end, 10);
        if (!*slash || *end || value < 0 || value > bits) return -1;
        bits = (unsigned)value;
    }
    if (rule->family && rule->family != family) return -1;
    unsigned char bytes[16] = {0}, mask[16] = {0};
    if (inet_pton(family == FW_AF_INET6 ? AF_INET6 : AF_INET, addr, bytes) != 1)
        return -1;
    for (unsigned i = 0; i < bits; i++) mask[i / 8] |= 0x80u >> (i % 8);
    if (family == FW_AF_INET6) {
        memcpy(source ? &rule->src_ip6 : &rule->dst_ip6, bytes, 16);
        memcpy(source ? &rule->src_mask6 : &rule->dst_mask6, mask, 16);
    } else {
        memcpy(source ? &rule->src_ip : &rule->dst_ip, bytes, 4);
        memcpy(source ? &rule->src_mask : &rule->dst_mask, mask, 4);
    }
    rule->family = family;
    rule->flags |= source ? RULE_FLAG_SRC_IP : RULE_FLAG_DST_IP;
    return 0;
}

int parse_port_range(const char *text, __u16 *min, __u16 *max)
{
    char *end;
    long first = strtol(text, &end, 10), last = first;
    if (end == text || first < 0 || first > 65535) return -1;
    if (*end == '-') {
        const char *next = end + 1;
        last = strtol(next, &end, 10);
        if (end == next) return -1;
    }
    if (*end || last < first || last > 65535) return -1;
    *min = first;
    *max = last;
    return 0;
}
