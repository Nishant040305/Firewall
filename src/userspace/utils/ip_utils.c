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
