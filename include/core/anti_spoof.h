#ifndef __CORE_ANTI_SPOOF_H__
#define __CORE_ANTI_SPOOF_H__
#include <linux/types.h>

#define ANTI_SPOOF_MAX_PREFIXES 1024
#define ANTI_SPOOF_MAX_SCOPES 16
/* The first 64 data bits identify an exact interface and address family.
 * Remaining bits are the network-order source address prefix. */
struct anti_spoof_key {
    __u32 prefixlen;
    __u32 ifindex;
    __u32 family;
    __u32 address[4];
};
#define ANTI_SPOOF_SCOPE_BITS 64
#endif
