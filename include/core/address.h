#ifndef __CORE_ADDRESS_H__
#define __CORE_ADDRESS_H__

#include <linux/types.h>

/* Stable on-wire family identifiers, not platform AF_* values. */
#define FW_AF_ANY 0
#define FW_AF_INET 4
#define FW_AF_INET6 6

struct ip6_addr {
    __u32 words[4]; /* Network byte order */
};

#endif
