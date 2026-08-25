#ifndef __UTILS_IP_UTILS_H__
#define __UTILS_IP_UTILS_H__

#include <linux/types.h>
#include <stddef.h>

/* Convert IPv4 uint32 (network byte order) to dotted string */
void ip_to_str(__u32 ip, char *buf, size_t buf_len);

/* Parse dotted IPv4 string to uint32 (network byte order). Returns 0 on success, -1 on error */
int parse_ip(const char *ip_str, __u32 *out_ip);

#endif /* __UTILS_IP_UTILS_H__ */
