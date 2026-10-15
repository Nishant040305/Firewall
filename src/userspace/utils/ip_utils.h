#ifndef __UTILS_IP_UTILS_H__
#define __UTILS_IP_UTILS_H__

#include <linux/types.h>
#include <stddef.h>
#include <core/rules.h>

/* Convert IPv4 uint32 (network byte order) to dotted string */
void ip_to_str(__u32 ip, char *buf, size_t buf_len);

/* Parse dotted IPv4 string to uint32 (network byte order). Returns 0 on success, -1 on error */
int parse_ip(const char *ip_str, __u32 *out_ip);

void address_to_str(__u8 family, __u32 ip, const struct ip6_addr *ip6,
                    char *buf, size_t size);
/* Parse an address or CIDR and infer a rule's family. Reject mixed families. */
int rule_set_address(struct fw_rule *rule, const char *text, int source);
int rule_set_family(struct fw_rule *rule, const char *text);
int parse_port_range(const char *text, __u16 *min, __u16 *max);

#endif /* __UTILS_IP_UTILS_H__ */
