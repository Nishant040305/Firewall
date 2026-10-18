#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "core/anti_spoof_mgr.h"

static struct anti_spoof_rule rules[ANTI_SPOOF_MAX_PREFIXES];
static void check(const char *text, int valid, unsigned expected)
{
    char path[] = "/tmp/opencode/anti-spoof-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    FILE *file = fdopen(fd, "w");
    assert(file);
    fputs(text, file);
    fclose(file);
    unsigned count = 999;
    assert((anti_spoof_parse_file(path, rules, &count) == 0) == valid);
    assert(count == expected);
    unlink(path);
}
int main(void)
{
    check("lan0 allow 192.168.1.123/24\nlan0 deny 192.168.1.10/32\nlan0 allow fd00:1::123/64\n", 1, 3);
    __u32 address;
    inet_pton(AF_INET, "192.168.1.0", &address);
    assert(rules[0].key.address[0] == address);
    assert(rules[0].key.prefixlen == ANTI_SPOOF_SCOPE_BITS + 24);
    assert(rules[1].allow == 0);
    __u32 ip6[4];
    inet_pton(AF_INET6, "fd00:1::", ip6);
    assert(!memcmp(rules[2].key.address, ip6, sizeof(ip6)));
    check("wan0 allow 0.0.0.0/0\nwan0 allow ::/0\n", 1, 2);
    check("# empty\n", 0, 0);
    check("lan0 allow 10.0.0.1/33\n", 0, 0);
    check("lan0 allow ::/129\n", 0, 0);
    check("lan0 allow ::/-1\n", 0, 0);
    check("lan0 allow ::/abc\n", 0, 0);
    check("lan0 allow not-an-ip/24\n", 0, 0);
    check("lan0 allow 10.0.0.1\n", 0, 0);
    check("lan0 alow 10.0.0.0/24\n", 0, 0);
    check("lan0 allow 10.0.0.0/24 extra\n", 0, 0);
    check("lan0 allow 10.0.0.123/24\nlan0 deny 10.0.0.0/24\n", 0, 0);
    check("lan0 allow 10.0.0.0/24\nlan1 deny 10.0.0.0/24\n", 1, 2);
    struct firewall_config cfg;
    config_set_defaults(&cfg);
    assert(!cfg.anti_spoof.enabled);
    cfg.anti_spoof.enabled = 1;
    assert(!config_validate(&cfg));
    cfg.direction = TRAFFIC_DIR_EGRESS;
    assert(config_validate(&cfg) < 0);
    puts("Anti-spoof CIDR parsing, canonicalization, duplicates and config tests passed");
}
