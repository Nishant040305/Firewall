#ifndef __ANTI_SPOOF_MGR_H__
#define __ANTI_SPOOF_MGR_H__
#include <core/anti_spoof.h>
#include "bpf_loader.h"

struct anti_spoof_rule {
    char interface[64];
    struct anti_spoof_key key;
    __u32 allow;
};
int anti_spoof_parse_file(const char *path, struct anti_spoof_rule *rules, unsigned *count);
int anti_spoof_initialize(struct bpf_loader_ctx *ctx, const struct firewall_config *cfg);
#endif
