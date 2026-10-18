#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <core/constants.h>
#include <core/conntrack.h>
#include "anti_spoof_mgr.h"

int anti_spoof_parse_file(const char *path, struct anti_spoof_rule *rules, unsigned *count)
{
    *count = 0;
    FILE *file = fopen(path, "r");
    if (!file) return -1;
    char line[256];
    unsigned number = 0;
    int result = -1;
    while (fgets(line, sizeof(line), file)) {
        number++;
        if (!strchr(line, '\n') && !feof(file)) goto invalid;
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';
        char *save = NULL;
        char *name = strtok_r(line, " \t\r\n", &save);
        if (!name) continue;
        char *action = strtok_r(NULL, " \t\r\n", &save);
        char *cidr = strtok_r(NULL, " \t\r\n", &save);
        if (!action || !cidr || strtok_r(NULL, " \t\r\n", &save) ||
            *count >= ANTI_SPOOF_MAX_PREFIXES || strlen(name) >= sizeof(rules[0].interface))
            goto invalid;
        struct anti_spoof_rule rule = {0};
        strcpy(rule.interface, name);
        if (!strcmp(action, "allow")) rule.allow = 1;
        else if (strcmp(action, "deny")) goto invalid;
        char *slash = strchr(cidr, '/');
        if (!slash) goto invalid;
        *slash++ = '\0';
        if (*slash < '0' || *slash > '9') goto invalid;
        char *end;
        errno = 0;
        unsigned long bits = strtoul(slash, &end, 10);
        if (errno || *end) goto invalid;
        unsigned width;
        if (inet_pton(AF_INET, cidr, rule.key.address) == 1) {
            rule.key.family = FW_AF_INET;
            width = 32;
        } else if (inet_pton(AF_INET6, cidr, rule.key.address) == 1) {
            rule.key.family = FW_AF_INET6;
            width = 128;
        } else goto invalid;
        if (bits > width) goto invalid;
        rule.key.prefixlen = ANTI_SPOOF_SCOPE_BITS + bits;
        /* Canonicalize host bits, then reject duplicate/conflicting prefixes. */
        unsigned char *address = (void *)rule.key.address;
        for (unsigned bit = bits; bit < width; bit++)
            address[bit / 8] &= ~(1u << (7 - bit % 8));
        for (unsigned i = 0; i < *count; i++)
            if (!strcmp(rules[i].interface, name) &&
                !memcmp(&rules[i].key, &rule.key, sizeof(rule.key))) goto invalid;
        rules[(*count)++] = rule;
    }
    if (ferror(file) || !*count) goto invalid;
    result = 0;
    goto done;
invalid:
    fprintf(stderr, "[-] Invalid or empty anti-spoof policy '%s' near line %u\n", path, number);
    *count = 0;
done:
    fclose(file);
    return result;
}

int anti_spoof_initialize(struct bpf_loader_ctx *ctx, const struct firewall_config *cfg)
{
    if (!cfg->anti_spoof.enabled) return 0;
    struct anti_spoof_rule *rules = calloc(ANTI_SPOOF_MAX_PREFIXES, sizeof(*rules));
    if (!rules) return -1;
    unsigned count;
    int result = -1;
    if (anti_spoof_parse_file(cfg->anti_spoof.path, rules, &count)) goto done;
    /* Resolve every interface before writing any policy. */
    for (unsigned i = 0; i < count; i++) {
        for (int j = 0; j < ctx->num_ifaces; j++)
            if (!strcmp(rules[i].interface, ctx->ifaces[j].ifname))
                rules[i].key.ifindex = ctx->ifaces[j].ifindex;
        if (!rules[i].key.ifindex) {
            fprintf(stderr, "[-] Anti-spoof interface '%s' is not attached\n", rules[i].interface);
            goto done;
        }
    }
    int prefixes = bpf_object__find_map_fd_by_name(ctx->obj, "anti_spoof_prefix");
    int scopes = bpf_object__find_map_fd_by_name(ctx->obj, "anti_spoof_scopes");
    for (unsigned i = 0; i < count; i++) {
        __u32 verified;
        if (bpf_map_update_elem(prefixes, &rules[i].key, &rules[i].allow, BPF_NOEXIST) ||
            bpf_map_lookup_elem(prefixes, &rules[i].key, &verified) || verified != rules[i].allow)
            goto done;
    }
    for (unsigned i = 0; i < count; i++) {
        __u32 enabled = 1, verified;
        if (bpf_map_update_elem(scopes, &rules[i].key.ifindex, &enabled, BPF_ANY) ||
            bpf_map_lookup_elem(scopes, &rules[i].key.ifindex, &verified) || verified != enabled)
            goto done;
    }
    printf("[+] Initialized %u anti-spoof source prefixes (unmatched sources on selected ingress are denied)\n", count);
    result = 0;
done:
    free(rules);
    if (result) fprintf(stderr, "[-] Anti-spoof initialization failed; no hooks attached\n");
    return result;
}
