#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "config.h"

const char *direction_to_str(enum traffic_direction dir)
{
    switch (dir) {
    case TRAFFIC_DIR_INGRESS: return "in (ingress)";
    case TRAFFIC_DIR_EGRESS:  return "out (egress)";
    case TRAFFIC_DIR_BOTH:    return "both (bidirectional)";
    default:                  return "unknown";
    }
}

const char *mode_to_str(enum attach_mode mode)
{
    switch (mode) {
    case ATTACH_MODE_HYBRID: return "hybrid (XDP Ingress + TC Egress)";
    case ATTACH_MODE_TC:     return "tc (TC Ingress + TC Egress)";
    case ATTACH_MODE_XDP:    return "xdp (Ingress only)";
    default:                 return "unknown";
    }
}

void config_set_defaults(struct firewall_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->interface, "eth0", sizeof(cfg->interface) - 1);
    strncpy(cfg->log_level, "info", sizeof(cfg->log_level) - 1);
    cfg->direction = TRAFFIC_DIR_BOTH;
    cfg->mode = ATTACH_MODE_HYBRID; /* Default: XDP ingress + TC egress */

    cfg->global.stats_interval_sec = 1;
    cfg->global.ringbuf_poll_timeout_ms = 100;
    cfg->global.default_policy = 1; /* PASS */
}

static char *trim_whitespace(char *str)
{
    while (*str == ' ' || *str == '\t' || *str == '\r' || *str == '\n') str++;
    if (*str == '\0') return str;

    char *end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }
    return str;
}

int config_load_file(const char *path, struct firewall_config *cfg)
{
    if (!path) return 0;

    FILE *f = fopen(path, "r");
    if (!f) {
        return -1;
    }

    char line[256];
    char current_section[32] = "";

    while (fgets(line, sizeof(line), f)) {
        char *p = trim_whitespace(line);
        if (*p == '#' || *p == '\0') continue;

        /* Section Header (e.g., "global:") */
        if (p[strlen(p) - 1] == ':') {
            p[strlen(p) - 1] = '\0';
            strncpy(current_section, p, sizeof(current_section) - 1);
            continue;
        }

        char *colon = strchr(p, ':');
        if (!colon) continue;

        *colon = '\0';
        char *key = trim_whitespace(p);
        char *val = trim_whitespace(colon + 1);

        if (strcmp(key, "interface") == 0) {
            strncpy(cfg->interface, val, sizeof(cfg->interface) - 1);
        } else if (strcmp(key, "log_level") == 0) {
            strncpy(cfg->log_level, val, sizeof(cfg->log_level) - 1);
        } else if (strcmp(key, "direction") == 0) {
            if (strcasecmp(val, "in") == 0 || strcasecmp(val, "ingress") == 0) {
                cfg->direction = TRAFFIC_DIR_INGRESS;
            } else if (strcasecmp(val, "out") == 0 || strcasecmp(val, "egress") == 0) {
                cfg->direction = TRAFFIC_DIR_EGRESS;
            } else {
                cfg->direction = TRAFFIC_DIR_BOTH;
            }
        } else if (strcmp(key, "mode") == 0) {
            if (strcasecmp(val, "hybrid") == 0 || strcasecmp(val, "xdp+tc") == 0 || strcasecmp(val, "xdp_tc") == 0) {
                cfg->mode = ATTACH_MODE_HYBRID;
            } else if (strcasecmp(val, "xdp") == 0) {
                cfg->mode = ATTACH_MODE_XDP;
            } else {
                cfg->mode = ATTACH_MODE_TC;
            }
        } else if (strcmp(current_section, "global") == 0) {
            if (strcmp(key, "direction") == 0) {
                if (strcasecmp(val, "in") == 0 || strcasecmp(val, "ingress") == 0) {
                    cfg->direction = TRAFFIC_DIR_INGRESS;
                } else if (strcasecmp(val, "out") == 0 || strcasecmp(val, "egress") == 0) {
                    cfg->direction = TRAFFIC_DIR_EGRESS;
                } else {
                    cfg->direction = TRAFFIC_DIR_BOTH;
                }
            } else if (strcmp(key, "mode") == 0) {
                if (strcasecmp(val, "hybrid") == 0 || strcasecmp(val, "xdp+tc") == 0 || strcasecmp(val, "xdp_tc") == 0) {
                    cfg->mode = ATTACH_MODE_HYBRID;
                } else if (strcasecmp(val, "xdp") == 0) {
                    cfg->mode = ATTACH_MODE_XDP;
                } else {
                    cfg->mode = ATTACH_MODE_TC;
                }
            } else if (strcmp(key, "stats_interval_sec") == 0) {
                cfg->global.stats_interval_sec = atoi(val);
            } else if (strcmp(key, "ringbuf_poll_timeout_ms") == 0) {
                cfg->global.ringbuf_poll_timeout_ms = atoi(val);
            } else if (strcmp(key, "default_policy") == 0) {
                cfg->global.default_policy = (strcmp(val, "pass") == 0 || strcmp(val, "allow") == 0 || strcmp(val, "1") == 0) ? 1 : 0;
            }
        }
    }

    fclose(f);
    return 0;
}

int config_validate(const struct firewall_config *cfg)
{
    if (strlen(cfg->interface) == 0) {
        return -1;
    }
    if (cfg->global.stats_interval_sec <= 0) {
        return -1;
    }
    return 0;
}

void config_dump(const struct firewall_config *cfg)
{
    printf("[*] Loaded Firewall Configuration:\n");
    printf("    - Interface: %s\n", cfg->interface);
    printf("    - Mode:      %s\n", mode_to_str(cfg->mode));
    printf("    - Direction: %s\n", direction_to_str(cfg->direction));
    printf("    - Log Level: %s\n", cfg->log_level);
}
