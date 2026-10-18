#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
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
    snprintf(cfg->interface, sizeof(cfg->interface), "eth0");
    snprintf(cfg->log_level, sizeof(cfg->log_level), "info");
    cfg->direction = TRAFFIC_DIR_BOTH;
    cfg->mode = ATTACH_MODE_HYBRID; /* Default: XDP ingress + TC egress */

    cfg->global.stats_interval_sec = 1;
    cfg->global.ringbuf_poll_timeout_ms = 100;
    cfg->global.default_policy = 0; /* Dataplane is default deny. */
    snprintf(cfg->telemetry.path, sizeof(cfg->telemetry.path), "telemetry/network.jsonl");
    cfg->telemetry.aggregate_window_sec = 30;
    cfg->telemetry.max_file_mb = 20;
    cfg->telemetry.console_events = 0;
#if FW_CONN_LIMIT
    cfg->connection_limit.source_max = 32;
#endif
#if FW_ANTI_SPOOF
    snprintf(cfg->anti_spoof.path, sizeof(cfg->anti_spoof.path), "config/anti_spoof.conf");
#endif
#if FW_RATE_LIMIT
    cfg->rate_limit.limits = (struct syn_rate_config){
        .source_rate = 100, .source_burst = 200,
        .aggregate_rate = 10000, .aggregate_burst = 20000,
        .aggregate_enabled = 1, /* Preserve behavior of existing configs. */
    };
#endif
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

#if FW_RATE_LIMIT
static int parse_rate_value(const char *text, __u32 *value)
{
    char *end;
    errno = 0;
    if (*text < '0' || *text > '9') return -1;
    unsigned long parsed = strtoul(text, &end, 10);
    if (errno || *end || !parsed || parsed > RATE_MAX_VALUE) return -1;
    *value = parsed;
    return 0;
}
#endif

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
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';
        char *p = trim_whitespace(line);
        if (*p == '#' || *p == '\0') continue;

        /* Section Header (e.g., "global:") */
        if (p[strlen(p) - 1] == ':' &&
            !(strcmp(current_section, "rate_limit") == 0 && strcmp(p, "interfaces:") == 0) &&
            !(strcmp(current_section, "connection_limit") == 0 && strcmp(p, "interfaces:") == 0) &&
            !(strcmp(current_section, "anti_spoof") == 0 && strcmp(p, "path:") == 0)) {
            p[strlen(p) - 1] = '\0';
            snprintf(current_section, sizeof(current_section), "%s", p);
            continue;
        }

        char *colon = strchr(p, ':');
        if (!colon) continue;

        *colon = '\0';
        char *key = trim_whitespace(p);
        char *val = trim_whitespace(colon + 1);

        if (strcmp(current_section, "connection_limit") == 0) {
#if FW_CONN_LIMIT
            int invalid = 0;
            if (!strcmp(key, "enabled")) {
                if (!strcmp(val, "true")) cfg->connection_limit.enabled = 1;
                else if (!strcmp(val, "false")) cfg->connection_limit.enabled = 0;
                else invalid = 1;
            } else if (!strcmp(key, "interfaces")) {
                if (strlen(val) >= sizeof(cfg->connection_limit.interfaces)) invalid = 1;
                else snprintf(cfg->connection_limit.interfaces, sizeof(cfg->connection_limit.interfaces), "%s", val);
            } else if (!strcmp(key, "source_max")) {
                char *end;
                errno = 0;
                unsigned long value = strtoul(val, &end, 10);
                if (*val < '0' || *val > '9' || errno || *end || !value || value > 32) invalid = 1;
                else cfg->connection_limit.source_max = value;
            } else invalid = 1;
            if (invalid) {
                fprintf(stderr, "[-] Invalid connection_limit setting: %s\n", key);
                fclose(f);
                return -1;
            }
#else
            continue;
#endif
        } else if (strcmp(current_section, "anti_spoof") == 0) {
#if FW_ANTI_SPOOF
            int invalid = 0;
            if (!strcmp(key, "enabled")) {
                if (!strcmp(val, "true")) cfg->anti_spoof.enabled = 1;
                else if (!strcmp(val, "false")) cfg->anti_spoof.enabled = 0;
                else invalid = 1;
            } else if (!strcmp(key, "path") && *val && strlen(val) < sizeof(cfg->anti_spoof.path))
                snprintf(cfg->anti_spoof.path, sizeof(cfg->anti_spoof.path), "%s", val);
            else invalid = 1;
            if (invalid) {
                fprintf(stderr, "[-] Invalid anti_spoof setting: %s\n", key);
                fclose(f);
                return -1;
            }
#else
            continue;
#endif
        } else if (strcmp(current_section, "rate_limit") == 0) {
#if FW_RATE_LIMIT
            int invalid = 0;
            if (!strcmp(key, "enabled")) {
                if (!strcmp(val, "true")) cfg->rate_limit.enabled = 1;
                else if (!strcmp(val, "false")) cfg->rate_limit.enabled = 0;
                else invalid = 1;
            } else if (!strcmp(key, "aggregate_enabled")) {
                if (!strcmp(val, "true")) cfg->rate_limit.limits.aggregate_enabled = 1;
                else if (!strcmp(val, "false")) cfg->rate_limit.limits.aggregate_enabled = 0;
                else invalid = 1;
            } else if (!strcmp(key, "interfaces")) {
                if (strlen(val) >= sizeof(cfg->rate_limit.interfaces)) invalid = 1;
                else snprintf(cfg->rate_limit.interfaces, sizeof(cfg->rate_limit.interfaces), "%s", val);
            } else if (!strcmp(key, "source_rate"))
                invalid = parse_rate_value(val, &cfg->rate_limit.limits.source_rate);
            else if (!strcmp(key, "source_burst"))
                invalid = parse_rate_value(val, &cfg->rate_limit.limits.source_burst);
            else if (!strcmp(key, "aggregate_rate"))
                invalid = parse_rate_value(val, &cfg->rate_limit.limits.aggregate_rate);
            else if (!strcmp(key, "aggregate_burst"))
                invalid = parse_rate_value(val, &cfg->rate_limit.limits.aggregate_burst);
            else invalid = 1;
            if (invalid) {
                fprintf(stderr, "[-] Invalid rate_limit setting: %s\n", key);
                fclose(f);
                return -1;
            }
#else
            /* Runtime configuration cannot enable a compiled-out feature. */
            continue;
#endif
        } else if (strcmp(key, "interface") == 0) {
            snprintf(cfg->interface, sizeof(cfg->interface), "%s", val);
        } else if (strcmp(key, "log_level") == 0) {
            snprintf(cfg->log_level, sizeof(cfg->log_level), "%s", val);
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
        } else if (strcmp(current_section, "telemetry") == 0) {
            if (strcmp(key, "path") == 0)
                snprintf(cfg->telemetry.path, sizeof(cfg->telemetry.path), "%s", val);
            else if (strcmp(key, "aggregate_window_sec") == 0)
                cfg->telemetry.aggregate_window_sec = atoi(val);
            else if (strcmp(key, "max_file_mb") == 0)
                cfg->telemetry.max_file_mb = atoi(val);
            else if (strcmp(key, "console_events") == 0)
                cfg->telemetry.console_events = !strcmp(val, "true");
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
#if FW_CONN_LIMIT
    if (!cfg->connection_limit.source_max || cfg->connection_limit.source_max > 32 ||
        (cfg->connection_limit.enabled && cfg->direction == TRAFFIC_DIR_EGRESS))
        return -1;
    if (cfg->connection_limit.enabled && strchr(cfg->interface, ',') &&
        !cfg->connection_limit.interfaces[0]) {
        fprintf(stderr, "[-] Select connection_limit.interfaces for multiple attached interfaces\n");
        return -1;
    }
#endif
#if FW_ANTI_SPOOF
    if (cfg->anti_spoof.enabled &&
        (!cfg->anti_spoof.path[0] || cfg->direction == TRAFFIC_DIR_EGRESS))
        return -1;
#endif
#if FW_RATE_LIMIT
    const struct syn_rate_config *rate = &cfg->rate_limit.limits;
    if (!rate->source_rate || !rate->source_burst ||
        rate->source_rate > RATE_MAX_VALUE || rate->source_burst > RATE_MAX_VALUE ||
        rate->aggregate_enabled > 1 ||
        (rate->aggregate_enabled && (!rate->aggregate_rate || !rate->aggregate_burst ||
         rate->aggregate_rate > RATE_MAX_VALUE || rate->aggregate_burst > RATE_MAX_VALUE)))
        return -1;
    if (cfg->rate_limit.enabled && cfg->direction == TRAFFIC_DIR_EGRESS)
        return -1;
    if (cfg->rate_limit.enabled && strchr(cfg->interface, ',') && !cfg->rate_limit.interfaces[0]) {
        fprintf(stderr, "[-] Select rate_limit.interfaces explicitly for multiple attached interfaces\n");
        return -1;
    }
#endif
    if (strlen(cfg->interface) == 0) {
        return -1;
    }
    if (cfg->global.stats_interval_sec <= 0) {
        return -1;
    }
    if (cfg->global.ringbuf_poll_timeout_ms < 1 || cfg->global.ringbuf_poll_timeout_ms > 10000)
        return -1;
#if FW_LOGGING
    if (
        !cfg->telemetry.path[0] || cfg->telemetry.aggregate_window_sec < 1 ||
        cfg->telemetry.aggregate_window_sec > 3600 || cfg->telemetry.max_file_mb < 1 ||
        cfg->telemetry.max_file_mb > 1024) return -1;
#endif
    return 0;
}

void config_dump(const struct firewall_config *cfg)
{
    printf("[*] Loaded Firewall Configuration:\n");
    printf("    - Interface: %s\n", cfg->interface);
    printf("    - Mode:      %s\n", mode_to_str(cfg->mode));
    printf("    - Direction: %s\n", direction_to_str(cfg->direction));
    printf("    - Log Level: %s\n", cfg->log_level);
#if FW_CONN_LIMIT
    printf("    - TCP connection limit: %s (maximum %u per initiator IP)\n",
           cfg->connection_limit.enabled ? "enabled" : "disabled", cfg->connection_limit.source_max);
#else
    puts("    - TCP connection limit: compiled out (connection_limit settings ignored)");
#endif
#if FW_ANTI_SPOOF
    printf("    - Anti-spoofing: %s (policy: %s)\n",
           cfg->anti_spoof.enabled ? "enabled" : "disabled", cfg->anti_spoof.path);
#else
    puts("    - Anti-spoofing: compiled out (anti_spoof configuration ignored)");
#endif
#if FW_RATE_LIMIT
    printf("    - SYN limiter: %s (source %u/s burst %u per ingress scope)\n",
           cfg->rate_limit.enabled ? "enabled" : "disabled",
           cfg->rate_limit.limits.source_rate, cfg->rate_limit.limits.source_burst);
    if (cfg->rate_limit.limits.aggregate_enabled)
        printf("    - Aggregate SYN budget: %u/s burst %u per ingress scope\n",
               cfg->rate_limit.limits.aggregate_rate, cfg->rate_limit.limits.aggregate_burst);
    else
        puts("    - Aggregate SYN budget: disabled (per-source limits only)");
#else
    puts("    - SYN limiter: compiled out (rate_limit configuration ignored)");
#endif
}
