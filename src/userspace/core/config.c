#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

void config_set_defaults(struct firewall_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->interface, "veth_server", sizeof(cfg->interface) - 1);
    strncpy(cfg->log_level, "info", sizeof(cfg->log_level) - 1);

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
        } else if (strcmp(current_section, "global") == 0) {
            if (strcmp(key, "stats_interval_sec") == 0) {
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
    printf("    - Log Level: %s\n", cfg->log_level);
}
