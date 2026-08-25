#ifndef __CORE_CONFIG_H__
#define __CORE_CONFIG_H__

#include <linux/types.h>

/* Typed Runtime Firewall Configuration */
struct firewall_config {
    char interface[32];
    char log_level[16];

    struct {
        int stats_interval_sec;
        int ringbuf_poll_timeout_ms;
        int default_policy; /* 0 = DROP, 1 = PASS */
    } global;

};

/* Initialize configuration with safe defaults */
void config_set_defaults(struct firewall_config *cfg);

/* Parse protocol-divided YAML configuration file */
int config_load_file(const char *path, struct firewall_config *cfg);

/* Validate configuration semantics */
int config_validate(const struct firewall_config *cfg);

/* Dump configuration values to stdout for diagnostics */
void config_dump(const struct firewall_config *cfg);

#endif /* __CORE_CONFIG_H__ */
