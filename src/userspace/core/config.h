#ifndef __CORE_CONFIG_H__
#define __CORE_CONFIG_H__

#include <linux/types.h>

enum traffic_direction {
    TRAFFIC_DIR_INGRESS = 1,
    TRAFFIC_DIR_EGRESS  = 2,
    TRAFFIC_DIR_BOTH    = 3,
};

enum attach_mode {
    ATTACH_MODE_HYBRID = 0, /* Default: XDP for Ingress, TC for Egress */
    ATTACH_MODE_TC     = 1, /* Pure TC (TC Ingress + TC Egress) */
    ATTACH_MODE_XDP    = 2, /* Pure XDP (Ingress only) */
};

/* Typed Runtime Firewall Configuration */
struct firewall_config {
    char interface[32];
    char log_level[16];
    enum traffic_direction direction; /* TRAFFIC_DIR_BOTH, etc. */
    enum attach_mode mode;            /* ATTACH_MODE_HYBRID, ATTACH_MODE_TC, or ATTACH_MODE_XDP */

    struct {
        int stats_interval_sec;
        int ringbuf_poll_timeout_ms;
        int default_policy; /* 0 = DROP, 1 = PASS */
    } global;

};

/* Helper strings */
const char *direction_to_str(enum traffic_direction dir);
const char *mode_to_str(enum attach_mode mode);

/* Initialize configuration with safe defaults */
void config_set_defaults(struct firewall_config *cfg);

/* Parse protocol-divided YAML configuration file */
int config_load_file(const char *path, struct firewall_config *cfg);

/* Validate configuration semantics */
int config_validate(const struct firewall_config *cfg);

/* Dump configuration values to stdout for diagnostics */
void config_dump(const struct firewall_config *cfg);

#endif /* __CORE_CONFIG_H__ */
