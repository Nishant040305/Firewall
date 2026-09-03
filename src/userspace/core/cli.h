#ifndef __CORE_CLI_H__
#define __CORE_CLI_H__

#include <core/rules.h>

enum cli_cmd {
    CMD_RUN = 0,
    CMD_RULE_LIST,
    CMD_RULE_ADD,
    CMD_RULE_DEL,
    CMD_RULE_FLUSH,
    CMD_RULE_LOAD,
    CMD_CONNTRACK_LIST,
    CMD_CONNTRACK_FLUSH,
    CMD_STATS_SHOW,
    CMD_STATS_RESET,
    CMD_STATUS,
};

struct firewall_options {
    enum cli_cmd cmd;
    const char *iface;
    const char *config_path;
    const char *rules_path;
    const char *direction;  /* "in", "out", "both" */
    const char *mode;       /* "tc", "xdp", "hybrid" */
    
    /* Subcommand parameters */
    struct fw_rule new_rule;
    __u32 del_rule_id;
    int json_output;
    int watch_interval;
};

/* Parse command-line arguments into options struct */
int parse_cli_args(int argc, char **argv, struct firewall_options *opts);

/* Print help and usage information */
void print_usage(const char *prog_name);

#endif /* __CORE_CLI_H__ */
