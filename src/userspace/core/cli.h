#ifndef __CORE_CLI_H__
#define __CORE_CLI_H__

// This can be extended to server configs , rules, stats, etc
struct firewall_options {
    const char *iface;
    const char *config_path;

};

/* Parse command-line arguments into options struct */
int parse_cli_args(int argc, char **argv, struct firewall_options *opts);

/* Print help and usage information */
void print_usage(const char *prog_name);

#endif /* __CORE_CLI_H__ */
