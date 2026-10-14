#include <assert.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "telemetry/network_log.h"
#include "core/config.h"

int main(void)
{
    char dir[] = "/tmp/opencode/network-log-XXXXXX";
    assert(mkdtemp(dir));
    char path[512], backup[515];
    snprintf(path, sizeof(path), "%s/events.jsonl", dir);
    snprintf(backup, sizeof(backup), "%s.1", path);
    struct network_log *log = calloc(1, sizeof(*log));
    assert(log);
    assert(network_log_init(log, path, 30, 4096, 0) == 0);
    struct packet_event event = {
        .timestamp_ns = 1000000000ULL, .src_ip = inet_addr("192.0.2.1"),
        .dst_ip = inet_addr("198.51.100.1"), .src_port = htons(12345),
        .dst_port = htons(443), .proto = 6, .direction = DIR_EGRESS,
        .action = ACTION_DROP, .reason = REASON_POLICY, .pkt_len = 60, .ifindex = 7,
    };
    network_log_record(log, &event);
    event.timestamp_ns += 1000000000ULL;
    network_log_record(log, &event);
    network_log_flush(log);
    FILE *file = fopen(path, "r");
    assert(file);
    char line[2048];
    assert(fgets(line, sizeof(line), file));
    assert(strstr(line, "\"event_count\":2"));
    assert(strstr(line, "\"observed_bytes\":120"));
    assert(strstr(line, "\"dst_port\":443"));
    assert(strstr(line, "\"direction\":\"out\""));
    assert(strstr(line, "\"reason\":\"policy\""));
    assert(strstr(line, "\"action\":\"drop\""));
    assert(!fgets(line, sizeof(line), file));
    fclose(file);
    network_log_record(log, &event);
    event.reason = REASON_INVALID_STATE;
    network_log_record(log, &event);
    assert(log->evictions == 1); /* different reasons never silently merge */
    network_log_flush(log);
    for (int i = 0; i < 50; i++) network_log_health(log, 3, 1);
    network_log_close(log);
    struct stat stat;
    assert(!lstat(path, &stat));
    assert((stat.st_mode & 0777) == 0600);
    assert(stat.st_size <= 4096);
    assert(!lstat(backup, &stat));
    assert(stat.st_size <= 4096);
    unlink(path);
    assert(!symlink(backup, path));
    assert(network_log_init(log, path, 30, 4096, 0) < 0);
    unlink(path);
    unlink(backup);
    rmdir(dir);
    free(log);

    struct firewall_config cfg;
    config_set_defaults(&cfg);
    assert(config_load_file("config/firewall.yaml", &cfg) == 0);
    assert(config_validate(&cfg) == 0);
    assert(cfg.mode == ATTACH_MODE_HYBRID); /* inline comments are stripped */
    assert(cfg.telemetry.console_events == 0);
    cfg.telemetry.aggregate_window_sec = 0;
    assert(config_validate(&cfg) < 0);
    puts("network logging tests passed");
    return 0;
}
