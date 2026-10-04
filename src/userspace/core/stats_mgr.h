#ifndef __CORE_STATS_MGR_H__
#define __CORE_STATS_MGR_H__

#include <stdio.h>
#include <core/stats.h>
#include <core/types.h>

/* Statistics & Performance Management API */
int stats_mgr_show(int map_fd, int perf_map_fd, int json_format);
int stats_mgr_write_stream(FILE *fp, int map_fd, int perf_map_fd, int json_format);
int stats_mgr_log_to_file(int map_fd, int perf_map_fd, const char *filepath, int json_format);
int stats_mgr_reset(int map_fd, int perf_map_fd);
int perf_mgr_show(int perf_map_fd, int json_format);
int perf_mgr_write_stream(FILE *fp, int perf_map_fd, int json_format);
int perf_mgr_reset(int perf_map_fd);

#endif /* __CORE_STATS_MGR_H__ */
