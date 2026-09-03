#ifndef __CORE_STATS_MGR_H__
#define __CORE_STATS_MGR_H__

#include <core/stats.h>

/* Statistics Management API (Step 11) */
int stats_mgr_show(int map_fd, int json_format);
int stats_mgr_reset(int map_fd);

#endif /* __CORE_STATS_MGR_H__ */
