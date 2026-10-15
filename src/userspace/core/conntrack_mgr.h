#ifndef __CORE_CONNTRACK_MGR_H__
#define __CORE_CONNTRACK_MGR_H__

#include <core/conntrack.h>

/* Connection Tracking Management for Userspace firewallctl (Steps 9 & 10) */
int conntrack_mgr_list(int map_fd);
int conntrack_mgr_flush(int map_fd, int cache_map_fd);
#if FW_ENGINE == FW_ENGINE_DUALMAP
int conntrack_mgr_gc_sweep(int map_fd);
#endif

#endif /* __CORE_CONNTRACK_MGR_H__ */
