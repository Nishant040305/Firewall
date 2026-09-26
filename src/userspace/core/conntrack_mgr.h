#ifndef __CORE_CONNTRACK_MGR_H__
#define __CORE_CONNTRACK_MGR_H__

#include <core/conntrack.h>

/* Connection Tracking Management for Userspace firewallctl (Steps 9 & 10) */
int conntrack_mgr_list(int map_fd);
int conntrack_mgr_list_dual(int estab_map_fd, int syn_map_fd);

int conntrack_mgr_flush(int map_fd);
int conntrack_mgr_flush_dual(int estab_map_fd, int syn_map_fd);

int conntrack_mgr_gc_sweep(int map_fd);
int conntrack_mgr_gc_sweep_dual(int estab_map_fd, int syn_map_fd);

int conntrack_mgr_start_gc(int estab_map_fd, int syn_map_fd, int interval_sec);
void conntrack_mgr_stop_gc(void);

#endif /* __CORE_CONNTRACK_MGR_H__ */
