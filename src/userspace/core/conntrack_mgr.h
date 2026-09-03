#ifndef __CORE_CONNTRACK_MGR_H__
#define __CORE_CONNTRACK_MGR_H__

#include <core/conntrack.h>

/* Connection Tracking Management for Userspace firewallctl (Steps 9 & 10) */
int conntrack_mgr_list(int map_fd);
int conntrack_mgr_flush(int map_fd);

#endif /* __CORE_CONNTRACK_MGR_H__ */
