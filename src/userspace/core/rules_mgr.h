#ifndef __CORE_RULES_MGR_H__
#define __CORE_RULES_MGR_H__

#include <core/rules.h>
#include <core/types.h>

/* Rule Management API for Userspace firewallctl */
int rules_mgr_add(int map_fd, const struct fw_rule *rule, __u32 *out_index);
int rules_mgr_del(int map_fd, __u32 index);
int rules_mgr_list(int map_fd);
int rules_mgr_flush(int map_fd);
int rules_mgr_load_file(int map_fd, const char *filepath);

#endif /* __CORE_RULES_MGR_H__ */
