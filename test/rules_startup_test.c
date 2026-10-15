#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <core/rules.h>

static struct fw_rule slots[MAX_RULE_ENTRIES];
static int fail_slot = -1;
static int corrupt_read;
static int mock_lookup(int fd, const void *key, void *value)
{
    assert(fd == 7);
    __u32 index = *(const __u32 *)key;
    memcpy(value, &slots[index], sizeof(slots[index]));
    if (corrupt_read && index == 0 && slots[0].proto == PROTO_ANY) {
        ((struct fw_rule *)value)->action = ACTION_DROP;
        corrupt_read = 0;
    }
    return 0;
}
static int mock_update(int fd, const void *key, const void *value, __u64 flags)
{
    assert(fd == 7 && flags == BPF_ANY);
    __u32 index = *(const __u32 *)key;
    if ((int)index == fail_slot) {
        fail_slot = -1;
        return -1;
    }
    memcpy(&slots[index], value, sizeof(slots[index]));
    return 0;
}
#define bpf_map_lookup_elem mock_lookup
#define bpf_map_update_elem mock_update
#include "../src/userspace/core/rules_mgr.c"
#undef bpf_map_lookup_elem
#undef bpf_map_update_elem

static void write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    assert(f);
    assert(fputs(content, f) >= 0);
    assert(!fclose(f));
}

int main(void)
{
    char path[] = "build/rules-startup-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    slots[0] = (struct fw_rule){.flags = RULE_FLAG_ACTIVE,
                               .proto = PROTO_TCP, .action = ACTION_DROP};
    struct fw_rule previous[MAX_RULE_ENTRIES];
    memcpy(previous, slots, sizeof(slots));
    assert(rules_mgr_replace_file(7, "build/nonexistent-rules-file") < 0);
    write_file(path, "# empty\n");
    assert(rules_mgr_replace_file(7, path) < 0);
    write_file(path, "- name: good\n  action: allow\n- name: bad\n  action: typo\n");
    assert(rules_mgr_replace_file(7, path) < 0);
    assert(!memcmp(previous, slots, sizeof(slots)));
    assert(rules_mgr_load_file(7, path) < 0);
    assert(!memcmp(previous, slots, sizeof(slots)));

    write_file(path, "- name: catch-all\n  proto: any\n  family: any\n  action: allow\n");
    fail_slot = 1;
    assert(rules_mgr_replace_file(7, path) < 0);
    assert(!memcmp(previous, slots, sizeof(slots)));
    corrupt_read = 1;
    assert(rules_mgr_replace_file(7, path) < 0);
    assert(!memcmp(previous, slots, sizeof(slots)));
    assert(rules_mgr_replace_file(7, path) == 1);
    assert(slots[0].flags & RULE_FLAG_ACTIVE);
    assert(slots[0].action == ACTION_PASS && slots[0].family == FW_AF_ANY);
    assert(slots[0].proto == PROTO_ANY);
    for (int i = 1; i < MAX_RULE_ENTRIES; i++) assert(!slots[i].flags);
    assert(!unlink(path));
    puts("Policy validation, catch-all readback and restoration tests passed");
    return 0;
}
