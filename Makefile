CC ?= gcc
CLANG ?= clang
# Presets only supply defaults; explicit feature variables still take priority.
PRESETS := default logging timing minimal lean debug
PRESET_GOALS := $(filter $(PRESETS),$(MAKECMDGOALS))
ifneq ($(word 2,$(PRESET_GOALS)),)
$(error Choose only one preset: $(PRESETS))
endif
PRESET ?= $(if $(PRESET_GOALS),$(PRESET_GOALS),default)
ifeq ($(filter $(PRESET),$(PRESETS)),)
$(error PRESET must be one of: $(PRESETS))
endif
ifneq ($(PRESET_GOALS),)
ifneq ($(PRESET),$(PRESET_GOALS))
$(error PRESET=$(PRESET) conflicts with target $(PRESET_GOALS))
endif
endif
preset_timing_default := 0
preset_timing_logging := 0
preset_timing_timing := 1
preset_timing_minimal := 0
preset_timing_lean := 0
preset_timing_debug := 1
preset_logging_default := 0
preset_logging_logging := 1
preset_logging_timing := 0
preset_logging_minimal := 0
preset_logging_lean := 0
preset_logging_debug := 1
preset_obs_default := full
preset_obs_logging := full
preset_obs_timing := minimal
preset_obs_minimal := minimal
preset_obs_lean := none
preset_obs_debug := full
ENGINE ?= fastcache
TIMING ?= $(preset_timing_$(PRESET))
LOGGING ?= $(preset_logging_$(PRESET))
OBSERVABILITY ?= $(preset_obs_$(PRESET))

ENGINES := stateful fastcache dualmap
OBS_MODES := full minimal none
ifeq ($(filter $(ENGINE),$(ENGINES)),)
$(error ENGINE must be one of: $(ENGINES))
endif
ifeq ($(filter $(OBSERVABILITY),$(OBS_MODES)),)
$(error OBSERVABILITY must be one of: $(OBS_MODES))
endif
ifneq ($(filter $(TIMING),0 1),$(TIMING))
$(error TIMING must be 0 or 1)
endif
ifneq ($(filter $(LOGGING),0 1),$(LOGGING))
$(error LOGGING must be 0 or 1)
endif
ifeq ($(TIMING):$(OBSERVABILITY),1:none)
$(error TIMING=1 requires OBSERVABILITY=full or minimal)
endif
ifeq ($(LOGGING),1)
ifneq ($(OBSERVABILITY),full)
$(error LOGGING=1 requires OBSERVABILITY=full)
endif
endif

engine_stateful := 1
engine_fastcache := 2
engine_dualmap := 3
obs_full := 0
obs_minimal := 1
obs_none := 2
PROFILE := $(ENGINE)-t$(TIMING)-l$(LOGGING)-$(OBSERVABILITY)
BUILD_DIR := build/profiles/$(PROFILE)
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/armv[0-9]*/arm/')
MULTIARCH ?= $(shell gcc -print-multiarch 2>/dev/null)
ARCH_INC := $(if $(MULTIARCH),-I/usr/include/$(MULTIARCH),)
RAW_ARCH ?= $(shell uname -m)
CPPFLAGS += -Iinclude -Isrc/userspace -DFW_ENGINE=$(engine_$(ENGINE)) -DFW_TIMING=$(TIMING) -DFW_LOGGING=$(LOGGING) -DFW_OBSERVABILITY=$(obs_$(OBSERVABILITY))
CPPFLAGS += -DFW_DEFAULT_BPF_OBJ='"$(BUILD_DIR)/firewall.bpf.o"'
CFLAGS ?= -O2 -g -Wall -Wextra
BPF_CFLAGS ?= -O2 -g -Wall -target bpf -mcpu=v3 -D__TARGET_ARCH_$(ARCH) -D__$(RAW_ARCH)__ $(ARCH_INC) -Isrc/kernel
LDLIBS := -lbpf -lelf -lz

USER_SRCS := $(addprefix src/userspace/,main.c core/cli.c core/config.c core/bpf_loader.c core/firewall_ctx.c core/rules_mgr.c core/conntrack_mgr.c core/stats_mgr.c utils/ip_utils.c)
ifeq ($(LOGGING),1)
USER_SRCS += src/userspace/telemetry/event_bus.c src/userspace/telemetry/network_log.c
else ifeq ($(OBSERVABILITY),full)
USER_SRCS += src/userspace/telemetry/console_bus.c
endif
ifeq ($(TIMING),1)
USER_SRCS += src/userspace/core/perf_mgr.c
endif
USER_OBJS := $(patsubst src/userspace/%.c,$(BUILD_DIR)/%.o,$(USER_SRCS))
BPF_OBJ := $(BUILD_DIR)/firewall.bpf.o
USER_BIN := $(BUILD_DIR)/fw-ctl
TEST_BIN := $(BUILD_DIR)/ipv6-test
.DEFAULT_GOAL := all
.PHONY: all $(PRESETS) help select bpf userspace tools baseline clean test-ipv6 test-ipv6-kernel test-logging test-tc-context test-rules-startup print-config FORCE

# Changing compiler/flags must invalidate this profile, but an unchanged
# invocation leaves timestamps alone and performs no compilation.
$(BUILD_DIR)/.flags: FORCE
	@mkdir -p $(BUILD_DIR)
	@printf '%s\n' '$(CC) $(CLANG) $(CPPFLAGS) $(CFLAGS) $(BPF_CFLAGS) $(LDLIBS)' > $@.tmp
	@cmp -s $@.tmp $@ && rm $@.tmp || mv $@.tmp $@

$(USER_OBJS) $(BPF_OBJ) $(TEST_BIN) $(BUILD_DIR)/test/ipv6_test.o: $(BUILD_DIR)/.flags

# Build one selected firewall object and its matching control plane only.
all: $(BPF_OBJ) $(USER_BIN)
$(PRESETS): all
bpf: $(BPF_OBJ)
userspace: $(USER_BIN)

select:
	@python3 scripts/build_selector.py

help:
	@printf '%s\n' \
	  'Build only; no target starts or attaches the firewall.' \
	  '' \
	  'Usage: make -j4 [preset] [ENGINE=fastcache|stateful|dualmap]' \
	  '  make select                            # Interactive build selector' \
	  '' \
	  'Preset    TIMING LOGGING OBSERVABILITY' \
	  'default   0      0       full  (plain make)' \
	  'logging   0      1       full' \
	  'timing    1      0       minimal' \
	  'minimal   0      0       minimal' \
	  'lean      0      0       none' \
	  'debug     1      1       full  (telemetry, not optimization flags)' \
	  '' \
	  'Examples:' \
	  '  make -j4 logging                       # FastCache + network logs' \
	  '  make -j4 lean ENGINE=stateful' \
	  '  make -j4 debug ENGINE=dualmap' \
	  '  make PRESET=logging print-config       # Preview without compiling' \
	  '  make PRESET=logging clean              # Clean only that profile' \
	  '' \
	  'Overrides: TIMING=0|1 LOGGING=0|1 OBSERVABILITY=full|minimal|none' \
	  'Logging requires full; timing requires full or minimal.' \
	  'Outputs: build/profiles/<engine>-t<timing>-l<logging>-<observability>/'

$(BUILD_DIR)/%.o: src/userspace/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(BPF_OBJ): src/kernel/main.bpf.c
	@mkdir -p $(dir $@)
	$(CLANG) $(CPPFLAGS) $(BPF_CFLAGS) -MMD -MP -c src/kernel/main.bpf.c -o $@

$(USER_BIN): $(USER_OBJS)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@
	ln -sf fw-ctl $(BUILD_DIR)/firewallctl

# Optional tools are not dependencies of all.
tools: $(BUILD_DIR)/conntrack_bench_tool
$(BUILD_DIR)/conntrack_bench_tool: test/conntrack_bench_tool.c include/core/conntrack.h include/core/build_config.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -lbpf -lm -o $@

baseline: $(BUILD_DIR)/xdp_pass.bpf.o
$(BUILD_DIR)/xdp_pass.bpf.o: src/kernel/xdp_pass.bpf.c
	@mkdir -p $(dir $@)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD_DIR)/test/ipv6_test.o: test/ipv6_test.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c test/ipv6_test.c -o $@
$(TEST_BIN): $(BUILD_DIR)/test/ipv6_test.o $(BUILD_DIR)/utils/ip_utils.o $(BUILD_DIR)/core/cli.o $(BUILD_DIR)/core/rules_mgr.o
	$(CC) $(CFLAGS) $(filter %.o,$^) $(LDLIBS) -o $@
test-ipv6: $(TEST_BIN)
	./$(TEST_BIN)
test-ipv6-kernel: $(BPF_OBJ) $(TEST_BIN)
	./$(TEST_BIN) $(BPF_OBJ)

test-rules-startup:
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) test/rules_startup_test.c src/userspace/utils/ip_utils.c -o $(BUILD_DIR)/rules-startup-test
	./$(BUILD_DIR)/rules-startup-test

test-tc-context:
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc/kernel test/tc_context_test.c -o $(BUILD_DIR)/tc-context-test
	./$(BUILD_DIR)/tc-context-test

test-logging:
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) test/network_log_test.c src/userspace/telemetry/network_log.c src/userspace/core/config.c -o $(BUILD_DIR)/network-log-test
	./$(BUILD_DIR)/network-log-test
	python3 test/test_network_logs.py

print-config:
	@echo "preset=$(PRESET) (explicit option overrides take priority)"
	@echo "engine=$(ENGINE) timing=$(TIMING) logging=$(LOGGING) observability=$(OBSERVABILITY)"
	@echo "output=$(BUILD_DIR)"
	@echo "sources=$(USER_SRCS)"

# Clean only this configuration; never discard other profile builds.
clean:
	rm -rf $(BUILD_DIR)

-include $(USER_OBJS:.o=.d) $(BPF_OBJ:.o=.d) $(BUILD_DIR)/test/ipv6_test.d
