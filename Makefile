CC ?= gcc
CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Iinclude -Isrc/userspace

# Architecture and multiarch header detection
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/armv[0-9]*/arm/')
MULTIARCH ?= $(shell gcc -print-multiarch 2>/dev/null)
ARCH_INC := $(if $(MULTIARCH),-I/usr/include/$(MULTIARCH),)

BPF_CFLAGS ?= -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) $(ARCH_INC) -I/usr/include -Iinclude -Isrc/kernel

BUILD_DIR = build

BPF_SRC = src/kernel/main.bpf.c
BPF_DEPS = $(shell find include/ -type f -name "*.h") $(shell find src/kernel/ -type f -name "*.h")
BPF_OBJ = $(BUILD_DIR)/firewall.bpf.o

USER_SRCS = src/userspace/main.c \
            src/userspace/core/cli.c \
            src/userspace/core/config.c \
            src/userspace/core/bpf_loader.c \
            src/userspace/core/firewall_ctx.c \
            src/userspace/utils/ip_utils.c \
            src/userspace/utils/format_utils.c \
            src/userspace/protocols/protocol_registry.c \
            src/userspace/protocols/proto_tcp.c \
            src/userspace/protocols/proto_udp.c \
            src/userspace/protocols/proto_icmp.c \
            src/userspace/telemetry/event_bus.c

USER_OBJS = $(patsubst src/userspace/%.c,$(BUILD_DIR)/%.o,$(USER_SRCS))
USER_BIN = $(BUILD_DIR)/fw-ctl

.DEFAULT_GOAL := all

.PHONY: all bpf userspace clean

all: $(BUILD_DIR) $(BPF_OBJ) $(USER_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/core $(BUILD_DIR)/utils $(BUILD_DIR)/protocols $(BUILD_DIR)/telemetry

bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) $(BPF_DEPS) | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

userspace: $(USER_BIN)

$(BUILD_DIR)/%.o: src/userspace/%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(USER_BIN): $(USER_OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -lbpf -lelf -lz -o $@

clean:
	rm -rf $(BUILD_DIR)
