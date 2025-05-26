#!/bin/bash

# Determine pkg-config command
PKG_CONFIG := $(shell command -v pkgconf >/dev/null 2>&1 && echo "pkgconf" || echo "pkg-config")
PKG_NAME_NGTCP2 := $(shell command -v pkgconf >/dev/null 2>&1 && echo "libngtcp2" || echo "ngtcp2")

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -g -O2 -D_GNU_SOURCE -I. -I./include -I./include/extern/libngtcp2/lib/includes -I./include/extern/libngtcp2/crypto/includes -I./include/extern/falcon $(shell $(PKG_CONFIG) --cflags $(PKG_NAME_NGTCP2)) -DNGTCP2_ENABLE_STREAM_API

# Store pkg-config output for libs separately
PKG_CONFIG_LIBS := $(shell $(PKG_CONFIG) --libs $(PKG_NAME_NGTCP2))

# Libraries: ensure -lngtcp2 is present and other system libs
LIBS := $(PKG_CONFIG_LIBS) -lpthread -lssl -lcrypto -lrt -lngtcp2_crypto_ossl -luuid

# Add Falcon source files
FALCON_SRCS := include/extern/falcon/falcon.c include/extern/falcon/shake.c include/extern/falcon/codec.c include/extern/falcon/common.c \
               include/extern/falcon/fft.c include/extern/falcon/fpr.c include/extern/falcon/keygen.c include/extern/falcon/rng.c \
               include/extern/falcon/sign.c include/extern/falcon/vrfy.c
FALCON_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(FALCON_SRCS))

# Linker flags (LDFLAGS is often used for -L paths if needed, but LIBS handles -l flags)
LDFLAGS :=

# Directories
BUILD_DIR := build
SRC_DIR := src
INCLUDE_DIR := include
TESTS_DIR := tests

# Source files and objects
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Define the common set of object files (excluding main executables)
COMMON_OBJS := $(filter-out $(BUILD_DIR)/main.o $(BUILD_DIR)/nexus_cli.o, $(OBJS))

# Binary name
TARGET := $(BUILD_DIR)/nexus
CLI_TARGET := $(BUILD_DIR)/nexus_cli
TEST_TARGET := $(BUILD_DIR)/nexus_tests
HANDSHAKE_TEST_TARGET := $(BUILD_DIR)/test_quic_handshake
IPV6_HANDSHAKE_TEST_TARGET := $(BUILD_DIR)/test_ipv6_quic_handshake
INTEGRATION_TEST_SCRIPT := $(TESTS_DIR)/nexus_integration_test.sh

# Default target
.DEFAULT_GOAL := all

all: check_deps $(BUILD_DIR) $(OBJS) $(TARGET) $(CLI_TARGET)

# Check dependencies
check_deps_ubuntu:
	@which pkg-config > /dev/null || (echo "Error: pkg-config not found" && exit 1)
	@pkg-config --exists ngtcp2 || (echo "Error: ngtcp2 development package not found" && exit 1)

check_deps_arch:
	@which pkgconf > /dev/null || (echo "Error: pkgconf not found" && exit 1)
	@pkgconf --exists libngtcp2 || (echo "Error: libngtcp2 development package not found" && exit 1)
	@echo "All dependencies found"

check_deps:
	@if command -v pkgconf >/dev/null 2>&1; then \
		make check_deps_arch; \
	else \
		make check_deps_ubuntu; \
	fi

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

# Link the program
$(TARGET): $(BUILD_DIR) $(BUILD_DIR)/main.o $(COMMON_OBJS)
	@echo "Linking $(TARGET)..."
	@$(CC) $(LDFLAGS) $(BUILD_DIR)/main.o $(COMMON_OBJS) include/extern/falcon/*.c $(LIBS) -o $(TARGET)
	@echo "Build successful!"
	@echo "Binary location: $(TARGET)"
	@echo "Usage example: $(TARGET) --mode private --hostname localhost --server localhost"
	@echo "CLI usage: $(TARGET) cli help"

# Link the CLI program
$(CLI_TARGET): $(BUILD_DIR) $(BUILD_DIR)/nexus_cli.o $(COMMON_OBJS)
	@echo "Linking $(CLI_TARGET)..."
	@$(CC) $(LDFLAGS) $(BUILD_DIR)/nexus_cli.o $(COMMON_OBJS) include/extern/falcon/*.c $(LIBS) -o $(CLI_TARGET)
	@echo "CLI build successful!"
	@echo "Binary location: $(CLI_TARGET)"
	@echo "Usage example: $(CLI_TARGET) help"

# Clean build files
clean:
	@echo "Cleaning build files..."
	@rm -rf $(BUILD_DIR)

deps:
	@echo "Determining system type..."
	@if command -v apt-get >/dev/null; then \
		echo "System type: Ubuntu/Debian"; \
		make deps_ubuntu; \
	elif command -v pacman >/dev/null; then \
		echo "System type: Arch Linux"; \
		make deps_arch; \
	else \
		echo "Unsupported system type. Please install the required dependencies manually."; \
		exit 1; \
	fi

# Install dependencies (example for Ubuntu/Debian)
deps_ubuntu:
	@echo "Installing dependencies..."
	@if command -v apt-get >/dev/null; then \
		sudo apt-get update && \
		sudo apt-get install -y \
			build-essential \
			pkg-config \
			libngtcp2-dev; \
	else \
		echo "Please install the required dependencies manually."; \
		exit 1; \
	fi

deps_arch:
	@echo "Installing dependencies..."
	@sudo pacman -S --needed --noconfirm \
		base-devel \
		pkgconf \
		libngtcp2

# Help target
help:
	@echo "Available targets:"
	@echo "  all        - Build the project (default)"
	@echo "  clean      - Remove build files"
	@echo "  deps       - Install dependencies"
	@echo "  help       - Show this help message"
	@echo "  test       - Build and run all unit tests"
	@echo "  test_handshake - Build and run QUIC handshake test"
	@echo "  test_ipv6  - Build and run IPv6 QUIC handshake test"
	@echo "  test_tld   - Run only TLD Manager tests"
	@echo "  test_packet - Run only Packet Protocol tests"
	@echo "  test_config - Run only Config Manager tests"
	@echo "  test_cli   - Run only CLI Interface tests"
	@echo "  test_ct    - Run only Certificate Transparency tests"
	@echo "  test_ca    - Run only Certificate Authority tests"
	@echo "  test_network - Run only Network Context tests"
	@echo "  integration_test - Run the full integration test suite"

# Phony targets
.PHONY: all check_deps clean deps help test test_handshake test_ipv6 test_tld test_packet test_config test_cli test_ct test_ca test_network integration_test

# Build will stop if any command fails
.DELETE_ON_ERROR:

# Keep intermediate files
.PRECIOUS: $(BUILD_DIR)/%.o

# --- Test Target --- 

# Test source files and objects
# Moved these definitions before their first use in $(TEST_TARGET)
# Filter out standalone test files from the main test suite sources
ALL_TEST_CSRCS := $(wildcard $(TESTS_DIR)/*.c)
STANDALONE_TEST_CSRCS := $(TESTS_DIR)/test_quic_handshake.c $(TESTS_DIR)/test_ipv6_quic_handshake.c
TEST_SUITE_CSRCS := $(filter-out $(STANDALONE_TEST_CSRCS), $(ALL_TEST_CSRCS))

TEST_SUITE_OBJS := $(TEST_SUITE_CSRCS:$(TESTS_DIR)/%.c=$(BUILD_DIR)/%.o)

# Objects for specific standalone tests will be handled by their own rules
# e.g. $(BUILD_DIR)/test_quic_handshake.o and $(BUILD_DIR)/test_ipv6_quic_handshake.o

# Use the common objects for the source files needed in tests (COMMON_OBJS is defined much earlier)
SRC_OBJS_FOR_TESTS := $(COMMON_OBJS)

# This variable seems unused, but keeping its definition here with other test vars.
# TEST_SRCS := $(wildcard $(TESTS_DIR)/*.c) $(wildcard $(SRC_DIR)/*.c) # This was too broad

# Rule to compile test files from tests/ directory (applies to all test .c files)
$(BUILD_DIR)/%.o: $(TESTS_DIR)/%.c
	@echo "Compiling test file $<..."
	@$(CC) $(CFLAGS) -I./$(INCLUDE_DIR) -c $< -o $@

# Rule to compile Falcon source files
$(BUILD_DIR)/include/extern/falcon/%.o: include/extern/falcon/%.c
	@mkdir -p $(dir $@)
	@echo "Compiling Falcon file $<..."
	@$(CC) $(CFLAGS) -c $< -o $@
	
# Link the test executable (nexus_tests)
# Use TEST_SUITE_OBJS instead of the overly broad TEST_FILES_OBJS
$(TEST_TARGET): $(BUILD_DIR) $(SRC_OBJS_FOR_TESTS) $(TEST_SUITE_OBJS)
	@echo "Linking $(TEST_TARGET)..."
	@$(CC) $(LDFLAGS) $(SRC_OBJS_FOR_TESTS) $(TEST_SUITE_OBJS) include/extern/falcon/*.c $(LIBS) -o $(TEST_TARGET)
	@echo "Test build successful!"
	@echo "Test binary location: $(TEST_TARGET)"

# Link the handshake test executable
# It correctly uses its own .o file and common app objects
$(HANDSHAKE_TEST_TARGET): $(BUILD_DIR) $(BUILD_DIR)/test_quic_handshake.o $(SRC_OBJS_FOR_TESTS)
	@echo "Linking $(HANDSHAKE_TEST_TARGET)..."
	@$(CC) $(LDFLAGS) $(BUILD_DIR)/test_quic_handshake.o $(SRC_OBJS_FOR_TESTS) include/extern/falcon/*.c $(LIBS) -o $(HANDSHAKE_TEST_TARGET)
	@echo "Handshake test build successful!"
	@echo "Test binary location: $(HANDSHAKE_TEST_TARGET)"

# Link the IPv6 handshake test executable
# It correctly uses its own .o file and common app objects
$(IPV6_HANDSHAKE_TEST_TARGET): $(BUILD_DIR) $(BUILD_DIR)/test_ipv6_quic_handshake.o $(SRC_OBJS_FOR_TESTS)
	@echo "Linking $(IPV6_HANDSHAKE_TEST_TARGET)..."
	@$(CC) $(LDFLAGS) $(BUILD_DIR)/test_ipv6_quic_handshake.o $(SRC_OBJS_FOR_TESTS) $(LIBS) -o $(IPV6_HANDSHAKE_TEST_TARGET)
	@echo "IPv6 handshake test build successful!"
	@echo "Test binary location: $(IPV6_HANDSHAKE_TEST_TARGET)"

# Run tests
test: $(TEST_TARGET)
	@echo "Running unit tests..."
	@./$(TEST_TARGET)

# Run handshake test
test_handshake: $(HANDSHAKE_TEST_TARGET)
	@echo "Running QUIC handshake test..."
	@./$(HANDSHAKE_TEST_TARGET)

# Run IPv6 handshake test
test_ipv6: $(IPV6_HANDSHAKE_TEST_TARGET)
	@echo "Running IPv6 QUIC handshake test..."
	@./$(IPV6_HANDSHAKE_TEST_TARGET)

# --- Individual Test Targets ---
test_tld: $(TEST_TARGET)
	@echo "Running TLD Manager tests only..."
	@./$(TEST_TARGET) tld

test_packet: $(TEST_TARGET)
	@echo "Running Packet Protocol tests only..."
	@./$(TEST_TARGET) packet

test_config: $(TEST_TARGET)
	@echo "Running Config Manager tests only..."
	@./$(TEST_TARGET) config

test_cli: $(TEST_TARGET)
	@echo "Running CLI Interface tests only..."
	@./$(TEST_TARGET) cli

# Run Certificate Transparency tests only
test_ct: $(BUILD_DIR)
	@echo "Compiling standalone CT test..."
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/test_ct tests/standalone_ct_test.c src/certificate_transparency.c \
		src/certificate_authority.c src/system.c src/network_context.c src/debug.c \
		src/tld_manager.c src/utils.c include/extern/falcon/*.c $(LIBS)
	@echo "Running Certificate Transparency tests only..."
	@./$(BUILD_DIR)/test_ct

# Run Certificate Authority tests only
test_ca: $(BUILD_DIR)
	@echo "Compiling standalone CA test..."
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/test_ca tests/standalone_ca_test.c src/certificate_authority.c \
		src/system.c src/network_context.c src/debug.c src/tld_manager.c src/utils.c \
		include/extern/falcon/*.c $(LIBS)
	@echo "Running Certificate Authority tests only..."
	@./$(BUILD_DIR)/test_ca

test_network: $(TEST_TARGET)
	@echo "Running Network Context tests only..."
	@./$(TEST_TARGET) network

# Integration test target
integration_test: all
	@echo "Running NEXUS integration tests..."
	@chmod +x $(INTEGRATION_TEST_SCRIPT)
	@$(INTEGRATION_TEST_SCRIPT)