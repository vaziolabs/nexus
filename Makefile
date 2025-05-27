#!/bin/bash

# Determine pkg-config command
PKG_CONFIG := pkg-config
PKG_NAME_NGTCP2 := libngtcp2

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -g -O2 -D_GNU_SOURCE -I. -I./include $(shell $(PKG_CONFIG) --cflags $(PKG_NAME_NGTCP2)) $(shell pkg-config --cflags openssl) -DNGTCP2_ENABLE_STREAM_API -DDEBUG
# Add general include paths for ngtcp2 lib and crypto (headers in crypto/includes should be general)
# These paths for the local submodule should take precedence.
CFLAGS += -I./include/extern/libngtcp2/lib/includes -I./include/extern/libngtcp2/crypto/includes -I./include/extern/falcon

# Store pkg-config output for libs separately
PKG_CONFIG_LIBS := $(shell $(PKG_CONFIG) --libs $(PKG_NAME_NGTCP2))

# ngtcp2 library paths and specific library flags
LIBNGTCP2_PATH := $(CURDIR)/include/extern/libngtcp2/lib
LIBNGTCP2_CRYPTO_PATH := $(CURDIR)/include/extern/libngtcp2/crypto

# Define common ngtcp2 library linker flags
LIBNGTCP2_CORE_FLAGS := -L$(LIBNGTCP2_PATH)/.libs -lngtcp2

# Define crypto backend specific flags - USE OSSL
LIBNGTCP2_CRYPTO_BACKEND_FLAGS := -L$(LIBNGTCP2_CRYPTO_PATH)/ossl/.libs -lngtcp2_crypto_ossl
# LIBNGTCP2_CRYPTO_BACKEND_FLAGS := -L$(LIBNGTCP2_CRYPTO_PATH)/quictls/.libs -lngtcp2_crypto_quictls

# Combine all ngtcp2 related lib flags
NGTCP2_LIBS_COMBINED := $(LIBNGTCP2_CORE_FLAGS) $(LIBNGTCP2_CRYPTO_BACKEND_FLAGS)

# General libraries
OPENSSL_LIBS := $(shell pkg-config --libs openssl)
PTHREAD_LIBS := -lpthread
MATH_LIBS := -lm
FALCON_LIBS := $(addprefix $(BUILD_DIR)/, $(FALCON_OBJS))

# Aggregate libraries for main executable and CLI
NEXUS_LIBS := $(NGTCP2_LIBS_COMBINED) $(OPENSSL_LIBS) $(PTHREAD_LIBS) $(MATH_LIBS) $(FALCON_LIBS) -luuid
CLI_LIBS := $(NGTCP2_LIBS_COMBINED) $(OPENSSL_LIBS) $(PTHREAD_LIBS) $(MATH_LIBS) $(FALCON_LIBS) -luuid

# Libraries: ensure -lngtcp2 is present and other system libs
LIBS := $(PKG_CONFIG_LIBS) -lpthread -lssl -lcrypto -lrt -lngtcp2_crypto_ossl -luuid

# Directories
BUILD_DIR := build
SRC_DIR := src
INCLUDE_DIR := include
TESTS_DIR := tests

# Add Falcon source files
FALCON_SRCS := falcon.c shake.c codec.c common.c fft.c fpr.c keygen.c rng.c sign.c vrfy.c
FALCON_OBJS := $(patsubst %.c,$(BUILD_DIR)/falcon/%.o,$(FALCON_SRCS))

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

all: check_deps $(BUILD_DIR) $(FALCON_OBJS) $(OBJS) $(TARGET) $(CLI_TARGET)

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
	@mkdir -p $(BUILD_DIR)/falcon

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

# Compile Falcon source files
$(BUILD_DIR)/falcon/%.o: include/extern/falcon/%.c
	@echo "Compiling Falcon file $<..."
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

# Link the program
$(TARGET): $(BUILD_DIR) $(BUILD_DIR)/main.o $(COMMON_OBJS) $(FALCON_OBJS)
	@echo "Linking $(TARGET)..."
	@$(CC) $(CFLAGS) $(BUILD_DIR)/main.o $(COMMON_OBJS) $(FALCON_OBJS) -o $(TARGET) $(NEXUS_LIBS)
	@echo "Build successful!"
	@echo "Binary location: $(TARGET)"
	@echo "Usage example: $(TARGET) --mode private --hostname localhost --server localhost"
	@echo "CLI usage: $(TARGET) cli help"

# Link the CLI program
$(CLI_TARGET): $(BUILD_DIR) $(BUILD_DIR)/nexus_cli.o $(COMMON_OBJS) $(FALCON_OBJS)
	@echo "Linking $(CLI_TARGET)..."
	@$(CC) $(CFLAGS) $(BUILD_DIR)/nexus_cli.o $(COMMON_OBJS) $(FALCON_OBJS) -o $(CLI_TARGET) $(CLI_LIBS)
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
.PHONY: all check_deps clean deps help test test_handshake test_ipv6 test_tld test_packet test_config test_cli test_ct test_ca test_network integration_test test_standalone_ca test_standalone_ct test_falcon_verify list_includes

# Build will stop if any command fails
.DELETE_ON_ERROR:

# Keep intermediate files
.PRECIOUS: $(BUILD_DIR)/%.o

# --- Test Target --- 

# Test source files and objects
# Moved these definitions before their first use in $(TEST_TARGET)
# Filter out standalone test files from the main test suite sources
ALL_TEST_CSRCS := $(wildcard $(TESTS_DIR)/*.c)
STANDALONE_TEST_CSRCS := $(TESTS_DIR)/test_quic_handshake.c $(TESTS_DIR)/test_ipv6_quic_handshake.c $(TESTS_DIR)/test_falcon_verify.c $(TESTS_DIR)/standalone_ca_test.c $(TESTS_DIR)/standalone_ct_test.c
TEST_SUITE_CSRCS := $(filter-out $(STANDALONE_TEST_CSRCS), $(ALL_TEST_CSRCS))

TEST_SUITE_OBJS := $(TEST_SUITE_CSRCS:$(TESTS_DIR)/%.c=$(BUILD_DIR)/%.o)

# Use the common objects for the source files needed in tests
SRC_OBJS_FOR_TESTS := $(COMMON_OBJS)

# Rule to compile test files from tests/ directory (applies to all test .c files)
$(BUILD_DIR)/%.o: $(TESTS_DIR)/%.c
	@echo "Compiling test file $<..."
	@$(CC) $(CFLAGS) -I./$(INCLUDE_DIR) -c $< -o $@

# Link the test executable (nexus_tests)
$(TEST_TARGET): $(BUILD_DIR) $(SRC_OBJS_FOR_TESTS) $(TEST_SUITE_OBJS) $(FALCON_OBJS)
	@echo "Linking $(TEST_TARGET)..."
	@$(CC) $(CFLAGS) $(SRC_OBJS_FOR_TESTS) $(TEST_SUITE_OBJS) $(FALCON_OBJS) -o $(TEST_TARGET) $(NEXUS_LIBS)
	@echo "Test build successful!"
	@echo "Test binary location: $(TEST_TARGET)"

# Link the handshake test executable
$(HANDSHAKE_TEST_TARGET): $(BUILD_DIR) $(BUILD_DIR)/test_quic_handshake.o $(SRC_OBJS_FOR_TESTS) $(FALCON_OBJS)
	@echo "Linking $(HANDSHAKE_TEST_TARGET)..."
	@$(CC) $(CFLAGS) $(BUILD_DIR)/test_quic_handshake.o $(SRC_OBJS_FOR_TESTS) $(FALCON_OBJS) -o $(HANDSHAKE_TEST_TARGET) $(NEXUS_LIBS)
	@echo "Handshake test build successful!"
	@echo "Test binary location: $(HANDSHAKE_TEST_TARGET)"

# Link the IPv6 handshake test executable
$(IPV6_HANDSHAKE_TEST_TARGET): $(BUILD_DIR) $(BUILD_DIR)/test_ipv6_quic_handshake.o $(SRC_OBJS_FOR_TESTS) $(FALCON_OBJS)
	@echo "Linking $(IPV6_HANDSHAKE_TEST_TARGET)..."
	@$(CC) $(CFLAGS) $(BUILD_DIR)/test_ipv6_quic_handshake.o $(SRC_OBJS_FOR_TESTS) $(FALCON_OBJS) -o $(IPV6_HANDSHAKE_TEST_TARGET) $(NEXUS_LIBS)
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
test_ct: $(TEST_TARGET)
	@echo "Running Certificate Transparency tests only..."
	@./$(TEST_TARGET) ct

# Run Certificate Authority tests only
test_ca: $(TEST_TARGET)
	@echo "Running Certificate Authority tests only..."
	@./$(TEST_TARGET) ca

test_network: $(TEST_TARGET)
	@echo "Running Network Context tests only..."
	@./$(TEST_TARGET) network

# Integration test target
integration_test: all
	@echo "Running NEXUS integration tests..."
	@chmod +x $(INTEGRATION_TEST_SCRIPT)
	@$(INTEGRATION_TEST_SCRIPT)

# Individual standalone test targets
build/standalone_ca_test: $(BUILD_DIR)/standalone_ca_test.o $(SRC_OBJS_FOR_TESTS) $(FALCON_OBJS)
	@echo "Linking $@..."
	@$(CC) $(CFLAGS) $(BUILD_DIR)/standalone_ca_test.o $(BUILD_DIR)/certificate_authority.o $(BUILD_DIR)/debug.o $(FALCON_OBJS) $(LIBS) -o $@

build/standalone_ct_test: $(BUILD_DIR)/standalone_ct_test.o $(SRC_OBJS_FOR_TESTS) $(FALCON_OBJS)
	@echo "Linking $@..."
	@$(CC) $(CFLAGS) $(BUILD_DIR)/standalone_ct_test.o $(BUILD_DIR)/certificate_authority.o $(BUILD_DIR)/certificate_transparency.o $(BUILD_DIR)/debug.o $(FALCON_OBJS) $(LIBS) -lpthread -o $@

build/test_falcon_verify: $(BUILD_DIR)/test_falcon_verify.o $(FALCON_OBJS)
	@echo "Linking $@..."
	@$(CC) $(CFLAGS) $(BUILD_DIR)/test_falcon_verify.o $(FALCON_OBJS) $(LIBS) -o $@

# Run standalone tests
test_standalone_ca: build/standalone_ca_test
	@echo "Running standalone CA test..."
	@./build/standalone_ca_test

test_standalone_ct: build/standalone_ct_test
	@echo "Running standalone CT test..."
	@./build/standalone_ct_test

test_falcon_verify: build/test_falcon_verify
	@echo "Running Falcon verify test..."
	@./build/test_falcon_verify

# Target to list includes for a specific file (e.g., nexus_client.c)
list_includes: $(BUILD_DIR)/nexus_client.o # Ensure object is built as part of this if not present
	@echo "Ngtcp2 headers included by nexus_client.c:"
	@$(CC) $(CFLAGS) -E -H $(SRC_DIR)/nexus_client.c 2>&1 | grep -E '^\.+ .*/ngtcp2/.*\\.h' | sort -u
	@echo "Compilation of nexus_client.o will proceed if not already done by dependency."

# Modify the rule for nexus_client.o to also show includes (optional, list_includes target is more direct)
# $(BUILD_DIR)/nexus_client.o: $(SRC_DIR)/nexus_client.c
# 	@echo "Compiling $< and listing NGTCP2 includes..."
# 	@$(CC) $(CFLAGS) -E -H $< 2>&1 | grep -E '^\\.+ .*/ngtcp2/.*\\.h' | sort -u || true
# 	@$(CC) $(CFLAGS) -c $< -o $@