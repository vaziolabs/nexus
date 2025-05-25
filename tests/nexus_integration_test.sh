#!/bin/bash

# NEXUS Protocol Integration Test
# This script tests the full functionality of the NEXUS protocol including:
# - IPv6 connectivity
# - Certificate creation and validation
# - TLD registration
# - DNS resolution
# - Data transmission
# - Multiple connection types (private, public, federated)

set -e # Exit on any error
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT_DIR/build"
LOG_DIR="$ROOT_DIR/logs"
mkdir -p "$LOG_DIR"

# Define colors for output
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
RESET="\033[0m"

# Log function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${RESET} $1"
}

# Success log
success() {
    echo -e "${GREEN}[SUCCESS]${RESET} $1"
}

# Error log
error() {
    echo -e "${RED}[ERROR]${RESET} $1"
    exit 1
}

# Warning log
warning() {
    echo -e "${YELLOW}[WARNING]${RESET} $1"
}

# Check if IPv6 is supported
check_ipv6() {
    log "Checking IPv6 support..."
    if ping -6 -c 1 ::1 >/dev/null 2>&1; then
        success "IPv6 is supported"
    else
        error "IPv6 is not supported on this system. Please enable IPv6."
    fi
}

# Check if the NEXUS binary exists
check_binary() {
    log "Checking for NEXUS binary..."
    if [ ! -f "$BUILD_DIR/nexus" ]; then
        error "NEXUS binary not found. Please build it first with 'make'."
    else
        success "NEXUS binary found at $BUILD_DIR/nexus"
    fi
}

# Start a NEXUS server in the specified mode
start_server() {
    local mode=$1
    local port=$2
    local hostname=$3
    local server_pid_file="$LOG_DIR/server_${mode}_${port}.pid"
    local server_log_file="$LOG_DIR/server_${mode}_${port}.log"
    
    log "Starting NEXUS server in $mode mode on port $port (hostname: $hostname)..."
    "$BUILD_DIR/nexus" --mode "$mode" --hostname "$hostname" > "$server_log_file" 2>&1 &
    local server_pid=$!
    echo $server_pid > "$server_pid_file"
    
    # Wait for server to start up
    sleep 2
    
    # Check if server is running
    if kill -0 $server_pid 2>/dev/null; then
        success "NEXUS server started successfully (PID: $server_pid)"
        return 0
    else
        error "Failed to start NEXUS server. Check logs at $server_log_file"
    fi
}

# Start a NEXUS client connecting to a server
start_client() {
    local mode=$1
    local server_port=$2
    local client_hostname=$3
    local server_hostname=$4
    local client_pid_file="$LOG_DIR/client_${mode}_${client_hostname}.pid"
    local client_log_file="$LOG_DIR/client_${mode}_${client_hostname}.log"
    
    log "Starting NEXUS client in $mode mode connecting to server on port $server_port..."
    "$BUILD_DIR/nexus" --mode "$mode" --hostname "$client_hostname" --server "$server_hostname" > "$client_log_file" 2>&1 &
    local client_pid=$!
    echo $client_pid > "$client_pid_file"
    
    # Wait for client to start up
    sleep 2
    
    # Check if client is running
    if kill -0 $client_pid 2>/dev/null; then
        success "NEXUS client started successfully (PID: $client_pid)"
        return 0
    else
        error "Failed to start NEXUS client. Check logs at $client_log_file"
    fi
}

# Register a TLD using nexus_cli
register_tld() {
    local tld=$1
    local mode=$2
    local server_port=$3
    local log_file="$LOG_DIR/register_tld_${tld}.log"
    
    log "Registering TLD '${tld}' in $mode mode..."
    "$BUILD_DIR/nexus_cli" --server "::1" register-tld "$tld" > "$log_file" 2>&1
    
    # Check if registration was successful by looking for success message in logs
    if grep -q "registered successfully" "$log_file"; then
        success "TLD '${tld}' registered successfully"
        return 0
    else
        error "Failed to register TLD '${tld}'. Check logs at $log_file"
    fi
}

# Resolve a DNS name using nexus_cli
resolve_dns() {
    local domain=$1
    local mode=$2
    local server_port=$3
    local log_file="$LOG_DIR/resolve_dns_${domain}.log"
    
    log "Resolving DNS for domain '${domain}' in $mode mode..."
    "$BUILD_DIR/nexus_cli" --server "::1" resolve "$domain" > "$log_file" 2>&1
    
    # Check if resolution was successful by looking for IP address in logs
    if grep -q -E "([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}" "$log_file"; then
        success "Domain '${domain}' resolved successfully"
        return 0
    else
        error "Failed to resolve domain '${domain}'. Check logs at $log_file"
    fi
}

# Verify certificate creation
verify_certificates() {
    local mode=$1
    local hostname=$2
    local log_file="$LOG_DIR/verify_cert_${mode}_${hostname}.log"
    
    log "Verifying certificate creation for hostname '${hostname}' in $mode mode..."
    "$BUILD_DIR/nexus_cli" --server "::1" verify-cert "$hostname" > "$log_file" 2>&1
    
    # Check if verification was successful
    if grep -q "Certificate is valid" "$log_file"; then
        success "Certificate for '${hostname}' in $mode mode is valid"
        return 0
    else
        error "Certificate verification failed for '${hostname}' in $mode mode. Check logs at $log_file"
    fi
}

# Test data transmission between nodes
test_data_transmission() {
    local source_hostname=$1
    local target_hostname=$2
    local data="Hello from $source_hostname to $target_hostname via NEXUS!"
    local log_file="$LOG_DIR/data_tx_${source_hostname}_to_${target_hostname}.log"
    
    log "Testing data transmission from '${source_hostname}' to '${target_hostname}'..."
    "$BUILD_DIR/nexus_cli" --server "::1" send-data "$target_hostname" "$data" > "$log_file" 2>&1
    
    # Check if transmission was successful
    if grep -q "Data sent successfully" "$log_file"; then
        success "Data transmission from '${source_hostname}' to '${target_hostname}' successful"
        return 0
    else
        error "Data transmission failed from '${source_hostname}' to '${target_hostname}'. Check logs at $log_file"
    fi
}

# Cleanup function to kill all started processes
cleanup() {
    log "Cleaning up processes..."
    for pid_file in "$LOG_DIR"/*.pid; do
        if [ -f "$pid_file" ]; then
            pid=$(cat "$pid_file")
            log "Killing process with PID $pid"
            kill -9 $pid 2>/dev/null || true
            rm "$pid_file"
        fi
    done
    success "Cleanup completed"
}

# Register trap to ensure cleanup on exit
trap cleanup EXIT INT TERM

# Main test execution
main() {
    log "Starting NEXUS protocol integration tests"
    check_ipv6
    check_binary
    
    # Start NEXUS servers in different modes
    start_server "private" "10443" "nexus-server-private.local"
    start_server "public" "10444" "nexus-server-public.local"
    start_server "federated" "10445" "nexus-server-federated.local"
    
    # Start NEXUS clients connecting to the servers
    start_client "private" "10443" "client1.local" "::1"
    start_client "public" "10444" "client2.local" "::1"
    start_client "federated" "10445" "client3.local" "::1"
    
    # Wait for connections to establish
    log "Waiting for connections to establish..."
    sleep 5
    
    # Register TLDs
    register_tld "test" "private" "10443"
    register_tld "example" "public" "10444"
    register_tld "mesh" "federated" "10445"
    
    # Register domains under TLDs
    log "Registering domains under TLDs..."
    "$BUILD_DIR/nexus_cli" --server "::1" register-domain "client1.test" "fd00::1"
    "$BUILD_DIR/nexus_cli" --server "::1" register-domain "client2.example" "fd00::2"
    "$BUILD_DIR/nexus_cli" --server "::1" register-domain "client3.mesh" "fd00::3"
    
    # Resolve domains
    resolve_dns "client1.test" "private" "10443"
    resolve_dns "client2.example" "public" "10444"
    resolve_dns "client3.mesh" "federated" "10445"
    
    # Verify certificates
    verify_certificates "private" "client1.local"
    verify_certificates "public" "client2.local"
    verify_certificates "federated" "client3.local"
    
    # Test data transmission
    test_data_transmission "client1.local" "client2.local"
    test_data_transmission "client2.local" "client3.local"
    test_data_transmission "client3.local" "client1.local"
    
    # Final success message
    success "All NEXUS protocol integration tests completed successfully!"
}

# Run the main function
main 