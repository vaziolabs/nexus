#!/bin/bash

# Full Stack Test Runner for NEXUS
# This script tests the complete stack including QUIC, DNS, and TLD functions

# Set up colors for better output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Define directory variables
BUILD_DIR="./build"
LOG_DIR="./logs"
TEST_SERVERS_DIR="./integration_test/server"
TEST_CLIENTS_DIR="./integration_test/client"
TEST_LOGS_DIR="./integration_test/logs"

# Create required directories
mkdir -p "$LOG_DIR"
mkdir -p "$TEST_LOGS_DIR"
mkdir -p "$TEST_SERVERS_DIR"
mkdir -p "$TEST_CLIENTS_DIR"

# Function to print status messages
function print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

function print_error() {
    echo -e "${RED}[!]${NC} $1"
}

function print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Build the project first
print_status "Building the project..."
make clean && make
if [ $? -ne 0 ]; then
    print_error "Build failed. Exiting."
    exit 1
fi
print_status "Build completed successfully."

# Generate a dummy certificate and key for the tests
print_status "Generating dummy certificate for tests..."
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.cert -subj "/CN=localhost"
if [ $? -ne 0 ]; then
    print_error "Failed to generate dummy certificate. Exiting."
    exit 1
fi

# Verify the binary exists
if [ ! -f "$BUILD_DIR/nexus" ]; then
    print_error "NEXUS binary not found at $BUILD_DIR/nexus"
    exit 1
fi

# Run unit tests first
print_status "Running unit tests..."
make test
if [ $? -ne 0 ]; then
    print_warning "Some unit tests failed."
fi

# Test Falcon cryptography integration
print_status "Testing Falcon cryptography integration..."
./test_falcon.sh
if [ $? -ne 0 ]; then
    print_error "Falcon cryptography test failed."
    exit 1
fi

# Test server-client TLD registration
print_status "Testing TLD registration..."

# Start server in the background
SERVER_LOG="$TEST_LOGS_DIR/server.log"
SERVER_PORT=10053
print_status "Starting server on port $SERVER_PORT..."

# Kill any existing server processes
pkill -f "$BUILD_DIR/nexus.*--port $SERVER_PORT" || true
sleep 1

# Start the server with private mode
$BUILD_DIR/nexus --mode private --hostname server.nexus.local > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 2

# Check if server started correctly
if ! ps -p $SERVER_PID > /dev/null; then
    print_error "Server failed to start."
    cat "$SERVER_LOG"
    exit 1
fi
print_status "Server started with PID $SERVER_PID"

# Start client and register a TLD
CLIENT_LOG="$TEST_LOGS_DIR/client.log"
print_status "Starting client and registering TLD..."

# Run client with command to register a TLD
$BUILD_DIR/nexus_cli --server localhost register-tld test > "$CLIENT_LOG" 2>&1
if [ $? -ne 0 ]; then
    print_error "Client failed to register TLD."
    cat "$CLIENT_LOG"
    # Clean up server
    kill $SERVER_PID
    exit 1
fi

# Verify the TLD was registered
if grep -q "TLD 'test' registered successfully" "$CLIENT_LOG"; then
    print_status "TLD registration successful."
else
    print_error "TLD registration verification failed."
    cat "$CLIENT_LOG"
    kill $SERVER_PID
    exit 1
fi

# Register a domain under the TLD
print_status "Registering a domain under the TLD..."
$BUILD_DIR/nexus_cli --server localhost:$SERVER_PORT register-domain example.test fd00::1 > "$CLIENT_LOG" 2>&1
if [ $? -ne 0 ]; then
    print_error "Failed to register domain."
    cat "$CLIENT_LOG"
    kill $SERVER_PID
    exit 1
fi

# Perform a DNS lookup
print_status "Performing DNS lookup for the registered domain..."
$BUILD_DIR/nexus_cli --server localhost:$SERVER_PORT lookup example.test > "$CLIENT_LOG" 2>&1
if [ $? -ne 0 ]; then
    print_error "DNS lookup failed."
    cat "$CLIENT_LOG"
    kill $SERVER_PID
    exit 1
fi

# Test Federation
print_status "Testing federation between servers..."

# Start a second server for federation test
SERVER2_LOG="$TEST_LOGS_DIR/server2.log"
SERVER2_PORT=10054
print_status "Starting second server on port $SERVER2_PORT..."

# Start the second server with federated mode
$BUILD_DIR/nexus --mode federated --hostname server2.nexus.local > "$SERVER2_LOG" 2>&1 &
SERVER2_PID=$!
sleep 2

# Check if second server started correctly
if ! ps -p $SERVER2_PID > /dev/null; then
    print_error "Second server failed to start."
    cat "$SERVER2_LOG"
    kill $SERVER_PID
    exit 1
fi
print_status "Second server started with PID $SERVER2_PID"

# Clean up
print_status "Cleaning up..."
kill $SERVER_PID
kill $SERVER2_PID
rm -f server.cert server.key
sleep 1

print_status "Full stack test completed successfully."
exit 0 