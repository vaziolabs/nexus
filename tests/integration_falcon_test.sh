#!/bin/bash

# Set error handling
set -e
trap 'echo "Error on line $LINENO"; exit 1' ERR

# Colors for output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
RESET="\033[0m"

echo -e "${YELLOW}Starting Nexus Network Protocol Integration Test with Falcon Certificates${RESET}"

# Get directory of the script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Make sure we have fresh binaries
echo -e "${YELLOW}Building Nexus...${RESET}"
cd "$PROJECT_ROOT"
make clean > /dev/null
make all > /dev/null

# Check if binaries were created successfully
if [ ! -f "$PROJECT_ROOT/build/nexus" ]; then
    echo -e "${RED}Failed to build nexus binary${RESET}"
    exit 1
fi

# Create test directories
TEST_DIR="$PROJECT_ROOT/integration_test"
mkdir -p "$TEST_DIR"
mkdir -p "$TEST_DIR/server"
mkdir -p "$TEST_DIR/client"
mkdir -p "$TEST_DIR/logs"

# Function to start server
start_server() {
    echo -e "${YELLOW}Starting Nexus server with Falcon certificates...${RESET}"
    cd "$TEST_DIR/server"
    $PROJECT_ROOT/build/nexus --mode private --hostname server.test.local > "$TEST_DIR/logs/server.log" 2>&1 &
    SERVER_PID=$!
    echo "Server started with PID: $SERVER_PID"
    
    # Wait for server to initialize
    sleep 2
    
    # Check if server is running
    if ! ps -p $SERVER_PID > /dev/null; then
        echo -e "${RED}Server failed to start. Check logs at $TEST_DIR/logs/server.log${RESET}"
        exit 1
    fi
    echo -e "${GREEN}Server started successfully${RESET}"
}

# Function to start client
start_client() {
    echo -e "${YELLOW}Starting Nexus client...${RESET}"
    cd "$TEST_DIR/client"
    $PROJECT_ROOT/build/nexus --mode private --hostname client.test.local --server server.test.local > "$TEST_DIR/logs/client.log" 2>&1 &
    CLIENT_PID=$!
    echo "Client started with PID: $CLIENT_PID"
    
    # Wait for client to initialize
    sleep 2
    
    # Check if client is running
    if ! ps -p $CLIENT_PID > /dev/null; then
        echo -e "${RED}Client failed to start. Check logs at $TEST_DIR/logs/client.log${RESET}"
        exit 1
    fi
    echo -e "${GREEN}Client started successfully${RESET}"
}

# Function to test connection and verify Falcon certificates
test_connection() {
    echo -e "${YELLOW}Testing connection with Falcon certificate verification...${RESET}"
    
    # Use the CLI to query certificate status
    $PROJECT_ROOT/build/nexus_cli status > "$TEST_DIR/logs/status.log" 2>&1
    
    # Check if the status log indicates successful certificate verification
    if grep -q "Certificate validated with Falcon" "$TEST_DIR/logs/status.log"; then
        echo -e "${GREEN}Falcon certificate verification successful${RESET}"
    else
        echo -e "${RED}Falcon certificate verification failed. Check logs at $TEST_DIR/logs/status.log${RESET}"
        exit 1
    fi
    
    # Test DNS resolution
    $PROJECT_ROOT/build/nexus_cli resolve server.test.local > "$TEST_DIR/logs/dns.log" 2>&1
    
    # Check if DNS resolution worked
    if grep -q "Resolution successful" "$TEST_DIR/logs/dns.log"; then
        echo -e "${GREEN}DNS resolution successful${RESET}"
    else
        echo -e "${RED}DNS resolution failed. Check logs at $TEST_DIR/logs/dns.log${RESET}"
        exit 1
    fi
    
    # Test data transfer
    echo "Hello Nexus Network" > "$TEST_DIR/client/test_message.txt"
    $PROJECT_ROOT/build/nexus_cli send server.test.local "$TEST_DIR/client/test_message.txt" > "$TEST_DIR/logs/transfer.log" 2>&1
    
    # Check if data transfer worked
    if grep -q "Transfer successful" "$TEST_DIR/logs/transfer.log"; then
        echo -e "${GREEN}Data transfer successful${RESET}"
    else
        echo -e "${RED}Data transfer failed. Check logs at $TEST_DIR/logs/transfer.log${RESET}"
        exit 1
    fi
}

# Function to clean up
cleanup() {
    echo -e "${YELLOW}Cleaning up...${RESET}"
    # Kill server and client
    if [ ! -z "$SERVER_PID" ]; then
        kill -9 $SERVER_PID 2>/dev/null || true
    fi
    if [ ! -z "$CLIENT_PID" ]; then
        kill -9 $CLIENT_PID 2>/dev/null || true
    fi
    
    # Wait for processes to exit
    sleep 1
    
    echo -e "${GREEN}Cleanup complete${RESET}"
}

# Register cleanup function to run on script exit
trap cleanup EXIT

# Run the tests
start_server
start_client
test_connection

echo -e "${GREEN}All tests passed successfully!${RESET}"
echo -e "${GREEN}The Nexus Network Protocol with Falcon certificates is fully functional!${RESET}"
exit 0 