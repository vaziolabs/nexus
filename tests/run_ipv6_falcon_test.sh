#!/bin/bash

# Set error handling
set -e
trap 'echo "Error on line $LINENO"; exit 1' ERR

# Colors for output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
RESET="\033[0m"

echo -e "${YELLOW}Starting NEXUS IPv6 Falcon Certificate Test${RESET}"

# Get directory of the script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Check if IPv6 is enabled
if ! ping6 -c 1 ::1 > /dev/null 2>&1; then
    echo -e "${BLUE}NOTE: IPv6 is not enabled on this system${RESET}"
    echo -e "${BLUE}We'll proceed with the test anyway using the loopback address.${RESET}"
    echo -e "${BLUE}The test will create a simulated IPv6 environment.${RESET}"
    
    # Continue with the test using a fallback approach
    USING_IPV6_FALLBACK=1
else
    echo -e "${GREEN}IPv6 support detected: OK${RESET}"
    USING_IPV6_FALLBACK=0
fi

# Create test directories
TEST_DIR="$PROJECT_ROOT/integration_test"
mkdir -p "$TEST_DIR/logs"

# Compile the test directly
echo -e "${YELLOW}Compiling the IPv6 Falcon certificate test...${RESET}"

# Check if build directory exists, if not create it
mkdir -p "$PROJECT_ROOT/build"

# Compile directly without rebuilding the entire project
gcc -o "$PROJECT_ROOT/build/test_ipv6_falcon_cert" "$SCRIPT_DIR/test_ipv6_falcon_cert.c" \
    -I"$PROJECT_ROOT/include" -L"$PROJECT_ROOT/build" \
    -Wall -Wextra -g -O2 -D_GNU_SOURCE \
    -lcrypto -lssl -lpthread

# Check if compilation was successful
if [ ! -f "$PROJECT_ROOT/build/test_ipv6_falcon_cert" ]; then
    echo -e "${RED}Failed to compile test_ipv6_falcon_cert${RESET}"
    exit 1
fi

echo -e "${GREEN}Successfully compiled test_ipv6_falcon_cert${RESET}"

# Run the test
echo -e "${YELLOW}Running the IPv6 Falcon certificate test...${RESET}"
cd "$PROJECT_ROOT"

if [ "$USING_IPV6_FALLBACK" -eq 1 ]; then
    # If IPv6 is not available, set environment variable to signal test to use fallback mode
    export NEXUS_TEST_IPV6_FALLBACK=1
else
    unset NEXUS_TEST_IPV6_FALLBACK
fi

"$PROJECT_ROOT/build/test_ipv6_falcon_cert" 2>&1 | tee "$TEST_DIR/logs/ipv6_falcon_test.log"

# Check the test result
TEST_RESULT=${PIPESTATUS[0]}
if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}IPv6 Falcon certificate test completed successfully!${RESET}"
elif [ $TEST_RESULT -eq 77 ]; then
    echo -e "${YELLOW}IPv6 Falcon certificate test skipped due to environment limitations.${RESET}"
    echo -e "${YELLOW}This is expected in environments without proper IPv6 support.${RESET}"
    echo -e "${YELLOW}To run a full test, please enable IPv6 on your system.${RESET}"
    # Exit with success when test is intentionally skipped
    exit 0
else
    echo -e "${RED}IPv6 Falcon certificate test failed!${RESET}"
    echo "Check the log file for details: $TEST_DIR/logs/ipv6_falcon_test.log"
    exit 1
fi

exit 0 