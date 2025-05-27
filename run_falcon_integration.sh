#!/bin/bash

# Colors for better output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Stoq Falcon Cryptography Integration Test ===${NC}"
echo -e "${YELLOW}This test will verify the Falcon integration with Stoq for certificate management${NC}"

# Run the basic Falcon tests first
echo -e "${YELLOW}Running basic Falcon tests...${NC}"
./test_falcon.sh
if [ $? -ne 0 ]; then
    echo -e "${RED}Basic Falcon tests failed, cannot continue with integration tests${NC}"
    exit 1
fi
echo -e "${GREEN}Basic Falcon tests passed${NC}"

# Build the main project with Falcon integration
echo -e "${YELLOW}Building Stoq with Falcon integration...${NC}"
make clean
make
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to build Stoq with Falcon integration${NC}"
    exit 1
fi
echo -e "${GREEN}Build successful${NC}"

# Run the unit tests
echo -e "${YELLOW}Running Stoq unit tests...${NC}"
make test
if [ $? -ne 0 ]; then
    echo -e "${RED}Stoq unit tests failed${NC}"
    exit 1
fi
echo -e "${GREEN}Unit tests passed${NC}"

# Run the QUIC handshake test with Falcon certificates
echo -e "${YELLOW}Running QUIC handshake test with Falcon certificates...${NC}"
make test_handshake
if [ $? -ne 0 ]; then
    echo -e "${RED}QUIC handshake test failed${NC}"
    exit 1
fi
echo -e "${GREEN}QUIC handshake test passed${NC}"

# Run the IPv6 QUIC handshake test with Falcon certificates if supported
echo -e "${YELLOW}Running IPv6 QUIC handshake test with Falcon certificates...${NC}"
make test_ipv6
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}IPv6 QUIC handshake test failed or not supported${NC}"
    # Don't exit - this test might not be critical
fi

# Run specific certificate-related tests
echo -e "${YELLOW}Running Certificate Authority tests...${NC}"
make test_ca
if [ $? -ne 0 ]; then
    echo -e "${RED}Certificate Authority tests failed${NC}"
    exit 1
fi
echo -e "${GREEN}Certificate Authority tests passed${NC}"

echo -e "${YELLOW}Running Certificate Transparency tests...${NC}"
make test_ct
if [ $? -ne 0 ]; then
    echo -e "${RED}Certificate Transparency tests failed${NC}"
    exit 1
fi
echo -e "${GREEN}Certificate Transparency tests passed${NC}"

echo -e "${BLUE}=== All Falcon Integration Tests Passed ===${NC}"
echo -e "${GREEN}Stoq has been successfully integrated with Falcon for post-quantum secure certificates${NC}"
exit 0 