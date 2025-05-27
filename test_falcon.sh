#!/bin/bash

# Colors for better output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Falcon Cryptography Integration Test ===${NC}"

# Ensure build directory exists
mkdir -p build
mkdir -p build/falcon

# First compile Falcon library files individually to see if there are any issues
echo -e "${YELLOW}Compiling Falcon library files...${NC}"
FALCON_SRC_DIR="include/extern/falcon"
for src in falcon.c shake.c codec.c common.c fft.c fpr.c keygen.c rng.c sign.c vrfy.c; do
    echo "Compiling $src..."
    gcc -Wall -Wextra -g -O2 -D_GNU_SOURCE -I. -I./include -c "$FALCON_SRC_DIR/$src" -o "build/falcon/${src%.c}.o"
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error compiling $src${NC}"
        exit 1
    fi
done
echo -e "${GREEN}All Falcon source files compiled successfully${NC}"

# Compile debug.c
echo -e "${YELLOW}Compiling debug.c...${NC}"
gcc -Wall -Wextra -g -O2 -D_GNU_SOURCE -I. -I./include -c src/debug.c -o build/debug.o
if [ $? -ne 0 ]; then
    echo -e "${RED}Error compiling debug.c${NC}"
    exit 1
fi

# Compile test_falcon_verify.c
echo -e "${YELLOW}Compiling Falcon verification test...${NC}"
FALCON_OBJS="build/falcon/falcon.o build/falcon/shake.o build/falcon/codec.o build/falcon/common.o build/falcon/fft.o build/falcon/fpr.o build/falcon/keygen.o build/falcon/rng.o build/falcon/sign.o build/falcon/vrfy.o"
gcc -Wall -Wextra -g -O2 -D_GNU_SOURCE -I. -I./include tests/test_falcon_verify.c $FALCON_OBJS -o build/test_falcon_verify -lssl -lcrypto

if [ $? -ne 0 ]; then
    echo -e "${RED}Error compiling test_falcon_verify.c${NC}"
    exit 1
fi

echo -e "${GREEN}test_falcon_verify compiled successfully${NC}"

# Run the test
echo -e "${YELLOW}Running Falcon verification test...${NC}"
./build/test_falcon_verify

if [ $? -ne 0 ]; then
    echo -e "${RED}Falcon verification test failed${NC}"
    exit 1
else
    echo -e "${GREEN}Falcon verification test passed${NC}"
fi

# Create test for testing standalone CA and CT functions
echo -e "${YELLOW}Compiling standalone CA test...${NC}"
gcc -Wall -Wextra -g -O2 -D_GNU_SOURCE -I. -I./include tests/standalone_ca_test.c src/certificate_authority.c build/debug.o $FALCON_OBJS -o build/standalone_ca_test -lssl -lcrypto

if [ $? -ne 0 ]; then
    echo -e "${RED}Error compiling standalone_ca_test.c${NC}"
    exit 1
fi

echo -e "${GREEN}standalone_ca_test compiled successfully${NC}"

# Run the CA test
echo -e "${YELLOW}Running standalone CA test...${NC}"
./build/standalone_ca_test

if [ $? -ne 0 ]; then
    echo -e "${RED}Standalone CA test failed${NC}"
    exit 1
else
    echo -e "${GREEN}Standalone CA test passed${NC}"
fi

# Create test for CT functions
echo -e "${YELLOW}Compiling standalone CT test...${NC}"
gcc -Wall -Wextra -g -O2 -D_GNU_SOURCE -I. -I./include tests/standalone_ct_test.c src/certificate_authority.c src/certificate_transparency.c build/debug.o $FALCON_OBJS -o build/standalone_ct_test -lssl -lcrypto -lpthread

if [ $? -ne 0 ]; then
    echo -e "${RED}Error compiling standalone_ct_test.c${NC}"
    exit 1
fi

echo -e "${GREEN}standalone_ct_test compiled successfully${NC}"

# Run the CT test
echo -e "${YELLOW}Running standalone CT test...${NC}"
./build/standalone_ct_test

if [ $? -ne 0 ]; then
    echo -e "${RED}Standalone CT test failed${NC}"
    exit 1
else
    echo -e "${GREEN}Standalone CT test passed${NC}"
fi

echo -e "${GREEN}All Falcon integration tests passed!${NC}" 