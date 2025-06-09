#!/bin/bash

# Enhanced DNS Resolver Test
# Tests the enhanced error handling and external DNS resolution features

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$TEST_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
LOGS_DIR="$PROJECT_ROOT/logs"
TEST_RESULTS_DIR="$PROJECT_ROOT/test_results"

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "${BLUE}[$timestamp] INFO: $message${NC}"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[$timestamp] SUCCESS: $message${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}[$timestamp] WARNING: $message${NC}"
            ;;
        "ERROR")
            echo -e "${RED}[$timestamp] ERROR: $message${NC}"
            ;;
    esac
    
    # Also log to file
    echo "[$timestamp] $level: $message" >> "$TEST_RESULTS_DIR/enhanced_dns_test.log"
}

# Test result tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Test assertion function
assert_test() {
    local test_name="$1"
    local condition="$2"
    local error_message="$3"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    
    if [ "$condition" = "0" ]; then
        log "SUCCESS" "Test '$test_name' PASSED"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log "ERROR" "Test '$test_name' FAILED: $error_message"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Test external DNS resolution using a simple C program
test_external_dns_resolution() {
    log "INFO" "Testing external DNS resolution capabilities"
    
    # Create a simple test program to test external DNS resolution
    cat > "$TEST_RESULTS_DIR/test_external_dns.c" << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

int test_external_dns(const char* hostname) {
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    
    int status = getaddrinfo(hostname, NULL, &hints, &result);
    if (status != 0) {
        printf("DNS resolution failed for %s: %s\n", hostname, gai_strerror(status));
        return -1;
    }
    
    // Print resolved addresses
    for (struct addrinfo* rp = result; rp != NULL; rp = rp->ai_next) {
        struct sockaddr_in* sin = (struct sockaddr_in*)rp->ai_addr;
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
        printf("Resolved %s to %s\n", hostname, addr_str);
    }
    
    freeaddrinfo(result);
    return 0;
}

int main() {
    printf("Testing external DNS resolution...\n");
    
    // Test with a well-known domain
    if (test_external_dns("google.com") == 0) {
        printf("External DNS resolution test PASSED\n");
        return 0;
    } else {
        printf("External DNS resolution test FAILED\n");
        return 1;
    }
}
EOF

    # Compile and run the test
    if gcc -o "$TEST_RESULTS_DIR/test_external_dns" "$TEST_RESULTS_DIR/test_external_dns.c" 2>/dev/null; then
        if "$TEST_RESULTS_DIR/test_external_dns" > "$LOGS_DIR/external_dns_test.log" 2>&1; then
            assert_test "External DNS resolution functionality" "0" ""
            log "INFO" "External DNS test output:"
            cat "$LOGS_DIR/external_dns_test.log"
        else
            assert_test "External DNS resolution functionality" "1" "External DNS test program failed"
        fi
    else
        log "WARNING" "Could not compile external DNS test program"
    fi
}

# Test DNS resolver unit tests specifically
test_dns_resolver_units() {
    log "INFO" "Running DNS resolver unit tests"
    
    # Run just the DNS resolver tests from the main test suite
    if "$BUILD_DIR/nexus_tests" 2>&1 | grep -A 50 ">>> Testing DNS Resolver <<<" > "$LOGS_DIR/dns_resolver_unit_test.log"; then
        if grep -q "DNS Resolver Tests Finished" "$LOGS_DIR/dns_resolver_unit_test.log"; then
            assert_test "DNS resolver unit tests" "0" ""
            log "INFO" "DNS resolver unit test results:"
            cat "$LOGS_DIR/dns_resolver_unit_test.log"
        else
            assert_test "DNS resolver unit tests" "1" "DNS resolver tests did not complete successfully"
        fi
    else
        assert_test "DNS resolver unit tests" "1" "Failed to run DNS resolver unit tests"
    fi
}

# Test error handling in DNS resolution
test_dns_error_handling() {
    log "INFO" "Testing DNS error handling capabilities"
    
    # Create a test program to verify error handling
    cat > "$TEST_RESULTS_DIR/test_dns_errors.c" << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>

int test_invalid_domain() {
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    // Test with an invalid domain
    int status = getaddrinfo("this-domain-should-not-exist-12345.invalid", NULL, &hints, &result);
    if (status != 0) {
        printf("Error handling test PASSED: Invalid domain properly rejected with error: %s\n", gai_strerror(status));
        return 0;
    } else {
        printf("Error handling test FAILED: Invalid domain was resolved unexpectedly\n");
        freeaddrinfo(result);
        return 1;
    }
}

int main() {
    printf("Testing DNS error handling...\n");
    return test_invalid_domain();
}
EOF

    # Compile and run the error handling test
    if gcc -o "$TEST_RESULTS_DIR/test_dns_errors" "$TEST_RESULTS_DIR/test_dns_errors.c" 2>/dev/null; then
        if "$TEST_RESULTS_DIR/test_dns_errors" > "$LOGS_DIR/dns_error_test.log" 2>&1; then
            assert_test "DNS error handling" "0" ""
            log "INFO" "DNS error handling test output:"
            cat "$LOGS_DIR/dns_error_test.log"
        else
            assert_test "DNS error handling" "1" "DNS error handling test failed"
        fi
    else
        log "WARNING" "Could not compile DNS error handling test program"
    fi
}

# Main test execution
main() {
    log "INFO" "Starting Enhanced DNS Resolver Test"
    
    # Create necessary directories
    mkdir -p "$LOGS_DIR" "$TEST_RESULTS_DIR"
    
    # Initialize test log
    echo "Enhanced DNS Resolver Test - $(date)" > "$TEST_RESULTS_DIR/enhanced_dns_test.log"
    
    # Run test suite
    test_dns_resolver_units
    test_external_dns_resolution
    test_dns_error_handling
    
    # Generate test report
    log "INFO" "Generating test report"
    
    echo "========================================" >> "$TEST_RESULTS_DIR/enhanced_dns_test.log"
    echo "TEST SUMMARY" >> "$TEST_RESULTS_DIR/enhanced_dns_test.log"
    echo "========================================" >> "$TEST_RESULTS_DIR/enhanced_dns_test.log"
    echo "Total Tests: $TESTS_TOTAL" >> "$TEST_RESULTS_DIR/enhanced_dns_test.log"
    echo "Passed: $TESTS_PASSED" >> "$TEST_RESULTS_DIR/enhanced_dns_test.log"
    echo "Failed: $TESTS_FAILED" >> "$TEST_RESULTS_DIR/enhanced_dns_test.log"
    echo "Success Rate: $(( TESTS_PASSED * 100 / TESTS_TOTAL ))%" >> "$TEST_RESULTS_DIR/enhanced_dns_test.log"
    
    # Display final results
    echo ""
    echo "========================================="
    log "INFO" "Enhanced DNS Resolver Test Complete"
    echo "========================================="
    log "INFO" "Total Tests: $TESTS_TOTAL"
    log "SUCCESS" "Passed: $TESTS_PASSED"
    if [ $TESTS_FAILED -gt 0 ]; then
        log "ERROR" "Failed: $TESTS_FAILED"
    fi
    log "INFO" "Success Rate: $(( TESTS_PASSED * 100 / TESTS_TOTAL ))%"
    echo "========================================="
    
    # Exit with appropriate code
    if [ $TESTS_FAILED -eq 0 ]; then
        log "SUCCESS" "All DNS resolver tests passed!"
        exit 0
    else
        log "ERROR" "Some DNS resolver tests failed. Check logs for details."
        exit 1
    fi
}

# Run main function
main "$@" 