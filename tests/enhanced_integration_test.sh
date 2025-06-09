#!/bin/bash

# Enhanced NEXUS Integration Test
# Tests core functionality with enhanced error handling and recovery mechanisms

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

# Test parameters
SERVER_PORT=10443
CLIENT_PORT=10444
TEST_TIMEOUT=30
PERFORMANCE_ITERATIONS=10

# Cleanup function
cleanup() {
    echo -e "${YELLOW}Cleaning up test processes...${NC}"
    
    # Kill any remaining NEXUS processes
    pkill -f "nexus" 2>/dev/null || true
    
    # Wait a moment for processes to terminate
    sleep 2
    
    # Force kill if necessary
    pkill -9 -f "nexus" 2>/dev/null || true
    
    echo -e "${GREEN}Cleanup completed${NC}"
}

# Set up cleanup trap
trap cleanup EXIT

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
    echo "[$timestamp] $level: $message" >> "$TEST_RESULTS_DIR/enhanced_test.log"
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

# Performance monitoring function
monitor_performance() {
    local process_name="$1"
    local duration="$2"
    local output_file="$3"
    
    log "INFO" "Monitoring performance of $process_name for ${duration}s"
    
    # Monitor CPU and memory usage
    for i in $(seq 1 $duration); do
        if pgrep -f "$process_name" > /dev/null; then
            ps -o pid,pcpu,pmem,vsz,rss,comm -C nexus >> "$output_file" 2>/dev/null || true
        fi
        sleep 1
    done
}

# Network connectivity test
test_network_connectivity() {
    log "INFO" "Testing network connectivity"
    
    # Test IPv6 loopback (make this a warning instead of failure)
    if ping6 -c 1 ::1 > /dev/null 2>&1; then
        assert_test "IPv6 loopback connectivity" "0" ""
    else
        log "WARNING" "IPv6 loopback not available - this may be expected in some environments"
        # Don't fail the test for IPv6 unavailability
    fi
    
    # Test port availability
    if ! ss -tuln 2>/dev/null | grep ":$SERVER_PORT " > /dev/null; then
        assert_test "Server port availability" "0" ""
    else
        assert_test "Server port availability" "1" "Port $SERVER_PORT already in use"
    fi
}

# Build verification test
test_build_verification() {
    log "INFO" "Verifying build artifacts"
    
    # Check if binaries exist
    if [ -f "$BUILD_DIR/nexus" ]; then
        assert_test "NEXUS daemon binary exists" "0" ""
    else
        assert_test "NEXUS daemon binary exists" "1" "Binary not found at $BUILD_DIR/nexus"
        return 1
    fi
    
    if [ -f "$BUILD_DIR/nexus_cli" ]; then
        assert_test "NEXUS CLI binary exists" "0" ""
    else
        assert_test "NEXUS CLI binary exists" "1" "Binary not found at $BUILD_DIR/nexus_cli"
        return 1
    fi
    
    # Check binary permissions
    if [ -x "$BUILD_DIR/nexus" ]; then
        assert_test "NEXUS daemon is executable" "0" ""
    else
        assert_test "NEXUS daemon is executable" "1" "Binary is not executable"
    fi
    
    if [ -x "$BUILD_DIR/nexus_cli" ]; then
        assert_test "NEXUS CLI is executable" "0" ""
    else
        assert_test "NEXUS CLI is executable" "1" "Binary is not executable"
    fi
}

# Server startup and stability test
test_server_startup() {
    log "INFO" "Testing server startup and stability"
    
    # Start server in background
    NEXUS_DEBUG=1 "$BUILD_DIR/nexus" --mode private --hostname test.local > "$LOGS_DIR/enhanced_server.log" 2>&1 &
    SERVER_PID=$!
    
    # Wait for server to start
    sleep 5
    
    # Check if server is still running
    if kill -0 $SERVER_PID 2>/dev/null; then
        assert_test "Server startup" "0" ""
    else
        assert_test "Server startup" "1" "Server process died during startup"
        return 1
    fi
    
    # Check if server is listening on the port
    sleep 2
    if ss -tuln 2>/dev/null | grep ":$SERVER_PORT " > /dev/null; then
        assert_test "Server port binding" "0" ""
    else
        assert_test "Server port binding" "1" "Server not listening on port $SERVER_PORT"
        kill $SERVER_PID 2>/dev/null || true
        return 1
    fi
    
    # Monitor server stability for 10 seconds
    monitor_performance "nexus" 10 "$TEST_RESULTS_DIR/server_performance.log" &
    MONITOR_PID=$!
    
    sleep 10
    
    # Check if server is still running after stability test
    if kill -0 $SERVER_PID 2>/dev/null; then
        assert_test "Server stability (10s)" "0" ""
    else
        assert_test "Server stability (10s)" "1" "Server crashed during stability test"
    fi
    
    # Stop monitoring
    kill $MONITOR_PID 2>/dev/null || true
    
    # Keep server running for subsequent tests
    echo $SERVER_PID > "$TEST_RESULTS_DIR/server.pid"
}

# DNS resolution test with error handling
test_dns_resolution() {
    log "INFO" "Testing DNS resolution with error handling"
    
    local server_pid=$(cat "$TEST_RESULTS_DIR/server.pid" 2>/dev/null || echo "")
    
    if [ -z "$server_pid" ] || ! kill -0 $server_pid 2>/dev/null; then
        assert_test "DNS resolution prerequisite" "1" "Server not running"
        return 1
    fi
    
    # Test TLD registration
    if "$BUILD_DIR/nexus_cli" --server localhost --port $SERVER_PORT register-tld "testdomain" > "$LOGS_DIR/tld_register.log" 2>&1; then
        assert_test "TLD registration" "0" ""
    else
        assert_test "TLD registration" "1" "Failed to register TLD"
        return 1
    fi
    
    # Test domain registration
    if "$BUILD_DIR/nexus_cli" --server localhost --port $SERVER_PORT register-domain "www.testdomain" "192.168.1.100" > "$LOGS_DIR/domain_register.log" 2>&1; then
        assert_test "Domain registration" "0" ""
    else
        assert_test "Domain registration" "1" "Failed to register domain"
        return 1
    fi
    
    # Test DNS resolution
    if "$BUILD_DIR/nexus_cli" --server localhost --port $SERVER_PORT resolve "www.testdomain" > "$LOGS_DIR/dns_resolve.log" 2>&1; then
        assert_test "DNS resolution" "0" ""
    else
        assert_test "DNS resolution" "1" "Failed to resolve domain"
    fi
    
    # Test external DNS resolution (if available)
    if "$BUILD_DIR/nexus_cli" --server localhost --port $SERVER_PORT resolve "google.com" > "$LOGS_DIR/external_dns_resolve.log" 2>&1; then
        assert_test "External DNS resolution" "0" ""
    else
        log "WARNING" "External DNS resolution failed - this may be expected in some environments"
    fi
}

# Error recovery test
test_error_recovery() {
    log "INFO" "Testing error recovery mechanisms"
    
    local server_pid=$(cat "$TEST_RESULTS_DIR/server.pid" 2>/dev/null || echo "")
    
    if [ -z "$server_pid" ] || ! kill -0 $server_pid 2>/dev/null; then
        assert_test "Error recovery prerequisite" "1" "Server not running"
        return 1
    fi
    
    # Test invalid domain resolution (should handle gracefully)
    if "$BUILD_DIR/nexus_cli" --server localhost --port $SERVER_PORT resolve "nonexistent.invalid" > "$LOGS_DIR/invalid_resolve.log" 2>&1; then
        # This should actually fail, but gracefully
        log "INFO" "Invalid domain resolution handled"
    else
        log "INFO" "Invalid domain resolution properly rejected"
    fi
    
    # Test server recovery after sending invalid data
    # (This is a simplified test - in a real scenario we'd send malformed packets)
    
    # Check if server is still responsive after error conditions
    if "$BUILD_DIR/nexus_cli" --server localhost --port $SERVER_PORT resolve "www.testdomain" > "$LOGS_DIR/recovery_test.log" 2>&1; then
        assert_test "Server recovery after errors" "0" ""
    else
        assert_test "Server recovery after errors" "1" "Server not responsive after error conditions"
    fi
}

# Performance test
test_performance() {
    log "INFO" "Testing performance under load"
    
    local server_pid=$(cat "$TEST_RESULTS_DIR/server.pid" 2>/dev/null || echo "")
    
    if [ -z "$server_pid" ] || ! kill -0 $server_pid 2>/dev/null; then
        assert_test "Performance test prerequisite" "1" "Server not running"
        return 1
    fi
    
    # Start performance monitoring
    monitor_performance "nexus" 30 "$TEST_RESULTS_DIR/load_performance.log" &
    MONITOR_PID=$!
    
    # Perform multiple DNS resolutions in parallel
    local start_time=$(date +%s)
    
    for i in $(seq 1 $PERFORMANCE_ITERATIONS); do
        "$BUILD_DIR/nexus_cli" --server localhost --port $SERVER_PORT resolve "www.testdomain" > "$LOGS_DIR/perf_$i.log" 2>&1 &
    done
    
    # Wait for all background jobs to complete
    wait
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Stop monitoring
    kill $MONITOR_PID 2>/dev/null || true
    
    log "INFO" "Performance test completed: $PERFORMANCE_ITERATIONS requests in ${duration}s"
    
    # Check if performance is reasonable (less than 3 seconds per request on average)
    local avg_time=$((duration * 1000 / PERFORMANCE_ITERATIONS))
    if [ $avg_time -lt 3000 ]; then
        assert_test "Performance under load" "0" ""
    else
        assert_test "Performance under load" "1" "Average response time too high: ${avg_time}ms"
    fi
}

# Memory leak test
test_memory_leaks() {
    log "INFO" "Testing for memory leaks"
    
    local server_pid=$(cat "$TEST_RESULTS_DIR/server.pid" 2>/dev/null || echo "")
    
    if [ -z "$server_pid" ] || ! kill -0 $server_pid 2>/dev/null; then
        assert_test "Memory leak test prerequisite" "1" "Server not running"
        return 1
    fi
    
    # Get initial memory usage
    local initial_memory=$(ps -o rss= -p $server_pid 2>/dev/null || echo "0")
    
    # Perform many operations to potentially trigger memory leaks
    for i in $(seq 1 50); do
        "$BUILD_DIR/nexus_cli" --server localhost --port $SERVER_PORT resolve "www.testdomain" > /dev/null 2>&1 || true
    done
    
    sleep 5
    
    # Get final memory usage
    local final_memory=$(ps -o rss= -p $server_pid 2>/dev/null || echo "0")
    
    # Calculate memory growth
    local memory_growth=$((final_memory - initial_memory))
    
    log "INFO" "Memory usage: initial=${initial_memory}KB, final=${final_memory}KB, growth=${memory_growth}KB"
    
    # Check if memory growth is reasonable (less than 10MB)
    if [ $memory_growth -lt 10240 ]; then
        assert_test "Memory leak test" "0" ""
    else
        assert_test "Memory leak test" "1" "Excessive memory growth: ${memory_growth}KB"
    fi
}

# Main test execution
main() {
    log "INFO" "Starting Enhanced NEXUS Integration Test"
    
    # Create necessary directories
    mkdir -p "$LOGS_DIR" "$TEST_RESULTS_DIR"
    
    # Initialize test log
    echo "Enhanced NEXUS Integration Test - $(date)" > "$TEST_RESULTS_DIR/enhanced_test.log"
    
    # Run test suite
    test_network_connectivity
    test_build_verification
    test_server_startup
    test_dns_resolution
    test_error_recovery
    test_performance
    test_memory_leaks
    
    # Clean up server
    local server_pid=$(cat "$TEST_RESULTS_DIR/server.pid" 2>/dev/null || echo "")
    if [ -n "$server_pid" ] && kill -0 $server_pid 2>/dev/null; then
        log "INFO" "Stopping test server"
        kill $server_pid 2>/dev/null || true
        sleep 2
        kill -9 $server_pid 2>/dev/null || true
    fi
    
    # Generate test report
    log "INFO" "Generating test report"
    
    echo "========================================" >> "$TEST_RESULTS_DIR/enhanced_test.log"
    echo "TEST SUMMARY" >> "$TEST_RESULTS_DIR/enhanced_test.log"
    echo "========================================" >> "$TEST_RESULTS_DIR/enhanced_test.log"
    echo "Total Tests: $TESTS_TOTAL" >> "$TEST_RESULTS_DIR/enhanced_test.log"
    echo "Passed: $TESTS_PASSED" >> "$TEST_RESULTS_DIR/enhanced_test.log"
    echo "Failed: $TESTS_FAILED" >> "$TEST_RESULTS_DIR/enhanced_test.log"
    echo "Success Rate: $(( TESTS_PASSED * 100 / TESTS_TOTAL ))%" >> "$TEST_RESULTS_DIR/enhanced_test.log"
    
    # Display final results
    echo ""
    echo "========================================="
    log "INFO" "Enhanced Integration Test Complete"
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
        log "SUCCESS" "All tests passed!"
        exit 0
    else
        log "ERROR" "Some tests failed. Check logs for details."
        exit 1
    fi
}

# Run main function
main "$@" 