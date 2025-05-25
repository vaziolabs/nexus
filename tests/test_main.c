#include <stdio.h>
#include <string.h>
#include "test_tld_manager.h"
#include "test_packet_protocol.h"
#include "test_config_manager.h"
#include "test_cli_interface.h"
#include "test_certificate_transparency.h"
#include "test_certificate_authority.h"
#include "test_network_context.h"

// Function declarations for test suite initializers
void ts_tld_manager_init(void);
void ts_packet_protocol_init(void);

// Color codes for test output formatting
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_RESET   "\x1b[0m"

// Function to print help message
void print_help(void) {
    printf("NEXUS Test Suite Usage:\n");
    printf("  nexus_tests            Run all tests\n");
    printf("  nexus_tests tld        Run only TLD Manager tests\n");
    printf("  nexus_tests packet     Run only Packet Protocol tests\n");
    printf("  nexus_tests config     Run only Config Manager tests\n");
    printf("  nexus_tests cli        Run only CLI Interface tests\n");
    printf("  nexus_tests ct         Run only Certificate Transparency tests\n");
    printf("  nexus_tests ca         Run only Certificate Authority tests\n");
    printf("  nexus_tests network    Run only Network Context tests\n");
    printf("  nexus_tests help       Show this help message\n");
}

int main(int argc, char *argv[]) {
    // Check if a specific test component was requested
    int run_tld = 1;
    int run_packet = 1;
    int run_config = 1;
    int run_cli = 1;
    int run_ct = 1;
    int run_ca = 1;
    int run_network = 1;
    
    // If a command-line argument is provided, only run the specified test
    if (argc > 1) {
        // Reset all flags to 0 first
        run_tld = run_packet = run_config = run_cli = run_ct = run_ca = run_network = 0;
        
        if (strcmp(argv[1], "tld") == 0) {
            run_tld = 1;
        } else if (strcmp(argv[1], "packet") == 0) {
            run_packet = 1;
        } else if (strcmp(argv[1], "config") == 0) {
            run_config = 1;
        } else if (strcmp(argv[1], "cli") == 0) {
            run_cli = 1;
        } else if (strcmp(argv[1], "ct") == 0) {
            run_ct = 1;
        } else if (strcmp(argv[1], "ca") == 0) {
            run_ca = 1;
        } else if (strcmp(argv[1], "network") == 0) {
            run_network = 1;
        } else if (strcmp(argv[1], "help") == 0) {
            print_help();
            return 0;
        } else {
            printf(COLOR_RED "Unknown test component: %s\n" COLOR_RESET, argv[1]);
            print_help();
            return 1;
        }
    }

    printf(COLOR_BLUE "\n=================================\n");
    printf("   NEXUS Test Suite Starting   \n");
    printf("=================================\n" COLOR_RESET);

    int success = 1; // Assume success until proven otherwise

    // Initialize and run tests for TLD Manager
    if (run_tld) {
        printf(COLOR_YELLOW "\n>>> Testing TLD Manager <<<\n" COLOR_RESET);
        ts_tld_manager_init();
    }

    // Initialize and run tests for Packet Protocol
    if (run_packet) {
        printf(COLOR_YELLOW "\n>>> Testing Packet Protocol <<<\n" COLOR_RESET);
        ts_packet_protocol_init();
    }

    // Run config manager tests
    if (run_config) {
        printf(COLOR_YELLOW "\n>>> Testing Config Manager <<<\n" COLOR_RESET);
        test_config_manager_all();
    }

    // Run CLI interface tests
    if (run_cli) {
        printf(COLOR_YELLOW "\n>>> Testing CLI Interface <<<\n" COLOR_RESET);
        test_cli_interface_all();
    }

    // Run certificate transparency tests
    if (run_ct) {
        printf(COLOR_YELLOW "\n>>> Testing Certificate Transparency <<<\n" COLOR_RESET);
        test_certificate_transparency_all();
    }

    // Run certificate authority tests
    if (run_ca) {
        printf(COLOR_YELLOW "\n>>> Testing Certificate Authority <<<\n" COLOR_RESET);
        test_certificate_authority_all();
    }

    // Run network context tests
    if (run_network) {
        printf(COLOR_YELLOW "\n>>> Testing Network Context <<<\n" COLOR_RESET);
        test_network_context_all();
    }

    printf(COLOR_BLUE "\n=================================\n");
    if (success) {
        printf(COLOR_GREEN "   NEXUS Test Suite Successful   \n" COLOR_RESET);
    } else {
        printf(COLOR_RED "   NEXUS Test Suite Failed      \n" COLOR_RESET);
    }
    printf(COLOR_BLUE "=================================\n\n" COLOR_RESET);

    return success ? 0 : 1; // Return 0 for success, 1 for failure
} 