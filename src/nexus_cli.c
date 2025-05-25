#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/cli_interface.h"
#include "../include/debug.h"

int main(int argc, char *argv[]) {
    // Initialize CLI interface
    if (init_cli_interface() != 0) {
        fprintf(stderr, "Failed to initialize CLI interface\n");
        return 1;
    }
    
    // If no arguments provided, show help
    if (argc < 2) {
        cmd_help();
        cleanup_cli_interface();
        return 0;
    }
    
    // Parse command line arguments
    cli_command_t cmd;
    if (parse_cli_args(argc, argv, &cmd) != 0) {
        fprintf(stderr, "Failed to parse command line arguments\n");
        cmd_help();
        cleanup_cli_interface();
        return 1;
    }
    
    // Process the command
    int result = process_cli_command(&cmd);
    
    // Free command resources
    free_cli_command(&cmd);
    
    // Clean up
    cleanup_cli_interface();
    
    return result == 0 ? 0 : 1;
} 