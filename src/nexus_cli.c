#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/cli_interface.h"
#include "../include/debug.h"

int main(int argc, char *argv[]) {
    // Process --host and --port options if present
    int new_argc = argc;
    char **new_argv = argv;
    
    // Skip options that we processed
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 || strcmp(argv[i], "--port") == 0) {
            // Skip the option and its value
            if (i + 1 < argc) {
                i++;
            }
            new_argc -= 2;
        }
    }
    
    // Create new argv without the processed options
    if (new_argc < argc) {
        new_argv = malloc(new_argc * sizeof(char*));
        if (!new_argv) {
            fprintf(stderr, "Memory allocation failed\n");
            return 1;
        }
        
        new_argv[0] = argv[0]; // Program name
        int j = 1;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--host") == 0 || strcmp(argv[i], "--port") == 0) {
                // Skip the option and its value
                if (i + 1 < argc) {
                    i++;
                }
            } else {
                new_argv[j++] = argv[i];
            }
        }
    }
    
    // Handle CLI commands
    int result = handle_cli_command(new_argc, new_argv);
    
    // Free allocated memory if necessary
    if (new_argv != argv) {
        free(new_argv);
    }
    
    return result;
} 