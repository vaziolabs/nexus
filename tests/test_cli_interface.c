#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../include/cli_interface.h"
#include "test_cli_interface.h"

static void test_cli_command_parsing(void) {
    printf("Testing CLI command parsing...\n");
    
    // Test help command
    {
        char *argv[] = {"nexus", "help"};
        int argc = 2;
        cli_command_t cmd;
        char *socket_path = NULL;
        char *config_profile_name = NULL;
        
        assert(parse_cli_args(argc, argv, &cmd, &socket_path, &config_profile_name) == 0);
        assert(cmd.type == CLI_CMD_HELP);
        
        free_cli_command(&cmd);
        free(socket_path);
        free(config_profile_name);
    }
    
    // Test status command
    {
        char *argv[] = {"nexus", "status"};
        int argc = 2;
        cli_command_t cmd;
        char *socket_path = NULL;
        char *config_profile_name = NULL;
        
        assert(parse_cli_args(argc, argv, &cmd, &socket_path, &config_profile_name) == 0);
        assert(cmd.type == CLI_CMD_STATUS);
        
        free_cli_command(&cmd);
        free(socket_path);
        free(config_profile_name);
    }
    
    // Test start command with profile
    {
        char *argv[] = {"nexus", "start", "testprofile"};
        int argc = 3;
        cli_command_t cmd;
        char *socket_path = NULL;
        char *config_profile_name = NULL;
        
        assert(parse_cli_args(argc, argv, &cmd, &socket_path, &config_profile_name) == 0);
        assert(cmd.type == CLI_CMD_START);
        assert(cmd.profile_name != NULL);
        assert(strcmp(cmd.profile_name, "testprofile") == 0);
        
        free_cli_command(&cmd);
        free(socket_path);
        free(config_profile_name);
    }
    
    // Test register-tld command
    {
        char *argv[] = {"nexus", "register-tld", "testprofile", "example"};
        int argc = 4;
        cli_command_t cmd;
        char *socket_path = NULL;
        char *config_profile_name = NULL;
        
        assert(parse_cli_args(argc, argv, &cmd, &socket_path, &config_profile_name) == 0);
        assert(cmd.type == CLI_CMD_REGISTER_TLD);
        assert(cmd.profile_name != NULL);
        assert(strcmp(cmd.profile_name, "testprofile") == 0);
        assert(cmd.param1 != NULL);
        assert(strcmp(cmd.param1, "example") == 0);
        
        free_cli_command(&cmd);
        free(socket_path);
        free(config_profile_name);
    }
    
    // Test lookup command
    {
        char *argv[] = {"nexus", "lookup", "example.com"};
        int argc = 3;
        cli_command_t cmd;
        char *socket_path = NULL;
        char *config_profile_name = NULL;
        
        assert(parse_cli_args(argc, argv, &cmd, &socket_path, &config_profile_name) == 0);
        assert(cmd.type == CLI_CMD_LOOKUP);
        assert(cmd.param1 != NULL);
        assert(strcmp(cmd.param1, "example.com") == 0);
        
        free_cli_command(&cmd);
        free(socket_path);
        free(config_profile_name);
    }
    
    // Test invalid command
    {
        char *argv[] = {"nexus", "invalid-command"};
        int argc = 2;
        cli_command_t cmd;
        char *socket_path = NULL;
        char *config_profile_name = NULL;
        
        assert(parse_cli_args(argc, argv, &cmd, &socket_path, &config_profile_name) != 0);
        free(socket_path);
        free(config_profile_name);
    }
    
    // Test missing required argument
    {
        char *argv[] = {"nexus", "lookup"};
        int argc = 2;
        cli_command_t cmd;
        char *socket_path = NULL;
        char *config_profile_name = NULL;
        
        assert(parse_cli_args(argc, argv, &cmd, &socket_path, &config_profile_name) != 0);
        free(socket_path);
        free(config_profile_name);
    }
    
    printf("CLI command parsing tests passed\n");
}

static void test_cli_command_memory(void) {
    printf("Testing CLI command memory management...\n");
    
    // Create a command with allocated fields
    cli_command_t cmd;
    memset(&cmd, 0, sizeof(cli_command_t));
    
    cmd.profile_name = strdup("testprofile");
    cmd.param1 = strdup("param1value");
    cmd.param2 = strdup("param2value");
    
    // Verify fields were allocated
    assert(cmd.profile_name != NULL);
    assert(cmd.param1 != NULL);
    assert(cmd.param2 != NULL);
    
    // Free the command
    free_cli_command(&cmd);
    
    // Verify fields were nulled
    assert(cmd.profile_name == NULL);
    assert(cmd.param1 == NULL);
    assert(cmd.param2 == NULL);
    
    printf("CLI command memory management tests passed\n");
}

// Note: We can't easily test socket connections in unit tests
// so we'll skip testing the actual IPC functions

void test_cli_interface_all(void) {
    printf("\n=== Running CLI Interface Tests ===\n");
    
    // Initialize CLI interface
    assert(init_cli_interface() == 0);
    
    test_cli_command_parsing();
    test_cli_command_memory();
    
    // Clean up
    cleanup_cli_interface();
    
    printf("All CLI interface tests passed\n");
} 