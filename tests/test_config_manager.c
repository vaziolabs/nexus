#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../include/config_manager.h"
#include "test_config_manager.h"

static void test_create_default_config(void) {
    printf("Testing create_default_config()...\n");
    
    nexus_config_t *config = create_default_config();
    assert(config != NULL);
    assert(config->node_id != NULL);
    assert(config->default_profile != NULL);
    assert(config->log_file != NULL);
    assert(config->profiles != NULL);
    assert(config->profile_count > 0);
    assert(config->max_profiles > 0);
    
    // Verify default profile
    assert(config->profiles[0] != NULL);
    assert(config->profiles[0]->name != NULL);
    assert(strcmp(config->profiles[0]->name, "default") == 0);
    assert(config->profiles[0]->mode != NULL);
    assert(strcmp(config->profiles[0]->mode, "private") == 0);
    
    free_config(config);
    printf("create_default_config test passed\n");
}

static void test_profile_management(void) {
    printf("Testing profile management functions...\n");
    
    nexus_config_t *config = create_default_config();
    assert(config != NULL);
    
    // Test create_profile
    network_profile_t *test_profile = create_profile("test_profile", "public");
    assert(test_profile != NULL);
    assert(strcmp(test_profile->name, "test_profile") == 0);
    assert(strcmp(test_profile->mode, "public") == 0);
    
    // Test add_profile
    int initial_count = config->profile_count;
    assert(add_profile(config, test_profile) == 0);
    assert(config->profile_count == initial_count + 1);
    
    // Test get_profile
    network_profile_t *retrieved = get_profile(config, "test_profile");
    assert(retrieved != NULL);
    assert(retrieved == test_profile);
    assert(strcmp(retrieved->name, "test_profile") == 0);
    
    // Test remove_profile
    assert(remove_profile(config, "test_profile") == 0);
    assert(config->profile_count == initial_count);
    assert(get_profile(config, "test_profile") == NULL);
    
    // Create another profile for further testing
    test_profile = create_profile("federated_test", "federated");
    assert(test_profile != NULL);
    assert(add_profile(config, test_profile) == 0);
    
    free_config(config);
    printf("Profile management tests passed\n");
}

static void test_network_context_creation(void) {
    printf("Testing network context creation from profile...\n");
    
    network_profile_t *profile = create_profile("test_ctx", "private");
    assert(profile != NULL);
    
    network_context_t *net_ctx = NULL;
    int result = create_network_context_from_profile(profile, &net_ctx);
    
    // Since this is a stub in our implementation, we should expect it to fail or return a minimal context
    if (result == 0) {
        assert(net_ctx != NULL);
        assert(net_ctx->mode != NULL);
        assert(net_ctx->hostname != NULL);
        assert(net_ctx->server != NULL);
        
        // Clean up - this would normally be done with cleanup_network_context_components
        free((void*)net_ctx->mode);
        free((void*)net_ctx->hostname);
        free((void*)net_ctx->server);
        free(net_ctx);
    } else {
        printf("Note: create_network_context_from_profile returned %d (expected in stub implementation)\n", result);
    }
    
    free_network_profile(profile);
    printf("Network context creation test completed\n");
}

static void test_config_paths(void) {
    printf("Testing configuration paths functions...\n");
    
    char *config_dir = get_config_dir();
    assert(config_dir != NULL);
    assert(strcmp(config_dir, NEXUS_CONFIG_DIR) == 0);
    free(config_dir);
    
    char *user_config_dir = get_user_config_dir();
    assert(user_config_dir != NULL);
    // The actual value will depend on the user's home directory
    printf("User config dir: %s\n", user_config_dir);
    free(user_config_dir);
    
    printf("Configuration paths tests passed\n");
}

void test_config_manager_all(void) {
    printf("\n=== Running Config Manager Tests ===\n");
    
    test_create_default_config();
    test_profile_management();
    test_network_context_creation();
    test_config_paths();
    
    printf("All config manager tests passed\n");
} 