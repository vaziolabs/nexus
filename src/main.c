#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdlib.h> // For system()
#include <inttypes.h> // For PRId64

// Include ngtcp2 v1.12.0
#include <ngtcp2/ngtcp2.h>
#include "ngtcp2_compat.h" // Compatibility layer for ngtcp2 v1.12.0

/*
 * IMPORTANT: This project requires version 1.12.0 of ngtcp2.
 * The code has been updated to use the API of this version.
 * 
 * See README.md for more details.
 */

// Project headers
#include "system.h"
#include "certificate_authority.h"
#include "nexus_node.h"
#include "network_context.h"
#include "tld_manager.h"
#include "debug.h" // For dlog
#include "config_manager.h" // Added for configuration management
#include "cli_interface.h" // Added for CLI functionality

// Add global variable for clean shutdown
static volatile int global_running = 1;

// Add signal handler
static void handle_signal(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        global_running = 0;
    }
}

// Add these new definitions
#define NEXUS_SERVER_PORT 10053
#define NEXUS_CLIENT_PORT 10443
#define MAX_PENDING_CONNECTIONS 10

// Add structure for multi-network context
typedef struct {
    network_context_t **contexts;
    nexus_node_t **nodes;
    int count;
    int max_count;
    pthread_mutex_t lock;
} multi_network_t;

// Global multi-network context
static multi_network_t *global_multi_network = NULL;

void print_usage() {
    printf("NEXUS Daemon - DNS-over-QUIC Protocol Implementation\n\n");
    printf("Usage: nexus [OPTIONS]\n");
    printf("Options:\n");
    printf("  --config    <config_file>              Config file path\n");
    printf("  --profile   <profile_name>             Use specific profile\n");
    printf("  --mode      <public|private|federated> Node mode (default: from config)\n");
    printf("  --hostname  <hostname>                 Node hostname (default: from config)\n");
    printf("  --server    <server>                   Server hostname (default: from config)\n");
    printf("  --register-tld <tld_name>              Register a new TLD with the connected server\n");
    printf("  --service                              Run as a service\n");
    printf("  --detect-network                       Auto-detect network settings\n");
    printf("  --test                                 Run unit tests\n");
    printf("  --help                                 Show this help message\n");
    printf("\n");
    printf("For CLI commands, use the nexus_cli executable:\n");
    printf("  nexus_cli help                         Show CLI help\n");
}

// Initialize multi-network context
int init_multi_network(void) {
    global_multi_network = malloc(sizeof(multi_network_t));
    if (!global_multi_network) {
        return -1;
    }
    
    memset(global_multi_network, 0, sizeof(multi_network_t));
    
    global_multi_network->max_count = 10;
    global_multi_network->count = 0;
    global_multi_network->contexts = malloc(global_multi_network->max_count * sizeof(network_context_t*));
    global_multi_network->nodes = malloc(global_multi_network->max_count * sizeof(nexus_node_t*));
    
    if (!global_multi_network->contexts || !global_multi_network->nodes) {
        free(global_multi_network->contexts);
        free(global_multi_network->nodes);
        free(global_multi_network);
        global_multi_network = NULL;
        return -1;
    }
    
    if (pthread_mutex_init(&global_multi_network->lock, NULL) != 0) {
        free(global_multi_network->contexts);
        free(global_multi_network->nodes);
        free(global_multi_network);
        global_multi_network = NULL;
        return -1;
    }
    
    return 0;
}

// Clean up multi-network context
void cleanup_multi_network(void) {
    if (!global_multi_network) {
        return;
    }
    
    pthread_mutex_lock(&global_multi_network->lock);
    
    for (int i = 0; i < global_multi_network->count; i++) {
        if (global_multi_network->nodes[i]) {
            cleanup_node(global_multi_network->nodes[i]);
        }
        
        if (global_multi_network->contexts[i]) {
            cleanup_network_context_components(global_multi_network->contexts[i]);
            free((void*)global_multi_network->contexts[i]->mode);
            free((void*)global_multi_network->contexts[i]->hostname);
            free((void*)global_multi_network->contexts[i]->server);
            free(global_multi_network->contexts[i]);
        }
    }
    
    free(global_multi_network->contexts);
    free(global_multi_network->nodes);
    
    pthread_mutex_unlock(&global_multi_network->lock);
    pthread_mutex_destroy(&global_multi_network->lock);
    
    free(global_multi_network);
    global_multi_network = NULL;
}

// Add a network context to the multi-network
int add_network_to_multi_network(network_context_t *net_ctx, nexus_node_t *node) {
    if (!global_multi_network || !net_ctx || !node) {
        return -1;
    }
    
    pthread_mutex_lock(&global_multi_network->lock);
    
    // Check if we need to resize the arrays
    if (global_multi_network->count >= global_multi_network->max_count) {
        int new_max = global_multi_network->max_count * 2;
        network_context_t **new_contexts = realloc(global_multi_network->contexts, 
                                                 new_max * sizeof(network_context_t*));
        nexus_node_t **new_nodes = realloc(global_multi_network->nodes, 
                                         new_max * sizeof(nexus_node_t*));
        
        if (!new_contexts || !new_nodes) {
            free(new_contexts);
            free(new_nodes);
            pthread_mutex_unlock(&global_multi_network->lock);
            return -1;
        }
        
        global_multi_network->contexts = new_contexts;
        global_multi_network->nodes = new_nodes;
        global_multi_network->max_count = new_max;
    }
    
    // Add the network
    global_multi_network->contexts[global_multi_network->count] = net_ctx;
    global_multi_network->nodes[global_multi_network->count] = node;
    global_multi_network->count++;
    
    pthread_mutex_unlock(&global_multi_network->lock);
    return 0;
}

// Start node from profile
int start_node_from_profile(network_profile_t *profile) {
    if (!profile) {
        return -1;
    }
    
    dlog("Starting node from profile %s", profile->name);
    
    // Create network context from profile
    network_context_t *net_ctx = NULL;
    if (create_network_context_from_profile(profile, &net_ctx) != 0) {
        fprintf(stderr, "Failed to create network context from profile %s\n", profile->name);
        return -1;
    }
    
    // Initialize CA
    ca_context_t* ca_ctx = NULL;
    if (init_certificate_authority(net_ctx, &ca_ctx) != 0) {
        fprintf(stderr, "Failed to initialize certificate authority for profile %s\n", profile->name);
        free((void*)net_ctx->mode);
        free((void*)net_ctx->hostname);
        free((void*)net_ctx->server);
        free(net_ctx);
        return -1;
    }
    
    // Initialize node
    nexus_node_t *node = NULL;
    int status = init_node(net_ctx, ca_ctx, profile->server_port, profile->client_port, &node);
    if (status != 0) {
        fprintf(stderr, "Failed to initialize node for profile %s\n", profile->name);
        cleanup_certificate_authority(ca_ctx);
        free((void*)net_ctx->mode);
        free((void*)net_ctx->hostname);
        free((void*)net_ctx->server);
        free(net_ctx);
        return -1;
    }
    
    // Add to multi-network
    if (add_network_to_multi_network(net_ctx, node) != 0) {
        fprintf(stderr, "Failed to add network to multi-network for profile %s\n", profile->name);
        cleanup_node(node);
        free((void*)net_ctx->mode);
        free((void*)net_ctx->hostname);
        free((void*)net_ctx->server);
        free(net_ctx);
        return -1;
    }
    
    dlog("Successfully started node for profile %s", profile->name);
    return 0;
}

// Start all profiles in configuration
int start_all_profiles(nexus_config_t *config) {
    if (!config) {
        return -1;
    }
    
    pthread_mutex_lock(&config->lock);
    
    int success_count = 0;
    for (int i = 0; i < config->profile_count; i++) {
        network_profile_t *profile = config->profiles[i];
        
        // Skip profiles that aren't set to auto-connect
        if (!profile->auto_connect) {
            dlog("Skipping profile %s (auto-connect disabled)", profile->name);
            continue;
        }
        
        if (start_node_from_profile(profile) == 0) {
            success_count++;
        }
    }
    
    pthread_mutex_unlock(&config->lock);
    
    if (success_count == 0) {
        fprintf(stderr, "Failed to start any profiles\n");
        return -1;
    }
    
    dlog("Started %d profiles", success_count);
    return 0;
}

// Run as a service
int run_as_service(void) {
    dlog("Running as a service");
    
    // Initialize config manager
    if (init_config_manager() != 0) {
        fprintf(stderr, "Failed to initialize configuration manager\n");
        return -1;
    }
    
    // Initialize multi-network
    if (init_multi_network() != 0) {
        fprintf(stderr, "Failed to initialize multi-network\n");
        cleanup_config_manager();
        return -1;
    }
    
    // Get global config (loaded by init_config_manager)
    nexus_config_t *config = create_default_config(); // In a real implementation, we would use the global config
    
    // Start all profiles
    if (start_all_profiles(config) != 0) {
        fprintf(stderr, "Failed to start any profiles\n");
        free_config(config);
        cleanup_multi_network();
        cleanup_config_manager();
        return -1;
    }
    
    dlog("Service started successfully");
    
    // Keep running until signal received
    while (global_running) {
        sleep(1);
    }
    
    dlog("Service shutting down");
    
    // Clean up
    free_config(config);
    cleanup_multi_network();
    cleanup_config_manager();
    
    return 0;
}

int main(int argc, char *argv[]) {
    // Default values
    const char* node_mode = NULL;
    const char* node_hostname = NULL;
    const char* node_server = NULL;
    const char* tld_to_register = NULL;
    const char* config_file = NULL;
    const char* profile_name = NULL;
    int run_as_service_flag = 0;
    int detect_network_flag = 0;

    // Define long options
    static struct option long_options[] = {
        {"config",        required_argument, 0, 'c'},
        {"profile",       required_argument, 0, 'p'},
        {"mode",          required_argument, 0, 'm'},
        {"hostname",      required_argument, 0, 'h'},
        {"server",        required_argument, 0, 's'},
        {"register-tld",  required_argument, 0, 'r'},
        {"service",       no_argument,       0, 'd'},
        {"detect-network",no_argument,       0, 'n'},
        {"test",          no_argument,       0, 't'},
        {"help",          no_argument,       0, '?'},
        {0, 0, 0, 0}
    };

    // Parse command line arguments
    int opt;
    while ((opt = getopt_long(argc, argv, "c:p:m:h:s:r:dnt", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'p':
                profile_name = optarg;
                break;
            case 'm':
                if (strcmp(optarg, "public") == 0 || 
                    strcmp(optarg, "private") == 0 || 
                    strcmp(optarg, "federated") == 0) {
                    node_mode = optarg;
                } else {
                    fprintf(stderr, "Invalid mode: %s\n", optarg);
                    print_usage();
                    return 1;
                }
                break;
            case 'h':
                node_hostname = optarg;
                break;
            case 's':
                node_server = optarg;
                break;
            case 'r':
                tld_to_register = optarg;
                break;
            case 'd':
                run_as_service_flag = 1;
                break;
            case 'n':
                detect_network_flag = 1;
                break;
            case 't':
                printf("Executing 'make test'...\n");
                int test_status = system("make test");
                if (test_status == -1) {
                    perror("system() failed to execute 'make test'");
                    return 1;
                } else {
                    if (WIFEXITED(test_status) && WEXITSTATUS(test_status) == 0) {
                        printf("'make test' executed successfully.\n");
                        return 0; // Exit after running tests
                    } else {
                        fprintf(stderr, "'make test' failed or returned non-zero exit status.\n");
                        return WEXITSTATUS(test_status); // Return test failure code
                    }
                }
                break;
            case '?':
                print_usage();
                return 0;
            default:
                print_usage();
                return 1;
        }
    }

    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Run as a service if requested
    if (run_as_service_flag) {
        return run_as_service();
    }
    
    // Load configuration if specified or use default values
    network_context_t *net_ctx = NULL;
    nexus_node_t *node = NULL;
    
    if (config_file || profile_name) {
        // Initialize config manager
        if (init_config_manager() != 0) {
            fprintf(stderr, "Failed to initialize configuration manager\n");
            return 1;
        }
        
        // Load config file if specified
        nexus_config_t *config = NULL;
        if (config_file) {
            config = load_config(config_file);
            if (!config) {
                fprintf(stderr, "Failed to load configuration from %s\n", config_file);
                cleanup_config_manager();
                return 1;
            }
        } else {
            // Use default config
            config = create_default_config();
            if (!config) {
                fprintf(stderr, "Failed to create default configuration\n");
                cleanup_config_manager();
                return 1;
            }
        }
        
        // Get profile
        network_profile_t *profile = NULL;
        if (profile_name) {
            profile = get_profile(config, profile_name);
            if (!profile) {
                fprintf(stderr, "Profile '%s' not found\n", profile_name);
                free_config(config);
                cleanup_config_manager();
                return 1;
            }
        } else if (config->default_profile) {
            profile = get_profile(config, config->default_profile);
            if (!profile) {
                fprintf(stderr, "Default profile '%s' not found\n", config->default_profile);
                free_config(config);
                cleanup_config_manager();
                return 1;
            }
        } else {
            fprintf(stderr, "No profile specified and no default profile set\n");
            free_config(config);
            cleanup_config_manager();
            return 1;
        }
        
        // Override profile settings if specified
        if (node_mode) {
            free(profile->mode);
            profile->mode = strdup(node_mode);
        }
        
        if (node_hostname) {
            free(profile->hostname);
            profile->hostname = strdup(node_hostname);
        }
        
        if (node_server) {
            free(profile->server);
            profile->server = strdup(node_server);
        }
        
        // Detect network settings if requested
        if (detect_network_flag) {
            detect_network_settings(profile);
        }
        
        // Create network context from profile
        if (create_network_context_from_profile(profile, &net_ctx) != 0) {
            fprintf(stderr, "Failed to create network context from profile\n");
            free_config(config);
            cleanup_config_manager();
            return 1;
        }
        
        // Clean up config now that we have the network context
        free_config(config);
    } else {
        // Use command line arguments
        if (!node_mode) node_mode = "private";
        if (!node_hostname) node_hostname = "localhost";
        if (!node_server) node_server = "localhost";
        
        net_ctx = malloc(sizeof(network_context_t));
        if (!net_ctx) {
            fprintf(stderr, "Failed to allocate network context\n");
            return 1;
        }
        
        memset(net_ctx, 0, sizeof(network_context_t));
        
        net_ctx->mode = strdup(node_mode);
        net_ctx->hostname = strdup(node_hostname);
        net_ctx->server = strdup(node_server);
        
        if (init_network_context_components(net_ctx) != 0) {
            fprintf(stderr, "Failed to initialize network context components\n");
            free((void*)net_ctx->mode);
            free((void*)net_ctx->hostname);
            free((void*)net_ctx->server);
            free(net_ctx);
            return 1;
        }
    }

    printf("Initializing NEXUS node\n");
    printf("Mode: %s\n", net_ctx->mode);
    printf("Hostname: %s\n", net_ctx->hostname);
    printf("Server: %s\n", net_ctx->server);

    // Initialize CA before starting network threads
    ca_context_t* ca_ctx;
    if (init_certificate_authority(net_ctx, &ca_ctx) != 0) {
        fprintf(stderr, "Failed to initialize certificate authority\n");
        cleanup_network_context_components(net_ctx);
        free((void*)net_ctx->mode);
        free((void*)net_ctx->hostname);
        free((void*)net_ctx->server);
        free(net_ctx);
        return 1;
    }

    printf("Initializing node\n");
    int status = init_node(net_ctx, ca_ctx, NEXUS_SERVER_PORT, NEXUS_CLIENT_PORT, &node);
    if (status != 0) {
        fprintf(stderr, "Failed to initialize node\n");
        // Cleanup components before exiting
        cleanup_certificate_authority(ca_ctx);
        cleanup_network_context_components(net_ctx);
        free((void*)net_ctx->mode);
        free((void*)net_ctx->hostname);
        free((void*)net_ctx->server);
        free(net_ctx);
        return 1;
    }

    // If --register-tld was passed, and we are in a mode that connects to a server
    if (tld_to_register && 
        (strcmp(net_ctx->mode, "private") == 0 || strcmp(net_ctx->mode, "federated") == 0) && 
        strcmp(net_ctx->hostname, net_ctx->server) != 0) {
        
        dlog("Main: Attempting to register TLD '%s'. Waiting for client connection...", tld_to_register);
        
        int connection_wait_attempts = 0;
        const int max_connection_wait_attempts = 10; // Wait for up to 10 seconds (10 * 1s)
        int client_ready = 0;

        while (connection_wait_attempts < max_connection_wait_attempts) {
            if (node && node->client_config.conn && ngtcp2_conn_get_handshake_completed(node->client_config.conn)) {
                dlog("Main: Client connection handshake completed.");
                client_ready = 1;
                break;
            }
            dlog("Main: Client not yet connected or handshake incomplete, attempt %d/%d. Waiting 1 second...", 
                 connection_wait_attempts + 1, max_connection_wait_attempts);
            sleep(1);
            connection_wait_attempts++;
        }

        if (client_ready) {
            dlog("Main: Proceeding with TLD registration for '%s'...", tld_to_register);
            int64_t stream_id = nexus_client_send_tld_register_request(&node->client_config, tld_to_register);
            if (stream_id < 0) {
                fprintf(stderr, "Main: Failed to send TLD registration request for '%s'. Error code: %" PRId64 "\n", tld_to_register, stream_id);
            } else {
                printf("Main: TLD registration request for '%s' sent on stream %" PRId64 ". Check logs for response.\n", tld_to_register, stream_id);
            }
        } else {
            fprintf(stderr, "Main: Client connection timeout or error after %d attempts. Cannot register TLD '%s'.\n", 
                    max_connection_wait_attempts, tld_to_register);
            fprintf(stderr, "Main: Ensure the --server option points to a running NEXUS server and client can connect.\n");
        }
    }

    printf("Node running. Press Ctrl+C to stop.\n");

    // Keep main thread running until signal received
    while (global_running) {
        sleep(1);
    }

    printf("\nShutting down...\n");
    
    // Clean up
    cleanup_node(node);
    cleanup_network_context_components(net_ctx);
    cleanup_certificate_authority(ca_ctx);
    
    free((void*)net_ctx->mode);
    free((void*)net_ctx->hostname);
    free((void*)net_ctx->server);
    free(net_ctx);
    
    // Clean up config manager if it was initialized
    cleanup_config_manager();

    return 0;
}

