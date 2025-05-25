#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <stdint.h>
#include <pthread.h>
#include "network_context.h"

// Configuration file paths
#define NEXUS_CONFIG_DIR        "/etc/nexus"
#define NEXUS_USER_CONFIG_DIR   "~/.config/nexus"
#define NEXUS_DEFAULT_CONFIG    "config.json"
#define NEXUS_PROFILES_DIR      "profiles"

// Network profile structure
typedef struct {
    char *name;                // Profile name
    char *mode;                // Operating mode (public, private, federated)
    char *hostname;            // Node hostname for this network
    char *server;              // Server hostname for this network
    int server_port;           // Server port
    int client_port;           // Client port
    char *ipv6_prefix;         // IPv6 prefix for tunnel allocation
    int ipv6_prefix_length;    // IPv6 prefix length
    int max_tunnels;           // Maximum number of tunnels
    char *ca_cert_path;        // Path to CA certificate
    char *cert_path;           // Path to node certificate
    char *private_key_path;    // Path to private key
    int auto_connect;          // Auto-connect on startup
    int enable_nat_traversal;  // Enable NAT traversal
    int enable_relay;          // Enable relay for symmetric NAT
    int enable_ct;             // Enable Certificate Transparency
    char *ct_log_path;         // Path to CT log
    char *tld_list_path;       // Path to TLD list
} network_profile_t;

// Configuration structure
typedef struct {
    char *node_id;             // Unique node identifier
    char *default_profile;     // Default profile name
    int auto_detect_network;   // Auto-detect network settings
    int run_as_service;        // Run as a service
    int log_level;             // Logging level
    char *log_file;            // Log file path
    network_profile_t **profiles; // Array of network profiles
    int profile_count;         // Number of profiles
    int max_profiles;          // Maximum number of profiles
    pthread_mutex_t lock;      // Lock for thread safety
} nexus_config_t;

// Function declarations
int init_config_manager(void);
void cleanup_config_manager(void);

// Configuration file operations
nexus_config_t* create_default_config(void);
nexus_config_t* load_config(const char *path);
int save_config(const nexus_config_t *config, const char *path);

// Profile management
network_profile_t* create_profile(const char *name, const char *mode);
int add_profile(nexus_config_t *config, network_profile_t *profile);
int remove_profile(nexus_config_t *config, const char *profile_name);
network_profile_t* get_profile(nexus_config_t *config, const char *profile_name);

// Network detection
int detect_network_settings(network_profile_t *profile);
int detect_ipv6_settings(network_profile_t *profile);
int detect_nat_type(void);

// Multi-network context management
int create_network_context_from_profile(network_profile_t *profile, network_context_t **net_ctx);
int update_network_context_from_profile(network_context_t *net_ctx, network_profile_t *profile);

// Utility functions
char* get_config_dir(void);
char* get_user_config_dir(void);
int ensure_config_dirs(void);
void free_network_profile(network_profile_t *profile);
void free_config(nexus_config_t *config);

#endif // CONFIG_MANAGER_H 