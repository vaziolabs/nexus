#include "../include/config_manager.h"
#include "../include/debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>
#include <uuid/uuid.h>

// Static variables
static nexus_config_t *global_config = NULL;

// Initialize the configuration manager
int init_config_manager(void) {
    dlog("Initializing configuration manager");
    
    // Ensure config directories exist
    if (ensure_config_dirs() != 0) {
        fprintf(stderr, "Failed to create configuration directories\n");
        return -1;
    }
    
    // Get config path
    char *config_path = NULL;
    char *user_config_dir = get_user_config_dir();
    if (user_config_dir) {
        size_t path_len = strlen(user_config_dir) + strlen("/") + strlen(NEXUS_DEFAULT_CONFIG) + 1;
        config_path = malloc(path_len);
        if (config_path) {
            snprintf(config_path, path_len, "%s/%s", user_config_dir, NEXUS_DEFAULT_CONFIG);
        }
        free(user_config_dir);
    }
    
    if (!config_path) {
        fprintf(stderr, "Failed to determine configuration path\n");
        return -1;
    }
    
    // Check if config file exists
    if (access(config_path, F_OK) != 0) {
        // Create default configuration
        dlog("No configuration found, creating default");
        global_config = create_default_config();
        if (!global_config) {
            fprintf(stderr, "Failed to create default configuration\n");
            free(config_path);
            return -1;
        }
        
        // Save default configuration
        if (save_config(global_config, config_path) != 0) {
            fprintf(stderr, "Failed to save default configuration to %s\n", config_path);
            free_config(global_config);
            global_config = NULL;
            free(config_path);
            return -1;
        }
    } else {
        // Load existing configuration
        dlog("Loading configuration from %s", config_path);
        global_config = load_config(config_path);
        if (!global_config) {
            fprintf(stderr, "Failed to load configuration from %s\n", config_path);
            free(config_path);
            return -1;
        }
    }
    
    free(config_path);
    return 0;
}

// Clean up the configuration manager
void cleanup_config_manager(void) {
    if (global_config) {
        free_config(global_config);
        global_config = NULL;
    }
}

// Create default configuration
nexus_config_t* create_default_config(void) {
    nexus_config_t *config = malloc(sizeof(nexus_config_t));
    if (!config) {
        return NULL;
    }
    
    memset(config, 0, sizeof(nexus_config_t));
    
    // Generate unique node ID
    uuid_t uuid;
    uuid_generate(uuid);
    char *node_id = malloc(37); // UUID string format: 8-4-4-4-12 + null terminator
    if (!node_id) {
        free(config);
        return NULL;
    }
    uuid_unparse_lower(uuid, node_id);
    config->node_id = node_id;
    
    // Set default values
    config->default_profile = strdup("default");
    config->auto_detect_network = 1;
    config->run_as_service = 0;
    config->log_level = 1; // INFO
    config->log_file = strdup("/var/log/nexus.log");
    
    // Initialize profiles array
    config->max_profiles = 10;
    config->profile_count = 0;
    config->profiles = malloc(config->max_profiles * sizeof(network_profile_t*));
    if (!config->profiles) {
        free(config->node_id);
        free(config->default_profile);
        free(config->log_file);
        free(config);
        return NULL;
    }
    
    // Create default profile
    network_profile_t *default_profile = create_profile("default", "private");
    if (!default_profile) {
        free(config->node_id);
        free(config->default_profile);
        free(config->log_file);
        free(config->profiles);
        free(config);
        return NULL;
    }
    
    // Add default profile
    if (add_profile(config, default_profile) != 0) {
        free_network_profile(default_profile);
        free(config->node_id);
        free(config->default_profile);
        free(config->log_file);
        free(config->profiles);
        free(config);
        return NULL;
    }
    
    // Initialize mutex
    if (pthread_mutex_init(&config->lock, NULL) != 0) {
        for (int i = 0; i < config->profile_count; i++) {
            free_network_profile(config->profiles[i]);
        }
        free(config->node_id);
        free(config->default_profile);
        free(config->log_file);
        free(config->profiles);
        free(config);
        return NULL;
    }
    
    return config;
}

// Load configuration from file
nexus_config_t* load_config(const char *path) {
    // This is a stub implementation for now
    // In a real implementation, this would parse a JSON or similar format
    dlog("Loading configuration from %s (stub implementation)", path);
    
    // For now, just create a default config
    // This will be replaced with actual file parsing
    return create_default_config();
}

// Save configuration to file
int save_config(const nexus_config_t *config, const char *path) {
    // This is a stub implementation for now
    // In a real implementation, this would serialize to JSON or similar format
    dlog("Saving configuration to %s (stub implementation)", path);
    
    // For now, just create an empty file to indicate success
    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "Failed to open %s for writing: %s\n", path, strerror(errno));
        return -1;
    }
    
    // Write a placeholder JSON structure
    fprintf(f, "{\n");
    fprintf(f, "  \"node_id\": \"%s\",\n", config->node_id);
    fprintf(f, "  \"default_profile\": \"%s\",\n", config->default_profile);
    fprintf(f, "  \"auto_detect_network\": %d,\n", config->auto_detect_network);
    fprintf(f, "  \"run_as_service\": %d,\n", config->run_as_service);
    fprintf(f, "  \"log_level\": %d,\n", config->log_level);
    fprintf(f, "  \"log_file\": \"%s\",\n", config->log_file);
    fprintf(f, "  \"profiles\": [\n");
    
    // Write profiles
    for (int i = 0; i < config->profile_count; i++) {
        network_profile_t *profile = config->profiles[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", profile->name);
        fprintf(f, "      \"mode\": \"%s\",\n", profile->mode);
        fprintf(f, "      \"hostname\": \"%s\",\n", profile->hostname);
        fprintf(f, "      \"server\": \"%s\"\n", profile->server);
        fprintf(f, "    }%s\n", (i < config->profile_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    return 0;
}

// Create a new network profile
network_profile_t* create_profile(const char *name, const char *mode) {
    if (!name || !mode) {
        return NULL;
    }
    
    network_profile_t *profile = malloc(sizeof(network_profile_t));
    if (!profile) {
        return NULL;
    }
    
    memset(profile, 0, sizeof(network_profile_t));
    
    // Set required fields
    profile->name = strdup(name);
    profile->mode = strdup(mode);
    profile->hostname = strdup("localhost");
    profile->server = strdup("localhost");
    profile->server_port = 10053;
    profile->client_port = 10443;
    
    // Set default values for optional fields
    profile->ipv6_prefix = strdup("fd00::");
    profile->ipv6_prefix_length = 64;
    profile->max_tunnels = 100;
    profile->auto_connect = 1;
    profile->enable_nat_traversal = 1;
    profile->enable_relay = 0;
    profile->enable_ct = 1;
    
    // Detect network settings if possible
    detect_network_settings(profile);
    
    return profile;
}

// Add a profile to the configuration
int add_profile(nexus_config_t *config, network_profile_t *profile) {
    if (!config || !profile) {
        return -1;
    }
    
    pthread_mutex_lock(&config->lock);
    
    // Check if we need to resize the profiles array
    if (config->profile_count >= config->max_profiles) {
        int new_max = config->max_profiles * 2;
        network_profile_t **new_profiles = realloc(config->profiles, 
                                                   new_max * sizeof(network_profile_t*));
        if (!new_profiles) {
            pthread_mutex_unlock(&config->lock);
            return -1;
        }
        
        config->profiles = new_profiles;
        config->max_profiles = new_max;
    }
    
    // Add the profile
    config->profiles[config->profile_count++] = profile;
    
    pthread_mutex_unlock(&config->lock);
    return 0;
}

// Remove a profile from the configuration
int remove_profile(nexus_config_t *config, const char *profile_name) {
    if (!config || !profile_name) {
        return -1;
    }
    
    pthread_mutex_lock(&config->lock);
    
    // Find the profile
    int found_idx = -1;
    for (int i = 0; i < config->profile_count; i++) {
        if (strcmp(config->profiles[i]->name, profile_name) == 0) {
            found_idx = i;
            break;
        }
    }
    
    if (found_idx < 0) {
        pthread_mutex_unlock(&config->lock);
        return -1;
    }
    
    // Free the profile
    free_network_profile(config->profiles[found_idx]);
    
    // Shift remaining profiles
    for (int i = found_idx; i < config->profile_count - 1; i++) {
        config->profiles[i] = config->profiles[i + 1];
    }
    
    config->profile_count--;
    
    pthread_mutex_unlock(&config->lock);
    return 0;
}

// Get a profile by name
network_profile_t* get_profile(nexus_config_t *config, const char *profile_name) {
    if (!config || !profile_name) {
        return NULL;
    }
    
    pthread_mutex_lock(&config->lock);
    
    network_profile_t *profile = NULL;
    for (int i = 0; i < config->profile_count; i++) {
        if (strcmp(config->profiles[i]->name, profile_name) == 0) {
            profile = config->profiles[i];
            break;
        }
    }
    
    pthread_mutex_unlock(&config->lock);
    return profile;
}

// Detect network settings
int detect_network_settings(network_profile_t *profile) {
    if (!profile) {
        return -1;
    }
    
    dlog("Detecting network settings for profile %s", profile->name);
    
    // In a real implementation, this would detect various network settings
    // For now, just set some reasonable defaults if they're not already set
    
    // Detect IPv6 settings
    detect_ipv6_settings(profile);
    
    return 0;
}

// Detect IPv6 settings
int detect_ipv6_settings(network_profile_t *profile) {
    if (!profile) {
        return -1;
    }
    
    dlog("Detecting IPv6 settings for profile %s", profile->name);
    
    // In a real implementation, this would detect IPv6 network configuration
    // For now, just ensure we have some reasonable defaults
    
    // If ipv6_prefix is not set, use a ULA prefix
    if (!profile->ipv6_prefix) {
        profile->ipv6_prefix = strdup("fd00::");
    }
    
    // If prefix length is not set, use 64
    if (profile->ipv6_prefix_length <= 0) {
        profile->ipv6_prefix_length = 64;
    }
    
    return 0;
}

// Detect NAT type
int detect_nat_type(void) {
    dlog("Detecting NAT type (stub implementation)");
    
    // In a real implementation, this would perform STUN/TURN checks
    // For now, just return 0 (unknown NAT)
    return 0;
}

// Create network context from profile
int create_network_context_from_profile(network_profile_t *profile, network_context_t **net_ctx) {
    if (!profile || !net_ctx) {
        return -1;
    }
    
    dlog("Creating network context from profile %s", profile->name);
    
    // Allocate network context
    *net_ctx = malloc(sizeof(network_context_t));
    if (!*net_ctx) {
        return -1;
    }
    
    memset(*net_ctx, 0, sizeof(network_context_t));
    
    // Set values from profile
    (*net_ctx)->mode = strdup(profile->mode);
    (*net_ctx)->hostname = strdup(profile->hostname);
    (*net_ctx)->server = strdup(profile->server);
    
    // Initialize components
    if (init_network_context_components(*net_ctx) != 0) {
        free((void*)(*net_ctx)->mode);
        free((void*)(*net_ctx)->hostname);
        free((void*)(*net_ctx)->server);
        free(*net_ctx);
        *net_ctx = NULL;
        return -1;
    }
    
    return 0;
}

// Update network context from profile
int update_network_context_from_profile(network_context_t *net_ctx, network_profile_t *profile) {
    if (!net_ctx || !profile) {
        return -1;
    }
    
    dlog("Updating network context from profile %s", profile->name);
    
    // Update values from profile
    // Note: This is simplistic and doesn't handle memory management correctly
    // In a real implementation, we would need to free the old strings and allocate new ones
    net_ctx->mode = strdup(profile->mode);
    net_ctx->hostname = strdup(profile->hostname);
    net_ctx->server = strdup(profile->server);
    
    return 0;
}

// Get the system-wide configuration directory
char* get_config_dir(void) {
    return strdup(NEXUS_CONFIG_DIR);
}

// Get the user-specific configuration directory
char* get_user_config_dir(void) {
    // Get user's home directory
    const char *home_dir = getenv("HOME");
    if (!home_dir) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) {
            home_dir = pw->pw_dir;
        }
    }
    
    if (!home_dir) {
        return NULL;
    }
    
    // Replace ~ with home directory in NEXUS_USER_CONFIG_DIR
    const char *user_config_template = NEXUS_USER_CONFIG_DIR;
    if (user_config_template[0] == '~') {
        size_t home_len = strlen(home_dir);
        size_t template_len = strlen(user_config_template);
        size_t result_len = home_len + template_len; // -1 for ~ +1 for null terminator
        
        char *result = malloc(result_len);
        if (!result) {
            return NULL;
        }
        
        strcpy(result, home_dir);
        strcat(result, user_config_template + 1); // Skip the ~
        
        return result;
    } else {
        return strdup(user_config_template);
    }
}

// Ensure configuration directories exist
int ensure_config_dirs(void) {
    // Create user config directory
    char *user_config_dir = get_user_config_dir();
    if (!user_config_dir) {
        return -1;
    }
    
    // Create directory and parents if they don't exist
    char *path = strdup(user_config_dir);
    if (!path) {
        free(user_config_dir);
        return -1;
    }
    
    for (char *p = path + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(path, 0755) != 0 && errno != EEXIST) {
                fprintf(stderr, "Failed to create directory %s: %s\n", path, strerror(errno));
                free(path);
                free(user_config_dir);
                return -1;
            }
            *p = '/';
        }
    }
    
    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Failed to create directory %s: %s\n", path, strerror(errno));
        free(path);
        free(user_config_dir);
        return -1;
    }
    
    free(path);
    
    // Create profiles directory
    size_t profiles_path_len = strlen(user_config_dir) + strlen("/") + strlen(NEXUS_PROFILES_DIR) + 1;
    char *profiles_path = malloc(profiles_path_len);
    if (!profiles_path) {
        free(user_config_dir);
        return -1;
    }
    
    snprintf(profiles_path, profiles_path_len, "%s/%s", user_config_dir, NEXUS_PROFILES_DIR);
    
    if (mkdir(profiles_path, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Failed to create directory %s: %s\n", profiles_path, strerror(errno));
        free(profiles_path);
        free(user_config_dir);
        return -1;
    }
    
    free(profiles_path);
    free(user_config_dir);
    
    return 0;
}

// Free a network profile
void free_network_profile(network_profile_t *profile) {
    if (!profile) {
        return;
    }
    
    free(profile->name);
    free(profile->mode);
    free(profile->hostname);
    free(profile->server);
    free(profile->ipv6_prefix);
    free(profile->ca_cert_path);
    free(profile->cert_path);
    free(profile->private_key_path);
    free(profile->ct_log_path);
    free(profile->tld_list_path);
    
    free(profile);
}

// Free a configuration
void free_config(nexus_config_t *config) {
    if (!config) {
        return;
    }
    
    pthread_mutex_lock(&config->lock);
    
    free(config->node_id);
    free(config->default_profile);
    free(config->log_file);
    
    for (int i = 0; i < config->profile_count; i++) {
        free_network_profile(config->profiles[i]);
    }
    
    free(config->profiles);
    
    pthread_mutex_unlock(&config->lock);
    pthread_mutex_destroy(&config->lock);
    
    free(config);
} 