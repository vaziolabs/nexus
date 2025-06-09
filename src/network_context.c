#include "../include/network_context.h"
#include "../include/debug.h"
#include "../include/tld_manager.h" // For init_tld_manager and cleanup_tld_manager
#include "../include/certificate_authority.h" // For cleanup_certificate_authority
#include <string.h>
#include <stdlib.h> // For malloc, free
#include <stdio.h>  // For fprintf, stderr

// Enhanced error handling for network context initialization
static int validate_network_context(network_context_t* ctx) {
    if (!ctx) {
        dlog("ERROR: Network context is NULL");
        return -1;
    }
    
    if (!ctx->hostname || strlen(ctx->hostname) == 0) {
        dlog("ERROR: Network context hostname is invalid");
        return -1;
    }
    
    if (ctx->mode < 0 || ctx->mode > 2) {
        dlog("ERROR: Network context mode %d is invalid (must be 0-2)", ctx->mode);
        return -1;
    }
    
    dlog("Network context validation passed: mode=%d, hostname=%s", ctx->mode, ctx->hostname);
    return 0;
}

// Enhanced component initialization with rollback on failure
static int init_network_context_components_safe(network_context_t* net_ctx) {
    if (!net_ctx) return -1;
    
    dlog("Initializing network context components safely");
    
    // Initialize mutex first
    if (pthread_mutex_init(&net_ctx->lock, NULL) != 0) {
        dlog("ERROR: Failed to initialize network context mutex");
        return -1;
    }
    
    // Initialize DNS Cache with error handling
    net_ctx->dns_cache = malloc(sizeof(dns_cache_t));
    if (!net_ctx->dns_cache) {
        dlog("ERROR: Failed to allocate DNS cache");
        pthread_mutex_destroy(&net_ctx->lock);
        return -1;
    }
    
    memset(net_ctx->dns_cache, 0, sizeof(dns_cache_t));
    net_ctx->dns_cache->head = NULL;
    net_ctx->dns_cache->count = 0;
    net_ctx->dns_cache->max_size = 1000;
    
    if (pthread_mutex_init(&net_ctx->dns_cache->lock, NULL) != 0) {
        dlog("ERROR: Failed to initialize DNS cache mutex");
        free(net_ctx->dns_cache);
        net_ctx->dns_cache = NULL;
        pthread_mutex_destroy(&net_ctx->lock);
        return -1;
    }
    
    // Initialize TLD Manager with error handling
    if (init_tld_manager(&net_ctx->tld_manager) != 0) {
        dlog("ERROR: Failed to initialize TLD manager");
        pthread_mutex_destroy(&net_ctx->dns_cache->lock);
        free(net_ctx->dns_cache);
        net_ctx->dns_cache = NULL;
        pthread_mutex_destroy(&net_ctx->lock);
        return -1;
    }
    
    dlog("Network context components initialized successfully");
    return 0;
}

// Enhanced cleanup with safety checks
static void cleanup_network_context_components_safe(network_context_t* net_ctx) {
    if (!net_ctx) {
        dlog("WARNING: Attempted to cleanup NULL network context");
        return;
    }
    
    dlog("Safely cleaning up network context components");
    
    // Cleanup Certificate Authority with safety check
    if (net_ctx->ca_ctx) {
        dlog("Cleaning up certificate authority");
        cleanup_certificate_authority(net_ctx->ca_ctx);
        net_ctx->ca_ctx = NULL;
    }
    
    // Cleanup TLD Manager with safety check
    if (net_ctx->tld_manager) {
        dlog("Cleaning up TLD manager");
        cleanup_tld_manager(net_ctx->tld_manager);
        net_ctx->tld_manager = NULL;
    }
    
    // Cleanup DNS Cache with safety checks
    if (net_ctx->dns_cache) {
        dlog("Cleaning up DNS cache");
        
        // Safely destroy mutex if it was initialized
        int mutex_destroy_result = pthread_mutex_destroy(&net_ctx->dns_cache->lock);
        if (mutex_destroy_result != 0) {
            dlog("WARNING: Failed to destroy DNS cache mutex (error %d)", mutex_destroy_result);
        }
        
        // Safely clean up cache entries
        dns_cache_node_t* current = net_ctx->dns_cache->head;
        int cleaned_entries = 0;
        
        while (current != NULL) {
            dns_cache_node_t* next_node = current->next;
            
            // Safely free entry components
            if (current->entry.fqdn) free(current->entry.fqdn);
            if (current->entry.record.name) free(current->entry.record.name);
            if (current->entry.record.rdata) free(current->entry.record.rdata);
            free(current);
            
            current = next_node;
            cleaned_entries++;
        }
        
        dlog("Cleaned up %d DNS cache entries", cleaned_entries);
        
        free(net_ctx->dns_cache);
        net_ctx->dns_cache = NULL;
    }
    
    // Safely destroy the main network context mutex
    int main_mutex_result = pthread_mutex_destroy(&net_ctx->lock);
    if (main_mutex_result != 0) {
        dlog("WARNING: Failed to destroy main network context mutex (error %d)", main_mutex_result);
    }
    
    dlog("Network context components cleanup completed");
}

// Initialize network context
int init_network_context(network_context_t **out_ctx, int mode, const char *hostname) {
    if (!out_ctx || !hostname) {
        dlog("ERROR: Invalid parameters for network context initialization");
        return -1;
    }
    
    dlog("Initializing network context: mode=%d, hostname=%s", mode, hostname);
    
    network_context_t *ctx = (network_context_t*)malloc(sizeof(network_context_t));
    if (!ctx) {
        dlog("ERROR: Failed to allocate memory for network context");
        return -1;
    }
    
    memset(ctx, 0, sizeof(network_context_t));
    
    // Initialize basic fields
    ctx->mode = mode;
    ctx->hostname = strdup(hostname);
    if (!ctx->hostname) {
        dlog("ERROR: Failed to duplicate hostname string");
        free(ctx);
        return -1;
    }
    
    // Validate the context before proceeding
    if (validate_network_context(ctx) != 0) {
        dlog("ERROR: Network context validation failed");
        free(ctx->hostname);
        free(ctx);
        return -1;
    }
    
    // Initialize components with enhanced error handling
    if (init_network_context_components_safe(ctx) != 0) {
        dlog("ERROR: Failed to initialize network context components");
        free(ctx->hostname);
        free(ctx);
        return -1;
    }
    
    *out_ctx = ctx;
    dlog("Network context initialized successfully");
    return 0;
}

// Cleanup network context
void cleanup_network_context(network_context_t *ctx) {
    if (!ctx) {
        return;
    }
    
    // First cleanup components
    cleanup_network_context_components_safe(ctx);
    
    // Then free allocated strings
    free(ctx->hostname);
    
    // Finally free the context itself
    free(ctx);
}

// Add connection status check
void check_connection_status(network_context_t *net_ctx) {
    dlog("Starting connection check...");
    
    // Print basic node info
    dlog("Node Status:");
    dlog("Mode: %d", net_ctx->mode);
    dlog("Hostname: %s", net_ctx->hostname);
    
    // Add connection test
    if (net_ctx->mode == 0) { // Private mode
        dlog("Private mode - listening for incoming connections");
    } else if (net_ctx->mode == 1) { // Public mode
        dlog("Public mode - attempting to connect to known peers");
    } else if (net_ctx->mode == 2) { // Federated mode
        dlog("Federated mode - connecting to federation network");
    }
}

int init_network_context_components(network_context_t* net_ctx) {
    if (!net_ctx) return -1;

    if (pthread_mutex_init(&net_ctx->lock, NULL) != 0) {
        fprintf(stderr, "Failed to initialize network context mutex\n");
        return -1;
    }

    // Initialize DNS Cache
    net_ctx->dns_cache = malloc(sizeof(dns_cache_t));
    if (!net_ctx->dns_cache) {
        fprintf(stderr, "Failed to allocate DNS cache\n");
        pthread_mutex_destroy(&net_ctx->lock);
        return -1;
    }
    memset(net_ctx->dns_cache, 0, sizeof(dns_cache_t));
    net_ctx->dns_cache->head = NULL;
    net_ctx->dns_cache->count = 0;
    net_ctx->dns_cache->max_size = 1000; // Default max size, can be configurable
    if (pthread_mutex_init(&net_ctx->dns_cache->lock, NULL) != 0) {
        fprintf(stderr, "Failed to initialize DNS cache mutex\n");
        free(net_ctx->dns_cache);
        pthread_mutex_destroy(&net_ctx->lock);
        return -1;
    }

    // Initialize TLD Manager
    if (init_tld_manager(&net_ctx->tld_manager) != 0) {
        fprintf(stderr, "Failed to initialize TLD manager\n");
        // Cleanup previously initialized components
        pthread_mutex_destroy(&net_ctx->dns_cache->lock);
        free(net_ctx->dns_cache);
        pthread_mutex_destroy(&net_ctx->lock);
        return -1;
    }

    return 0;
}

void cleanup_network_context_components(network_context_t* net_ctx) {
    if (!net_ctx) return;

    // Cleanup Certificate Authority
    if (net_ctx->ca_ctx) {
        cleanup_certificate_authority(net_ctx->ca_ctx);
        net_ctx->ca_ctx = NULL;
    }

    // Cleanup TLD Manager
    if (net_ctx->tld_manager) {
        cleanup_tld_manager(net_ctx->tld_manager);
        net_ctx->tld_manager = NULL;
    }

    // Cleanup DNS Cache
    if (net_ctx->dns_cache) {
        pthread_mutex_destroy(&net_ctx->dns_cache->lock);
        // Iterate through dns_cache->head and free all dns_cache_node_t and their contents
        dns_cache_node_t* current = net_ctx->dns_cache->head;
        dns_cache_node_t* next_node;
        while (current != NULL) {
            next_node = current->next;
            free(current->entry.fqdn);
            free(current->entry.record.name);
            free(current->entry.record.rdata);
            free(current);
            current = next_node;
        }
        free(net_ctx->dns_cache);
        net_ctx->dns_cache = NULL;
    }

    // Destroy the main network context mutex
    pthread_mutex_destroy(&net_ctx->lock);
}