#include "../include/network_context.h"
#include "../include/debug.h"
#include "../include/tld_manager.h" // For init_tld_manager and cleanup_tld_manager
#include "../include/certificate_authority.h" // For cleanup_certificate_authority
#include <string.h>
#include <stdlib.h> // For malloc, free
#include <stdio.h>  // For fprintf, stderr

// Initialize network context
int init_network_context(network_context_t **out_ctx, int mode, const char *hostname) {
    if (!out_ctx || !hostname) {
        return -1;
    }
    
    network_context_t *ctx = (network_context_t*)malloc(sizeof(network_context_t));
    if (!ctx) {
        return -1;
    }
    
    memset(ctx, 0, sizeof(network_context_t));
    
    // Initialize basic fields
    ctx->mode = mode;
    ctx->hostname = strdup(hostname);
    if (!ctx->hostname) {
        free(ctx);
        return -1;
    }
    
    // Initialize components
    if (init_network_context_components(ctx) != 0) {
        free(ctx->hostname);
        free(ctx);
        return -1;
    }
    
    *out_ctx = ctx;
    return 0;
}

// Cleanup network context
void cleanup_network_context(network_context_t *ctx) {
    if (!ctx) {
        return;
    }
    
    // First cleanup components
    cleanup_network_context_components(ctx);
    
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
        // TODO: Iterate through dns_cache->head and free all dns_cache_node_t and their contents
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