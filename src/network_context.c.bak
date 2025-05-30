#include "network_context.h"
#include "debug.h"
#include "tld_manager.h" // For init_tld_manager and cleanup_tld_manager
#include <string.h>
#include <stdlib.h> // For malloc, free
#include <stdio.h>  // For fprintf, stderr

// Add connection status check
void check_connection_status(network_context_t *net_ctx) {
    dlog("Starting connection check...");
    
    // Print basic node info
    dlog("Node Status:");
    dlog("Mode: %s", net_ctx->mode);
    dlog("Hostname: %s", net_ctx->hostname);
    dlog("Server: %s", net_ctx->server);
    
    // Add connection test
    if (strcmp(net_ctx->mode, "private") == 0) {
        dlog("Private mode - listening for incoming connections");
    } else if (strcmp(net_ctx->mode, "public") == 0) {
        dlog("Public mode - attempting to connect to known peers");
    } else if (strcmp(net_ctx->mode, "federated") == 0) {
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

    net_ctx->peer_list = NULL; // Explicitly NULL, to be managed elsewhere or later
    net_ctx->active_requests = NULL; // Explicitly NULL, to be managed elsewhere or later

    return 0;
}

void cleanup_network_context_components(network_context_t* net_ctx) {
    if (!net_ctx) return;

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

    // TODO: Cleanup peer_list, tld_manager, active_requests if they were allocated
}