#ifndef NETWORK_CONTEXT_H
#define NETWORK_CONTEXT_H

#include <pthread.h>
#include <stdint.h>
#include "dns_types.h"

// Forward declarations
typedef struct nexus_cert nexus_cert_t;

// Network context
typedef struct {
    const char *mode;         // Operating mode (public, private, federated)
    const char *hostname;     // Node hostname
    const char *server;       // Server hostname
    void *peer_list;          // List of connected peers
    dns_cache_t *dns_cache;   // DNS cache
    tld_manager_t *tld_manager; // TLD manager
    void *active_requests;    // Active DNS requests
    pthread_mutex_t lock;     // Lock for thread safety
} network_context_t;

// Initialize network context components
int init_network_context_components(network_context_t *net_ctx);

// Clean up network context components
void cleanup_network_context_components(network_context_t *net_ctx);

#endif // NETWORK_CONTEXT_H