#ifndef NETWORK_CONTEXT_H
#define NETWORK_CONTEXT_H

#include <pthread.h>
#include <stdint.h>
#include "tld_manager.h"
#include "dns_types.h"
#include "dns_resolver.h"

// Forward declarations to avoid circular dependencies
struct tld_manager_s;
struct dns_resolver_s;
typedef struct nexus_cert nexus_cert_t;

// Main network context structure
typedef struct {
    char* hostname;           // Hostname for this node
    char* ip_address;         // Primary IP address for this node
    uint16_t server_port;     // Port to bind to for server mode
    uint16_t client_port;     // Port to bind to for client mode
    int mode;                 // Network mode (private, public, federated)
    dns_cache_t *dns_cache;   // DNS cache
    tld_manager_t *tld_manager; // TLD manager
    dns_resolver_t *dns_resolver; // DNS resolver
    pthread_mutex_t lock;     // Lock for the context
} network_context_t;

// Initialize a network context
int init_network_context(network_context_t **ctx, int mode, const char *hostname);

// Initialize network context components (internal)
int init_network_context_components(network_context_t* net_ctx);

// Clean up a network context and free resources
void cleanup_network_context(network_context_t *ctx);

// Clean up network context components (internal)
void cleanup_network_context_components(network_context_t* net_ctx);

// Check connection status
void check_connection_status(network_context_t *net_ctx);

// Configure a network context
int configure_network_context(network_context_t *ctx, const char *hostname, 
                             const char *ip_address, uint16_t server_port,
                             uint16_t client_port, int mode);

#endif /* NETWORK_CONTEXT_H */