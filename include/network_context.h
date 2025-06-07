#ifndef NETWORK_CONTEXT_H
#define NETWORK_CONTEXT_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include "dns_types.h"
#include "tld_manager.h"
#include "dns_resolver.h"

// Forward declarations to avoid circular dependencies
typedef struct nexus_cert_s nexus_cert_t;
typedef struct ca_context_s ca_context_t;

// Main network context structure
typedef struct {
    int mode;                   // Network mode (e.g., private, public, federated)
    char* hostname;             // Hostname of the local node
    char* ip_address;           // IP address of the local node
    int server_port;            // Port for the server to listen on
    int client_port;            // Port for the client to connect from
    nexus_cert_t* certificate;  // Node's certificate
    tld_manager_t *tld_manager; // TLD manager
    dns_resolver_t *dns_resolver; // DNS resolver
    ca_context_t *ca_ctx;       // Certificate authority context
    pthread_mutex_t lock;       // Lock for the context
    dns_cache_t *dns_cache;     // DNS cache
} network_context_t;

// Function to initialize the network context
int init_network_context(network_context_t **out_ctx, int mode, const char *hostname);

// Function to clean up the network context
void cleanup_network_context(network_context_t *ctx);

// Function to initialize network context components
int init_network_context_components(network_context_t* net_ctx);

// Function to cleanup network context components
void cleanup_network_context_components(network_context_t* net_ctx);

#endif // NETWORK_CONTEXT_H