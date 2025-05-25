#ifndef NEXUS_NODE_H
#define NEXUS_NODE_H

#include <stdint.h>
#include <pthread.h>
#include "nexus_client.h"
#include "nexus_server.h"
#include "certificate_authority.h"
#include "network_context.h"

// Node structure
typedef struct {
    nexus_client_config_t client_config;
    nexus_server_config_t server_config;
    network_context_t *net_ctx;      // Reference to network context
    pthread_t server_thread;         // Server thread
    pthread_t client_thread;         // Client thread
    int running;                     // Flag to control thread execution
    int server_connected;            // Flag to track server connection status
    int client_connected;            // Flag to track client connection status
} nexus_node_t;

// Initialize node
int init_node(network_context_t *net_ctx, ca_context_t *ca_ctx, 
              uint16_t server_port, uint16_t client_port, 
              nexus_node_t **node);

// Clean up node
void cleanup_node(nexus_node_t *node);

// Thread function declarations
void* server_thread_func(void* arg);
void* client_thread_func(void* arg);

#endif // NEXUS_NODE_H