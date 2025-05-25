#include "nexus_node.h"
#include "nexus_server.h"
#include "nexus_client.h"
#include "network_context.h"
#include "certificate_authority.h"
#include "debug.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>  // For bool type
#include <stdlib.h>   // For malloc


int init_node(network_context_t *net_ctx, ca_context_t *ca_ctx, 
             uint16_t server_port, uint16_t client_port, nexus_node_t **out_node) {
    dlog("Starting node initialization");
    
    // Allocate node structure on heap so it persists
    nexus_node_t *node = malloc(sizeof(nexus_node_t));
    if (!node) {
        fprintf(stderr, "Failed to allocate node structure\n");
        return 1;
    }

    dlog("Node structure allocated");

    // Initialize node structure with only the fields defined in the header
    node->server_config.bind_address = net_ctx->hostname;
    node->server_config.port = server_port;
    node->server_config.net_ctx = net_ctx;
    
    node->client_config.bind_address = net_ctx->hostname;
    node->client_config.port = client_port;
    node->client_config.net_ctx = net_ctx;
    node->client_config.next_stream_id = 0;
    
    // Initialize additional fields
    node->net_ctx = net_ctx;
    node->running = 1;
    node->server_connected = 0;
    node->client_connected = 0;

    dlog("Node structure initialized");

    // Start server thread
    if (pthread_create(&node->server_thread, NULL, server_thread_func, node) != 0) {
        fprintf(stderr, "Failed to start server thread\n");
        free(node);
        return 1;
    }

    dlog("Server thread started");

    // Start client thread
    if (pthread_create(&node->client_thread, NULL, client_thread_func, node) != 0) {
        fprintf(stderr, "Failed to start client thread\n");
        node->running = 0;
        pthread_join(node->server_thread, NULL);
        free(node);
        return 1;
    }

    dlog("Client thread started");

    // Set output parameter
    *out_node = node;
    dlog("Node initialization complete");
    return 0;
}

void* server_thread_func(void* arg) {
    nexus_node_t* node = (nexus_node_t*)arg;
    bool server_initialized = false;
    
    printf("Starting NEXUS server on port %d\n", node->server_config.port);
    
    if (init_nexus_server(node->server_config.net_ctx, 
                         node->server_config.bind_address,
                         node->server_config.port, 
                         &node->server_config) != 0) {
        fprintf(stderr, "Failed to initialize QUIC server\n");
        node->running = 0;
        return NULL;
    }

    server_initialized = true;
    dlog("Server initialized and listening");
    
    while (node->running) {
        if (server_initialized) {
            int ret = nexus_server_process_events(&node->server_config);
            if (ret < 0) {
                dlog("Server error processing events");
                break;
            }
            
            // Check connection state - only if we have a connection
            if (node->server_config.conn && 
                ngtcp2_conn_get_handshake_completed(node->server_config.conn)) {
                if (!node->server_connected) {
                    node->server_connected = 1;
                    dlog("Server connection established");
                }
            }
        }

        usleep(1000); // Small sleep to prevent CPU spinning
    }

    return NULL;
}


void* client_thread_func(void* arg) {
    nexus_node_t* node = (nexus_node_t*)arg;
    bool client_initialized = false;
    
    printf("Starting NEXUS client on port %d\n", node->client_config.port);

    if (strcmp(node->net_ctx->mode, "federated") == 0 || 
        strcmp(node->net_ctx->mode, "private") == 0) {
        
        // In private mode, we should connect even if server is localhost
        if (strlen(node->net_ctx->server) > 0) {
            dlog("%s", node->net_ctx->mode);
            const char *target_server = node->net_ctx->server;
            
            // If server and hostname are the same, we still need to connect to
            // 127.0.0.1 for loopback connections
            if (strcmp(node->net_ctx->server, node->net_ctx->hostname) == 0) {
                dlog("Server and hostname are the same, using loopback for client connection");
                target_server = "127.0.0.1";
            }
            
            dlog("Initializing client connection to %s", target_server);
            
            if (init_nexus_client(node->net_ctx, 
                               target_server, 
                               node->server_config.port,
                               &node->client_config) != 0) {
                dlog("Failed to initialize client");
                node->running = 0;
                return NULL;
            }

            dlog("Client initialized, attempting connection");
            
            if (nexus_client_connect(&node->client_config) != 0) {
                dlog("Failed to connect to server");
                node->running = 0;
                return NULL;
            }

            client_initialized = true;
            dlog("Client connection initiated");
        } else {
            dlog("Client not connecting to server (no server specified)");
        }
    }

    while (node->running) {
        if (client_initialized) {
            int ret = nexus_client_process_events(&node->client_config);
            if (ret < 0) {
                dlog("Client error processing events");
                break;
            }
            
            // Check connection state - only if we have a connection
            if (node->client_config.conn && 
                ngtcp2_conn_get_handshake_completed(node->client_config.conn)) {
                if (!node->client_connected) {
                    node->client_connected = 1;
                    dlog("Client connection established");
                }
            }
        } else {
            // No client connection to process, just sleep
            usleep(10000);
        }

        usleep(1000);
    }

    return NULL;
}

void cleanup_node(nexus_node_t *node) {
    if (!node) return;

    // Signal threads to stop
    node->running = 0;

    // Wait for threads to finish
    pthread_join(node->server_thread, NULL);
    pthread_join(node->client_thread, NULL);

    // Cleanup server
    if (node->server_config.conn) {
        ngtcp2_conn_del(node->server_config.conn);
        node->server_config.conn = NULL;
    }
    if (node->server_config.sock > 0) {
        close(node->server_config.sock);
        node->server_config.sock = -1;
    }

    // Cleanup client
    if (node->client_config.conn) {
        ngtcp2_conn_del(node->client_config.conn);
        node->client_config.conn = NULL;
    }
    if (node->client_config.sock > 0) {
        close(node->client_config.sock);
        node->client_config.sock = -1;
    }
    
    // Free the node structure itself
    free(node);
}