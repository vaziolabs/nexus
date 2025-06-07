#include "../include/nexus_node.h"
#include "../include/nexus_server.h"
#include "../include/nexus_client.h"
#include "../include/network_context.h"
#include "../include/certificate_authority.h"
#include "../include/debug.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>  // For bool type
#include <stdlib.h>   // For malloc
#include <stdint.h> // For uint16_t


int init_node(network_context_t *net_ctx, ca_context_t *ca_ctx, 
             uint16_t server_port, uint16_t client_port, nexus_node_t **out_node) {
    (void)ca_ctx; // Mark ca_ctx as unused
    dlog("Starting node initialization");
    
    // Allocate node structure on heap so it persists
    nexus_node_t *node = malloc(sizeof(nexus_node_t));
    if (!node) {
        fprintf(stderr, "Failed to allocate node structure\n");
        return 1;
    }

    dlog("Node structure allocated");

    // Initialize node structure with only the fields defined in the header
    node->server_config.bind_address = net_ctx->hostname ? strdup(net_ctx->hostname) : NULL;
    node->server_config.port = server_port;
    node->server_config.net_ctx = net_ctx;
    
    node->client_config.bind_address = net_ctx->hostname ? strdup(net_ctx->hostname) : NULL;
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
    
    // Add a short delay to allow the server to fully initialize before client connects
    usleep(100000); // 100ms delay
    
    int idle_count = 0;
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
                    dlog("Server connection established and handshake completed!");
                    printf("Server handshake completed successfully!\n");
                }
            }
            
            // Add some extra debugging output
            if (++idle_count % 100 == 0) {
                dlog("Server still running (conn=%p, handshake_completed=%d)", 
                     node->server_config.conn,
                     node->server_config.conn ? 
                        ngtcp2_conn_get_handshake_completed(node->server_config.conn) : -1);
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

    // Check mode: 0 = private, 2 = federated
    if (node->net_ctx->mode == 0 || node->net_ctx->mode == 2) {
        
        // In private or federated mode, we need to connect to a server
        // For private mode, connect to localhost (same machine)
        // For federated mode, would connect to a remote server
        const char *target_server = "::1"; // Use IPv6 localhost
        int target_port = node->server_config.port;  // Connect to our own server port
        
        dlog("Mode: %d", node->net_ctx->mode);
        dlog("Initializing client connection to %s:%d", target_server, target_port);
        
        // Add a short delay to ensure the server is ready
        usleep(200000); // 200ms delay
        
        if (init_nexus_client(node->net_ctx, 
                           target_server, 
                           target_port, 
                           &node->client_config) != 0) {
            fprintf(stderr, "Failed to initialize QUIC client\n");
            node->running = 0;
            return NULL;
        }

        client_initialized = true;
        dlog("Client initialized, attempting connection");
    }
    
    // Main client loop
    int idle_count = 0;
    while (node->running) {
        if (client_initialized) {
            nexus_client_process_events(&node->client_config);
            
            // Check if the handshake has completed
            if (node->client_config.conn && 
                ngtcp2_conn_get_handshake_completed(node->client_config.conn)) {
                
                if (!node->client_config.handshake_completed) {
                    dlog("QUIC handshake completed on client side!");
                    node->client_config.handshake_completed = 1;
                }
            }
            
            dlog("Client still running (conn=%p, handshake_completed=%d)", 
                 node->client_config.conn, node->client_config.handshake_completed);
        }
        
        // Avoid burning CPU in the loop
        usleep(10000); // 10ms delay
        
        idle_count++;
        if (idle_count >= 10) {
            idle_count = 0;
            // Optionally add some idle processing here
        }
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
    free(node->server_config.bind_address); // Free strdup'd memory
    if (node->server_config.conn) {
        ngtcp2_conn_del(node->server_config.conn);
        node->server_config.conn = NULL;
    }
    if (node->server_config.sock > 0) {
        close(node->server_config.sock);
        node->server_config.sock = -1;
    }

    // Cleanup client
    free(node->client_config.bind_address); // Free strdup'd memory
    if (node->client_config.conn) {
        ngtcp2_conn_del(node->client_config.conn);
        node->client_config.conn = NULL;
    }
    if (node->client_config.sock > 0) {
        close(node->client_config.sock);
        node->client_config.sock = -1;
    }
    
    // Note: Don't free the node structure itself - let the caller handle it
}