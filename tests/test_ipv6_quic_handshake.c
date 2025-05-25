#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "network_context.h"
#include "nexus_server.h"
#include "nexus_client.h"
#include "certificate_authority.h"
#include "debug.h"

#define TEST_SERVER_PORT 10553
#define TEST_CLIENT_PORT 10554

static volatile int running = 1;

void handle_signal(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        running = 0;
    }
}

// Check if IPv6 is supported on the system
int check_ipv6_support() {
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        return 0; // IPv6 not supported
    }
    close(sock);
    return 1; // IPv6 is supported
}

int main(int argc, char *argv[]) {
    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("NEXUS IPv6 QUIC Handshake Test\n");
    printf("==============================\n\n");

    // Check IPv6 support
    if (!check_ipv6_support()) {
        fprintf(stderr, "ERROR: IPv6 is not supported on this system.\n");
        return 1;
    }
    printf("IPv6 support: OK\n");

    // Initialize network context for server
    network_context_t server_ctx = {
        .mode = "private",
        .hostname = "server.nexus.local",
        .server = "::1",
        .peer_list = NULL,
        .dns_cache = NULL,
        .tld_manager = NULL,
        .active_requests = NULL
    };

    // Initialize network context components
    if (init_network_context_components(&server_ctx) != 0) {
        fprintf(stderr, "ERROR: Failed to initialize server network context components\n");
        return 1;
    }
    printf("Server network context: OK\n");

    // Initialize network context for client
    network_context_t client_ctx = {
        .mode = "private",
        .hostname = "client.nexus.local",
        .server = "::1",
        .peer_list = NULL,
        .dns_cache = NULL,
        .tld_manager = NULL,
        .active_requests = NULL
    };

    // Initialize network context components
    if (init_network_context_components(&client_ctx) != 0) {
        fprintf(stderr, "ERROR: Failed to initialize client network context components\n");
        cleanup_network_context_components(&server_ctx);
        return 1;
    }
    printf("Client network context: OK\n");

    // Initialize CA for server
    ca_context_t* server_ca_ctx;
    if (init_certificate_authority(&server_ctx, &server_ca_ctx) != 0) {
        fprintf(stderr, "ERROR: Failed to initialize server certificate authority\n");
        cleanup_network_context_components(&client_ctx);
        cleanup_network_context_components(&server_ctx);
        return 1;
    }
    printf("Server CA: OK\n");

    // Initialize CA for client
    ca_context_t* client_ca_ctx;
    if (init_certificate_authority(&client_ctx, &client_ca_ctx) != 0) {
        fprintf(stderr, "ERROR: Failed to initialize client certificate authority\n");
        cleanup_certificate_authority(server_ca_ctx);
        cleanup_network_context_components(&client_ctx);
        cleanup_network_context_components(&server_ctx);
        return 1;
    }
    printf("Client CA: OK\n");

    // Initialize server
    nexus_server_config_t server_config;
    if (init_nexus_server(&server_ctx, "::1", TEST_SERVER_PORT, &server_config) != 0) {
        fprintf(stderr, "ERROR: Failed to initialize NEXUS server\n");
        cleanup_certificate_authority(client_ca_ctx);
        cleanup_certificate_authority(server_ca_ctx);
        cleanup_network_context_components(&client_ctx);
        cleanup_network_context_components(&server_ctx);
        return 1;
    }
    printf("NEXUS server initialized at [::1]:%d\n", TEST_SERVER_PORT);

    // Let server process any startup events
    for (int i = 0; i < 5 && running; i++) {
        nexus_server_process_events(&server_config);
        usleep(10000); // 10ms
    }
    printf("Server event loop started\n");

    // Initialize client
    nexus_client_config_t client_config;
    if (init_nexus_client(&client_ctx, "::1", TEST_SERVER_PORT, &client_config) != 0) {
        fprintf(stderr, "ERROR: Failed to initialize NEXUS client\n");
        // TODO: Proper cleanup for server_config (missing in current API)
        cleanup_certificate_authority(client_ca_ctx);
        cleanup_certificate_authority(server_ca_ctx);
        cleanup_network_context_components(&client_ctx);
        cleanup_network_context_components(&server_ctx);
        return 1;
    }
    printf("NEXUS client initialized, connecting to [::1]:%d\n", TEST_SERVER_PORT);

    // Start client connection
    if (nexus_client_connect(&client_config) != 0) {
        fprintf(stderr, "ERROR: Failed to start client connection\n");
        // TODO: Proper cleanup for client_config and server_config
        cleanup_certificate_authority(client_ca_ctx);
        cleanup_certificate_authority(server_ca_ctx);
        cleanup_network_context_components(&client_ctx);
        cleanup_network_context_components(&server_ctx);
        return 1;
    }
    printf("Client connection started\n");

    // Process events to complete handshake
    printf("Waiting for handshake completion...\n");
    int handshake_completed = 0;
    int attempt_count = 0;
    const int max_attempts = 20;

    while (running && attempt_count < max_attempts) {
        // Process server events
        nexus_server_process_events(&server_config);
        
        // Process client events
        nexus_client_process_events(&client_config);
        
        // Check if handshake is completed
        if (client_config.conn && ngtcp2_conn_get_handshake_completed(client_config.conn)) {
            handshake_completed = 1;
            break;
        }
        
        attempt_count++;
        printf("Handshake attempt %d/%d\n", attempt_count, max_attempts);
        usleep(500000); // 500ms between attempts
    }

    if (handshake_completed) {
        printf("\n[SUCCESS] IPv6 QUIC handshake completed successfully!\n");
        
        // Test TLD registration
        printf("\nTesting TLD registration over IPv6...\n");
        int64_t stream_id = nexus_client_send_tld_register_request(&client_config, "nexustest");
        if (stream_id >= 0) {
            printf("TLD registration request sent on stream %ld\n", stream_id);
            
            // Process events to handle TLD registration
            for (int i = 0; i < 10 && running; i++) {
                nexus_server_process_events(&server_config);
                nexus_client_process_events(&client_config);
                usleep(100000); // 100ms
            }
            
            printf("[SUCCESS] TLD registration test completed\n");
        } else {
            printf("[ERROR] Failed to send TLD registration request: %ld\n", stream_id);
        }
    } else {
        printf("\n[ERROR] IPv6 QUIC handshake did not complete within timeout period\n");
    }

    // Cleanup
    printf("\nCleaning up...\n");
    
    // TODO: Implement and call proper cleanup functions for client_config and server_config
    // For now, just closing sockets
    if (client_config.sock) close(client_config.sock);
    if (server_config.sock) close(server_config.sock);
    
    cleanup_certificate_authority(client_ca_ctx);
    cleanup_certificate_authority(server_ca_ctx);
    cleanup_network_context_components(&client_ctx);
    cleanup_network_context_components(&server_ctx);
    
    printf("Cleanup completed\n");

    return handshake_completed ? 0 : 1;
} 