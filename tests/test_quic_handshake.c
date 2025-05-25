#include "network_context.h"
#include "nexus_node.h"
#include "certificate_authority.h"
#include "debug.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

static volatile int running = 1;

void handle_signal(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        running = 0;
    }
}

int main(int argc, char *argv[]) {
    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Initialize network context
    network_context_t net_ctx = {
        .mode = "private",
        .hostname = "localhost",
        .server = "localhost",
        .peer_list = NULL,
        .dns_cache = NULL,
        .tld_manager = NULL,
        .active_requests = NULL
    };

    // Initialize network context components
    if (init_network_context_components(&net_ctx) != 0) {
        fprintf(stderr, "Failed to initialize network context components\n");
        return 1;
    }

    // Initialize CA
    ca_context_t* ca_ctx;
    if (init_certificate_authority(&net_ctx, &ca_ctx) != 0) {
        fprintf(stderr, "Failed to initialize certificate authority\n");
        cleanup_network_context_components(&net_ctx);
        return 1;
    }

    printf("Initializing test node\n");
    nexus_node_t *node;
    int status = init_node(&net_ctx, ca_ctx, 10053, 10443, &node);
    if (status != 0) {
        fprintf(stderr, "Failed to initialize node\n");
        cleanup_certificate_authority(ca_ctx);
        cleanup_network_context_components(&net_ctx);
        return 1;
    }

    printf("Node initialized, waiting for handshake completion...\n");

    // Give the handshake some time to complete
    int wait_attempts = 0;
    const int max_wait_attempts = 10;
    int handshake_completed = 0;

    while (wait_attempts < max_wait_attempts && running) {
        // Check if the handshake has completed
        if (node->client_config.conn && ngtcp2_conn_get_handshake_completed(node->client_config.conn)) {
            handshake_completed = 1;
            printf("Client handshake completed successfully!\n");
            break;
        }

        printf("Waiting for handshake completion (attempt %d/%d)...\n", 
               wait_attempts + 1, max_wait_attempts);
        sleep(1);
        wait_attempts++;
    }

    if (!handshake_completed) {
        fprintf(stderr, "Handshake did not complete within the timeout period\n");
    }

    printf("Cleaning up...\n");
    cleanup_node(node);
    cleanup_certificate_authority(ca_ctx);
    cleanup_network_context_components(&net_ctx);

    return handshake_completed ? 0 : 1;
} 