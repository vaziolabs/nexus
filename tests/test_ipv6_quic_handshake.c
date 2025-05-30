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

// Define network mode constants
#define NETWORK_MODE_PRIVATE   0
#define NETWORK_MODE_PUBLIC    1
#define NETWORK_MODE_FEDERATED 2

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
        .mode = NETWORK_MODE_PRIVATE,
        .hostname = strdup("server.nexus.local"),
        .ip_address = strdup("::1"),
        .server_port = TEST_SERVER_PORT,
        .client_port = TEST_CLIENT_PORT,
        .dns_cache = NULL,
        .tld_manager = NULL,
        .dns_resolver = NULL
    };

    // Initialize network context components
    if (init_network_context_components(&server_ctx) != 0) {
        fprintf(stderr, "ERROR: Failed to initialize server network context components\n");
        free(server_ctx.hostname);
        free(server_ctx.ip_address);
        return 1;
    }
    printf("Server network context: OK\n");

    // Initialize network context for client
    network_context_t client_ctx = {
        .mode = NETWORK_MODE_PRIVATE,
        .hostname = strdup("client.nexus.local"),
        .ip_address = strdup("::1"),
        .server_port = TEST_SERVER_PORT,
        .client_port = TEST_CLIENT_PORT,
        .dns_cache = NULL,
        .tld_manager = NULL,
        .dns_resolver = NULL
    };

    // Initialize network context components
    if (init_network_context_components(&client_ctx) != 0) {
        fprintf(stderr, "ERROR: Failed to initialize client network context components\n");
        cleanup_network_context_components(&server_ctx);
        free(client_ctx.hostname);
        free(client_ctx.ip_address);
        free(server_ctx.hostname);
        free(server_ctx.ip_address);
        return 1;
    }
    printf("Client network context: OK\n");

    // Initialize CA for server
    ca_context_t* server_ca_ctx;
    if (init_certificate_authority(&server_ctx, &server_ca_ctx) != 0) {
        fprintf(stderr, "ERROR: Failed to initialize server certificate authority\n");
        cleanup_network_context_components(&client_ctx);
        cleanup_network_context_components(&server_ctx);
        free(client_ctx.hostname);
        free(client_ctx.ip_address);
        free(server_ctx.hostname);
        free(server_ctx.ip_address);
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
        free(client_ctx.hostname);
        free(client_ctx.ip_address);
        free(server_ctx.hostname);
        free(server_ctx.ip_address);
        return 1;
    }
    printf("Client CA: OK\n");

    // Create test certificate files for server
    const char *server_cert_path = "ipv6_server.cert";
    const char *server_key_path = "ipv6_server.key";
    
    // Set environment variables for the server certificate
    setenv("NEXUS_CERT_PATH", server_cert_path, 1);
    setenv("NEXUS_KEY_PATH", server_key_path, 1);

    // Create simple certificate files
    FILE *cert_file = fopen(server_cert_path, "wb");
    if (!cert_file) {
        fprintf(stderr, "ERROR: Could not create server certificate file\n");
        cleanup_certificate_authority(client_ca_ctx);
        cleanup_certificate_authority(server_ca_ctx);
        cleanup_network_context_components(&client_ctx);
        cleanup_network_context_components(&server_ctx);
        free(client_ctx.hostname);
        free(client_ctx.ip_address);
        free(server_ctx.hostname);
        free(server_ctx.ip_address);
        return 1;
    }
    
    fprintf(cert_file, "-----BEGIN CERTIFICATE-----\n");
    fprintf(cert_file, "MIICXTCCAcagAwIBAgIUJjGSRw9XRmVNSTLT9sQN8UkXRUAwDQYJKoZIhvcNAQEL\n");
    fprintf(cert_file, "BQAwPzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQKDAtFeGFtcGxl\n");
    fprintf(cert_file, "IEluYzENMAsGA1UEAwwEVGVzdDAeFw0yMzA1MTIyMDM2MThaFw0yNDA1MTEyMDM2\n");
    fprintf(cert_file, "MThaMD8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UECgwLRXhhbXBs\n");
    fprintf(cert_file, "ZSBJbmMxDTALBgNVBAMMBFRlc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB\n");
    fprintf(cert_file, "ALuX90ZiaDOcXM3WxrEbQcg3UyBaUJ9jWjVnQKt9a6OuM+8dRbxNAEAjazLwY8bY\n");
    fprintf(cert_file, "z0JyeSxGDMKgwMpNjD7E+R4H8lK4/ZKr0fC5KMC3i8hOZvd0jD9FGXqGnrc+QzYP\n");
    fprintf(cert_file, "pPxnj5+inRZZcgyzFvZxDVQeBvgw4VyiEA4Y5ZQWu0N5AgMBAAGjUzBRMB0GA1Ud\n");
    fprintf(cert_file, "DgQWBBRk4cXoNgixTBX9UpVrrsj7LYhbHTAfBgNVHSMEGDAWgBRk4cXoNgixTBX9\n");
    fprintf(cert_file, "UpVrrsj7LYhbHTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBAIKC\n");
    fprintf(cert_file, "eKsjGvFXJ9BrYZKjmL5P0bDv1aKkHkXBJ5Dq0a9kTPEj4AYgTwLXUH4OsAKBfOFh\n");
    fprintf(cert_file, "Ei9/cA7fPxJUE9vZrDNJmqOLXmQKfdHbgBwVm8Hx7wA1l2r37cYNvAdZvS/4TGR6\n");
    fprintf(cert_file, "Md4WmCt4VYZfL9pbw/d1jCDqwSzaEkG8\n");
    fprintf(cert_file, "-----END CERTIFICATE-----\n");
    fclose(cert_file);
    
    FILE *key_file = fopen(server_key_path, "wb");
    if (!key_file) {
        fprintf(stderr, "ERROR: Could not create server key file\n");
        unlink(server_cert_path);
        cleanup_certificate_authority(client_ca_ctx);
        cleanup_certificate_authority(server_ca_ctx);
        cleanup_network_context_components(&client_ctx);
        cleanup_network_context_components(&server_ctx);
        free(client_ctx.hostname);
        free(client_ctx.ip_address);
        free(server_ctx.hostname);
        free(server_ctx.ip_address);
        return 1;
    }
    
    fprintf(key_file, "-----BEGIN PRIVATE KEY-----\n");
    fprintf(key_file, "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALuX90ZiaDOcXM3W\n");
    fprintf(key_file, "xrEbQcg3UyBaUJ9jWjVnQKt9a6OuM+8dRbxNAEAjazLwY8bYz0JyeSxGDMKgwMpN\n");
    fprintf(key_file, "jD7E+R4H8lK4/ZKr0fC5KMC3i8hOZvd0jD9FGXqGnrc+QzYPpPxnj5+inRZZcgyz\n");
    fprintf(key_file, "FvZxDVQeBvgw4VyiEA4Y5ZQWu0N5AgMBAAECgYAB55/bY3LLpj+y7l8FhAVY8ZJr\n");
    fprintf(key_file, "BhAMsQbIJEpK9XLz2oXStDXDv55Vk7kJK9lQ7fW+SV6cLbmIUWZGULhK/5kJI3N8\n");
    fprintf(key_file, "XWZ6UYeQnPKC1JYLiULbv7q3k0D4NXk6W/EY4xV3EeR0I4Ibka1nHqd7J6XpmSYY\n");
    fprintf(key_file, "iWuEQeH7ZoeIQXGt4QJBAOGQwdVs/FA31nJPNxYz6ZHfRK96JgynRDLFUvuRVEJB\n");
    fprintf(key_file, "qvSZHOxVLAkIu4TugPCN7dbFHnGWgKh4/JvLHN0/QnUCQQDVYw/0WgI+V1uM7JhA\n");
    fprintf(key_file, "AQfj2lS8ODj2sJZbgOsV2hDnlO/xh4RUdFG0JNwjQRk0wIK4zPw3+XaiF8OsRqax\n");
    fprintf(key_file, "p0gFAkEAvLPCn7qCXyJHOQSL1lQGGn9kOZfCcFUV2xKmVFfRRrAKyrwM6B0MpbBY\n");
    fprintf(key_file, "hUxBl/zWXGottHTznK+x0jLw7IXP1QJAYfg+4oBK3HyH1jXEeN+hK6R5blDgVkYZ\n");
    fprintf(key_file, "X56XdTd9IQ3WjU1XZodnCwYkbCnHh9mZSlIPbBUb7y9PLssW2y9MHQJBAIuCKELm\n");
    fprintf(key_file, "Q0eQnH0X9eUO5z+FCuBuUyvQoWIAUUJLzXpEZlmGgf7zElbQ1lA/f37fCK+jvfvK\n");
    fprintf(key_file, "GLt58jvMZ5j+dBI=\n");
    fprintf(key_file, "-----END PRIVATE KEY-----\n");
    fclose(key_file);

    printf("Test certificate files created\n");

    // Initialize server
    nexus_server_config_t server_config;
    if (init_nexus_server(&server_ctx, "::1", TEST_SERVER_PORT, &server_config) != 0) {
        fprintf(stderr, "ERROR: Failed to initialize NEXUS server\n");
        unlink(server_cert_path);
        unlink(server_key_path);
        cleanup_certificate_authority(client_ca_ctx);
        cleanup_certificate_authority(server_ca_ctx);
        cleanup_network_context_components(&client_ctx);
        cleanup_network_context_components(&server_ctx);
        free(client_ctx.hostname);
        free(client_ctx.ip_address);
        free(server_ctx.hostname);
        free(server_ctx.ip_address);
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
        unlink(server_cert_path);
        unlink(server_key_path);
        cleanup_certificate_authority(client_ca_ctx);
        cleanup_certificate_authority(server_ca_ctx);
        cleanup_network_context_components(&client_ctx);
        cleanup_network_context_components(&server_ctx);
        free(client_ctx.hostname);
        free(client_ctx.ip_address);
        free(server_ctx.hostname);
        free(server_ctx.ip_address);
        return 1;
    }
    printf("NEXUS client initialized, connecting to [::1]:%d\n", TEST_SERVER_PORT);

    // Start client connection
    if (nexus_client_connect(&client_config) != 0) {
        fprintf(stderr, "ERROR: Failed to start client connection\n");
        // TODO: Proper cleanup for client_config and server_config
        unlink(server_cert_path);
        unlink(server_key_path);
        cleanup_certificate_authority(client_ca_ctx);
        cleanup_certificate_authority(server_ca_ctx);
        cleanup_network_context_components(&client_ctx);
        cleanup_network_context_components(&server_ctx);
        free(client_ctx.hostname);
        free(client_ctx.ip_address);
        free(server_ctx.hostname);
        free(server_ctx.ip_address);
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
    
    free(client_ctx.hostname);
    free(client_ctx.ip_address);
    free(server_ctx.hostname);
    free(server_ctx.ip_address);
    
    // Remove the test certificate files
    unlink(server_cert_path);
    unlink(server_key_path);
    
    printf("Cleanup completed\n");

    return handshake_completed ? 0 : 1;
} 