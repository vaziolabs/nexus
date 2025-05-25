#ifndef NEXUS_SERVER_H
#define NEXUS_SERVER_H

#include <stdint.h>
#include <ngtcp2/ngtcp2.h>
#include <openssl/ssl.h>
#include "certificate_authority.h"
#include "network_context.h"

// Forward declaration of connection reference struct
typedef struct {
    ngtcp2_conn *(*get_conn)(void *user_data);
    void *user_data;
} nexus_conn_ref;

// Server crypto context - full definition
typedef struct nexus_server_crypto_ctx {
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    nexus_conn_ref conn_ref;  // Use our custom struct instead
} nexus_server_crypto_ctx;

// Server configuration
typedef struct {
    ngtcp2_conn *conn;
    int sock;
    char *bind_address;
    uint16_t port;
    ca_context_t *ca_ctx;
    nexus_cert_t *cert;
    network_context_t *net_ctx;
    nexus_server_crypto_ctx *crypto_ctx;
    // Other server config fields
} nexus_server_config_t;

// Initialize server
int init_nexus_server(network_context_t *net_ctx, const char *bind_address,
                     uint16_t port, nexus_server_config_t *config);

// Process server events
int nexus_server_process_events(nexus_server_config_t *config);

#endif // NEXUS_SERVER_H