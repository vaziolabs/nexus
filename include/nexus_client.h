#ifndef NEXUS_CLIENT_H
#define NEXUS_CLIENT_H

#include "network_context.h"
#include "certificate_authority.h"
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <stdint.h>
#include <pthread.h>
#include <openssl/ssl.h>

// Structure to hold data pending to be sent on a stream - REMOVED
/*
typedef struct nexus_stream_data_pending_s {
    int64_t stream_id;
    uint8_t* data;
    size_t data_len;
    size_t sent_offset;
    int fin;
    struct nexus_stream_data_pending_s* next;
} nexus_stream_data_pending_t;
*/

// Define crypto context structure
typedef struct nexus_crypto_ctx {
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    ngtcp2_crypto_conn_ref conn_ref;
} nexus_crypto_ctx;

typedef struct {
    ngtcp2_conn *conn;
    int sock;
    char *bind_address;
    uint16_t port;
    ca_context_t *ca_ctx;
    nexus_cert_t *cert;
    network_context_t* net_ctx;
    int64_t next_stream_id; // Keep for reference, but open_bidi_stream manages IDs
    nexus_crypto_ctx *crypto_ctx; // TLS crypto context
    int handshake_completed;  // Flag to indicate if handshake has completed

    // Added fields for new crypto and connection management logic
    ngtcp2_callbacks callbacks;       // Store ngtcp2 callbacks
    ngtcp2_settings settings;         // Store ngtcp2 settings
} nexus_client_config_t;

// Update function declaration to match implementation
int init_nexus_client(network_context_t *net_ctx, const char *remote_addr, 
                    uint16_t port, nexus_client_config_t *config);

int nexus_client_connect(nexus_client_config_t *config);
int nexus_client_process_events(nexus_client_config_t *config);

// New function to send a TLD registration request
// Returns the stream ID used for the request, or < 0 on error.
int64_t nexus_client_send_tld_register_request(nexus_client_config_t* client_config, const char* tld_name);

#endif // NEXUS_CLIENT_H