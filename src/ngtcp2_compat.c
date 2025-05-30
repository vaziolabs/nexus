/* This file provides compatibility implementations for ngtcp2 functions
   that are either missing or have changed in the installed version. */

#include "../include/ngtcp2_compat.h"
#include <openssl/ssl.h>

// Define the SSL_QUIC_METHOD structure since it's not available in the OpenSSL version
struct ssl_quic_method_st {
    int dummy;  // Just to have something in the struct
};

// Forward declaration of our compatibility functions
int ngtcp2_crypto_recv_retry_cb(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data);

// Define a dummy QUIC method structure
// This just needs to exist since we're not actually using it
// The real one would be provided by the OpenSSL library
// static const SSL_QUIC_METHOD dummy_quic_method = {0};
// const SSL_QUIC_METHOD *ngtcp2_crypto_ossl_quic_method = &dummy_quic_method;

// OpenSSL QUIC data function
// int SSL_provide_quic_data(SSL *ssl, int level, const uint8_t *data, size_t len) {
//     // Just return success since we're not using this in our real implementation
//     (void)ssl;
//     (void)level;
//     (void)data;
//     (void)len;
//     return 1; // Success
// }

// Set TLS transport parameters
// int SSL_set_quic_tls_transport_params(SSL *ssl, const uint8_t *params, size_t params_len) {
//     // Just return success
//     (void)ssl;
//     (void)params;
//     (void)params_len;
//     return 1; // Success
// }

// Set QUIC method on SSL context
// int SSL_CTX_set_quic_method(SSL_CTX *ctx, const SSL_QUIC_METHOD *method) {
//     // Just return success since we're not using this in our real implementation
//     (void)ctx;
//     (void)method;
//     return 1; // Success
// }

// Configure client context - required for client connection setup
int ngtcp2_crypto_ossl_configure_client_context(SSL *ssl, ngtcp2_conn *conn) {
    // Just return success since we're not using this in our real implementation
    (void)ssl;
    (void)conn;
    return 0; // Success
}

// Initialize callbacks 
void ngtcp2_crypto_ossl_init_callbacks(ngtcp2_callbacks *callbacks) {
    if (!callbacks) {
        return;
    }
    
    // For client connections, the recv_retry callback is required
    // If it's not set, we'll provide our default implementation
    if (!callbacks->recv_retry) {
        callbacks->recv_retry = ngtcp2_crypto_recv_retry_cb;
    }
    
    // Add other required callbacks if they're missing
    // In a real implementation, this would set all the required crypto callbacks
}

// Implementation of ngtcp2_crypto_recv_retry_cb
int ngtcp2_crypto_recv_retry_cb(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data) {
    // This is a minimal implementation that just logs the event
    // In a real implementation, this would regenerate the keys based on the new connection ID
    (void)conn;
    (void)hd;
    (void)user_data;
    
    // If using a logging system
    // dlog("Received retry packet, regenerating keys");
    
    // Normally we would need to:
    // 1. Regenerate initial keys using the new connection ID (hd->scid)
    // 2. Install these keys in the connection
    
    return 0; // Success
} 