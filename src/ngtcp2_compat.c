/* This file provides compatibility implementations for ngtcp2 functions
   that are either missing or have changed in the installed version. */

#include "../include/ngtcp2_compat.h"
#include "../include/debug.h"
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <string.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

// Define the SSL_QUIC_METHOD structure since it's not available in the OpenSSL version
struct ssl_quic_method_st {
    int dummy;  // Just to have something in the struct
};

// Most ngtcp2_crypto functions are now available in the system library
// We only need to provide compatibility wrappers where needed

// The real ngtcp2_crypto_ossl_configure_client_session is available in ngtcp2_crypto_ossl.h
// No need to implement our own version

int SSL_set_quic_tls_transport_params(SSL *ssl, const uint8_t *params, size_t params_len) {
    (void)ssl;
    (void)params;
    (void)params_len;
    // This would set QUIC transport parameters
    // For now, just return success
    return 1;
}

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
    
    // Use the real ngtcp2_crypto callback functions
    callbacks->client_initial = ngtcp2_crypto_client_initial_cb;
    callbacks->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks->encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks->decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks->hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks->update_key = ngtcp2_crypto_update_key_cb;
    callbacks->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks->delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks->get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    
    // For client connections, the recv_retry callback is required
    if (!callbacks->recv_retry) {
        callbacks->recv_retry = ngtcp2_crypto_recv_retry_cb;
    }
} 