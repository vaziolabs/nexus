#ifndef NGTCP2_COMPAT_H
#define NGTCP2_COMPAT_H

/**
 * This file provides compatibility between different versions of ngtcp2 API.
 * It handles the transition from older versions to ngtcp2 v1.12.0.
 */

#include <stddef.h>
#include <stdint.h>

// Include the v1.12.0 headers (paths are set in Makefile)
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

// OpenSSL related headers
#include <openssl/ssl.h>

// SSL QUIC Method
// typedef struct ssl_quic_method_st SSL_QUIC_METHOD;
// extern const SSL_QUIC_METHOD *ngtcp2_crypto_ossl_quic_method;

// Constants for building with different versions
#ifndef NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO
#define NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO 0
#endif

// OpenSSL compatibility functions
// int SSL_provide_quic_data(SSL *ssl, int level, const uint8_t *data, size_t len);
// int SSL_CTX_set_quic_method(SSL_CTX *ctx, const SSL_QUIC_METHOD *method);
// int SSL_set_quic_tls_transport_params(SSL *ssl, const uint8_t *params, size_t params_len);

// Additional missing functions
int ngtcp2_crypto_ossl_configure_client_context(SSL *ssl, ngtcp2_conn *conn);
int ngtcp2_crypto_recv_retry_cb(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data);

// Use existing function declarations but provide custom implementations
// so we don't need to link against the actual ngtcp2_crypto library
void ngtcp2_crypto_ossl_init_callbacks(ngtcp2_callbacks *callbacks);

// Connection reference getter matching the required signature
static inline ngtcp2_conn *ngtcp2_crypto_conn_ref_default_get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
    return (ngtcp2_conn*)conn_ref->user_data;
}

#endif // NGTCP2_COMPAT_H 