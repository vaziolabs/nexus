#ifndef NGTCP2_COMPAT_H
#define NGTCP2_COMPAT_H

// Include standard system headers first
#include <stddef.h>
#include <stdint.h>

// Include OpenSSL headers
#include <openssl/ssl.h>
#include <openssl/err.h>

// Forward declarations to avoid header conflicts
struct ngtcp2_conn;
struct ngtcp2_callbacks;

// Function declarations for compatibility functions
// Note: ngtcp2_crypto_ossl_configure_client_session is available in ngtcp2_crypto_ossl.h
int ngtcp2_crypto_ossl_configure_client_context(SSL *ssl, struct ngtcp2_conn *conn);
int SSL_set_quic_tls_transport_params(SSL *ssl, const uint8_t *params, size_t params_len);
void ngtcp2_crypto_ossl_init_callbacks(struct ngtcp2_callbacks *callbacks);

#endif // NGTCP2_COMPAT_H 