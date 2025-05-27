#ifndef NGTCP2_COMPAT_H
#define NGTCP2_COMPAT_H

/**
 * This file provides compatibility between different versions of ngtcp2 API.
 * Instead of trying to redefine types, we'll fix specific function calls
 * in the code as needed.
 */

// Include standard system headers first
#include <stddef.h>
#include <stdint.h>

// Include OpenSSL headers
#include <openssl/ssl.h>
#include <openssl/err.h>

// We'll use ngtcp2's own headers directly without trying to fix types
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

// Constants for building with different versions
#ifndef NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO
#define NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO 0
#endif

// Accessor function for ngtcp2_conn from conn_ref
static inline ngtcp2_conn *ngtcp2_crypto_conn_ref_default_get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
    return (ngtcp2_conn*)conn_ref->user_data;
}

#endif // NGTCP2_COMPAT_H 