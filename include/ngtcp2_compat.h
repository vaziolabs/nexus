#ifndef NGTCP2_COMPAT_H
#define NGTCP2_COMPAT_H

// Include standard system headers first
#include <stddef.h>
#include <stdint.h>

// Include OpenSSL headers
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/quic.h>

// Include the main ngtcp2 header which defines core types
#include <ngtcp2/ngtcp2.h>

// Compatibility functions for ngtcp2_conn_ref
#if NGTCP2_VERSION_NUM < 0x010000
    // For very old versions (pre-1.0.0) - adjust as needed
    typedef struct {
        ngtcp2_conn *conn;
        void* user_data;
    } ngtcp2_conn_ref_compat_t;

    static inline void* ngtcp2_conn_get_user_data(ngtcp2_conn_ref_compat_t *conn_ref) {
        return conn_ref->user_data;
    }
    static inline ngtcp2_conn* ngtcp2_conn_get_conn(ngtcp2_conn_ref_compat_t *conn_ref) {
        return conn_ref->conn;
    }
#else
    // For ngtcp2 v1.0.0 and later
    static inline void* ngtcp2_conn_get_user_data(ngtcp2_conn_ref *conn_ref) {
        if (conn_ref) {
            return conn_ref->user_data;
        }
        return NULL;
    }
    static inline ngtcp2_conn* ngtcp2_conn_get_conn(ngtcp2_conn_ref *conn_ref) {
        if (conn_ref && conn_ref->user_data) {
            return (ngtcp2_conn*)conn_ref->user_data;
        }
        return NULL;
    }
#endif

// Constants for building with different versions (if needed)
#ifndef NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO
#define NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO 0
#endif

#endif // NGTCP2_COMPAT_H 