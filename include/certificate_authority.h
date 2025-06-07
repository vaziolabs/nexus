#ifndef CERTIFICATE_AUTHORITY_H
#define CERTIFICATE_AUTHORITY_H

#include <stdint.h>
#include <time.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

// Forward declaration - don't redefine the typedef
struct network_context_t;

/**
 * @file certificate_authority.h
 * @brief Certificate Authority functionality for Stoq using Falcon post-quantum cryptography
 * 
 * This file provides the functionality for managing certificates in the Stoq network,
 * including certificate creation, signing, verification, and management. It uses
 * Falcon post-quantum cryptography for key generation and signature operations.
 * 
 * Falcon is a post-quantum digital signature algorithm based on NTRU lattices.
 * It's designed to be resistant to quantum computer attacks, while maintaining
 * reasonable key and signature sizes. The implementation here uses Falcon-1024,
 * which provides 256 bits of quantum security.
 */

#define FALCON_SIG_LEN 1280 // Example for Falcon-512

// Certificate types
typedef enum {
    CERT_TYPE_SELF_SIGNED,    // For private networks
    CERT_TYPE_FEDERATED,      // For nodes in federated networks
    CERT_TYPE_PUBLIC          // For public network CAs
} cert_type_t;

// Structure for a NEXUS certificate
typedef struct nexus_cert_s {
    char* common_name;
    char* subject_alt_name;
    time_t not_before;
    time_t not_after;
    uint8_t* signature;
    size_t signature_len;
    X509 *x509;
    cert_type_t cert_type;
} nexus_cert_t;

// CA context structure
typedef struct ca_context_s {
    nexus_cert_t *ca_cert;
    EVP_PKEY *falcon_pkey;
    char *authority_name;
} ca_context_t;

// Function declarations
int init_certificate_authority(struct network_context_t* net_ctx, ca_context_t** ca_ctx);
int ca_issue_certificate(ca_context_t* ca_ctx, const char* common_name, nexus_cert_t** cert_out);
int verify_certificate(nexus_cert_t* cert, ca_context_t* ca);
void free_certificate(nexus_cert_t* cert);
void cleanup_certificate_authority(ca_context_t* ca_ctx);

// New functions for Falcon integration
int generate_falcon_keypair(uint8_t *public_key, uint8_t *private_key);
int falcon_sign(const uint8_t *private_key, const void *data, size_t data_len, uint8_t *signature);
int falcon_verify_sig(const uint8_t *public_key, const void *data, size_t data_len, const uint8_t *signature);

#endif