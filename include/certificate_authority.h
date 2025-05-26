#ifndef CERTIFICATE_AUTHORITY_H
#define CERTIFICATE_AUTHORITY_H

#include <stdint.h>
#include "system.h"
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "network_context.h"  // For network_context_t definition

// Certificate types
typedef enum {
    CERT_TYPE_SELF_SIGNED,    // For private networks
    CERT_TYPE_FEDERATED,      // For nodes in federated networks
    CERT_TYPE_PUBLIC          // For public network CAs
} cert_type_t;

// Falcon-1024 key structure
typedef struct {
    uint8_t public_key[1793];  // Falcon-1024 public key size
    uint8_t private_key[2305]; // Falcon-1024 private key size
    uint8_t signature[1330];   // Falcon-1024 signature size
} falcon_keys_t;

// Certificate structure
struct nexus_cert {
    char *common_name;
    uint8_t signature[1330];   // Falcon-1024 signature
    uint64_t valid_from;
    uint64_t valid_until;
    cert_type_t cert_type;
    // Other certificate fields
};

// CA context structure
typedef struct {
    struct nexus_cert *ca_cert;
    falcon_keys_t *keys;
    char *authority_name;
    // Other CA fields
} ca_context_t;

// Function declarations
int init_certificate_authority(network_context_t* net_ctx, ca_context_t** ca_ctx);
int handle_cert_request(ca_context_t* ca_ctx, const char* hostname, nexus_cert_t** cert);
int save_certificate(nexus_cert_t* cert, const char* filename);
nexus_cert_t* load_certificate(const char* filename);
void free_certificate(nexus_cert_t* cert);
int verify_certificate(nexus_cert_t* cert, ca_context_t* ca);
int sign_certificate(nexus_cert_t* cert, ca_context_t* ca);
int add_federation_signature(nexus_cert_t* cert, const uint8_t* signature);
void cleanup_certificate_authority(ca_context_t* ca_ctx);

// New functions for Falcon integration
int generate_falcon_keypair(uint8_t *public_key, uint8_t *private_key);
int falcon_sign(const uint8_t *private_key, const void *data, size_t data_len, uint8_t *signature);
int falcon_verify_sig(const uint8_t *public_key, const void *data, size_t data_len, const uint8_t *signature);

#endif