#include "../include/certificate_authority.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include "../include/extern/falcon/falcon.h"  // Direct include of the Falcon header

// Define Falcon hash functions if not already defined
#ifndef FALCON_SHAKE256
#define FALCON_SHAKE256 2  // Typical value for SHAKE256 in Falcon implementations
#endif

// Initialize certificate authority with Falcon keys
int init_certificate_authority(network_context_t *net_ctx, ca_context_t **ca_ctx) {
    (void)net_ctx;
    *ca_ctx = malloc(sizeof(ca_context_t));
    if (!*ca_ctx) {
        return -1;
    }
    
    memset(*ca_ctx, 0, sizeof(ca_context_t));
    
    // Allocate memory for Falcon keys
    (*ca_ctx)->keys = malloc(sizeof(falcon_keys_t));
    if (!(*ca_ctx)->keys) {
        free(*ca_ctx);
        return -1;
    }
    
    // Generate Falcon keypair
    if (generate_falcon_keypair((*ca_ctx)->keys->public_key, (*ca_ctx)->keys->private_key) != 0) {
        free((*ca_ctx)->keys);
        free(*ca_ctx);
        return -1;
    }
    
    // Create CA certificate
    (*ca_ctx)->ca_cert = malloc(sizeof(struct nexus_cert));
    if (!(*ca_ctx)->ca_cert) {
        free((*ca_ctx)->keys);
        free(*ca_ctx);
        return -1;
    }
    
    memset((*ca_ctx)->ca_cert, 0, sizeof(struct nexus_cert));
    (*ca_ctx)->ca_cert->common_name = strdup("Stoq Certificate Authority");
    if (!(*ca_ctx)->ca_cert->common_name) {
        printf("ERROR: Failed to allocate memory for certificate common name\n");
        free((*ca_ctx)->ca_cert);
        free((*ca_ctx)->keys);
        free(*ca_ctx);
        return -1;
    }
    
    printf("DEBUG: Created certificate with common_name: '%s'\n", (*ca_ctx)->ca_cert->common_name);
    
    (*ca_ctx)->ca_cert->valid_from = (uint64_t)time(NULL);
    (*ca_ctx)->ca_cert->valid_until = (*ca_ctx)->ca_cert->valid_from + (365 * 24 * 60 * 60); // Valid for 1 year
    (*ca_ctx)->ca_cert->cert_type = CERT_TYPE_PUBLIC;
    
    // Self-sign CA certificate
    if (sign_certificate((*ca_ctx)->ca_cert, *ca_ctx) != 0) {
        free((*ca_ctx)->ca_cert->common_name);
        free((*ca_ctx)->ca_cert);
        free((*ca_ctx)->keys);
        free(*ca_ctx);
        return -1;
    }
    
    return 0;
}

// Handle certificate request using Falcon signatures
int handle_cert_request(ca_context_t *ca_ctx, const char *hostname, nexus_cert_t **cert) {
    if (!ca_ctx || !hostname || !cert) {
        return -1;
    }
    
    *cert = malloc(sizeof(struct nexus_cert));
    if (!*cert) {
        return -1;
    }
    
    memset(*cert, 0, sizeof(struct nexus_cert));
    (*cert)->common_name = strdup(hostname);
    if (!(*cert)->common_name) {
        free(*cert);
        return -1;
    }
    
    (*cert)->valid_from = (uint64_t)time(NULL);
    (*cert)->valid_until = (*cert)->valid_from + (90 * 24 * 60 * 60); // Valid for 90 days
    (*cert)->cert_type = CERT_TYPE_FEDERATED;
    
    // Sign the certificate with CA's private key
    if (sign_certificate(*cert, ca_ctx) != 0) {
        free((*cert)->common_name);
        free(*cert);
        return -1;
    }
    
    return 0;
}

// Free certificate
void free_certificate(nexus_cert_t *cert) {
    if (!cert) {
        return;
    }
    
    free(cert->common_name);
    free(cert);
}

// Verify certificate using Falcon
int verify_certificate(nexus_cert_t* cert, ca_context_t* ca) {
    if (!cert || !ca || !ca->keys || !cert->common_name) {
        printf("ERROR: Invalid parameters passed to verify_certificate\n");
        return -1;
    }
    
    printf("Verifying certificate for '%s', valid from %lu to %lu, type %d\n", 
           cert->common_name, cert->valid_from, cert->valid_until, cert->cert_type);
    
    // Debug signature format first
    printf("DEBUG: Signature header byte: 0x%02x\n", cert->signature[0]);
    unsigned sig_logn = cert->signature[0] & 0x0F;
    unsigned sig_format = cert->signature[0] & 0xF0;
    printf("DEBUG: Signature logn: %u, format: 0x%02x\n", sig_logn, sig_format);
    
    // Check if signature has non-zero content
    int nonzero = 0;
    for (size_t i = 0; i < sizeof(cert->signature); i++) {
        if (cert->signature[i] != 0) {
            nonzero = 1;
            break;
        }
    }
    if (!nonzero) {
        printf("ERROR: Certificate signature contains all zeros\n");
        return -1;
    }
    
    // Create message to verify (common_name + validity period + cert_type)
    uint8_t message[1024];
    size_t message_len = 0;
    
    // Add common_name to message
    size_t common_name_len = strlen(cert->common_name);
    if (common_name_len > 512) {
        printf("ERROR: Common name too long\n");
        return -1; // Common name too long
    }
    memcpy(message, cert->common_name, common_name_len);
    message_len += common_name_len;
    
    // Add validity period to message
    memcpy(message + message_len, &cert->valid_from, sizeof(cert->valid_from));
    message_len += sizeof(cert->valid_from);
    memcpy(message + message_len, &cert->valid_until, sizeof(cert->valid_until));
    message_len += sizeof(cert->valid_until);
    
    // Add cert_type to message
    memcpy(message + message_len, &cert->cert_type, sizeof(cert->cert_type));
    message_len += sizeof(cert->cert_type);
    
    printf("DEBUG: Message length for verification: %zu bytes\n", message_len);
    
    // Verify the signature using falcon_verify_sig
    int result = falcon_verify_sig(ca->keys->public_key, message, message_len, cert->signature);
    if (result != 0) {
        printf("Certificate verification failed for '%s' with error code %d\n", cert->common_name, result);
        return -1;
    }
    
    printf("Certificate for '%s' successfully verified.\n", cert->common_name);
    return 0;
}

// Sign certificate using Falcon
int sign_certificate(nexus_cert_t* cert, ca_context_t* ca) {
    if (!cert || !ca || !ca->keys) {
        printf("ERROR: Invalid parameters passed to sign_certificate\n");
        return -1;
    }
    
    // Check for NULL common name and handle it
    const char *common_name = cert->common_name ? cert->common_name : "(null)";
    
    printf("Signing certificate for '%s', valid from %lu to %lu, type %d\n", 
           common_name, cert->valid_from, cert->valid_until, cert->cert_type);
    
    // Create message to sign (common_name + validity period + cert_type)
    uint8_t message[1024];
    size_t message_len = 0;
    
    // Add common_name to message if it exists
    if (cert->common_name) {
        size_t common_name_len = strlen(cert->common_name);
        if (common_name_len > 512) {
            printf("ERROR: Common name too long\n");
            return -1; // Common name too long
        }
        memcpy(message, cert->common_name, common_name_len);
        message_len += common_name_len;
    }
    
    // Add validity period to message
    memcpy(message + message_len, &cert->valid_from, sizeof(cert->valid_from));
    message_len += sizeof(cert->valid_from);
    memcpy(message + message_len, &cert->valid_until, sizeof(cert->valid_until));
    message_len += sizeof(cert->valid_until);
    
    // Add cert_type to message
    memcpy(message + message_len, &cert->cert_type, sizeof(cert->cert_type));
    message_len += sizeof(cert->cert_type);
    
    printf("DEBUG: Message length for signing: %zu bytes\n", message_len);
    
    // Initialize a signature buffer with zeros first
    memset(cert->signature, 0, sizeof(cert->signature));
    
    // Sign the message with Falcon
    if (falcon_sign(ca->keys->private_key, message, message_len, cert->signature) != 0) {
        printf("ERROR: Failed to sign certificate for '%s'\n", common_name);
        return -1;
    }
    
    printf("Certificate for '%s' successfully signed.\n", common_name);
    return 0;
}

// Generate Falcon keypair
int generate_falcon_keypair(uint8_t *public_key, uint8_t *private_key) {
    if (!public_key || !private_key) {
        return -1;
    }
    
    // Initialize SHAKE256 context for random number generation
    shake256_context rng;
    if (shake256_init_prng_from_system(&rng) != 0) {
        printf("ERROR: Failed to initialize random number generator\n");
        return -1;
    }
    
    // Create temporary buffer for key generation
    uint8_t tmp[FALCON_TMPSIZE_KEYGEN(10)];
    
    // Generate keypair using actual Falcon implementation
    int ret = falcon_keygen_make(
        &rng,
        10, // logn=10 for Falcon-1024
        private_key, FALCON_PRIVKEY_SIZE(10),
        public_key, FALCON_PUBKEY_SIZE(10),
        tmp, sizeof(tmp)
    );
    
    if (ret != 0) {
        printf("ERROR: Falcon key generation failed with code %d\n", ret);
        return -1;
    }
    
    printf("Successfully generated Falcon-1024 keypair\n");
    return 0;
}

// Sign data using Falcon
int falcon_sign(const uint8_t *private_key, const void *data, size_t data_len, uint8_t *signature) {
    if (!private_key || !data || !signature) {
        printf("ERROR: Invalid parameters passed to falcon_sign\n");
        return -1;
    }
    
    // Initialize SHAKE256 context for random number generation
    shake256_context rng;
    if (shake256_init_prng_from_system(&rng) != 0) {
        printf("ERROR: Failed to initialize random number generator\n");
        return -1;
    }
    
    // Create temporary buffer for signing
    uint8_t tmp[FALCON_TMPSIZE_SIGNDYN(10)];
    
    // Size variable for the signature
    size_t sig_len = FALCON_SIG_COMPRESSED_MAXSIZE(10);
    
    // Sign using actual Falcon implementation
    int ret = falcon_sign_dyn(
        &rng,
        signature, &sig_len, FALCON_SIG_COMPRESSED,
        private_key, FALCON_PRIVKEY_SIZE(10),
        data, data_len,
        tmp, sizeof(tmp)
    );
    
    if (ret != 0) {
        printf("ERROR: Falcon signature generation failed with code %d\n", ret);
        return -1;
    }
    
    printf("Successfully generated Falcon signature (size: %zu bytes)\n", sig_len);
    return 0;
}

// Verify signature using Falcon
int falcon_verify_sig(const uint8_t *public_key, const void *data, size_t data_len, const uint8_t *signature) {
    if (!public_key || !data || !signature) {
        printf("ERROR: Invalid parameters passed to falcon_verify_sig\n");
        return -1;
    }
    
    // Create temporary buffer for verification
    uint8_t tmp[FALCON_TMPSIZE_VERIFY(10)];
    
    // Extract signature length based on the first byte
    size_t max_sig_len = FALCON_SIG_COMPRESSED_MAXSIZE(10);
    size_t sig_len = max_sig_len; // Default to max size
    
    // First attempt verification with max length
    int ret = falcon_verify(
        signature, sig_len, FALCON_SIG_COMPRESSED,
        public_key, FALCON_PUBKEY_SIZE(10),
        data, data_len,
        tmp, sizeof(tmp)
    );
    
    if (ret == 0) {
        printf("Falcon signature successfully verified\n");
        return 0;
    }
    
    // If verification failed, try to determine the actual signature length
    // This is necessary because we don't store the actual length
    unsigned sig_format = signature[0] & 0xF0;
    unsigned sig_logn = signature[0] & 0x0F;
    
    printf("DEBUG: Signature format: 0x%02x, logn: %u\n", sig_format, sig_logn);
    
    // For compressed signatures, we need to scan for a non-zero byte from the end
    for (size_t i = max_sig_len - 1; i > 0; i--) {
        if (signature[i] != 0) {
            sig_len = i + 1;
            break;
        }
    }
    
    printf("DEBUG: Trying signature length: %zu bytes\n", sig_len);
    
    // Try verification with the determined length
    ret = falcon_verify(
        signature, sig_len, FALCON_SIG_COMPRESSED,
        public_key, FALCON_PUBKEY_SIZE(10),
        data, data_len,
        tmp, sizeof(tmp)
    );
    
    if (ret == FALCON_ERR_BADSIG) {
        printf("Falcon signature verification failed: Invalid signature\n");
        return -1;
    } else if (ret != 0) {
        printf("ERROR: Falcon signature verification failed with code %d\n", ret);
        return -1;
    }
    
    printf("Falcon signature successfully verified\n");
    return 0;
}

// Stub implementation for add_federation_signature
int add_federation_signature(nexus_cert_t* cert, const uint8_t* signature) {
    // This is a stub for now
    // In a full implementation, this would add a federation-level signature
    (void)cert;
    (void)signature;
    return 0;
}

// Cleanup certificate authority
void cleanup_certificate_authority(ca_context_t *ca_ctx) {
    if (!ca_ctx) {
        return;
    }
    
    if (ca_ctx->ca_cert) {
        if (ca_ctx->ca_cert->common_name) {
            free(ca_ctx->ca_cert->common_name);
            ca_ctx->ca_cert->common_name = NULL;
        }
        free(ca_ctx->ca_cert);
        ca_ctx->ca_cert = NULL;
    }
    
    if (ca_ctx->keys) {
        // Securely wipe keys before freeing
        memset(ca_ctx->keys->private_key, 0, sizeof(ca_ctx->keys->private_key));
        free(ca_ctx->keys);
        ca_ctx->keys = NULL;
    }
    
    if (ca_ctx->authority_name) {
        free(ca_ctx->authority_name);
        ca_ctx->authority_name = NULL;
    }
    
    free(ca_ctx);
}

// Alias cleanup_certificate_authority as free_ca_context for compatibility
void free_ca_context(ca_context_t *ca_ctx) {
    cleanup_certificate_authority(ca_ctx);
}