#include "../include/certificate_authority.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include "../include/extern/falcon/falcon.h"

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
        return -1;
    }
    
    // Create message to verify (common_name + validity period + cert_type)
    uint8_t message[1024];
    size_t message_len = 0;
    
    // Add common_name to message
    size_t common_name_len = strlen(cert->common_name);
    if (common_name_len > 512) {
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
    
    // Verify the signature using Falcon
    if (falcon_verify_sig(ca->keys->public_key, message, message_len, cert->signature) != 0) {
        printf("Certificate verification failed for '%s'\n", cert->common_name);
        return -1;
    }
    
    printf("Certificate for '%s' successfully verified.\n", cert->common_name);
    return 0; // Success
}

// Sign certificate using Falcon
int sign_certificate(nexus_cert_t* cert, ca_context_t* ca) {
    if (!cert || !ca || !ca->keys || !cert->common_name) {
        return -1;
    }
    
    // Create message to sign (common_name + validity period + cert_type)
    uint8_t message[1024];
    size_t message_len = 0;
    
    // Add common_name to message
    size_t common_name_len = strlen(cert->common_name);
    if (common_name_len > 512) {
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
    
    // Sign the message using Falcon
    if (falcon_sign(ca->keys->private_key, message, message_len, cert->signature) != 0) {
        printf("Failed to sign certificate for '%s'\n", cert->common_name);
        return -1;
    }
    
    printf("Certificate for '%s' successfully signed.\n", cert->common_name);
    return 0; // Success
}

// Generate Falcon keypair
int generate_falcon_keypair(uint8_t *public_key, uint8_t *private_key) {
    if (!public_key || !private_key) {
        return -1;
    }
    
    // Initialize SHAKE256 context for randomness
    shake256_context rng;
    if (shake256_init_prng_from_system(&rng) != 0) {
        fprintf(stderr, "Failed to initialize system RNG for Falcon\n");
        return -1;
    }
    
    // Temporary buffer for Falcon keygen
    size_t tmp_len = FALCON_TMPSIZE_KEYGEN(10); // For Falcon-1024 (logn=10)
    uint8_t *tmp = malloc(tmp_len);
    if (!tmp) {
        return -1;
    }
    
    // Generate keypair
    int result = falcon_keygen_make(&rng, 10, private_key, FALCON_PRIVKEY_SIZE(10),
                                   public_key, FALCON_PUBKEY_SIZE(10), tmp, tmp_len);
    
    free(tmp);
    
    if (result != 0) {
        fprintf(stderr, "Falcon key generation failed with error code %d\n", result);
        return -1;
    }
    
    return 0;
}

// Sign data using Falcon
int falcon_sign(const uint8_t *private_key, const void *data, size_t data_len, uint8_t *signature) {
    if (!private_key || !data || !signature) {
        return -1;
    }
    
    // Initialize SHAKE256 context for randomness
    shake256_context rng;
    if (shake256_init_prng_from_system(&rng) != 0) {
        fprintf(stderr, "Failed to initialize system RNG for Falcon\n");
        return -1;
    }
    
    // Temporary buffer for Falcon signing
    size_t tmp_len = FALCON_TMPSIZE_SIGNDYN(10); // For Falcon-1024 (logn=10)
    uint8_t *tmp = malloc(tmp_len);
    if (!tmp) {
        return -1;
    }
    
    // Sign the data
    size_t sig_len = 1330; // Maximum size for Falcon-1024 signature
    int result = falcon_sign_dyn(&rng, signature, &sig_len, FALCON_SIG_COMPRESSED,
                                private_key, FALCON_PRIVKEY_SIZE(10),
                                data, data_len, tmp, tmp_len);
    
    free(tmp);
    
    if (result != 0) {
        fprintf(stderr, "Falcon signing failed with error code %d\n", result);
        return -1;
    }
    
    return 0;
}

// Verify signature using Falcon
int falcon_verify_sig(const uint8_t *public_key, const void *data, size_t data_len, const uint8_t *signature) {
    if (!public_key || !data || !signature) {
        return -1;
    }
    
    // Temporary buffer for Falcon verification
    size_t tmp_len = FALCON_TMPSIZE_VERIFY(10); // For Falcon-1024 (logn=10)
    uint8_t *tmp = malloc(tmp_len);
    if (!tmp) {
        return -1;
    }
    
    // Verify the signature
    int result = falcon_verify(signature, 1330, FALCON_SIG_COMPRESSED,
                              public_key, FALCON_PUBKEY_SIZE(10),
                              data, data_len, tmp, tmp_len);
    
    free(tmp);
    
    if (result != 0) {
        fprintf(stderr, "Falcon verification failed with error code %d\n", result);
        return -1;
    }
    
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
        free_certificate(ca_ctx->ca_cert);
    }
    
    if (ca_ctx->keys) {
        // Securely wipe keys before freeing
        memset(ca_ctx->keys->private_key, 0, sizeof(ca_ctx->keys->private_key));
        free(ca_ctx->keys);
    }
    
    if (ca_ctx->authority_name) {
        free(ca_ctx->authority_name);
    }
    
    free(ca_ctx);
}