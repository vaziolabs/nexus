#include "../include/certificate_authority.h"
#include "../include/network_context.h"
#include "../include/extern/falcon/falcon.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Falcon configuration - using Falcon-1024 for maximum security
#define FALCON_LOGN 10  // Falcon-1024
#define FALCON_PRIVKEY_LEN FALCON_PRIVKEY_SIZE(FALCON_LOGN)
#define FALCON_PUBKEY_LEN FALCON_PUBKEY_SIZE(FALCON_LOGN)

// Initialize certificate authority with RSA keys (simplified version)
int init_certificate_authority(network_context_t *net_ctx, ca_context_t **ca_ctx) {
    (void)net_ctx; // Unused for now
    
    *ca_ctx = malloc(sizeof(ca_context_t));
    if (!*ca_ctx) {
        return -1;
    }
    
    memset(*ca_ctx, 0, sizeof(ca_context_t));
    
    // Generate Falcon keypair for CA
    if (generate_falcon_keypair((*ca_ctx)->falcon_public_key, (*ca_ctx)->falcon_private_key) != 0) {
        printf("ERROR: Failed to generate Falcon keypair for CA\n");
        free(*ca_ctx);
        return -1;
    }
    
    // Generate RSA key pair for X509 compatibility
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        free(*ca_ctx);
        return -1;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        free(*ca_ctx);
        return -1;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        free(*ca_ctx);
        return -1;
    }
    
    if (EVP_PKEY_keygen(ctx, &(*ca_ctx)->falcon_pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        free(*ca_ctx);
        return -1;
    }
    
    EVP_PKEY_CTX_free(ctx);
    
    // Create CA certificate
    (*ca_ctx)->ca_cert = malloc(sizeof(nexus_cert_t));
    if (!(*ca_ctx)->ca_cert) {
        EVP_PKEY_free((*ca_ctx)->falcon_pkey);
        free(*ca_ctx);
        return -1;
    }
    
    memset((*ca_ctx)->ca_cert, 0, sizeof(nexus_cert_t));
    (*ca_ctx)->ca_cert->common_name = strdup("NEXUS Certificate Authority");
    (*ca_ctx)->ca_cert->not_before = time(NULL);
    (*ca_ctx)->ca_cert->not_after = (*ca_ctx)->ca_cert->not_before + (365 * 24 * 60 * 60); // Valid for 1 year
    (*ca_ctx)->ca_cert->cert_type = CERT_TYPE_SELF_SIGNED;
    
    // Copy Falcon public key to certificate
    memcpy((*ca_ctx)->ca_cert->falcon_pubkey, (*ca_ctx)->falcon_public_key, FALCON_PUBKEY_SIZE_1024);
    
    // Create Falcon signature for the CA certificate (self-signed)
    const char *cert_data = (*ca_ctx)->ca_cert->common_name;
    if (falcon_sign((*ca_ctx)->falcon_private_key, cert_data, strlen(cert_data), 
                   (*ca_ctx)->ca_cert->falcon_signature) != 0) {
        printf("ERROR: Failed to create Falcon signature for CA certificate\n");
        free((*ca_ctx)->ca_cert->common_name);
        free((*ca_ctx)->ca_cert);
        EVP_PKEY_free((*ca_ctx)->falcon_pkey);
        free(*ca_ctx);
        return -1;
    }
    
    // Create X509 certificate for compatibility
    X509 *x509 = X509_new();
    if (!x509) {
        free((*ca_ctx)->ca_cert->common_name);
        free((*ca_ctx)->ca_cert);
        EVP_PKEY_free((*ca_ctx)->falcon_pkey);
        free(*ca_ctx);
        return -1;
    }
    
    // Set version
    X509_set_version(x509, 2);
    
    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    
    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 60 * 60);
    
    // Set public key
    X509_set_pubkey(x509, (*ca_ctx)->falcon_pkey);
    
    // Set subject name
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
                              (unsigned char*)(*ca_ctx)->ca_cert->common_name, -1, -1, 0);
    
    // Self-sign (issuer = subject for CA)
    X509_set_issuer_name(x509, name);
    
    // Sign the certificate
    if (!X509_sign(x509, (*ca_ctx)->falcon_pkey, EVP_sha256())) {
        X509_free(x509);
        free((*ca_ctx)->ca_cert->common_name);
        free((*ca_ctx)->ca_cert);
        EVP_PKEY_free((*ca_ctx)->falcon_pkey);
        free(*ca_ctx);
        return -1;
    }
    
    (*ca_ctx)->ca_cert->x509 = x509;
    (*ca_ctx)->authority_name = strdup("NEXUS CA");
    
    printf("Certificate Authority initialized successfully with Falcon-1024 post-quantum cryptography\n");
    return 0;
}

// Issue a certificate for a given common name
int ca_issue_certificate(ca_context_t* ca_ctx, const char* common_name, nexus_cert_t** cert_out) {
    if (!ca_ctx || !common_name || !cert_out) {
        return -1;
    }
    
    *cert_out = malloc(sizeof(nexus_cert_t));
    if (!*cert_out) {
        return -1;
    }
    
    memset(*cert_out, 0, sizeof(nexus_cert_t));
    (*cert_out)->common_name = strdup(common_name);
    (*cert_out)->not_before = time(NULL);
    (*cert_out)->not_after = (*cert_out)->not_before + (90 * 24 * 60 * 60); // Valid for 90 days
    (*cert_out)->cert_type = CERT_TYPE_FEDERATED;
    
    // Generate Falcon keypair for the certificate
    uint8_t cert_private_key[FALCON_PRIVKEY_SIZE_1024];
    if (generate_falcon_keypair((*cert_out)->falcon_pubkey, cert_private_key) != 0) {
        printf("ERROR: Failed to generate Falcon keypair for certificate\n");
        free((*cert_out)->common_name);
        free(*cert_out);
        return -1;
    }
    
    // Create certificate data to sign (common name + validity period)
    char cert_data[512];
    snprintf(cert_data, sizeof(cert_data), "%s:%ld:%ld", 
             common_name, (*cert_out)->not_before, (*cert_out)->not_after);
    
    // Sign the certificate data with CA's Falcon private key
    if (falcon_sign(ca_ctx->falcon_private_key, cert_data, strlen(cert_data), 
                   (*cert_out)->falcon_signature) != 0) {
        printf("ERROR: Failed to create Falcon signature for certificate\n");
        free((*cert_out)->common_name);
        free(*cert_out);
        // Clear the generated private key
        memset(cert_private_key, 0, sizeof(cert_private_key));
        return -1;
    }
    
    // Generate RSA key pair for X509 compatibility
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        free((*cert_out)->common_name);
        free(*cert_out);
        memset(cert_private_key, 0, sizeof(cert_private_key));
        return -1;
    }
    
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        free((*cert_out)->common_name);
        free(*cert_out);
        memset(cert_private_key, 0, sizeof(cert_private_key));
        return -1;
    }
    
    EVP_PKEY_CTX_free(ctx);
    
    // Create X509 certificate for compatibility
    X509 *x509 = X509_new();
    if (!x509) {
        EVP_PKEY_free(pkey);
        free((*cert_out)->common_name);
        free(*cert_out);
        memset(cert_private_key, 0, sizeof(cert_private_key));
        return -1;
    }
    
    // Set version
    X509_set_version(x509, 2);
    
    // Set serial number (use a simple counter for now)
    static long serial = 2;
    ASN1_INTEGER_set(X509_get_serialNumber(x509), serial++);
    
    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 90 * 24 * 60 * 60);
    
    // Set public key
    X509_set_pubkey(x509, pkey);
    
    // Set subject name
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
                              (unsigned char*)common_name, -1, -1, 0);
    
    // Set issuer name (from CA)
    X509_set_issuer_name(x509, X509_get_subject_name(ca_ctx->ca_cert->x509));
    
    // Sign with CA's private key
    if (!X509_sign(x509, ca_ctx->falcon_pkey, EVP_sha256())) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        free((*cert_out)->common_name);
        free(*cert_out);
        memset(cert_private_key, 0, sizeof(cert_private_key));
        return -1;
    }
    
    (*cert_out)->x509 = x509;
    
    // Clean up the generated private key (in real implementation, this would be saved)
    EVP_PKEY_free(pkey);
    memset(cert_private_key, 0, sizeof(cert_private_key));
    
    printf("Certificate issued for '%s' with Falcon-1024 post-quantum signature\n", common_name);
    return 0;
}

// Verify certificate using CA's public key
int verify_certificate(nexus_cert_t* cert, ca_context_t* ca) {
    if (!cert || !ca || !cert->x509 || !ca->ca_cert || !ca->ca_cert->x509) {
        printf("ERROR: Invalid parameters for certificate verification\n");
        return -1;
    }
    
    // Get CA's public key
    EVP_PKEY *ca_pubkey = X509_get_pubkey(ca->ca_cert->x509);
    if (!ca_pubkey) {
        printf("ERROR: Failed to get CA public key\n");
        return -1;
    }
    
    // Verify the certificate signature
    int result = X509_verify(cert->x509, ca_pubkey);
    EVP_PKEY_free(ca_pubkey);
    
    if (result == 1) {
        printf("Certificate for '%s' successfully verified\n", cert->common_name);
        return 0;
    } else {
        printf("Certificate verification failed for '%s'\n", cert->common_name);
        return -1;
    }
}

// Free certificate
void free_certificate(nexus_cert_t* cert) {
    if (!cert) {
        return;
    }
    
    free(cert->common_name);
    free(cert->subject_alt_name);
    free(cert->signature);
    if (cert->x509) {
        X509_free(cert->x509);
    }
    free(cert);
}

// Cleanup certificate authority
void cleanup_certificate_authority(ca_context_t *ca_ctx) {
    if (!ca_ctx) {
        return;
    }
    
    if (ca_ctx->ca_cert) {
        free_certificate(ca_ctx->ca_cert);
    }
    
    if (ca_ctx->falcon_pkey) {
        EVP_PKEY_free(ca_ctx->falcon_pkey);
    }
    
    free(ca_ctx->authority_name);
    free(ca_ctx);
}

// Implement Falcon functions (replacing stubs)
int generate_falcon_keypair(uint8_t *public_key, uint8_t *private_key) {
    if (!public_key || !private_key) {
        return -1;
    }
    
    // Initialize SHAKE256 PRNG from system entropy
    shake256_context rng;
    if (shake256_init_prng_from_system(&rng) != 0) {
        printf("ERROR: Failed to initialize PRNG for Falcon key generation\n");
        return -1;
    }
    
    // Allocate temporary buffer for key generation
    size_t tmp_len = FALCON_TMPSIZE_KEYGEN(FALCON_LOGN);
    void *tmp = malloc(tmp_len);
    if (!tmp) {
        printf("ERROR: Failed to allocate temporary buffer for Falcon key generation\n");
        return -1;
    }
    
    // Generate Falcon keypair
    int result = falcon_keygen_make(&rng, FALCON_LOGN, 
                                   private_key, FALCON_PRIVKEY_LEN,
                                   public_key, FALCON_PUBKEY_LEN,
                                   tmp, tmp_len);
    
    // Clear and free temporary buffer
    memset(tmp, 0, tmp_len);
    free(tmp);
    
    if (result != 0) {
        printf("ERROR: Falcon key generation failed with code %d\n", result);
        return -1;
    }
    
    printf("Falcon-1024 keypair generated successfully\n");
    return 0;
}

int falcon_sign(const uint8_t *private_key, const void *data, size_t data_len, uint8_t *signature) {
    if (!private_key || !data || !signature) {
        return -1;
    }
    
    // Initialize SHAKE256 PRNG from system entropy
    shake256_context rng;
    if (shake256_init_prng_from_system(&rng) != 0) {
        printf("ERROR: Failed to initialize PRNG for Falcon signing\n");
        return -1;
    }
    
    // Allocate temporary buffer for signing
    size_t tmp_len = FALCON_TMPSIZE_SIGNDYN(FALCON_LOGN);
    void *tmp = malloc(tmp_len);
    if (!tmp) {
        printf("ERROR: Failed to allocate temporary buffer for Falcon signing\n");
        return -1;
    }
    
    // Sign the data
    size_t sig_len = FALCON_SIG_LEN;
    int result = falcon_sign_dyn(&rng, signature, &sig_len, FALCON_SIG_PADDED,
                                private_key, FALCON_PRIVKEY_LEN,
                                data, data_len,
                                tmp, tmp_len);
    
    // Clear and free temporary buffer
    memset(tmp, 0, tmp_len);
    free(tmp);
    
    if (result != 0) {
        printf("ERROR: Falcon signing failed with code %d\n", result);
        return -1;
    }
    
    if (sig_len != FALCON_SIG_LEN) {
        printf("ERROR: Falcon signature length mismatch: expected %d, got %zu\n", 
               FALCON_SIG_LEN, sig_len);
        return -1;
    }
    
    return 0;
}

int falcon_verify_sig(const uint8_t *public_key, const void *data, size_t data_len, const uint8_t *signature) {
    if (!public_key || !data || !signature) {
        return -1;
    }
    
    // Allocate temporary buffer for verification
    size_t tmp_len = FALCON_TMPSIZE_VERIFY(FALCON_LOGN);
    void *tmp = malloc(tmp_len);
    if (!tmp) {
        printf("ERROR: Failed to allocate temporary buffer for Falcon verification\n");
        return -1;
    }
    
    // Verify the signature
    int result = falcon_verify(signature, FALCON_SIG_LEN, FALCON_SIG_PADDED,
                              public_key, FALCON_PUBKEY_LEN,
                              data, data_len,
                              tmp, tmp_len);
    
    // Clear and free temporary buffer
    memset(tmp, 0, tmp_len);
    free(tmp);
    
    if (result != 0) {
        printf("ERROR: Falcon signature verification failed with code %d\n", result);
        return -1;
    }
    
    return 0;
} 