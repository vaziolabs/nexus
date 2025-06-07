#include "../include/certificate_authority.h"
#include "../include/network_context.h"
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

// Initialize certificate authority with RSA keys (simplified version)
int init_certificate_authority(struct network_context_t *net_ctx, ca_context_t **ca_ctx) {
    (void)net_ctx; // Unused for now
    
    *ca_ctx = malloc(sizeof(ca_context_t));
    if (!*ca_ctx) {
        return -1;
    }
    
    memset(*ca_ctx, 0, sizeof(ca_context_t));
    
    // Generate RSA key pair for CA
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
    
    // Create X509 certificate for CA
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
    
    printf("Certificate Authority initialized successfully\n");
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
    
    // Generate key pair for the certificate
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        free((*cert_out)->common_name);
        free(*cert_out);
        return -1;
    }
    
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        free((*cert_out)->common_name);
        free(*cert_out);
        return -1;
    }
    
    EVP_PKEY_CTX_free(ctx);
    
    // Create X509 certificate
    X509 *x509 = X509_new();
    if (!x509) {
        EVP_PKEY_free(pkey);
        free((*cert_out)->common_name);
        free(*cert_out);
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
        return -1;
    }
    
    (*cert_out)->x509 = x509;
    
    // Clean up the generated private key (in real implementation, this would be saved)
    EVP_PKEY_free(pkey);
    
    printf("Certificate issued for '%s'\n", common_name);
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

// Stub implementations for Falcon functions (to satisfy linker)
int generate_falcon_keypair(uint8_t *public_key, uint8_t *private_key) {
    (void)public_key;
    (void)private_key;
    printf("WARNING: Falcon keypair generation not implemented (using RSA instead)\n");
    return -1; // Not implemented
}

int falcon_sign(const uint8_t *private_key, const void *data, size_t data_len, uint8_t *signature) {
    (void)private_key;
    (void)data;
    (void)data_len;
    (void)signature;
    printf("WARNING: Falcon signing not implemented (using RSA instead)\n");
    return -1; // Not implemented
}

int falcon_verify_sig(const uint8_t *public_key, const void *data, size_t data_len, const uint8_t *signature) {
    (void)public_key;
    (void)data;
    (void)data_len;
    (void)signature;
    printf("WARNING: Falcon signature verification not implemented (using RSA instead)\n");
    return -1; // Not implemented
} 