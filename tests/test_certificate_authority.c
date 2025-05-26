#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "../include/certificate_authority.h"
#include "../include/network_context.h"
#include "test_certificate_authority.h"

static void test_ca_initialization(void) {
    printf("Testing certificate authority initialization with Falcon keys...\n");
    
    // Create a minimal network context
    network_context_t net_ctx;
    memset(&net_ctx, 0, sizeof(network_context_t));
    net_ctx.mode = strdup("private");
    net_ctx.hostname = strdup("localhost");
    net_ctx.server = strdup("localhost");
    
    // Initialize the CA
    ca_context_t *ca_ctx = NULL;
    int result = init_certificate_authority(&net_ctx, &ca_ctx);
    
    // Check that Falcon keys were properly initialized
    assert(result == 0);
    assert(ca_ctx != NULL);
    assert(ca_ctx->keys != NULL);
    
    // Verify keys have proper values (not all zeros)
    int public_key_has_value = 0;
    int private_key_has_value = 0;
    
    for (int i = 0; i < sizeof(ca_ctx->keys->public_key); i++) {
        if (ca_ctx->keys->public_key[i] != 0) {
            public_key_has_value = 1;
            break;
        }
    }
    
    for (int i = 0; i < sizeof(ca_ctx->keys->private_key); i++) {
        if (ca_ctx->keys->private_key[i] != 0) {
            private_key_has_value = 1;
            break;
        }
    }
    
    assert(public_key_has_value);
    assert(private_key_has_value);
    
    // Verify CA certificate was properly created and self-signed
    assert(ca_ctx->ca_cert != NULL);
    assert(ca_ctx->ca_cert->common_name != NULL);
    assert(strcmp(ca_ctx->ca_cert->common_name, "Stoq Certificate Authority") == 0);
    assert(ca_ctx->ca_cert->valid_from > 0);
    assert(ca_ctx->ca_cert->valid_until > ca_ctx->ca_cert->valid_from);
    assert(ca_ctx->ca_cert->cert_type == CERT_TYPE_PUBLIC);
    
    // Verify CA certificate signature (not all zeros)
    int signature_has_value = 0;
    for (int i = 0; i < sizeof(ca_ctx->ca_cert->signature); i++) {
        if (ca_ctx->ca_cert->signature[i] != 0) {
            signature_has_value = 1;
            break;
        }
    }
    assert(signature_has_value);
    
    // Clean up
    cleanup_certificate_authority(ca_ctx);
    
    // Clean up network context
    free((void*)net_ctx.mode);
    free((void*)net_ctx.hostname);
    free((void*)net_ctx.server);
    
    printf("Certificate authority initialization test passed\n");
}

static void test_certificate_request(void) {
    printf("Testing certificate request handling with Falcon signatures...\n");
    
    // Create a minimal network context
    network_context_t net_ctx;
    memset(&net_ctx, 0, sizeof(network_context_t));
    net_ctx.mode = strdup("private");
    net_ctx.hostname = strdup("localhost");
    net_ctx.server = strdup("localhost");
    
    // Initialize the CA
    ca_context_t *ca_ctx = NULL;
    int init_result = init_certificate_authority(&net_ctx, &ca_ctx);
    assert(init_result == 0);
    assert(ca_ctx != NULL);
    
    // Request a certificate
    nexus_cert_t *cert = NULL;
    int request_result = handle_cert_request(ca_ctx, "test.localhost", &cert);
    
    // Check results
    assert(request_result == 0);
    assert(cert != NULL);
    assert(cert->common_name != NULL);
    assert(strcmp(cert->common_name, "test.localhost") == 0);
    assert(cert->valid_from > 0);
    assert(cert->valid_until > cert->valid_from);
    assert(cert->cert_type == CERT_TYPE_FEDERATED);
    
    // Verify signature (not all zeros)
    int signature_has_value = 0;
    for (int i = 0; i < sizeof(cert->signature); i++) {
        if (cert->signature[i] != 0) {
            signature_has_value = 1;
            break;
        }
    }
    assert(signature_has_value);
    
    // Clean up
    free_certificate(cert);
    cleanup_certificate_authority(ca_ctx);
    
    // Clean up network context
    free((void*)net_ctx.mode);
    free((void*)net_ctx.hostname);
    free((void*)net_ctx.server);
    
    printf("Certificate request handling test passed\n");
}

static void test_certificate_verification(void) {
    printf("Testing certificate verification with Falcon...\n");
    
    // Create a minimal network context
    network_context_t net_ctx;
    memset(&net_ctx, 0, sizeof(network_context_t));
    net_ctx.mode = strdup("private");
    net_ctx.hostname = strdup("localhost");
    net_ctx.server = strdup("localhost");
    
    // Initialize the CA
    ca_context_t *ca_ctx = NULL;
    int init_result = init_certificate_authority(&net_ctx, &ca_ctx);
    assert(init_result == 0);
    assert(ca_ctx != NULL);
    
    // Request a certificate
    nexus_cert_t *cert = NULL;
    int request_result = handle_cert_request(ca_ctx, "test.localhost", &cert);
    assert(request_result == 0);
    assert(cert != NULL);
    
    // Verify the certificate
    int verify_result = verify_certificate(cert, ca_ctx);
    assert(verify_result == 0);
    printf("Certificate verification successful\n");
    
    // Tamper with the certificate and verify it fails
    nexus_cert_t *tampered_cert = (nexus_cert_t *)malloc(sizeof(nexus_cert_t));
    memcpy(tampered_cert, cert, sizeof(nexus_cert_t));
    tampered_cert->common_name = strdup("tampered.localhost");
    
    verify_result = verify_certificate(tampered_cert, ca_ctx);
    assert(verify_result != 0);
    printf("Tampered certificate verification failed as expected\n");
    
    // Clean up
    free(tampered_cert->common_name);
    free(tampered_cert);
    free_certificate(cert);
    cleanup_certificate_authority(ca_ctx);
    
    // Clean up network context
    free((void*)net_ctx.mode);
    free((void*)net_ctx.hostname);
    free((void*)net_ctx.server);
    
    printf("Certificate verification test passed\n");
}

static void test_falcon_keypair_generation(void) {
    printf("Testing Falcon keypair generation...\n");
    
    uint8_t public_key[1793];  // Falcon-1024 public key size
    uint8_t private_key[2305]; // Falcon-1024 private key size
    
    // Clear keys before test
    memset(public_key, 0, sizeof(public_key));
    memset(private_key, 0, sizeof(private_key));
    
    // Generate keypair
    int result = generate_falcon_keypair(public_key, private_key);
    assert(result == 0);
    
    // Verify keys have proper values (not all zeros)
    int public_key_has_value = 0;
    int private_key_has_value = 0;
    
    for (int i = 0; i < sizeof(public_key); i++) {
        if (public_key[i] != 0) {
            public_key_has_value = 1;
            break;
        }
    }
    
    for (int i = 0; i < sizeof(private_key); i++) {
        if (private_key[i] != 0) {
            private_key_has_value = 1;
            break;
        }
    }
    
    assert(public_key_has_value);
    assert(private_key_has_value);
    
    printf("Falcon keypair generation test passed\n");
}

static void test_falcon_sign_and_verify(void) {
    printf("Testing Falcon signature and verification...\n");
    
    uint8_t public_key[1793];  // Falcon-1024 public key size
    uint8_t private_key[2305]; // Falcon-1024 private key size
    uint8_t signature[1330];   // Falcon-1024 signature size
    
    // Generate keypair
    int result = generate_falcon_keypair(public_key, private_key);
    assert(result == 0);
    
    // Create test message
    const char *message = "This is a test message to sign";
    
    // Sign the message
    result = falcon_sign(private_key, message, strlen(message), signature);
    assert(result == 0);
    
    // Verify signature has value (not all zeros)
    int signature_has_value = 0;
    for (int i = 0; i < sizeof(signature); i++) {
        if (signature[i] != 0) {
            signature_has_value = 1;
            break;
        }
    }
    assert(signature_has_value);
    
    // Verify the signature
    result = falcon_verify_sig(public_key, message, strlen(message), signature);
    assert(result == 0);
    printf("Signature verification successful\n");
    
    // Modify the message and verify it fails
    const char *modified_message = "This is a modified test message";
    result = falcon_verify_sig(public_key, modified_message, strlen(modified_message), signature);
    assert(result != 0);
    printf("Modified message verification failed as expected\n");
    
    printf("Falcon signature and verification test passed\n");
}

static void test_certificate_chain(void) {
    printf("Testing certificate chain with Falcon...\n");
    
    // Create a minimal network context
    network_context_t net_ctx;
    memset(&net_ctx, 0, sizeof(network_context_t));
    net_ctx.mode = strdup("private");
    net_ctx.hostname = strdup("localhost");
    net_ctx.server = strdup("localhost");
    
    // Initialize the CA
    ca_context_t *ca_ctx = NULL;
    int init_result = init_certificate_authority(&net_ctx, &ca_ctx);
    assert(init_result == 0);
    assert(ca_ctx != NULL);
    
    // Request a certificate for a domain
    nexus_cert_t *domain_cert = NULL;
    int request_result = handle_cert_request(ca_ctx, "domain.localhost", &domain_cert);
    assert(request_result == 0);
    assert(domain_cert != NULL);
    
    // Request a certificate for a subdomain
    nexus_cert_t *subdomain_cert = NULL;
    request_result = handle_cert_request(ca_ctx, "sub.domain.localhost", &subdomain_cert);
    assert(request_result == 0);
    assert(subdomain_cert != NULL);
    
    // Verify both certificates against the CA
    int verify_result = verify_certificate(domain_cert, ca_ctx);
    assert(verify_result == 0);
    
    verify_result = verify_certificate(subdomain_cert, ca_ctx);
    assert(verify_result == 0);
    
    // Clean up
    free_certificate(domain_cert);
    free_certificate(subdomain_cert);
    cleanup_certificate_authority(ca_ctx);
    
    // Clean up network context
    free((void*)net_ctx.mode);
    free((void*)net_ctx.hostname);
    free((void*)net_ctx.server);
    
    printf("Certificate chain test passed\n");
}

void test_certificate_authority_all(void) {
    printf("\n=== Running Certificate Authority Tests with Falcon ===\n");
    
    test_ca_initialization();
    test_certificate_request();
    test_certificate_verification();
    test_falcon_keypair_generation();
    test_falcon_sign_and_verify();
    test_certificate_chain();
    
    printf("All certificate authority tests completed successfully\n");
} 