#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <time.h>
#include "../include/certificate_transparency.h"
#include "../include/network_context.h"
#include "test_certificate_transparency.h"
#include "../include/certificate_authority.h"

// Helper function to create a proper certificate for testing
static nexus_cert_t* create_test_certificate(const char* name) {
    nexus_cert_t* cert = (nexus_cert_t*)malloc(sizeof(nexus_cert_t));
    if (!cert) return NULL;
    
    memset(cert, 0, sizeof(nexus_cert_t));
    cert->common_name = strdup(name);
    if (!cert->common_name) {
        free(cert);
        return NULL;
    }
    
    // Set certificate properties
    cert->valid_from = (uint64_t)time(NULL);
    cert->valid_until = cert->valid_from + (90 * 24 * 60 * 60); // Valid for 90 days
    cert->cert_type = CERT_TYPE_FEDERATED;
    
    // Generate a Falcon keypair
    uint8_t public_key[1793];
    uint8_t private_key[2305];
    if (generate_falcon_keypair(public_key, private_key) != 0) {
        free(cert->common_name);
        free(cert);
        return NULL;
    }
    
    // Create message to sign
    uint8_t message[1024];
    size_t message_len = 0;
    
    // Add common_name to message
    size_t common_name_len = strlen(cert->common_name);
    memcpy(message + message_len, cert->common_name, common_name_len);
    message_len += common_name_len;
    
    // Add validity period to message
    memcpy(message + message_len, &cert->valid_from, sizeof(cert->valid_from));
    message_len += sizeof(cert->valid_from);
    memcpy(message + message_len, &cert->valid_until, sizeof(cert->valid_until));
    message_len += sizeof(cert->valid_until);
    
    // Add cert_type to message
    memcpy(message + message_len, &cert->cert_type, sizeof(cert->cert_type));
    message_len += sizeof(cert->cert_type);
    
    // Sign the certificate
    if (falcon_sign(private_key, message, message_len, cert->signature) != 0) {
        free(cert->common_name);
        free(cert);
        return NULL;
    }
    
    return cert;
}

static void free_test_certificate(nexus_cert_t* cert) {
    if (cert) {
        free(cert->common_name);
        free(cert);
    }
}

static void test_ct_log_creation(void) {
    printf("Testing CT log creation with Falcon keys...\n");
    
    ct_log_t *log = create_ct_log("test_creation.ctlog", "testnode.local", "private");
    assert(log != NULL);
    assert(log->entries != NULL);
    assert(log->entry_count == 0);
    assert(log->max_entries > 0);
    assert(log->keys != NULL);
    
    // Verify Falcon keys were generated
    int public_key_has_value = 0;
    int private_key_has_value = 0;
    
    for (int i = 0; i < (int)sizeof(log->keys->public_key); i++) {
        if (log->keys->public_key[i] != 0) {
            public_key_has_value = 1;
            break;
        }
    }
    
    for (int i = 0; i < (int)sizeof(log->keys->private_key); i++) {
        if (log->keys->private_key[i] != 0) {
            private_key_has_value = 1;
            break;
        }
    }
    
    assert(public_key_has_value);
    assert(private_key_has_value);
    
    cleanup_certificate_transparency(log);
    printf("CT log creation test passed\n");
}

static void test_certificate_operations(void) {
    printf("Testing certificate operations in CT log with Falcon signatures...\n");
    
    ct_log_t *log = create_ct_log("test_ops.ctlog", "opsnode.local", "private");
    assert(log != NULL);
    
    nexus_cert_t *cert = create_test_certificate("ops.example.com");
    assert(cert != NULL);
    
    // Add certificate to log
    ct_log_entry_t* entry = add_certificate_to_ct_log(log, cert, NULL, 0);
    assert(entry != NULL);
    assert(log->entry_count == 1);
    
    // Verify entry signature (not all zeros)
    int signature_has_value = 0;
    for (int i = 0; i < (int)sizeof(entry->signature); i++) {
        if (entry->signature[i] != 0) {
            signature_has_value = 1;
            break;
        }
    }
    assert(signature_has_value);
    
    // Verify certificate is in the log
    int found = verify_certificate_in_ct_log(log, cert, NULL);
    assert(found == 1);
    
    // Get proof of inclusion
    ct_proof_t *proof = NULL;
    found = verify_certificate_in_ct_log(log, cert, &proof);
    assert(found == 1);
    assert(proof != NULL);
    assert(proof->log_pubkey != NULL);
    assert(proof->log_pubkey_len > 0);
    
    // Verify log's public key was copied to the proof
    int pubkey_match = 1;
    for (size_t i = 0; i < proof->log_pubkey_len; i++) {
        if (proof->log_pubkey[i] != log->keys->public_key[i]) {
            pubkey_match = 0;
            break;
        }
    }
    assert(pubkey_match);
    
    free_ct_proof(proof);
    free_test_certificate(cert);
    cleanup_certificate_transparency(log);
    
    printf("Certificate operations tests passed\n");
}

static void test_merkle_tree(void) {
    printf("Testing Merkle tree with Falcon signatures...\n");
    ct_log_t* log = create_ct_log("test_log_merkle.ct", "merkle.node.com", "test_mode");
    assert(log != NULL);

    // Add several certificates to the log
    for (int i = 0; i < 5; ++i) {
        char cert_name[256];
        snprintf(cert_name, sizeof(cert_name), "test%d.example.com", i);
        nexus_cert_t* cert_loop = create_test_certificate(cert_name);
        assert(cert_loop != NULL);
        ct_log_entry_t* entry = add_certificate_to_ct_log(log, cert_loop, NULL, 0);
        assert(entry != NULL);
        free_test_certificate(cert_loop);
    }

    // Build the Merkle tree
    int build_result = build_merkle_tree(log);
    assert(build_result == 0);

    // Add another certificate and verify it
    nexus_cert_t* cert1 = create_test_certificate("verify.example.com");
    assert(cert1 != NULL);
    ct_log_entry_t* entry1 = add_certificate_to_ct_log(log, cert1, NULL, 0);
    assert(entry1 != NULL);

    // Rebuild the Merkle tree
    build_result = build_merkle_tree(log);
    assert(build_result == 0);

    // Get proof of inclusion
    ct_proof_t* proof = NULL;
    int verified = verify_certificate_in_ct_log(log, cert1, &proof);
    assert(verified == 1);
    assert(proof != NULL);
    
    // Verify proof has the log's public key
    assert(proof->log_pubkey != NULL);
    assert(proof->log_pubkey_len > 0);
    
    // Check that a non-existent certificate is not found
    nexus_cert_t* cert_non_existent = create_test_certificate("nonexistent.example.com");
    assert(cert_non_existent != NULL);
    verified = verify_certificate_in_ct_log(log, cert_non_existent, NULL);
    assert(verified != 1);
    
    // Clean up
    free_ct_proof(proof);
    free_test_certificate(cert1);
    free_test_certificate(cert_non_existent);
    cleanup_certificate_transparency(log);
    
    printf("Merkle tree operations test passed\n");
}

static void test_signature_verification(void) {
    printf("Testing CT log entry signature verification...\n");
    
    // Initialize RNG
    shake256_context rng;
    assert(shake256_init_prng_from_system(&rng) == 0);
    
    // Create keypair
    uint8_t private_key[FALCON_PRIVKEY_SIZE(10)];
    uint8_t public_key[FALCON_PUBKEY_SIZE(10)];
    uint8_t tmp[FALCON_TMPSIZE_KEYGEN(10)];
    
    assert(falcon_keygen_make(&rng, 10, private_key, sizeof(private_key), 
                             public_key, sizeof(public_key), 
                             tmp, sizeof(tmp)) == 0);
    
    // Create test message
    const char *message = "Test message for Falcon signature verification in CT log";
    size_t message_len = strlen(message);
    
    // Sign the message
    uint8_t signature[FALCON_SIG_COMPRESSED_MAXSIZE(10)];
    size_t signature_len = FALCON_SIG_COMPRESSED_MAXSIZE(10);
    
    uint8_t tmp2[FALCON_TMPSIZE_SIGNDYN(10)];
    
    assert(falcon_sign_dyn(&rng, signature, &signature_len, FALCON_SIG_COMPRESSED,
                          private_key, sizeof(private_key), 
                          message, message_len,
                          tmp2, sizeof(tmp2)) == 0);
    
    printf("Message signed successfully, signature length: %zu bytes\n", signature_len);
    
    // Verify the signature
    uint8_t tmp3[FALCON_TMPSIZE_VERIFY(10)];
    
    int verify_result = falcon_verify(signature, signature_len, FALCON_SIG_COMPRESSED,
                                     public_key, sizeof(public_key),
                                     message, message_len,
                                     tmp3, sizeof(tmp3));
    
    assert(verify_result == 0);
    printf("Signature verified successfully\n");
    
    // Tamper with the message and verify the signature fails
    char tampered_message[256];
    strcpy(tampered_message, message);
    tampered_message[0] ^= 0xFF; // Flip some bits
    
    verify_result = falcon_verify(signature, signature_len, FALCON_SIG_COMPRESSED,
                                 public_key, sizeof(public_key),
                                 tampered_message, strlen(tampered_message),
                                 tmp3, sizeof(tmp3));
    
    assert(verify_result != 0);
    printf("Tampered message verification failed as expected\n");
    
    printf("CT log entry signature verification test passed\n");
}

static void test_network_context_integration(void) {
    printf("Testing CT log with network context integration...\n");
    
    network_context_t net_ctx;
    memset(&net_ctx, 0, sizeof(network_context_t));
    net_ctx.mode = 0; // 0 = private mode
    net_ctx.hostname = strdup("localhost");
    
    // Initialize network context components
    int result = init_network_context_components(&net_ctx);
    assert(result == 0);

    ct_log_t *log = init_certificate_transparency(&net_ctx);
    assert(log != NULL);
    assert(log->keys != NULL);
    
    // Verify Falcon keys were generated
    int public_key_has_value = 0;
    int private_key_has_value = 0;
    
    for (int i = 0; i < (int)sizeof(log->keys->public_key); i++) {
        if (log->keys->public_key[i] != 0) {
            public_key_has_value = 1;
            break;
        }
    }
    
    for (int i = 0; i < (int)sizeof(log->keys->private_key); i++) {
        if (log->keys->private_key[i] != 0) {
            private_key_has_value = 1;
            break;
        }
    }
    
    assert(public_key_has_value);
    assert(private_key_has_value);
    
    cleanup_certificate_transparency(log);
    cleanup_network_context_components(&net_ctx);
    free(net_ctx.hostname);
    
    printf("Network context integration test passed\n");
}

static void test_ca_ct_integration(void) {
    printf("Testing certificate authority and transparency integration...\n");
    
    // Create a minimal network context
    network_context_t net_ctx;
    memset(&net_ctx, 0, sizeof(network_context_t));
    net_ctx.mode = 0; // 0 = private mode
    net_ctx.hostname = strdup("localhost");
    
    // Initialize network context components
    int init_comp_result = init_network_context_components(&net_ctx);
    assert(init_comp_result == 0);
    
    // Initialize the CA
    ca_context_t *ca_ctx = NULL;
    int init_result = init_certificate_authority(&net_ctx, &ca_ctx);
    assert(init_result == 0);
    assert(ca_ctx != NULL);
    
    // Initialize certificate transparency log
    ct_log_t *log = init_certificate_transparency(&net_ctx);
    assert(log != NULL);
    
    // Request a certificate from the CA
    nexus_cert_t *cert = NULL;
    int result = handle_cert_request(ca_ctx, "integration.test.com", &cert);
    assert(result == 0);
    assert(cert != NULL);
    
    // Add the certificate to the CT log
    ct_log_entry_t* entry = add_certificate_to_ct_log(log, cert, NULL, 0);
    assert(entry != NULL);
    
    // Verify the certificate is in the log
    int found = verify_certificate_in_ct_log(log, cert, NULL);
    assert(found == 1);
    
    // Get a proof of inclusion
    ct_proof_t *proof = NULL;
    found = verify_certificate_in_ct_log(log, cert, &proof);
    assert(found == 1);
    assert(proof != NULL);
    
    // Clean up
    free_ct_proof(proof);
    free_certificate(cert);
    cleanup_certificate_transparency(log);
    cleanup_certificate_authority(ca_ctx);
    cleanup_network_context_components(&net_ctx);
    free(net_ctx.hostname);
    
    printf("CA and CT integration test passed\n");
}

void test_certificate_transparency_all(void) {
    printf("\n=== Running Certificate Transparency Tests with Falcon ===\n");
    
    test_ct_log_creation();
    test_certificate_operations();
    test_merkle_tree();
    test_signature_verification();
    test_network_context_integration();
    test_ca_ct_integration();
    
    printf("All certificate transparency tests passed\n");
} 