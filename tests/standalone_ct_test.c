#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "../include/certificate_authority.h"
#include "../include/certificate_transparency.h"
#include "../include/network_context.h"

// Test CT log creation
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
    
    for (int i = 0; i < sizeof(log->keys->public_key); i++) {
        if (log->keys->public_key[i] != 0) {
            public_key_has_value = 1;
            break;
        }
    }
    
    for (int i = 0; i < sizeof(log->keys->private_key); i++) {
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

// Helper function to create a test certificate
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

// Helper to free a test certificate
static void free_test_certificate(nexus_cert_t* cert) {
    if (cert) {
        free(cert->common_name);
        free(cert);
    }
}

// Test certificate operations
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
    for (int i = 0; i < sizeof(entry->signature); i++) {
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

int test_standalone_ct_main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    
    printf("\n=== Running Certificate Transparency Tests with Falcon ===\n");
    test_ct_log_creation();
    test_certificate_operations();
    printf("All certificate transparency tests passed\n");
    return 0;
} 