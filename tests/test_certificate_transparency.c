#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../include/certificate_transparency.h"
#include "../include/network_context.h"
#include "test_certificate_transparency.h"

// Mock certificate for testing
static nexus_cert_t* create_mock_certificate(void) {
    nexus_cert_t *cert = malloc(sizeof(nexus_cert_t));
    assert(cert != NULL);
    
    // Fill with test data
    memset(cert, 0, sizeof(nexus_cert_t));
    strncpy(cert->subject, "test.example.com", sizeof(cert->subject) - 1);
    cert->valid_from = 1000000000;  // Some timestamp
    cert->valid_until = 2000000000; // Some future timestamp
    
    return cert;
}

static void test_ct_log_creation(void) {
    printf("Testing CT log creation...\n");
    
    ct_log_t *log = NULL;
    assert(create_ct_log("test-scope", &log) == 0);
    assert(log != NULL);
    assert(log->scope_id != NULL);
    assert(strcmp(log->scope_id, "test-scope") == 0);
    assert(log->entries != NULL);
    assert(log->entry_count == 0);
    assert(log->max_entries > 0);
    
    cleanup_certificate_transparency(log);
    printf("CT log creation test passed\n");
}

static void test_certificate_operations(void) {
    printf("Testing certificate operations in CT log...\n");
    
    ct_log_t *log = NULL;
    assert(create_ct_log("test-scope", &log) == 0);
    
    // Create a test certificate
    nexus_cert_t *cert = create_mock_certificate();
    
    // Add certificate to log
    assert(add_certificate_to_ct_log(log, cert) == 0);
    assert(log->entry_count == 1);
    
    // Verify certificate in log
    assert(verify_certificate_in_ct_log(log, cert, NULL) == 0);
    
    // Get proof for certificate
    ct_proof_t *proof = NULL;
    assert(verify_certificate_in_ct_log(log, cert, &proof) == 0);
    assert(proof != NULL);
    
    // Verify the proof
    assert(verify_merkle_proof(proof, log) == 0);
    
    // Clean up
    free_ct_proof(proof);
    free(cert);
    cleanup_certificate_transparency(log);
    
    printf("Certificate operations tests passed\n");
}

static void test_merkle_tree(void) {
    printf("Testing Merkle tree operations...\n");
    
    ct_log_t *log = NULL;
    assert(create_ct_log("test-scope", &log) == 0);
    
    // Add multiple certificates
    for (int i = 0; i < 5; i++) {
        nexus_cert_t *cert = create_mock_certificate();
        snprintf(cert->subject, sizeof(cert->subject), "test%d.example.com", i);
        assert(add_certificate_to_ct_log(log, cert) == 0);
        // Note: We're leaking certificates here, but in this simple test it's acceptable
    }
    
    assert(log->entry_count == 5);
    
    // Build Merkle tree
    assert(build_merkle_tree(log) == 0);
    
    // Check that the Merkle tree was created
    assert(log->merkle_tree != NULL);
    
    cleanup_certificate_transparency(log);
    printf("Merkle tree operations test passed\n");
}

static void test_network_context_integration(void) {
    printf("Testing CT log with network context...\n");
    
    // Create a minimal network context
    network_context_t net_ctx;
    memset(&net_ctx, 0, sizeof(network_context_t));
    net_ctx.mode = strdup("private");
    net_ctx.hostname = strdup("localhost");
    net_ctx.server = strdup("localhost");
    
    // Initialize CT for this context
    ct_log_t *log = NULL;
    assert(init_certificate_transparency(&net_ctx, &log) == 0);
    assert(log != NULL);
    
    // Check that scope ID includes mode and hostname
    assert(strstr(log->scope_id, "private") != NULL);
    assert(strstr(log->scope_id, "localhost") != NULL);
    
    // Clean up
    cleanup_certificate_transparency(log);
    free((void*)net_ctx.mode);
    free((void*)net_ctx.hostname);
    free((void*)net_ctx.server);
    
    printf("Network context integration test passed\n");
}

void test_certificate_transparency_all(void) {
    printf("\n=== Running Certificate Transparency Tests ===\n");
    
    test_ct_log_creation();
    test_certificate_operations();
    test_merkle_tree();
    test_network_context_integration();
    
    printf("All certificate transparency tests passed\n");
} 