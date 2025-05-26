#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "../include/certificate_authority.h"
#include "../include/network_context.h"

// Redefine the test functions here to avoid linking issues
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

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    
    printf("\n=== Running Certificate Authority Test with Falcon ===\n");
    test_ca_initialization();
    printf("All tests passed successfully!\n");
    return 0;
} 