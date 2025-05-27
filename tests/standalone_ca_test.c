#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../include/certificate_authority.h"
#include "../include/network_context.h"
#include "../include/system.h"

int test_standalone_ca_main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    
    printf("\n=== Running Simplified CA Test ===\n");
    
    // Test key generation directly
    printf("Testing Falcon key generation...\n");
    uint8_t public_key[FALCON_PUBKEY_SIZE(10)];
    uint8_t private_key[FALCON_PRIVKEY_SIZE(10)];
    
    int result = generate_falcon_keypair(public_key, private_key);
    printf("Key generation result: %d\n", result);
    
    // Check that the keys contain non-zero values
    int has_nonzero_pub = 0;
    int has_nonzero_priv = 0;
    
    for (int i = 0; i < 10; i++) {
        if (public_key[i] != 0) has_nonzero_pub = 1;
        if (private_key[i] != 0) has_nonzero_priv = 1;
    }
    
    printf("Public key has non-zero values: %s\n", has_nonzero_pub ? "yes" : "no");
    printf("Private key has non-zero values: %s\n", has_nonzero_priv ? "yes" : "no");
    
    // Test signature generation
    printf("\nTesting Falcon signature...\n");
    uint8_t message[] = "Test message for Falcon signature";
    size_t message_len = strlen((char*)message);
    
    uint8_t signature[FALCON_SIG_CT_SIZE(10)];
    memset(signature, 0, sizeof(signature));
    
    result = falcon_sign(private_key, message, message_len, signature);
    printf("Signature generation result: %d\n", result);
    
    // Check signature contains non-zero values
    int has_nonzero_sig = 0;
    for (int i = 0; i < 10; i++) {
        if (signature[i] != 0) has_nonzero_sig = 1;
    }
    printf("Signature has non-zero values: %s\n", has_nonzero_sig ? "yes" : "no");
    
    // Test signature verification
    printf("\nTesting Falcon verification...\n");
    result = falcon_verify_sig(public_key, message, message_len, signature);
    printf("Signature verification result: %d\n", result);
    
    printf("\nTest completed\n");
    return 0;
} 