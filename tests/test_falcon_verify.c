#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/extern/falcon/falcon.h"

int main(void) {
    printf("=== Falcon Sign/Verify Test ===\n");
    
    // Initialize RNG
    shake256_context rng;
    if (shake256_init_prng_from_system(&rng) != 0) {
        printf("Failed to initialize RNG\n");
        return 1;
    }
    
    // Create keypair
    uint8_t private_key[FALCON_PRIVKEY_SIZE(10)];
    uint8_t public_key[FALCON_PUBKEY_SIZE(10)];
    uint8_t tmp[FALCON_TMPSIZE_KEYGEN(10)];
    
    printf("Generating keypair...\n");
    int ret = falcon_keygen_make(&rng, 10, private_key, sizeof(private_key), 
                          public_key, sizeof(public_key), 
                          tmp, sizeof(tmp));
    if (ret != 0) {
        printf("Failed to generate keypair with error code %d\n", ret);
        return 1;
    }
    
    printf("Keypair generated successfully\n");
    printf("Public key starts with: 0x%02x 0x%02x 0x%02x...\n", 
           public_key[0], public_key[1], public_key[2]);
    
    // Message to sign
    const char *message = "Test message for Falcon";
    size_t message_len = strlen(message);
    
    // Sign the message
    uint8_t signature[FALCON_SIG_COMPRESSED_MAXSIZE(10)];
    size_t signature_len = FALCON_SIG_COMPRESSED_MAXSIZE(10);
    
    uint8_t tmp2[FALCON_TMPSIZE_SIGNDYN(10)];
    
    printf("Signing message...\n");
    ret = falcon_sign_dyn(&rng, signature, &signature_len, FALCON_SIG_COMPRESSED,
                       private_key, sizeof(private_key), 
                       message, message_len,
                       tmp2, sizeof(tmp2));
    if (ret != 0) {
        printf("Failed to sign message with error code %d\n", ret);
        return 1;
    }
    
    printf("Message signed successfully, signature length: %zu\n", signature_len);
    printf("Signature starts with: 0x%02x 0x%02x 0x%02x...\n", 
           signature[0], signature[1], signature[2]);
    
    // Verify the signature
    uint8_t tmp3[FALCON_TMPSIZE_VERIFY(10)];
    
    printf("Verifying signature...\n");
    ret = falcon_verify(signature, signature_len, FALCON_SIG_COMPRESSED,
                       public_key, sizeof(public_key),
                       message, message_len,
                       tmp3, sizeof(tmp3));
    
    if (ret != 0) {
        printf("Signature verification failed with code %d\n", ret);
        return 1;
    }
    
    printf("Signature verified successfully\n");
    
    // Tamper with the message and verify it fails
    const char *tampered = "Tampered message for Falcon";
    size_t tampered_len = strlen(tampered);
    
    printf("Verifying with tampered message (should fail)...\n");
    ret = falcon_verify(signature, signature_len, FALCON_SIG_COMPRESSED,
                       public_key, sizeof(public_key),
                       tampered, tampered_len,
                       tmp3, sizeof(tmp3));
    
    if (ret == 0) {
        printf("ERROR: Tampered message verification should have failed\n");
        return 1;
    }
    
    printf("Tampered message verification failed as expected with code %d\n", ret);
    
    printf("All tests passed\n");
    return 0;
} 