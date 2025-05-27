#include "../include/certificate_transparency.h"
#include "../include/certificate_authority.h"
#include "../include/debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <pthread.h>

// Initialize certificate transparency
ct_log_t* init_certificate_transparency(network_context_t *net_ctx) {
    if (!net_ctx || !net_ctx->hostname || !net_ctx->mode) {
        fprintf(stderr, "Error: Invalid network context for CT log initialization.\n");
        return NULL;
    }

    // Construct a log filename, e.g., "private_myhost_ct.log"
    char log_filename[512];
    snprintf(log_filename, sizeof(log_filename), "%s_%s_ct.log", net_ctx->mode, net_ctx->hostname);

    ct_log_t *log = create_ct_log(log_filename, net_ctx->hostname, net_ctx->mode);
    if (!log) {
        fprintf(stderr, "Error: Failed to create CT log during initialization.\n");
        return NULL;
    }
    
    // The scope_id is now set inside create_ct_log based on its params
    // log->scope_id = strdup(scope_id_buffer); // No longer needed here directly

    printf("Certificate Transparency log initialized for scope: %s\n", log->scope_id ? log->scope_id : "N/A");
    return log;
}

// Clean up certificate transparency
void cleanup_certificate_transparency(ct_log_t *ct_log) {
    if (!ct_log) {
        return;
    }
    
    dlog("Cleaning up certificate transparency log for scope %s", ct_log->scope_id);
    
    pthread_mutex_lock(&ct_log->lock);
    
    // Free all entries
    for (int i = 0; i < ct_log->entry_count; i++) {
        free_ct_log_entry(ct_log->entries[i]);
    }
    
    // Free entries array
    free(ct_log->entries);
    
    // Free merkle tree if it exists
    if (ct_log->merkle_tree) {
        // Check if it's not the (void*)1 placeholder before treating as merkle_tree_t*
        if (ct_log->merkle_tree != (void*)1) {
            merkle_tree_t *tree = (merkle_tree_t *)ct_log->merkle_tree;
            if (tree->root) { // If root was allocated, free it
                // In a real tree, this would be a recursive free of all nodes
                free(tree->root);
            }
            free(tree); // Free the tree structure itself
        }
        ct_log->merkle_tree = NULL;
    }
    
    // Free scope ID
    free(ct_log->scope_id);
    
    pthread_mutex_unlock(&ct_log->lock);
    pthread_mutex_destroy(&ct_log->lock);
    
    // Free the log itself
    free(ct_log);
}

// Create a new CT log
ct_log_t* create_ct_log(const char *log_filename, const char *node_hostname, const char *network_mode) {
    ct_log_t *log = (ct_log_t*)malloc(sizeof(ct_log_t));
    if (!log) {
        perror("Failed to allocate memory for CT log");
        return NULL;
    }
    
    // Initialize the log structure
    memset(log, 0, sizeof(ct_log_t));
    
    // Initialize mutex
    if (pthread_mutex_init(&log->lock, NULL) != 0) {
        perror("Failed to initialize mutex for CT log");
        free(log);
        return NULL;
    }
    
    // Initialize entries array
    log->max_entries = 1000; // Default max entries
    log->entries = (ct_log_entry_t**)malloc(sizeof(ct_log_entry_t*) * log->max_entries);
    if (!log->entries) {
        perror("Failed to allocate memory for CT log entries");
        pthread_mutex_destroy(&log->lock);
        free(log);
        return NULL;
    }
    memset(log->entries, 0, sizeof(ct_log_entry_t*) * log->max_entries);
    
    // Set log filename
    if (log_filename) {
        log->log_filename = strdup(log_filename);
        if (!log->log_filename) {
            perror("Failed to allocate memory for log filename");
            free(log->entries);
            pthread_mutex_destroy(&log->lock);
            free(log);
            return NULL;
        }
    } else {
        log->log_filename = NULL;
    }
    
    // Create a unique scope ID based on network mode and node hostname
    char scope_id_buf[256] = {0};
    if (network_mode || node_hostname) {
        snprintf(scope_id_buf, sizeof(scope_id_buf), "%s@%s", network_mode ? network_mode : "default_mode", node_hostname ? node_hostname : "default_host");
        log->scope_id = strdup(scope_id_buf);
    } else {
        log->scope_id = strdup("default_scope");
    }
    if (!log->scope_id) {
        perror("Failed to allocate memory for log scope_id");
        free(log->entries);
        free(log);
        return NULL;
    }
    
    // Initialize Falcon keys for the log
    log->keys = (falcon_keys_t*)malloc(sizeof(falcon_keys_t));
    if (!log->keys) {
        perror("Failed to allocate memory for Falcon keys");
        free(log->scope_id);
        free(log->entries);
        free(log);
        return NULL;
    }

    // Generate Falcon keypair for the log
    if (generate_falcon_keypair(log->keys->public_key, log->keys->private_key) != 0) {
        fprintf(stderr, "Failed to generate Falcon keypair for CT log\n");
        free(log->keys);
        free(log->scope_id);
        free(log->entries);
        free(log);
        return NULL;
    }

    printf("CT Log: Falcon keys initialized for log scope %s.\n", log->scope_id);

    return log;
}

// Load a CT log from disk
int load_ct_log(const char *path, ct_log_t **ct_log) {
    // This is a stub implementation
    // In a real implementation, this would load the log from the given path
    printf("load_ct_log: STUB IMPLEMENTATION. Path: %s\n", path);
    if (!path || !ct_log) {
        return -1; // Invalid arguments
    }

    // Create a new dummy log for now, as if it were loaded
    // Use the new signature for create_ct_log: ct_log_t* create_ct_log(const char *log_filename, const char *node_hostname, const char *network_mode)
    *ct_log = create_ct_log(path, "loaded_host", "loaded_mode");
    if (!*ct_log) {
        fprintf(stderr, "load_ct_log: Failed to create dummy log for path %s\n", path);
        return -1;
    }
    
    // Simulate loading some data or setting a specific state if needed for testing stubs
    printf("load_ct_log: Successfully created dummy log for path %s\n", path);
    return 0; // Success
}

// Save a CT log to disk
int save_ct_log(const ct_log_t *ct_log, const char *path) {
    if (!ct_log || !path) {
        return -1;
    }
    
    dlog("Saving CT log to %s (stub implementation)", path);
    
    // This is a stub implementation
    // In a real implementation, this would save to disk
    
    // For now, just create an empty file
    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "Failed to open %s for writing\n", path);
        return -1;
    }
    
    fclose(f);
    
    return 0; // Success
}

// Add a certificate to the CT log
ct_log_entry_t* add_certificate_to_ct_log(ct_log_t *log, nexus_cert_t *cert, const uint8_t *sct_signature, size_t sct_signature_len) {
    if (!log || !cert) {
        fprintf(stderr, "Error: Invalid arguments to add_certificate_to_ct_log.\n");
        return NULL;
    }

    pthread_mutex_lock(&log->lock);

    if (log->entry_count >= log->max_entries) {
        fprintf(stderr, "Error: CT log is full. Cannot add new certificate.\n");
        pthread_mutex_unlock(&log->lock);
        return NULL;
    }

    ct_log_entry_t *entry = (ct_log_entry_t *)malloc(sizeof(ct_log_entry_t));
    if (!entry) {
        perror("Failed to allocate memory for CT log entry");
        pthread_mutex_unlock(&log->lock);
        return NULL;
    }

    entry->timestamp = (uint64_t)time(NULL); // Current time
    
    // Create a copy of the certificate data for the log entry
    entry->cert = (nexus_cert_t*)malloc(sizeof(nexus_cert_t));
    if(!entry->cert) {
        perror("Failed to allocate memory for cert in log entry");
        free(entry);
        pthread_mutex_unlock(&log->lock);
        return NULL;
    }
    
    // Copy certificate data
    if (cert->common_name) {
        entry->cert->common_name = strdup(cert->common_name);
        if (!entry->cert->common_name) {
             perror("Failed to duplicate common_name for log entry");
             free(entry->cert);
             free(entry);
             pthread_mutex_unlock(&log->lock);
             return NULL;
        }
    } else {
        entry->cert->common_name = NULL;
    }
    
    // Copy other certificate fields
    entry->cert->valid_from = cert->valid_from;
    entry->cert->valid_until = cert->valid_until;
    entry->cert->cert_type = cert->cert_type;
    memcpy(entry->cert->signature, cert->signature, sizeof(cert->signature));

    // Create message to sign (cert + timestamp + log_id)
    uint8_t message[2048];
    size_t message_len = 0;
    
    // Add certificate common_name to message
    if (entry->cert->common_name) {
        size_t common_name_len = strlen(entry->cert->common_name);
        memcpy(message + message_len, entry->cert->common_name, common_name_len);
        message_len += common_name_len;
    }
    
    // Add certificate signature to message
    memcpy(message + message_len, entry->cert->signature, sizeof(entry->cert->signature));
    message_len += sizeof(entry->cert->signature);
    
    // Add timestamp to message
    memcpy(message + message_len, &entry->timestamp, sizeof(entry->timestamp));
    message_len += sizeof(entry->timestamp);
    
    // Calculate SHA-256 of log's public key for log_id
    // In a real implementation, this would be:
    // SHA256(log->keys->public_key, sizeof(log->keys->public_key), entry->log_id);
    // For now, we'll use a simplified hash (first 32 bytes of public key)
    memcpy(entry->log_id, log->keys->public_key, sizeof(entry->log_id));
    
    // Add log_id to message
    memcpy(message + message_len, entry->log_id, sizeof(entry->log_id));
    message_len += sizeof(entry->log_id);
    
    // Sign the entry with the log's private key
    if (falcon_sign(log->keys->private_key, message, message_len, entry->signature) != 0) {
        fprintf(stderr, "Failed to sign CT log entry\n");
        if(entry->cert->common_name) free(entry->cert->common_name);
        free(entry->cert);
        free(entry);
        pthread_mutex_unlock(&log->lock);
        return NULL;
    }

    entry->scope_id = strdup(log->scope_id); // Copy scope from log
    if(!entry->scope_id){
        perror("Failed to duplicate scope_id for log entry");
        if(entry->cert->common_name) free(entry->cert->common_name);
        free(entry->cert);
        free(entry);
        pthread_mutex_unlock(&log->lock);
        return NULL;
    }

    log->entries[log->entry_count++] = entry;

    // Rebuild Merkle tree (or update it incrementally)
    // build_merkle_tree(log); // This might be inefficient; consider incremental updates or batching.
    // For now, assume it's called separately or handled by the caller.

    pthread_mutex_unlock(&log->lock);
    
    // Suppress unused parameter warnings for sct_signature and sct_signature_len if not used yet
    (void)sct_signature;
    (void)sct_signature_len;

    return entry;
}

// Verify that a certificate is in the CT log
int verify_certificate_in_ct_log(ct_log_t *ct_log, nexus_cert_t *cert_to_find, ct_proof_t **proof) {
    if (!ct_log || !cert_to_find) {
        return -1;
    }
    
    dlog("Verifying certificate in CT log for scope %s", ct_log->scope_id);
    
    pthread_mutex_lock(&ct_log->lock);
    
    // Find the certificate in the log
    int found = 0;
    int index = -1;
    
    for (int i = 0; i < ct_log->entry_count; i++) {
        // In a real implementation, we would compare the certificate contents
        // For now, just compare the common name
        if (ct_log->entries[i]->cert->common_name && cert_to_find->common_name &&
            strcmp(ct_log->entries[i]->cert->common_name, cert_to_find->common_name) == 0) {
            found = 1;
            index = i;
            break;
        }
    }
    
    if (!found) {
        fprintf(stderr, "Certificate not found in CT log\n");
        pthread_mutex_unlock(&ct_log->lock);
        return -1;
    }
    
    // If proof is requested, generate it
    if (found && proof) {
        *proof = generate_merkle_proof(ct_log, cert_to_find);
        if (!*proof) {
            fprintf(stderr, "Error: Failed to generate Merkle proof for certificate.\n");
            // No specific error code to return here to indicate proof generation failure vs. not found
            // The function's main job is to find; proof is extra.
        }
    }
    
    pthread_mutex_unlock(&ct_log->lock);
    
    return found; // 1 if found, 0 if not
}

// Build a merkle tree from the certificates in the log
int build_merkle_tree(ct_log_t *ct_log) {
    if (!ct_log) {
        return -1;
    }
    
    dlog("Building merkle tree for CT log (stub - minimal allocation)");

    // Free existing tree to prevent leaks if called multiple times.
    // Note: This simple free won't handle a real tree with many nodes.
    if (ct_log->merkle_tree && ct_log->merkle_tree != (void*)1) {
        merkle_tree_t *old_tree = (merkle_tree_t *)ct_log->merkle_tree;
        // In a real tree, old_tree->root would be recursively freed here if it existed.
        // For this stub, if root was ever allocated, it should be freed too.
        if (old_tree->root) { 
            free(old_tree->root); 
        }
        free(old_tree);
    }
    ct_log->merkle_tree = NULL; // Set to NULL before new allocation

    merkle_tree_t *tree = (merkle_tree_t *)malloc(sizeof(merkle_tree_t));
    if (!tree) {
        perror("Failed to allocate Merkle tree (stub)");
        return -1;
    }
    tree->root = NULL; // CRITICAL: Initialize root to NULL for safe checking in generate_merkle_proof
    tree->leaf_count = ct_log->entry_count; // Or 0, as it's a stub

    ct_log->merkle_tree = tree;
    
    return 0;
}

// Verify a merkle proof
int verify_merkle_proof(ct_proof_t *proof, const uint8_t *expected_root_hash, size_t root_hash_len, ct_log_entry_t *entry_to_verify) {
    if (!proof || !expected_root_hash || !entry_to_verify) {
        return -1;
    }
    
    // Stub implementation for now
    // In a real implementation, this would verify the Merkle proof
    
    // Verify that the entry's signature is valid
    // Create message to verify (cert + timestamp + log_id)
    uint8_t message[2048];
    size_t message_len = 0;
    
    // Add certificate common_name to message
    if (entry_to_verify->cert->common_name) {
        size_t common_name_len = strlen(entry_to_verify->cert->common_name);
        memcpy(message + message_len, entry_to_verify->cert->common_name, common_name_len);
        message_len += common_name_len;
    }
    
    // Add certificate signature to message
    memcpy(message + message_len, entry_to_verify->cert->signature, sizeof(entry_to_verify->cert->signature));
    message_len += sizeof(entry_to_verify->cert->signature);
    
    // Add timestamp to message
    memcpy(message + message_len, &entry_to_verify->timestamp, sizeof(entry_to_verify->timestamp));
    message_len += sizeof(entry_to_verify->timestamp);
    
    // Add log_id to message
    memcpy(message + message_len, entry_to_verify->log_id, sizeof(entry_to_verify->log_id));
    message_len += sizeof(entry_to_verify->log_id);
    
    // Verify the signature using Falcon
    if (falcon_verify_sig(proof->log_pubkey, message, message_len, entry_to_verify->signature) != 0) {
        fprintf(stderr, "CT log entry signature verification failed\n");
        return -1;
    }
    
    // In a real implementation, we would also verify the Merkle path
    // For now, just compare the root hash
    if (root_hash_len != 32) {
        return -1; // Invalid root hash length
    }
    
    // For stub, assume verification passed
    printf("verify_merkle_proof: STUB implementation. Assuming proof is valid.\n");
    
    return 0; // Success
}

// Generate a merkle proof for a certificate
// NOTE: Caller must hold the log->lock before calling this function.
ct_proof_t* generate_merkle_proof(ct_log_t *log, nexus_cert_t *cert) {
    if (!log || !cert) {
        return NULL;
    }
    
    // Stub implementation for now
    // In a real implementation, this would generate a Merkle proof
    
    ct_proof_t *proof = (ct_proof_t*)malloc(sizeof(ct_proof_t));
    if (!proof) {
        return NULL;
    }
    
    // Initialize proof structure
    memset(proof, 0, sizeof(ct_proof_t));
    
    // Set proof fields
    proof->cert = cert;
    proof->log_id = (uint8_t*)malloc(32); // SHA-256 hash size
    if (!proof->log_id) {
        free(proof);
        return NULL;
    }
    memcpy(proof->log_id, log->entries[0]->log_id, 32); // Use first entry's log_id
    
    // Copy Falcon public key for verification
    proof->log_pubkey = (uint8_t*)malloc(sizeof(log->keys->public_key));
    if (!proof->log_pubkey) {
        free(proof->log_id);
        free(proof);
        return NULL;
    }
    memcpy(proof->log_pubkey, log->keys->public_key, sizeof(log->keys->public_key));
    proof->log_pubkey_len = sizeof(log->keys->public_key);
    
    return proof;
}

// Sync the CT log with peers in the network
int sync_ct_log_with_peers(ct_log_t *ct_log, network_context_t *net_ctx) {
    if (!ct_log || !net_ctx) {
        return -1;
    }
    
    dlog("Syncing CT log with peers (stub implementation)");
    
    // This is a stub implementation
    // In a real implementation, this would send the log to peers and request their logs
    
    return 0;
}

// Request a CT log from a peer
int request_ct_log_from_peer(network_context_t *net_ctx, const char *peer_hostname, ct_log_t **ct_log) {
    if (!net_ctx || !peer_hostname || !ct_log) {
        return -1;
    }
    
    // This is a stub implementation
    // In a real implementation, this would request the log from the peer
    
    printf("request_ct_log_from_peer: STUB implementation. Peer: %s\n", peer_hostname);
    
    // Create a dummy log
    *ct_log = create_ct_log("peer_log.db", peer_hostname, "requested");
    
    return 0; // Success
}

// Send the CT log to a peer
int send_ct_log_to_peer(network_context_t *net_ctx, const char *peer_hostname, ct_log_t *ct_log) {
    if (!net_ctx || !peer_hostname || !ct_log) {
        return -1;
    }
    
    dlog("Sending CT log to peer %s (stub implementation)", peer_hostname);
    
    // This is a stub implementation
    // In a real implementation, this would send the log to the peer
    
    printf("send_ct_log_to_peer: STUB implementation. Peer: %s, Log entries: %d\n", peer_hostname, ct_log->entry_count);
    
    return 0; // Success
}

// Free a CT log entry
void free_ct_log_entry(ct_log_entry_t *entry) {
    if (!entry) {
        return;
    }
    
    if (entry->cert) {
        if (entry->cert->common_name) {
            free(entry->cert->common_name);
        }
        free(entry->cert);
    }
    
    if (entry->scope_id) {
        free(entry->scope_id);
    }
    
    free(entry);
}

// Free a merkle proof
void free_ct_proof(ct_proof_t *proof) {
    if (!proof) {
        return;
    }
    
    if (proof->log_id) {
        free(proof->log_id);
    }
    
    if (proof->log_pubkey) {
        free(proof->log_pubkey);
    }
    
    free(proof);
}

// Verify a certificate signature
int verify_certificate_signature(nexus_cert_t *cert, const uint8_t *public_key) {
    if (!cert || !public_key) {
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
    return falcon_verify_sig(public_key, message, message_len, cert->signature);
}

// Sign a certificate
int ct_sign_certificate(nexus_cert_t *cert, const uint8_t *private_key, uint8_t *signature) {
    if (!cert || !private_key || !signature) {
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
    return falcon_sign(private_key, message, message_len, signature);
}

// Function to verify signatures in the CT log
static int verify_signature_in_ct_log(ct_log_t *log, ct_log_entry_t *entry_to_verify, ct_proof_t *proof) {
    if (!log || !entry_to_verify || !proof || !proof->log_pubkey) {
        printf("ERROR: Invalid parameters passed to verify_signature_in_ct_log\n");
        return -1;
    }
    
    // Create message to verify (cert + timestamp + log_id)
    uint8_t message[2048];
    size_t message_len = 0;
    
    // Add certificate common_name to message
    if (entry_to_verify->cert->common_name) {
        size_t common_name_len = strlen(entry_to_verify->cert->common_name);
        memcpy(message + message_len, entry_to_verify->cert->common_name, common_name_len);
        message_len += common_name_len;
    }
    
    // Add certificate signature to message
    memcpy(message + message_len, entry_to_verify->cert->signature, sizeof(entry_to_verify->cert->signature));
    message_len += sizeof(entry_to_verify->cert->signature);
    
    // Add timestamp to message
    memcpy(message + message_len, &entry_to_verify->timestamp, sizeof(entry_to_verify->timestamp));
    message_len += sizeof(entry_to_verify->timestamp);
    
    // Add log_id to message
    memcpy(message + message_len, entry_to_verify->log_id, sizeof(entry_to_verify->log_id));
    message_len += sizeof(entry_to_verify->log_id);
    
    // Determine signature length from header byte
    size_t max_sig_len = FALCON_SIG_COMPRESSED_MAXSIZE(10);
    size_t sig_len = max_sig_len;
    
    // From the end, find the last non-zero byte to determine actual length
    for (size_t i = max_sig_len - 1; i > 0; i--) {
        if (entry_to_verify->signature[i] != 0) {
            sig_len = i + 1;
            break;
        }
    }
    
    // Create temporary buffer for verification
    uint8_t tmp[FALCON_TMPSIZE_VERIFY(10)];
    
    // Verify using direct Falcon API
    int verify_result = falcon_verify(
        entry_to_verify->signature, sig_len, FALCON_SIG_COMPRESSED,
        proof->log_pubkey, FALCON_PUBKEY_SIZE(10),
        message, message_len,
        tmp, sizeof(tmp)
    );
    
    if (verify_result != 0) {
        printf("ERROR: Falcon signature verification in CT log failed with code %d\n", verify_result);
        return -1;
    }
    
    return 0;
} 