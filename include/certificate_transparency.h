#ifndef CERTIFICATE_TRANSPARENCY_H
#define CERTIFICATE_TRANSPARENCY_H

#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include "certificate_authority.h"
#include "network_context.h"

// Maximum number of entries in the CT log
#define CT_LOG_MAX_ENTRIES 10000

// CT log entry structure (simplified)
typedef struct {
    uint64_t timestamp;
    nexus_cert_t *cert;
    uint8_t signature[256];   // Simplified signature
    uint8_t log_id[32];       // Log identifier
    int log_entry_type;       // Type of log entry
} ct_entry_t;

// CT log structure (simplified)
typedef struct ct_log_s {
    char *log_id;
    char *log_url;
    void *signing_key;        // EVP_PKEY pointer (opaque)
    ct_entry_t *entries;
    size_t entry_count;
    size_t max_entries;
    pthread_mutex_t lock;
} ct_log_t;

// Merkle tree node structure
typedef struct merkle_node {
    uint8_t hash[32];          // SHA-256 hash
    struct merkle_node *left;
    struct merkle_node *right;
} merkle_node_t;

// Merkle tree structure
typedef struct {
    merkle_node_t *root;
    int leaf_count;
} merkle_tree_t;

// Proof structure for certificate inclusion (simplified)
typedef struct {
    nexus_cert_t *cert;        // Certificate for which the proof is generated
    uint8_t *log_id;           // ID of the log that issued the proof
    uint8_t *log_pubkey;       // Public key of the log
    size_t log_pubkey_len;     // Length of the public key
    uint8_t **path;            // Array of hashes on the path to the root
    int path_len;              // Length of the path
    uint8_t root_hash[32];     // Root hash of the Merkle tree
    uint64_t timestamp;        // Timestamp of the proof
} merkle_proof_t;

// Function declarations
ct_log_t* init_certificate_transparency(network_context_t *net_ctx);
void cleanup_certificate_transparency(ct_log_t *ct_log);

// CT log operations (simplified signatures)
ct_log_t* create_ct_log(const char* log_id, const char* log_url);
int add_certificate_to_ct_log(ct_log_t* log, nexus_cert_t* cert);
int verify_certificate_signature(nexus_cert_t* cert, ca_context_t* ca_ctx);
int ct_sign_certificate(ct_log_t* log, nexus_cert_t* cert);
void cleanup_ct_log(ct_log_t* log);

// Merkle tree operations (simplified)
int verify_merkle_proof(ct_entry_t* entry_to_verify, merkle_proof_t* proof);
merkle_proof_t* generate_merkle_proof(ct_log_t* log, size_t entry_index);
void free_merkle_proof(merkle_proof_t* proof);

// Network operations (stubs for now)
int sync_ct_log_with_peers(ct_log_t *ct_log, network_context_t *net_ctx);

#endif // CERTIFICATE_TRANSPARENCY_H 