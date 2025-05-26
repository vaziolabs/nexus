#ifndef CERTIFICATE_TRANSPARENCY_H
#define CERTIFICATE_TRANSPARENCY_H

#include <stdint.h>
#include <pthread.h>
#include "certificate_authority.h"
#include "network_context.h"

// Maximum number of entries in the CT log
#define CT_LOG_MAX_ENTRIES 10000

// CT log entry structure
typedef struct {
    uint64_t timestamp;
    nexus_cert_t *cert;
    uint8_t signature[1330];  // Falcon-1024 signature
    uint8_t log_id[32];       // SHA-256 hash of the CT log's public key
    char *scope_id;           // Network scope identifier
} ct_log_entry_t;

// CT log structure
typedef struct {
    ct_log_entry_t **entries;
    int entry_count;
    int max_entries;
    void *merkle_tree;         // Merkle tree for efficient verification
    pthread_mutex_t lock;
    char *scope_id;            // Network scope identifier (private/public/federated/ephemeral)
    char *log_filename;        // Path to the log file on disk
    falcon_keys_t *keys;       // Falcon-1024 keys for this log
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

// Proof structure for certificate inclusion
typedef struct {
    nexus_cert_t *cert;        // Certificate for which the proof is generated
    uint8_t *log_id;           // ID of the log that issued the proof
    uint8_t *log_pubkey;       // Public key of the log
    size_t log_pubkey_len;     // Length of the public key
    uint8_t **path;            // Array of hashes on the path to the root
    int path_len;              // Length of the path
    uint8_t root_hash[32];     // Root hash of the Merkle tree
    uint64_t timestamp;        // Timestamp of the proof
} ct_proof_t;

// Function declarations
ct_log_t* init_certificate_transparency(network_context_t *net_ctx);
void cleanup_certificate_transparency(ct_log_t *ct_log);

// CT log operations
ct_log_t* create_ct_log(const char *log_filename, const char *node_hostname, const char *network_mode);
int load_ct_log(const char *path, ct_log_t **ct_log);
int save_ct_log(const ct_log_t *ct_log, const char *path);
ct_log_entry_t* add_certificate_to_ct_log(ct_log_t *ct_log, nexus_cert_t *cert, const uint8_t *sct_signature, size_t sct_signature_len);
int verify_certificate_in_ct_log(ct_log_t *ct_log, nexus_cert_t *cert, ct_proof_t **proof);

// Merkle tree operations
int build_merkle_tree(ct_log_t *ct_log);
int verify_merkle_proof(ct_proof_t *proof, const uint8_t *expected_root_hash, size_t root_hash_len, ct_log_entry_t *entry_to_verify);
ct_proof_t* generate_merkle_proof(ct_log_t *ct_log, nexus_cert_t *cert);

// Network operations
int sync_ct_log_with_peers(ct_log_t *ct_log, network_context_t *net_ctx);
int request_ct_log_from_peer(network_context_t *net_ctx, const char *peer_hostname, ct_log_t **ct_log);
int send_ct_log_to_peer(network_context_t *net_ctx, const char *peer_hostname, ct_log_t *ct_log);

// Utility functions
void free_ct_log_entry(ct_log_entry_t *entry);
void free_ct_proof(ct_proof_t *proof);
int verify_certificate_signature(nexus_cert_t *cert, const uint8_t *public_key);
int ct_sign_certificate(nexus_cert_t *cert, const uint8_t *private_key, uint8_t *signature);

#endif // CERTIFICATE_TRANSPARENCY_H 