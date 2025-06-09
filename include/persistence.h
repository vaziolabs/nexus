#ifndef PERSISTENCE_H
#define PERSISTENCE_H

#include <stdint.h>
#include <time.h>
#include "dns_types.h"

// Forward declarations
typedef struct persistence_context_s persistence_context_t;

// Persistence configuration
typedef struct {
    char* db_path;              // Path to SQLite database file
    int enable_wal_mode;        // Enable WAL mode for better concurrency
    int cache_size_kb;          // SQLite cache size in KB
    int sync_mode;              // SQLite synchronous mode (0=OFF, 1=NORMAL, 2=FULL)
} persistence_config_t;

// Database schema version for migrations
#define PERSISTENCE_SCHEMA_VERSION 1

// Function declarations

// Initialization and cleanup
int init_persistence(persistence_context_t** ctx, const persistence_config_t* config);
void cleanup_persistence(persistence_context_t* ctx);

// TLD persistence
int persist_tld(persistence_context_t* ctx, const tld_t* tld);
int load_tld(persistence_context_t* ctx, const char* tld_name, tld_t** tld_out);
int delete_tld(persistence_context_t* ctx, const char* tld_name);
int list_tlds(persistence_context_t* ctx, char*** tld_names, size_t* count);

// DNS record persistence
int persist_dns_record(persistence_context_t* ctx, const char* tld_name, const dns_record_t* record);
int load_dns_records(persistence_context_t* ctx, const char* tld_name, dns_record_t** records, size_t* count);
int delete_dns_record(persistence_context_t* ctx, const char* tld_name, const char* record_name, dns_record_type_t type);

// TLD node persistence (authoritative and mirror nodes)
int persist_tld_nodes(persistence_context_t* ctx, const char* tld_name, const tld_node_t* nodes, size_t count, int is_authoritative);
int load_tld_nodes(persistence_context_t* ctx, const char* tld_name, tld_node_t** auth_nodes, size_t* auth_count, tld_node_t** mirror_nodes, size_t* mirror_count);

// Configuration persistence
int persist_network_config(persistence_context_t* ctx, const char* profile_name, const char* config_data);
int load_network_config(persistence_context_t* ctx, const char* profile_name, char** config_data);

// Database maintenance
int vacuum_database(persistence_context_t* ctx);
int backup_database(persistence_context_t* ctx, const char* backup_path);
int get_database_stats(persistence_context_t* ctx, size_t* total_records, size_t* total_tlds, size_t* db_size_bytes);

// Transaction support
int begin_transaction(persistence_context_t* ctx);
int commit_transaction(persistence_context_t* ctx);
int rollback_transaction(persistence_context_t* ctx);

// Default configuration helper
persistence_config_t* create_default_persistence_config(const char* db_path);
void free_persistence_config(persistence_config_t* config);

#endif // PERSISTENCE_H 