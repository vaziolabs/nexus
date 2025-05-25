#ifndef DNS_TYPES_H
#define DNS_TYPES_H

#include <stdint.h>
#include <stddef.h> // For size_t
#include <pthread.h> // For pthread_mutex_t and pthread_rwlock_t
#include <time.h>
// #include "falcon.h" // For public key type, assuming falcon_public_key_t

// Forward declaration for tld_t to resolve circular dependency if any future struct needs it
struct tld_s;

// DNS Record Types
typedef enum {
    DNS_RECORD_TYPE_A = 1,      // IPv4 address
    DNS_RECORD_TYPE_AAAA = 28,  // IPv6 address
    DNS_RECORD_TYPE_TXT = 16,   // Text record
    DNS_RECORD_TYPE_MX = 15,    // Mail exchange
    DNS_RECORD_TYPE_CNAME = 5   // Canonical name
} dns_record_type_t;

// DNS Record Structure
typedef struct {
    char* name;                 // e.g., "www" for www.example.com or "example.com" for the TLD NS record
    dns_record_type_t type;
    uint32_t ttl;
    time_t last_updated;        // Timestamp of last update for cache management
    char* rdata;                // Record data (e.g., IP address for A/AAAA, hostname for CNAME/NS/MX)
    // For SOA records, rdata might point to a more complex structure or be a formatted string
} dns_record_t;

// Node Mirroring/Serving a TLD
typedef struct {
    char* hostname;             // Hostname of the node
    char* ip_address;           // IP address of the node
    // falcon_public_key_t public_key; // For verifying updates from this node (TODO: Define/include actual type)
    time_t last_seen;
} tld_node_t;

// Top-Level Domain Structure
typedef struct tld_s {
    char* name;                     // TLD name, e.g., ".nexus" or "example.nexus"
    tld_node_t* authoritative_nodes; // Array of authoritative nodes for this TLD
    size_t authoritative_node_count;
    dns_record_t* records;          // Array of DNS records within this TLD
    size_t record_count;
    tld_node_t* mirror_nodes;       // Array of nodes mirroring this TLD
    size_t mirror_node_count;
    time_t created_at;
    time_t last_modified;
    // char* admin_contact; // (Optional)
    // Other TLD specific metadata (e.g., policies)
} tld_t;

// DNS Cache Entry (for individual records from various TLDs)
typedef struct {
    char* fqdn;                 // Fully qualified domain name (e.g., www.example.com)
    dns_record_t record;        // The cached DNS record
    time_t fetched_at;          // When this record was fetched/validated
    time_t expires_at;          // When this record should be considered stale (fetched_at + ttl)
} dns_cache_entry_t;

// DNS Cache Structure (linked list or hash table of dns_cache_entry_t)
typedef struct dns_cache_node_s {
    dns_cache_entry_t entry;
    struct dns_cache_node_s* next;
} dns_cache_node_t;

typedef struct {
    dns_cache_node_t* head;
    size_t count;
    size_t max_size; // Max number of records or total memory
    pthread_mutex_t lock;
} dns_cache_t;

// TLD Manager Structure
typedef struct {
    tld_t** tlds;           // Dynamic array of pointers to TLDs
    size_t tld_count;       // Number of TLDs currently managed/known
    size_t tld_capacity;    // Current capacity of the tlds array
    pthread_rwlock_t lock;  // Read-write lock for concurrent access to TLD list
} tld_manager_t;

// Functions for managing these types will be declared in other headers (e.g., dns_cache.h, tld_manager.h)

// Maximum length for a domain name (including null terminator)
#define MAX_DOMAIN_NAME_LEN 256

// TLD registration response status
typedef enum {
    TLD_REG_RESP_SUCCESS = 0,
    TLD_REG_RESP_ERROR_ALREADY_EXISTS = 1,
    TLD_REG_RESP_ERROR_INTERNAL_SERVER_ERROR = 2
} tld_reg_response_status_t;

// TLD mirror request payload
typedef struct {
    char tld_name[64];           // TLD name to mirror
} payload_tld_mirror_req_t;

// TLD mirror response payload
typedef struct {
    uint8_t status;              // Status code
    char message[128];           // Status message
    int record_count;            // Number of records
    // Records follow in the serialized data
} payload_tld_mirror_resp_t;

// TLD sync update payload
typedef struct {
    char tld_name[64];           // TLD name being updated
    int record_count;            // Number of records
    // Records follow in the serialized data
} payload_tld_sync_update_t;

// DNS query payload
typedef struct {
    char query_name[256];        // Name to query
    dns_record_type_t type;      // Record type to query
} payload_dns_query_t;

// DNS response payload
typedef struct {
    uint8_t status;              // Status code
    int record_count;            // Number of records
    // Records follow in the serialized data
} payload_dns_response_t;

#endif // DNS_TYPES_H 