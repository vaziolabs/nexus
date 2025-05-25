#ifndef PACKET_PAYLOADS_H
#define PACKET_PAYLOADS_H

#include <stdint.h>
#include "dns_types.h" // For dns_record_t, etc.

// Note: All multi-byte fields are assumed to be in network byte order (big-endian)
// when serialized. Functions for serialization/deserialization will handle this.
// Strings are typically null-terminated or preceded by a length field.

// Payload for PACKET_TYPE_TLD_REGISTER_REQ
// Client requests to register a new TLD.
typedef struct {
    char tld_name[256];         // Max TLD name length, null-terminated.
    // char public_key_pem[1024]; // Requesting node's public key for administrative purposes (optional)
    // uint32_t desired_authoritative_nodes; // Optional: proposed number of auth nodes
} payload_tld_register_req_t;

// Payload for PACKET_TYPE_TLD_REGISTER_RESP
// Server responds to a TLD registration request.
typedef enum {
    TLD_REG_RESP_SUCCESS = 0,
    TLD_REG_RESP_ERROR_ALREADY_EXISTS,
    TLD_REG_RESP_ERROR_INVALID_NAME,
    TLD_REG_RESP_ERROR_POLICY_VIOLATION,
    TLD_REG_RESP_ERROR_INTERNAL_SERVER_ERROR,
    TLD_REG_RESP_ERROR_NOT_AUTHORIZED,
} tld_reg_response_status_t;

typedef struct {
    tld_reg_response_status_t status;
    char message[256];          // Optional: human-readable message, especially on error.
    // tld_t registered_tld_info; // Optional: Full TLD info if successful (could be large)
} payload_tld_register_resp_t;

// Payload for PACKET_TYPE_TLD_MIRROR_REQ
// Client requests to become a mirror for a specific TLD.
typedef struct {
    char tld_name[256];         // TLD they want to mirror.
    // char node_ip_port[128];  // IP:Port where this node can be reached for sync updates by the server.
} payload_tld_mirror_req_t;

// Payload for PACKET_TYPE_TLD_MIRROR_RESP
typedef enum {
    TLD_MIRROR_RESP_SUCCESS = 0,            // Mirroring approved, server will start sending updates.
    TLD_MIRROR_RESP_ERROR_TLD_NOT_FOUND,
    TLD_MIRROR_RESP_ERROR_NOT_ACCEPTING_MIRRORS,
    TLD_MIRROR_RESP_ERROR_INTERNAL_SERVER_ERROR,
    TLD_MIRROR_RESP_ERROR_NOT_AUTHORIZED,
} tld_mirror_response_status_t;

typedef struct {
    tld_mirror_response_status_t status;
    char message[256];
    // uint32_t sync_interval_seconds; // Optional: Suggested sync interval from server
} payload_tld_mirror_resp_t;


// Payload for PACKET_TYPE_TLD_SYNC_UPDATE
// Server sends DNS records or TLD metadata changes to a mirror.
// This can be complex. For simplicity, one update packet might carry one record or one metadata change.
// Or, it could be a batch of records.

typedef enum {
    TLD_SYNC_ITEM_DNS_RECORD_ADD_OR_UPDATE = 0, // Carries a full dns_record_t
    TLD_SYNC_ITEM_DNS_RECORD_DELETE,          // Carries record name and type to delete
    TLD_SYNC_ITEM_AUTH_NODE_ADD,              // Carries tld_node_t for an authoritative node
    TLD_SYNC_ITEM_AUTH_NODE_DELETE,           // Carries hostname of auth node to delete
    // ... other types of sync items (e.g., TLD metadata changes)
} tld_sync_item_type_t;

typedef struct {
    char record_name_to_delete[256];
    dns_record_type_t record_type_to_delete;
} tld_sync_delete_payload_t;

// A single item in a sync update (can be part of an array in a larger packet)
// The actual payload format for dns_record_t and tld_node_t will need careful serialization.
typedef struct {
    tld_sync_item_type_t item_type;
    // The actual data will depend on item_type. Example using a union or just a flexible byte array + length.
    // For simplicity, let's assume a packet carries one type of item, or we have specific packet types for each.
    // Here, we might just define the structure for sending a single DNS record as an example.
    dns_record_t record_data; // Used when item_type is TLD_SYNC_ITEM_DNS_RECORD_ADD_OR_UPDATE
    // tld_node_t node_data; // Used for TLD_SYNC_ITEM_AUTH_NODE_ADD
    // tld_sync_delete_payload_t delete_data; // Used for TLD_SYNC_ITEM_DNS_RECORD_DELETE
    // char changed_metadata_field[64];
    // char new_metadata_value[256];
} payload_tld_sync_item_t; // This represents one item in a sync

// If a sync update packet can contain multiple items:
// typedef struct {
//     char tld_name[256];
//     uint32_t sequence_number; // For ordering updates
//     uint16_t item_count;
//     payload_tld_sync_item_t items[]; // Flexible array member, or fixed max and actual count
// } payload_tld_sync_update_batch_t;

// For now, let's assume a TLD_SYNC_UPDATE packet carries a single dns_record_t for simplicity.
// A more robust system would batch these or have specific item types within the payload.
typedef struct {
    char tld_name[256];         // Which TLD this update is for.
    dns_record_t record;        // The DNS record being added/updated.
    // Or, if deleting, different fields would be needed.
    // Or use a more generic item_type as above.
} payload_tld_sync_update_t;

// PACKET_TYPE_DNS_QUERY payload
typedef struct {
    char fqdn[256];             // Fully qualified domain name to query.
    dns_record_type_t record_type; // Type of record requested.
} payload_dns_query_t;

// PACKET_TYPE_DNS_RESPONSE payload
typedef struct {
    char fqdn[256];
    dns_record_type_t record_type;
    uint16_t record_count;      // Number of records in response (can be >1 for some types or CNAME chains)
    // dns_record_t records[]; // Flexible array of records. Serialization needs care.
    // For simplicity, send one record per response packet, or fixed max.
    dns_record_t record;        // Simplified: one record per response for now.
    uint8_t response_code;      // 0=NOERROR, 1=FORMERR, 2=SERVFAIL, 3=NXDOMAIN, etc. (standard DNS RCODEs)
} payload_dns_response_t;


// --- Serialization/Deserialization Function Prototypes ---
// These would ideally be in a separate .c file (e.g., packet_protocol.c)

// Generic packet serialization/deserialization
// Returns bytes written or -1 on error. buf must be large enough.
// int serialize_nexus_packet(const nexus_packet_t* packet, uint8_t* buf, size_t buf_len);
// int deserialize_nexus_packet(const uint8_t* buf, size_t buf_len, nexus_packet_t* packet);

// Example for a specific payload type:
// Returns bytes written to out_buf or -1 on error.
// Caller ensures out_buf is large enough (e.g., sizeof(payload_tld_register_req_t) is often not enough due to strings).
// A better approach is to calculate required size first, or write to a dynamic buffer.
// int serialize_payload_tld_register_req(const payload_tld_register_req_t* payload, uint8_t* out_buf, size_t out_buf_len);
// int deserialize_payload_tld_register_req(const uint8_t* data, size_t data_len, payload_tld_register_req_t* payload);

#endif // PACKET_PAYLOADS_H 