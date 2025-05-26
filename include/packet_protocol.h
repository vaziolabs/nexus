#ifndef PACKET_PROTOCOL_H
#define PACKET_PROTOCOL_H

#include <stdint.h>
#include <stddef.h> // For size_t
#include <sys/types.h> // For ssize_t
#include "dns_types.h" // Include for payload_dns_query_t, payload_dns_response_t

// NEXUS packet types
typedef enum {
    PACKET_TYPE_RESERVED = 0,
    PACKET_TYPE_HANDSHAKE_HELLO,
    PACKET_TYPE_HANDSHAKE_ACK,
    PACKET_TYPE_DNS_QUERY,
    PACKET_TYPE_DNS_RESPONSE,
    PACKET_TYPE_TLD_REGISTER_REQ,
    PACKET_TYPE_TLD_REGISTER_RESP,
    PACKET_TYPE_TLD_MIRROR_REQ,
    PACKET_TYPE_TLD_MIRROR_RESP,
    PACKET_TYPE_TLD_SYNC_UPDATE,
    PACKET_TYPE_TLD_SYNC_ACK,
    PACKET_TYPE_PEER_DISCOVERY,
    PACKET_TYPE_HEARTBEAT
} nexus_packet_type_t;

// NEXUS packet structure
typedef struct {
    uint8_t version;
    nexus_packet_type_t type;
    uint64_t session_id;
    uint32_t data_len;
    uint8_t *data;
} nexus_packet_t;

// TLD register request payload
typedef struct {
    char tld_name[64];
} payload_tld_register_req_t;

// TLD register response payload
typedef struct {
    int status;
    char message[256];
} payload_tld_register_resp_t;

// Serialization functions
ssize_t serialize_nexus_packet(const nexus_packet_t *packet, uint8_t *buffer, size_t buffer_len);
ssize_t deserialize_nexus_packet(const uint8_t *buffer, size_t buffer_len, nexus_packet_t *packet);

ssize_t serialize_payload_tld_register_req(const payload_tld_register_req_t *payload, uint8_t *buffer, size_t buffer_len);
ssize_t deserialize_payload_tld_register_req(const uint8_t *buffer, size_t buffer_len, payload_tld_register_req_t *payload);

ssize_t serialize_payload_tld_register_resp(const payload_tld_register_resp_t *payload, uint8_t *buffer, size_t buffer_len);
ssize_t deserialize_payload_tld_register_resp(const uint8_t *buffer, size_t buffer_len, payload_tld_register_resp_t *payload);

// DNS Query/Response Payload Serialization/Deserialization
ssize_t get_serialized_payload_dns_query_size(const payload_dns_query_t* payload);
ssize_t serialize_payload_dns_query(const payload_dns_query_t* payload, uint8_t* out_buf, size_t out_buf_len);
ssize_t deserialize_payload_dns_query(const uint8_t* data, size_t data_len, payload_dns_query_t* payload);

ssize_t get_serialized_payload_dns_response_size(const payload_dns_response_t* payload);
ssize_t serialize_payload_dns_response(const payload_dns_response_t* payload, uint8_t* out_buf, size_t out_buf_len);
ssize_t deserialize_payload_dns_response(const uint8_t* data, size_t data_len, payload_dns_response_t* payload);

// DNS Record Serialization/Deserialization (if they become standalone)
// ssize_t get_serialized_dns_record_size(const dns_record_t* record);
// ssize_t serialize_dns_record(const dns_record_t* record, uint8_t* out_buf, size_t out_buf_len);
// ssize_t deserialize_dns_record(const uint8_t* data, size_t data_len, dns_record_t* record, size_t* rdata_len_out);

#endif // PACKET_PROTOCOL_H 