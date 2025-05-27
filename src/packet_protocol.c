#include "../include/packet_protocol.h"
#include "../include/dns_types.h"
#include "../include/debug.h"
#include <stdio.h>
#include <string.h> // For memcpy, strlen, strncpy
#include <stdlib.h> // For malloc, free
#include <arpa/inet.h> // For htonl, ntohl, htons, ntohs (endian conversion)

// --- Helper Functions for Serialization --- 

// Forward declarations for static helper functions
static int write_uint8(uint8_t val, uint8_t* buf, size_t buf_len, size_t* offset);
// Unused function - commented out to eliminate warning
//static int write_uint16(uint16_t val, uint8_t* buf, size_t buf_len, size_t* offset);
static int write_uint32(uint32_t val, uint8_t* buf, size_t buf_len, size_t* offset);
static int write_uint64(uint64_t val, uint8_t* buf, size_t buf_len, size_t* offset);
static int write_fixed_string(const char* str, size_t str_fixed_len, uint8_t* buf, size_t buf_len, size_t* offset);
static int write_bytes(const uint8_t* data, uint32_t data_len, uint8_t* buf, size_t buf_len, size_t* offset);

static int read_uint8(const uint8_t* buf, size_t buf_len, size_t* offset, uint8_t* out_val);
// Unused function - commented out to eliminate warning
//static int read_uint16(const uint8_t* buf, size_t buf_len, size_t* offset, uint16_t* out_val);
static int read_uint32(const uint8_t* buf, size_t buf_len, size_t* offset, uint32_t* out_val);
static int read_uint64(const uint8_t* buf, size_t buf_len, size_t* offset, uint64_t* out_val);
static int read_fixed_string(const uint8_t* buf, size_t buf_len, size_t* offset, char* out_str, size_t str_fixed_len);
static int read_bytes_alloc(const uint8_t* buf, size_t buf_len, size_t* offset, uint32_t data_len, uint8_t** out_data);
static int read_bytes(const uint8_t* buf, size_t buf_len, size_t* offset, uint8_t* out_data, uint32_t data_to_read_len);

// Write a uint8_t to buffer and advance offset
static int write_uint8(uint8_t val, uint8_t* buf, size_t buf_len, size_t* offset) {
    if (*offset + sizeof(uint8_t) > buf_len) return -1; // Buffer too small
    buf[*offset] = val;
    *offset += sizeof(uint8_t);
    return 0;
}

/* Unused function - commented out to eliminate warning
// Write a uint16_t to buffer (network byte order) and advance offset
static int write_uint16(uint16_t val, uint8_t* buf, size_t buf_len, size_t* offset) {
    if (*offset + sizeof(uint16_t) > buf_len) return -1;
    uint16_t net_val = htons(val);
    memcpy(buf + *offset, &net_val, sizeof(uint16_t));
    *offset += sizeof(uint16_t);
    return 0;
}
*/

// Write a uint32_t to buffer (network byte order) and advance offset
static int write_uint32(uint32_t val, uint8_t* buf, size_t buf_len, size_t* offset) {
    if (*offset + sizeof(uint32_t) > buf_len) return -1;
    uint32_t net_val = htonl(val);
    memcpy(buf + *offset, &net_val, sizeof(uint32_t));
    *offset += sizeof(uint32_t);
    return 0;
}

// Write a uint64_t to buffer (network byte order) and advance offset
static int write_uint64(uint64_t val, uint8_t* buf, size_t buf_len, size_t* offset) {
    if (*offset + sizeof(uint64_t) > buf_len) return -1;
    // For now, just writing uint64_t as is; proper network byte order
    // would need to be considered for cross-platform consistency
    uint64_t net_val = val;
    if (htonl(1) != 1) { // Check if system is big-endian; if not, swap for uint64_t manually
        uint8_t* s = (uint8_t*)&val;
        uint8_t* d = (uint8_t*)&net_val;
        d[0] = s[7]; d[1] = s[6]; d[2] = s[5]; d[3] = s[4];
        d[4] = s[3]; d[5] = s[2]; d[6] = s[1]; d[7] = s[0];
    }
    memcpy(buf + *offset, &net_val, sizeof(uint64_t));
    *offset += sizeof(uint64_t);
    return 0;
}

// Write a fixed-size string (char array) to buffer and advance offset
// Ensures null termination within the fixed size if source is shorter.
static int write_fixed_string(const char* str, size_t fixed_len, uint8_t* buf, size_t buf_len, size_t* offset) {
    if (*offset + fixed_len > buf_len) return -1;
    strncpy((char*)(buf + *offset), str, fixed_len);
    // Ensure null termination if fixed_len allows and str was shorter
    if (strlen(str) < fixed_len) {
        buf[*offset + strlen(str)] = '\0';
    } else {
        buf[*offset + fixed_len - 1] = '\0'; // Ensure last char is null if str is too long or exactly fixed_len
    }
    *offset += fixed_len;
    return 0;
}

// Write variable length data (byte array)
static int write_bytes(const uint8_t* data, uint32_t data_len, uint8_t* buf, size_t buf_len, size_t* offset) {
    if (!data && data_len > 0) return -1; // Null data with non-zero length
    if (*offset + data_len > buf_len) return -1; // Buffer too small
    if (data_len > 0) {
        memcpy(buf + *offset, data, data_len);
    }
    *offset += data_len;
    return 0;
}

// --- Helper Functions for Deserialization ---

static int read_uint8(const uint8_t* buf, size_t buf_len, size_t* offset, uint8_t* out_val) {
    if (*offset + sizeof(uint8_t) > buf_len) return -1;
    *out_val = buf[*offset];
    *offset += sizeof(uint8_t);
    return 0;
}

/* Unused function - commented out to eliminate warning
static int read_uint16(const uint8_t* buf, size_t buf_len, size_t* offset, uint16_t* out_val) {
    if (*offset + sizeof(uint16_t) > buf_len) return -1;
    uint16_t net_val;
    memcpy(&net_val, buf + *offset, sizeof(uint16_t));
    *out_val = ntohs(net_val);
    *offset += sizeof(uint16_t);
    return 0;
}
*/

static int read_uint32(const uint8_t* buf, size_t buf_len, size_t* offset, uint32_t* out_val) {
    if (*offset + sizeof(uint32_t) > buf_len) return -1;
    uint32_t net_val;
    memcpy(&net_val, buf + *offset, sizeof(uint32_t));
    *out_val = ntohl(net_val);
    *offset += sizeof(uint32_t);
    return 0;
}

static int read_uint64(const uint8_t* buf, size_t buf_len, size_t* offset, uint64_t* out_val) {
    if (*offset + sizeof(uint64_t) > buf_len) return -1;
    uint64_t net_val;
    memcpy(&net_val, buf + *offset, sizeof(uint64_t));
    // Placeholder for proper uint64_t network to host conversion
    *out_val = net_val; 
    if (htonl(1) != 1) { // Check if system is big-endian; if not, swap for uint64_t manually
        uint8_t* s = (uint8_t*)&net_val;
        uint8_t* d = (uint8_t*)out_val;
        d[0] = s[7]; d[1] = s[6]; d[2] = s[5]; d[3] = s[4];
        d[4] = s[3]; d[5] = s[2]; d[6] = s[1]; d[7] = s[0];
    }
    *offset += sizeof(uint64_t);
    return 0;
}

// Reads into a fixed-size char array, ensures null termination.
static int read_fixed_string(const uint8_t* buf, size_t buf_len, size_t* offset, char* out_str, size_t fixed_len) {
    if (*offset + fixed_len > buf_len) return -1;
    memcpy(out_str, buf + *offset, fixed_len);
    out_str[fixed_len - 1] = '\0'; // Ensure null termination
    *offset += fixed_len;
    return 0;
}

// Reads variable length data. Allocates memory for out_data which caller must free.
static int read_bytes_alloc(const uint8_t* buf, size_t buf_len, size_t* offset, uint32_t data_len, uint8_t** out_data) {
    if (!buf || !offset || !out_data) {
        dlog("ERROR: Invalid parameters to read_bytes_alloc");
        if(out_data) *out_data = NULL;
        return -1;
    }
    if (*offset + data_len > buf_len) {
        dlog("ERROR: Buffer too small in read_bytes_alloc. Offset: %zu, DataLen: %u, BufLen: %zu", *offset, data_len, buf_len);
        *out_data = NULL;
        return -1; 
    }
    
    if (data_len == 0) {
        *out_data = NULL; // No data to read, ensure out_data is NULL
        // *offset remains unchanged as no bytes are read
        return 0;
    }

    *out_data = malloc(data_len);
    if (!*out_data) {
        dlog("ERROR: Failed to allocate memory in read_bytes_alloc (%u bytes)", data_len);
        return -1; 
    }
    
    memcpy(*out_data, buf + *offset, data_len);
    *offset += data_len;
    return 0;
}

// Read a sequence of bytes from buffer into a pre-allocated buffer, and advance offset.
static int read_bytes(const uint8_t* buf, size_t buf_len, size_t* offset, uint8_t* out_data, uint32_t data_to_read_len) {
    if (!buf || !offset || !out_data) return -1;
    if (*offset + data_to_read_len > buf_len) return -1; // Buffer too small or trying to read past end

    if (data_to_read_len > 0) {
        memcpy(out_data, buf + *offset, data_to_read_len);
    }
    *offset += data_to_read_len;
    return 0;
}

// --- NEXUS Packet Serialization/Deserialization ---

#define NEXUS_PACKET_HEADER_SIZE (sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t) + sizeof(uint32_t)) // version + type + session_id + data_len

ssize_t get_serialized_nexus_packet_size(const nexus_packet_t* packet) {
    if (!packet) return -1;
    return NEXUS_PACKET_HEADER_SIZE + packet->data_len;
}

ssize_t serialize_nexus_packet(const nexus_packet_t* packet, uint8_t* out_buf, size_t out_buf_len) {
    if (!packet || !out_buf) return -1;
    ssize_t required_size = get_serialized_nexus_packet_size(packet);
    if (required_size < 0 || (size_t)required_size > out_buf_len) return -1; // Not enough space

    size_t offset = 0;
    dlog("Serializing packet: version=%d, type=%d, session_id=%lx, data_len=%u",
         packet->version, packet->type, packet->session_id, packet->data_len);

    if (write_uint8(packet->version, out_buf, out_buf_len, &offset) != 0) return -1;
    // Assuming nexus_packet_type_t is effectively uint8_t or similar small int for direct write.
    // If it's a larger enum, ensure correct size handling.
    // Forcing to uint8_t for serialization if it fits.
    if (write_uint8((uint8_t)packet->type, out_buf, out_buf_len, &offset) != 0) return -1; 
    if (write_uint64(packet->session_id, out_buf, out_buf_len, &offset) != 0) return -1;
    if (write_uint32(packet->data_len, out_buf, out_buf_len, &offset) != 0) return -1;
    if (packet->data_len > 0 && packet->data != NULL) {
        if (write_bytes(packet->data, packet->data_len, out_buf, out_buf_len, &offset) != 0) return -1;
    }
    
    dlog("Serialized packet size: %zu", offset);
    return offset;
}

ssize_t deserialize_nexus_packet(const uint8_t* buf, size_t buf_len, nexus_packet_t* packet) {
    if (!buf || !packet) return -1;
    if (buf_len < NEXUS_PACKET_HEADER_SIZE) {
        dlog("ERROR: Buffer too small for header: %zu < %zu", buf_len, NEXUS_PACKET_HEADER_SIZE);
        return -1; // Not enough data for header
    }

    size_t offset = 0;
    if (read_uint8(buf, buf_len, &offset, &packet->version) != 0) {
        dlog("ERROR: Failed to read version");
        return -1;
    }
    uint8_t type_val_u8;
    if (read_uint8(buf, buf_len, &offset, &type_val_u8) != 0) {
        dlog("ERROR: Failed to read type");
        return -1;
    }
    packet->type = (nexus_packet_type_t)type_val_u8;
    if (read_uint64(buf, buf_len, &offset, &packet->session_id) != 0) {
        dlog("ERROR: Failed to read session_id");
        return -1;
    }
    if (read_uint32(buf, buf_len, &offset, &packet->data_len) != 0) {
        dlog("ERROR: Failed to read data_len");
        return -1;
    }

    if (packet->data_len > 0) {
        // Validate that the data size is reasonable
        if (packet->data_len > buf_len - offset) {
            dlog("ERROR: Data length too large: %u > %zu", packet->data_len, buf_len - offset);
            packet->data = NULL;
            return -1;
        }

        if (read_bytes_alloc(buf, buf_len, &offset, packet->data_len, &packet->data) != 0) {
            // packet->data would be NULL if data_len is 0, or garbage on error.
            // If read_bytes_alloc failed after partially reading, offset is advanced but packet->data might be bad.
            // Ensure packet->data is NULL on error if it was to be allocated.
            dlog("ERROR: Failed to read data bytes");
            packet->data = NULL; 
            return -1;
        }
    } else {
        packet->data = NULL;
    }
    return offset; // Total bytes read for this packet
}

// --- TLD Register Request --- (payload_tld_register_req_t)

ssize_t get_serialized_payload_tld_register_req_size(const payload_tld_register_req_t* payload) {
    if (!payload) return -1;
    return sizeof(payload->tld_name); // Assumes fixed size array for tld_name
}

ssize_t serialize_payload_tld_register_req(const payload_tld_register_req_t* payload, uint8_t* out_buf, size_t out_buf_len) {
    if (!payload || !out_buf) return -1;
    ssize_t required_size = get_serialized_payload_tld_register_req_size(payload);
    if (required_size < 0 || (size_t)required_size > out_buf_len) return -1;

    size_t offset = 0;
    if (write_fixed_string(payload->tld_name, sizeof(payload->tld_name), out_buf, out_buf_len, &offset) != 0) return -1;
    return offset;
}

ssize_t deserialize_payload_tld_register_req(const uint8_t* data, size_t data_len, payload_tld_register_req_t* payload) {
    if (!data || !payload) return -1;
    // For fixed size payloads, data_len should match expected size.
    if (data_len < sizeof(payload->tld_name)) return -1; 

    size_t offset = 0;
    if (read_fixed_string(data, data_len, &offset, payload->tld_name, sizeof(payload->tld_name)) != 0) return -1;
    return offset;
}

// --- TLD Register Response --- (payload_tld_register_resp_t)
ssize_t get_serialized_payload_tld_register_resp_size(const payload_tld_register_resp_t* payload) {
    if (!payload) return -1;
    return sizeof(uint8_t) + sizeof(payload->message); // status (as uint8_t) + message
}

ssize_t serialize_payload_tld_register_resp(const payload_tld_register_resp_t* payload, uint8_t* out_buf, size_t out_buf_len) {
    if (!payload || !out_buf) return -1;
    ssize_t required_size = get_serialized_payload_tld_register_resp_size(payload);
    if (required_size < 0 || (size_t)required_size > out_buf_len) return -1;

    size_t offset = 0;
    if (write_uint8((uint8_t)payload->status, out_buf, out_buf_len, &offset) != 0) return -1;
    if (write_fixed_string(payload->message, sizeof(payload->message), out_buf, out_buf_len, &offset) != 0) return -1;
    return offset;
}

ssize_t deserialize_payload_tld_register_resp(const uint8_t* data, size_t data_len, payload_tld_register_resp_t* payload) {
    if (!data || !payload) return -1;
    if (data_len < (sizeof(uint8_t) + sizeof(payload->message))) return -1;

    size_t offset = 0;
    uint8_t status_u8;
    if (read_uint8(data, data_len, &offset, &status_u8) != 0) return -1;
    payload->status = (tld_reg_response_status_t)status_u8;
    if (read_fixed_string(data, data_len, &offset, payload->message, sizeof(payload->message)) != 0) return -1;
    return offset;
}


// --- DNS Record (Helper) ---
// Size: len(name) + 1 (null) + sizeof(type) + sizeof(ttl) + sizeof(last_updated) + len(rdata) + 1 (null)
// This is an example. A more robust way is to send len prefix for strings.
ssize_t get_serialized_dns_record_size(const dns_record_t* record) {
    if (!record || !record->name || !record->rdata) return -1;

    ssize_t total_size = 0;
    size_t name_len = strlen(record->name) + 1; // Include null terminator as per serialize_dns_record
    size_t rdata_len = strlen(record->rdata) + 1; // Include null terminator

    total_size += sizeof(uint32_t); // name_len (serialized as uint32_t)
    total_size += name_len;         // name bytes (including null)
    
    total_size += sizeof(uint32_t); // type (serialized as uint32_t)
    total_size += sizeof(uint32_t); // ttl
    total_size += sizeof(uint64_t); // last_updated

    total_size += sizeof(uint32_t); // rdata_len (serialized as uint32_t)
    total_size += rdata_len;        // rdata bytes (including null)
    
    return total_size;
}

// Serializes a single dns_record_t. out_buf must be large enough.
// bytes_written is an out-parameter for the actual bytes written.
ssize_t serialize_dns_record(const dns_record_t* record, uint8_t* out_buf, size_t out_buf_len, size_t* bytes_written) {
    if (!record || !record->name || !record->rdata || !out_buf || !bytes_written) return -1;

    size_t offset = 0;
    size_t name_len = strlen(record->name) + 1;
    size_t rdata_len = strlen(record->rdata) + 1;

    if (write_uint32(name_len, out_buf, out_buf_len, &offset) != 0) return -1;
    if (write_bytes((const uint8_t*)record->name, name_len, out_buf, out_buf_len, &offset) != 0) return -1;
    
    if (write_uint32((uint32_t)record->type, out_buf, out_buf_len, &offset) != 0) return -1; // Assuming enum fits uint32 for simplicity
    if (write_uint32(record->ttl, out_buf, out_buf_len, &offset) != 0) return -1;
    if (write_uint64((uint64_t)record->last_updated, out_buf, out_buf_len, &offset) != 0) return -1; // time_t often 64-bit

    if (write_uint32(rdata_len, out_buf, out_buf_len, &offset) != 0) return -1;
    if (write_bytes((const uint8_t*)record->rdata, rdata_len, out_buf, out_buf_len, &offset) != 0) return -1;

    *bytes_written = offset;
    return 0; // Success
}

// Deserializes a single dns_record_t. Allocates memory for name and rdata.
// bytes_read is an out-parameter for actual bytes read.
ssize_t deserialize_dns_record(const uint8_t* data, size_t data_len, dns_record_t* record, size_t* bytes_read) {
    if (!data || !record || !bytes_read) return -1;
    
    size_t offset = 0;
    uint32_t name_len_u32, rdata_len_u32; // Use more descriptive names for length variables
    uint32_t type_u32;
    uint64_t last_updated_u64;

    record->name = NULL;  // Initialize to NULL before allocation attempts
    record->rdata = NULL; // Initialize to NULL

    if (read_uint32(data, data_len, &offset, &name_len_u32) != 0) return -1;
    if (name_len_u32 > 0) {
        // read_bytes_alloc will allocate memory for record->name (as uint8_t*)
        // and copy name_len_u32 bytes into it.
        if (read_bytes_alloc(data, data_len, &offset, name_len_u32, (uint8_t**)&record->name) != 0) {
            // On failure, read_bytes_alloc should ensure *out_data is NULL or unchanged if malloc failed.
            // If record->name was assigned by a failed malloc, it should be NULL.
            return -1;
        }
        // Ensure null-termination if name_len_u32 was the exact string length without null.
        // Assuming name_len_u32 includes the null terminator as per serialize_dns_record.
    } else {
        record->name = NULL; // Explicitly set to NULL if length is 0
    }

    if (read_uint32(data, data_len, &offset, &type_u32) != 0) { free(record->name); record->name = NULL; return -1; }
    record->type = (dns_record_type_t)type_u32;
    if (read_uint32(data, data_len, &offset, &record->ttl) != 0) { free(record->name); record->name = NULL; return -1; }
    if (read_uint64(data, data_len, &offset, &last_updated_u64) != 0) { free(record->name); record->name = NULL; return -1; }
    record->last_updated = (time_t)last_updated_u64;

    if (read_uint32(data, data_len, &offset, &rdata_len_u32) != 0) { free(record->name); record->name = NULL; return -1; }
    if (rdata_len_u32 > 0) {
        if (read_bytes_alloc(data, data_len, &offset, rdata_len_u32, (uint8_t**)&record->rdata) != 0) {
            free(record->name); record->name = NULL;
            // record->rdata would be NULL if read_bytes_alloc failed malloc or data_len was 0 inside it.
            return -1;
        }
        // Assuming rdata_len_u32 includes null terminator if it's a string.
    } else {
        record->rdata = NULL; // Explicitly set to NULL if length is 0
    }

    *bytes_read = offset;
    return 0; // Success
}


// --- Implement other payload types as needed, following the pattern ---
// For example:
// --- TLD Mirror Request ---
ssize_t get_serialized_payload_tld_mirror_req_size(const payload_tld_mirror_req_t* payload) {
    if (!payload) return -1;
    return sizeof(payload->tld_name);
}

ssize_t serialize_payload_tld_mirror_req(const payload_tld_mirror_req_t* payload, uint8_t* out_buf, size_t out_buf_len) {
    if (!payload || !out_buf) return -1;
    if (get_serialized_payload_tld_mirror_req_size(payload) > (ssize_t)out_buf_len) return -1;
    size_t offset = 0;
    if (write_fixed_string(payload->tld_name, sizeof(payload->tld_name), out_buf, out_buf_len, &offset) != 0) return -1;
    return offset;
}

ssize_t deserialize_payload_tld_mirror_req(const uint8_t* data, size_t data_len, payload_tld_mirror_req_t* payload) {
    if (!data || !payload || data_len < sizeof(payload->tld_name)) return -1;
    size_t offset = 0;
    if (read_fixed_string(data, data_len, &offset, payload->tld_name, sizeof(payload->tld_name)) != 0) return -1;
    return offset;
}

// Stubs for others - to be implemented
ssize_t get_serialized_payload_tld_mirror_resp_size(const payload_tld_mirror_resp_t* payload) { (void)payload; return -1; }
ssize_t serialize_payload_tld_mirror_resp(const payload_tld_mirror_resp_t* payload, uint8_t* out_buf, size_t out_buf_len) { (void)payload; (void)out_buf; (void)out_buf_len; return -1; }
ssize_t deserialize_payload_tld_mirror_resp(const uint8_t* data, size_t data_len, payload_tld_mirror_resp_t* payload) { (void)data; (void)data_len; (void)payload; return -1; }

ssize_t get_serialized_payload_tld_sync_update_size(const payload_tld_sync_update_t* payload) { (void)payload; return -1; }
ssize_t serialize_payload_tld_sync_update(const payload_tld_sync_update_t* payload, uint8_t* out_buf, size_t out_buf_len) { (void)payload; (void)out_buf; (void)out_buf_len; return -1; }
ssize_t deserialize_payload_tld_sync_update(const uint8_t* data, size_t data_len, payload_tld_sync_update_t* payload) { (void)data; (void)data_len; (void)payload; return -1; }

ssize_t get_serialized_payload_dns_query_size(const payload_dns_query_t* payload) {
    if (!payload) return -1;
    // Size of query_name (fixed buffer) + size of type enum (serialized as uint32_t)
    return sizeof(payload->query_name) + sizeof(uint32_t);
}

ssize_t serialize_payload_dns_query(const payload_dns_query_t* payload, uint8_t* out_buf, size_t out_buf_len) {
    if (!payload || !out_buf) return -1;
    ssize_t required_size = get_serialized_payload_dns_query_size(payload);
    if (required_size < 0 || (size_t)required_size > out_buf_len) return -1;

    size_t offset = 0;
    // query_name is a fixed-size char array, write it directly
    if (write_bytes((const uint8_t*)payload->query_name, sizeof(payload->query_name), out_buf, out_buf_len, &offset) != 0) return -1;
    // Serialize dns_record_type_t as uint32_t
    if (write_uint32((uint32_t)payload->type, out_buf, out_buf_len, &offset) != 0) return -1;
    return offset;
}

ssize_t deserialize_payload_dns_query(const uint8_t* data, size_t data_len, payload_dns_query_t* payload) {
    if (!data || !payload) return -1;
    // Minimum size: fixed query_name buffer + uint32_t for type
    ssize_t min_size = sizeof(payload->query_name) + sizeof(uint32_t);
    if (data_len < (size_t)min_size) return -1;

    size_t offset = 0;
    // query_name is a fixed-size char array, read it directly
    if (read_bytes(data, data_len, &offset, (uint8_t*)payload->query_name, sizeof(payload->query_name)) != 0) return -1;
    // Ensure null termination for query_name, as read_bytes might not guarantee it if source wasn't null-terminated within the fixed size
    payload->query_name[sizeof(payload->query_name) - 1] = '\0';

    uint32_t type_u32;
    if (read_uint32(data, data_len, &offset, &type_u32) != 0) return -1;
    payload->type = (dns_record_type_t)type_u32;
    return offset;
}

ssize_t get_serialized_payload_dns_response_size(const payload_dns_response_t* payload) {
    if (!payload) return -1;
    // Size of status (uint8_t) + size of record_count (uint32_t)
    ssize_t total_size = sizeof(uint8_t) + sizeof(uint32_t);
    for (int i = 0; i < payload->record_count; ++i) {
        if (!payload->records) return -1; // Invalid record array
        ssize_t record_size = get_serialized_dns_record_size(&payload->records[i]);
        if (record_size < 0) return -1; // Error getting size of a record
        total_size += record_size;
    }
    return total_size;
}

ssize_t serialize_payload_dns_response(const payload_dns_response_t* payload, uint8_t* out_buf, size_t out_buf_len) {
    if (!payload || !out_buf) return -1;
    ssize_t required_size = get_serialized_payload_dns_response_size(payload);
    if (required_size < 0 || (size_t)required_size > out_buf_len) return -1;

    size_t offset = 0;
    if (write_uint8(payload->status, out_buf, out_buf_len, &offset) != 0) return -1;
    if (write_uint32((uint32_t)payload->record_count, out_buf, out_buf_len, &offset) != 0) return -1;

    for (int i = 0; i < payload->record_count; ++i) {
        if (!payload->records) return -1; // Should not happen if size check passed
        size_t record_bytes_written = 0; // To capture bytes written by serialize_dns_record
        if (serialize_dns_record(&payload->records[i], out_buf + offset, out_buf_len - offset, &record_bytes_written) != 0) {
            return -1; // Error serializing a record
        }
        offset += record_bytes_written; // Advance offset by actual bytes written for the record
    }
    return offset;
}

ssize_t deserialize_payload_dns_response(const uint8_t* data, size_t data_len, payload_dns_response_t* payload) {
    if (!data || !payload) return -1;
    // Minimum size: status (uint8_t) + record_count (uint32_t)
    if (data_len < (sizeof(uint8_t) + sizeof(uint32_t))) return -1;

    size_t offset = 0;
    uint8_t status_u8;
    if (read_uint8(data, data_len, &offset, &status_u8) != 0) return -1;
    payload->status = (dns_response_status_t)status_u8;

    uint32_t record_count_u32;
    if (read_uint32(data, data_len, &offset, &record_count_u32) != 0) return -1;
    payload->record_count = (int)record_count_u32;

    if (payload->record_count < 0) return -1; // Invalid record count

    if (payload->record_count > 0) {
        payload->records = malloc(payload->record_count * sizeof(dns_record_t));
        if (!payload->records) {
            // Failed to allocate memory for records
            payload->record_count = 0; // Ensure consistency
            return -1; 
        }
        // Initialize memory for safety, especially for char* members in dns_record_t
        memset(payload->records, 0, payload->record_count * sizeof(dns_record_t)); 

        for (int i = 0; i < payload->record_count; ++i) {
            size_t record_bytes_read = 0;
            if (deserialize_dns_record(data + offset, data_len - offset, &payload->records[i], &record_bytes_read) != 0) {
                // Error deserializing a record. Free already allocated records and return error.
                for (int j = 0; j < i; ++j) {
                    free(payload->records[j].name);
                    free(payload->records[j].rdata);
                }
                free(payload->records);
                payload->records = NULL;
                payload->record_count = 0;
                return -1;
            }
            offset += record_bytes_read; // Advance offset by actual bytes read for the record
        }
    } else {
        payload->records = NULL; // No records to deserialize
    }
    return offset;
} 