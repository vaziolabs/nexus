#include "test_packet_protocol.h"
#include "packet_protocol.h"
#include "debug.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h> // For malloc/free

// Re-define test_case or include a common test helper header
static void test_case(const char* name, int condition) {
    printf("  Test: %-55s - %s\\n", name, condition ? "PASSED" : "FAILED");
    assert(condition);
}

static void test_nexus_packet_serialization_deserialization(void) {
    nexus_packet_t original_packet, deserialized_packet;
    uint8_t buffer[1024];
    ssize_t serialized_size, deserialized_size;

    printf("Starting packet serialization test...\n");

    // Test Case 1: Packet with no data
    memset(&original_packet, 0, sizeof(nexus_packet_t));
    original_packet.version = 1;
    original_packet.type = PACKET_TYPE_HEARTBEAT; // Assuming this type exists
    original_packet.session_id = 0x1234567890ABCDEFULL;
    original_packet.data_len = 0;
    original_packet.data = NULL;

    printf("Serializing packet with no data...\n");
    serialized_size = serialize_nexus_packet(&original_packet, buffer, sizeof(buffer));
    printf("Serialized size: %zd\n", serialized_size);
    test_case("nexus_packet_t (no data) serialization size > 0", serialized_size > 0);
    
    if (serialized_size > 0) {
        printf("Deserializing packet...\n");
        memset(&deserialized_packet, 0, sizeof(nexus_packet_t));
        deserialized_size = deserialize_nexus_packet(buffer, serialized_size, &deserialized_packet);
        printf("Deserialized size: %zd\n", deserialized_size);
        test_case("nexus_packet_t (no data) deserialization successful", deserialized_size > 0);
        
        printf("Original packet: version=%d, type=%d, session_id=%lx, data_len=%u\n", 
               original_packet.version, original_packet.type, original_packet.session_id, original_packet.data_len);
        printf("Deserialized packet: version=%d, type=%d, session_id=%lx, data_len=%u\n", 
               deserialized_packet.version, deserialized_packet.type, deserialized_packet.session_id, deserialized_packet.data_len);
        
        test_case("nexus_packet_t (no data) version matches", deserialized_packet.version == original_packet.version);
        test_case("nexus_packet_t (no data) type matches", deserialized_packet.type == original_packet.type);
        test_case("nexus_packet_t (no data) session_id matches", deserialized_packet.session_id == original_packet.session_id);
        test_case("nexus_packet_t (no data) data_len is 0", deserialized_packet.data_len == 0);
        test_case("nexus_packet_t (no data) data is NULL", deserialized_packet.data == NULL);
        free(deserialized_packet.data); // Should be NULL, but good practice
    }

    // Test Case 2: Packet with some data
    printf("\nStarting test with data...\n");
    uint8_t* sample_data = malloc(4);
    if (!sample_data) {
        printf("Failed to allocate sample data\n");
        return;
    }
    
    sample_data[0] = 0xDE;
    sample_data[1] = 0xAD;
    sample_data[2] = 0xBE;
    sample_data[3] = 0xEF;
    
    original_packet.version = 2;
    original_packet.type = PACKET_TYPE_DNS_QUERY;
    original_packet.session_id = 0xFFEEDDCCBBAA9988ULL;
    original_packet.data_len = 4;
    original_packet.data = sample_data;

    printf("Serializing packet with data...\n");
    memset(buffer, 0, sizeof(buffer));
    serialized_size = serialize_nexus_packet(&original_packet, buffer, sizeof(buffer));
    printf("Serialized size: %zd\n", serialized_size);
    test_case("nexus_packet_t (with data) serialization size > 0", serialized_size > 0);

    if (serialized_size > 0) {
        printf("Deserializing packet with data...\n");
        memset(&deserialized_packet, 0, sizeof(nexus_packet_t));
        deserialized_size = deserialize_nexus_packet(buffer, serialized_size, &deserialized_packet);
        printf("Deserialized size: %zd\n", deserialized_size);
        test_case("nexus_packet_t (with data) deserialization successful", deserialized_size > 0);
        
        printf("Original packet: version=%d, type=%d, session_id=%lx, data_len=%u\n", 
               original_packet.version, original_packet.type, original_packet.session_id, original_packet.data_len);
        printf("Deserialized packet: version=%d, type=%d, session_id=%lx, data_len=%u\n", 
               deserialized_packet.version, deserialized_packet.type, deserialized_packet.session_id, deserialized_packet.data_len);
               
        test_case("nexus_packet_t (with data) version matches", deserialized_packet.version == original_packet.version);
        test_case("nexus_packet_t (with data) type matches", deserialized_packet.type == original_packet.type);
        test_case("nexus_packet_t (with data) session_id matches", deserialized_packet.session_id == original_packet.session_id);
        test_case("nexus_packet_t (with data) data_len matches", deserialized_packet.data_len == original_packet.data_len);
        test_case("nexus_packet_t (with data) data is not NULL", deserialized_packet.data != NULL);
        if (deserialized_packet.data) {
            test_case("nexus_packet_t (with data) data content matches", memcmp(deserialized_packet.data, original_packet.data, original_packet.data_len) == 0);
        }
        free(deserialized_packet.data);
    }
    
    free(sample_data);
}

static void test_tld_register_req_payload_serialization_deserialization(void) {
    payload_tld_register_req_t original_payload, deserialized_payload;
    uint8_t buffer[sizeof(payload_tld_register_req_t) + 10]; // A bit of padding
    ssize_t serialized_size, deserialized_size;

    // Test Case 1: Basic TLD name
    memset(&original_payload, 0, sizeof(payload_tld_register_req_t));
    strncpy(original_payload.tld_name, "exampletld", sizeof(original_payload.tld_name) - 1);

    serialized_size = serialize_payload_tld_register_req(&original_payload, buffer, sizeof(buffer));
    // Current fixed-size serialization just returns sizeof(payload->tld_name)
    test_case("payload_tld_register_req_t serialization size correct", serialized_size == (ssize_t)sizeof(original_payload.tld_name));

    if (serialized_size > 0) {
        memset(&deserialized_payload, 0, sizeof(payload_tld_register_req_t));
        deserialized_size = deserialize_payload_tld_register_req(buffer, serialized_size, &deserialized_payload);
        test_case("payload_tld_register_req_t deserialization size matches", deserialized_size == serialized_size);
        test_case("payload_tld_register_req_t tld_name matches", strcmp(deserialized_payload.tld_name, original_payload.tld_name) == 0);
    }

    // Test Case 2: TLD name that is max length
    memset(original_payload.tld_name, 'a', sizeof(original_payload.tld_name) -1 );
    original_payload.tld_name[sizeof(original_payload.tld_name) - 1] = '\0';
    
    serialized_size = serialize_payload_tld_register_req(&original_payload, buffer, sizeof(buffer));
    test_case("payload_tld_register_req_t (max name) serialization size correct", serialized_size == (ssize_t)sizeof(original_payload.tld_name));

    if (serialized_size > 0) {
        memset(&deserialized_payload, 0, sizeof(payload_tld_register_req_t));
        deserialized_size = deserialize_payload_tld_register_req(buffer, serialized_size, &deserialized_payload);
        test_case("payload_tld_register_req_t (max name) deserialization size matches", deserialized_size == serialized_size);
        test_case("payload_tld_register_req_t (max name) tld_name matches", strcmp(deserialized_payload.tld_name, original_payload.tld_name) == 0);
    }
}

// TODO: Add tests for other payload types
// - test_tld_register_resp_payload_s10n_d10n
// - test_dns_record_s10n_d10n (this one is complex)

void ts_packet_protocol_init(void) {
    printf("Initializing Packet Protocol Tests...\\n");
    test_nexus_packet_serialization_deserialization();
    test_tld_register_req_payload_serialization_deserialization();
    // Call other test functions here
    printf("Packet Protocol Tests Finished.\\n");
} 