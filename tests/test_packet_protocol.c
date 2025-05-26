#include "test_packet_protocol.h"
#include "../include/packet_protocol.h"
#include "../include/dns_types.h"
#include "../include/debug.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h> // For malloc/free
#include <time.h>   // For time()

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

static void test_dns_query_payload_serialization_deserialization(void) {
    payload_dns_query_t original_payload, deserialized_payload;
    uint8_t buffer[sizeof(payload_dns_query_t) + 50]; // Buffer with padding
    ssize_t serialized_size, deserialized_size;
    ssize_t expected_size;

    printf("\nStarting DNS Query Payload Serialization/Deserialization Tests...\n");

    // Test Case 1: Basic DNS Query
    memset(&original_payload, 0, sizeof(payload_dns_query_t));
    strncpy(original_payload.query_name, "test.example.com", sizeof(original_payload.query_name) - 1);
    original_payload.type = DNS_RECORD_TYPE_AAAA;

    expected_size = get_serialized_payload_dns_query_size(&original_payload);
    serialized_size = serialize_payload_dns_query(&original_payload, buffer, sizeof(buffer));
    test_case("payload_dns_query_t serialization size correct", serialized_size == expected_size && serialized_size > 0);

    if (serialized_size > 0) {
        memset(&deserialized_payload, 0, sizeof(payload_dns_query_t));
        deserialized_size = deserialize_payload_dns_query(buffer, serialized_size, &deserialized_payload);
        test_case("payload_dns_query_t deserialization size matches serialized", deserialized_size == serialized_size);
        test_case("payload_dns_query_t query_name matches", strcmp(deserialized_payload.query_name, original_payload.query_name) == 0);
        test_case("payload_dns_query_t type matches", deserialized_payload.type == original_payload.type);
    }

    // Test Case 2: Query name at max length
    memset(&original_payload, 0, sizeof(payload_dns_query_t));
    memset(original_payload.query_name, 'a', sizeof(original_payload.query_name) -1);
    original_payload.query_name[sizeof(original_payload.query_name)-1] = '\0';
    original_payload.type = DNS_RECORD_TYPE_A;

    expected_size = get_serialized_payload_dns_query_size(&original_payload);
    serialized_size = serialize_payload_dns_query(&original_payload, buffer, sizeof(buffer));
    test_case("payload_dns_query_t (max name) serialization size correct", serialized_size == expected_size && serialized_size > 0);

    if (serialized_size > 0) {
        memset(&deserialized_payload, 0, sizeof(payload_dns_query_t));
        deserialized_size = deserialize_payload_dns_query(buffer, serialized_size, &deserialized_payload);
        test_case("payload_dns_query_t (max name) deserialization size matches serialized", deserialized_size == serialized_size);
        test_case("payload_dns_query_t (max name) query_name matches", strcmp(deserialized_payload.query_name, original_payload.query_name) == 0);
        test_case("payload_dns_query_t (max name) type matches", deserialized_payload.type == original_payload.type);
    }
}

static void test_dns_response_payload_serialization_deserialization(void) {
    payload_dns_response_t original_payload, deserialized_payload;
    uint8_t buffer[1024]; // Buffer for response, might need to be larger for many records
    ssize_t serialized_size, deserialized_size;
    ssize_t expected_size;

    printf("\nStarting DNS Response Payload Serialization/Deserialization Tests...\n");

    // Test Case 1: Success with one AAAA record
    memset(&original_payload, 0, sizeof(payload_dns_response_t));
    original_payload.status = DNS_STATUS_SUCCESS;
    original_payload.record_count = 1;
    original_payload.records = malloc(sizeof(dns_record_t));
    assert(original_payload.records != NULL);
    original_payload.records[0].name = strdup("test.example.com");
    original_payload.records[0].type = DNS_RECORD_TYPE_AAAA;
    original_payload.records[0].ttl = 3600;
    original_payload.records[0].rdata = strdup("2001:db8::1");
    original_payload.records[0].last_updated = time(NULL);
    assert(original_payload.records[0].name != NULL && original_payload.records[0].rdata != NULL);

    expected_size = get_serialized_payload_dns_response_size(&original_payload);
    serialized_size = serialize_payload_dns_response(&original_payload, buffer, sizeof(buffer));
    printf("DNS Response Test Case 1: expected_size = %zd, serialized_size = %zd\n", expected_size, serialized_size);
    test_case("payload_dns_response_t (1 AAAA record) serialization size correct", serialized_size == expected_size && serialized_size > 0);

    if (serialized_size > 0) {
        memset(&deserialized_payload, 0, sizeof(payload_dns_response_t));
        deserialized_size = deserialize_payload_dns_response(buffer, serialized_size, &deserialized_payload);
        test_case("payload_dns_response_t (1 AAAA record) deserialization size matches serialized", deserialized_size == serialized_size);
        test_case("payload_dns_response_t (1 AAAA record) status matches", deserialized_payload.status == original_payload.status);
        test_case("payload_dns_response_t (1 AAAA record) record_count matches", deserialized_payload.record_count == original_payload.record_count);
        if (deserialized_payload.record_count == 1 && deserialized_payload.records) {
            test_case("payload_dns_response_t (1 AAAA record) record name matches", strcmp(deserialized_payload.records[0].name, original_payload.records[0].name) == 0);
            test_case("payload_dns_response_t (1 AAAA record) record type matches", deserialized_payload.records[0].type == original_payload.records[0].type);
            test_case("payload_dns_response_t (1 AAAA record) record ttl matches", deserialized_payload.records[0].ttl == original_payload.records[0].ttl);
            test_case("payload_dns_response_t (1 AAAA record) record rdata matches", strcmp(deserialized_payload.records[0].rdata, original_payload.records[0].rdata) == 0);
            // last_updated might differ slightly if serialization/deserialization adds any delay and a new time(NULL) is used.
            // For this test, we assume they are close enough or the test needs to account for it.
            // Or better, the deserialized record should preserve the original timestamp.
            test_case("payload_dns_response_t (1 AAAA record) record last_updated matches", deserialized_payload.records[0].last_updated == original_payload.records[0].last_updated);
        }
        // Cleanup deserialized payload records
        if (deserialized_payload.records) {
            for (int i = 0; i < deserialized_payload.record_count; ++i) {
                free(deserialized_payload.records[i].name);
                free(deserialized_payload.records[i].rdata);
            }
            free(deserialized_payload.records);
        }
    }
    // Cleanup original payload records
    free(original_payload.records[0].name);
    free(original_payload.records[0].rdata);
    free(original_payload.records);

    // Test Case 2: NXDOMAIN response (no records)
    memset(&original_payload, 0, sizeof(payload_dns_response_t));
    original_payload.status = DNS_STATUS_NXDOMAIN;
    original_payload.record_count = 0;
    original_payload.records = NULL;

    expected_size = get_serialized_payload_dns_response_size(&original_payload);
    serialized_size = serialize_payload_dns_response(&original_payload, buffer, sizeof(buffer));
    printf("DNS Response Test Case 2 (NXDOMAIN): expected_size = %zd, serialized_size = %zd\n", expected_size, serialized_size);
    test_case("payload_dns_response_t (NXDOMAIN) serialization size correct", serialized_size == expected_size && serialized_size > 0);

    if (serialized_size > 0) {
        memset(&deserialized_payload, 0, sizeof(payload_dns_response_t));
        deserialized_size = deserialize_payload_dns_response(buffer, serialized_size, &deserialized_payload);
        test_case("payload_dns_response_t (NXDOMAIN) deserialization size matches serialized", deserialized_size == serialized_size);
        test_case("payload_dns_response_t (NXDOMAIN) status matches", deserialized_payload.status == original_payload.status);
        test_case("payload_dns_response_t (NXDOMAIN) record_count is 0", deserialized_payload.record_count == 0);
        test_case("payload_dns_response_t (NXDOMAIN) records is NULL", deserialized_payload.records == NULL);
        // No records to cleanup in deserialized_payload for NXDOMAIN
    }
    // No records to cleanup in original_payload for NXDOMAIN

    // TODO: Add test case for multiple records of different types if supported by dns_record_t serialization
}

// TODO: Add tests for other payload types
// - test_tld_register_resp_payload_s10n_d10n
// - test_dns_record_s10n_d10n (this one is complex)

void ts_packet_protocol_init(void) {
    printf("Initializing Packet Protocol Tests...\\n");
    test_nexus_packet_serialization_deserialization();
    test_tld_register_req_payload_serialization_deserialization();
    test_dns_query_payload_serialization_deserialization();
    test_dns_response_payload_serialization_deserialization();
    // Call other test functions here
    printf("Packet Protocol Tests Finished.\\n");
} 