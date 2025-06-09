#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../include/dns_resolver.h"
#include "../include/tld_manager.h"
#include "../include/debug.h"

// Test helper function
static void test_assert(int condition, const char* test_name) {
    if (condition) {
        printf("  Test: %-50s - PASSED\n", test_name);
    } else {
        printf("  Test: %-50s - FAILED\n", test_name);
        exit(1);
    }
}

int test_dns_resolver() {
    printf(">>> Testing DNS Resolver <<<\n");
    
    // Initialize TLD manager
    tld_manager_t* tld_manager = NULL;
    test_assert(init_tld_manager(&tld_manager) == 0, "Initialize TLD Manager");
    
    // Initialize DNS cache
    dns_cache_t* cache = malloc(sizeof(dns_cache_t));
    memset(cache, 0, sizeof(dns_cache_t));
    cache->max_size = 100;
    pthread_mutex_init(&cache->lock, NULL);
    
    // Initialize DNS resolver
    dns_resolver_t* resolver = NULL;
    test_assert(init_dns_resolver(&resolver, tld_manager, cache) == 0, "Initialize DNS Resolver");
    
    // Register a test TLD
    test_assert(register_new_tld(tld_manager, "test") != NULL, "Register test TLD");
    
    // Test adding different record types
    test_assert(add_record_to_tld(tld_manager, "test", "www", DNS_RECORD_TYPE_A, "192.168.1.1", 3600) == 0,
                "Add A record");
    
    test_assert(add_record_to_tld(tld_manager, "test", "www", DNS_RECORD_TYPE_AAAA, "2001:db8::1", 3600) == 0,
                "Add AAAA record");
    
    test_assert(add_record_to_tld(tld_manager, "test", "mail", DNS_RECORD_TYPE_MX, "10 mail.test", 3600) == 0,
                "Add MX record");
    
    test_assert(add_record_to_tld(tld_manager, "test", "info", DNS_RECORD_TYPE_TXT, "v=spf1 include:_spf.test ~all", 3600) == 0,
                "Add TXT record");
    
    test_assert(add_record_to_tld(tld_manager, "test", "_http._tcp", DNS_RECORD_TYPE_SRV, "10 20 80 web.test", 3600) == 0,
                "Add SRV record");
    
    test_assert(add_record_to_tld(tld_manager, "test", "alias", DNS_RECORD_TYPE_CNAME, "www.test", 3600) == 0,
                "Add CNAME record");
    
    // Test DNS resolution for different record types
    dns_record_t* records = NULL;
    int record_count = 0;
    
    // Test A record resolution
    dns_response_status_t status = resolve_dns_query(resolver, "www.test", DNS_RECORD_TYPE_A, &records, &record_count);
    test_assert(status == DNS_STATUS_SUCCESS, "Resolve A record");
    test_assert(record_count == 1, "A record count is 1");
    test_assert(strcmp(records[0].rdata, "192.168.1.1") == 0, "A record data matches");
    if (records) {
        for (int i = 0; i < record_count; i++) {
            free(records[i].name);
            free(records[i].rdata);
        }
        free(records);
        records = NULL;
    }
    
    // Test AAAA record resolution
    status = resolve_dns_query(resolver, "www.test", DNS_RECORD_TYPE_AAAA, &records, &record_count);
    test_assert(status == DNS_STATUS_SUCCESS, "Resolve AAAA record");
    test_assert(record_count == 1, "AAAA record count is 1");
    test_assert(strcmp(records[0].rdata, "2001:db8::1") == 0, "AAAA record data matches");
    if (records) {
        for (int i = 0; i < record_count; i++) {
            free(records[i].name);
            free(records[i].rdata);
        }
        free(records);
        records = NULL;
    }
    
    // Test MX record resolution
    status = resolve_dns_query(resolver, "mail.test", DNS_RECORD_TYPE_MX, &records, &record_count);
    test_assert(status == DNS_STATUS_SUCCESS, "Resolve MX record");
    test_assert(record_count == 1, "MX record count is 1");
    test_assert(strcmp(records[0].rdata, "10 mail.test") == 0, "MX record data matches");
    if (records) {
        for (int i = 0; i < record_count; i++) {
            free(records[i].name);
            free(records[i].rdata);
        }
        free(records);
        records = NULL;
    }
    
    // Test TXT record resolution
    status = resolve_dns_query(resolver, "info.test", DNS_RECORD_TYPE_TXT, &records, &record_count);
    test_assert(status == DNS_STATUS_SUCCESS, "Resolve TXT record");
    test_assert(record_count == 1, "TXT record count is 1");
    test_assert(strcmp(records[0].rdata, "v=spf1 include:_spf.test ~all") == 0, "TXT record data matches");
    if (records) {
        for (int i = 0; i < record_count; i++) {
            free(records[i].name);
            free(records[i].rdata);
        }
        free(records);
        records = NULL;
    }
    
    // Test SRV record resolution
    status = resolve_dns_query(resolver, "_http._tcp.test", DNS_RECORD_TYPE_SRV, &records, &record_count);
    test_assert(status == DNS_STATUS_SUCCESS, "Resolve SRV record");
    test_assert(record_count == 1, "SRV record count is 1");
    test_assert(strcmp(records[0].rdata, "10 20 80 web.test") == 0, "SRV record data matches");
    if (records) {
        for (int i = 0; i < record_count; i++) {
            free(records[i].name);
            free(records[i].rdata);
        }
        free(records);
        records = NULL;
    }
    
    // Test CNAME record resolution
    status = resolve_dns_query(resolver, "alias.test", DNS_RECORD_TYPE_CNAME, &records, &record_count);
    test_assert(status == DNS_STATUS_SUCCESS, "Resolve CNAME record");
    test_assert(record_count == 1, "CNAME record count is 1");
    test_assert(strcmp(records[0].rdata, "www.test") == 0, "CNAME record data matches");
    if (records) {
        for (int i = 0; i < record_count; i++) {
            free(records[i].name);
            free(records[i].rdata);
        }
        free(records);
        records = NULL;
    }
    
    // Test non-existent record
    status = resolve_dns_query(resolver, "nonexistent.test", DNS_RECORD_TYPE_A, &records, &record_count);
    test_assert(status == DNS_STATUS_NXDOMAIN, "Non-existent record returns NXDOMAIN");
    test_assert(record_count == 0, "Non-existent record count is 0");
    
    // Test external DNS resolution (if enabled)
    if (resolver->config.enable_recursive_resolution) {
        printf("  Testing external DNS resolution...\n");
        
        // Test resolving a well-known external domain
        status = resolve_dns_query(resolver, "google.com", DNS_RECORD_TYPE_A, &records, &record_count);
        if (status == DNS_STATUS_SUCCESS) {
            test_assert(record_count > 0, "External DNS resolution returns records");
            test_assert(records != NULL, "External DNS records are not NULL");
            
            printf("  External DNS resolved google.com to %d A record(s)\n", record_count);
            for (int i = 0; i < record_count; i++) {
                printf("    %s -> %s\n", records[i].name, records[i].rdata);
            }
            
            // Clean up external records
            if (records) {
                for (int i = 0; i < record_count; i++) {
                    free(records[i].name);
                    free(records[i].rdata);
                }
                free(records);
                records = NULL;
            }
        } else {
            printf("  External DNS resolution failed (status: %d) - this may be expected in some environments\n", status);
        }
        
        // Test IPv6 external resolution
        status = resolve_dns_query(resolver, "google.com", DNS_RECORD_TYPE_AAAA, &records, &record_count);
        if (status == DNS_STATUS_SUCCESS) {
            test_assert(record_count > 0, "External DNS IPv6 resolution returns records");
            printf("  External DNS resolved google.com to %d AAAA record(s)\n", record_count);
            
            // Clean up external records
            if (records) {
                for (int i = 0; i < record_count; i++) {
                    free(records[i].name);
                    free(records[i].rdata);
                }
                free(records);
                records = NULL;
            }
        }
    } else {
        printf("  External DNS resolution disabled - skipping external tests\n");
    }
    
    // Clean up
    cleanup_dns_resolver(resolver);
    cleanup_tld_manager(tld_manager);
    pthread_mutex_destroy(&cache->lock);
    free(cache);
    
    printf("DNS Resolver Tests Finished.\n");
    return 0;
} 