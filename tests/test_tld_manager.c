#include "test_tld_manager.h"
#include "tld_manager.h" // Access to tld_manager functions
#include "debug.h"    // For dlog, if its usage is widespread or for consistency
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h> // For malloc/free if directly manipulating structures for tests

// Test a single case
static void test_case(const char* name, int condition) {
    printf("  Test: %-50s - %s\\n", name, condition ? "PASSED" : "FAILED");
    assert(condition);
}

// Test initializing and cleaning up the TLD manager
static void test_init_cleanup_tld_manager(void) {
    tld_manager_t* manager = NULL;
    int result = init_tld_manager(&manager);
    test_case("Initialize TLD Manager", result == 0 && manager != NULL);
    if (manager) {
        // Don't test lock internals directly as it's implementation-dependent
        test_case("Manager TLDs allocated", manager->tlds != NULL);
        test_case("Manager TLD count is 0", manager->tld_count == 0);
        test_case("Manager TLD capacity is > 0", manager->tld_capacity > 0);
    }
    cleanup_tld_manager(manager); // Should handle NULL if init failed
    // No easy way to assert cleanup without inspecting memory, trust it works if no crash
    test_case("Cleanup TLD Manager (no crash)", 1); 
}

// Test registering a new TLD
static void test_register_and_find_tld(void) {
    tld_manager_t* manager = NULL;
    init_tld_manager(&manager);
    if (!manager) {
        test_case("Register TLD (setup failed)", 0);
        return;
    }

    const char* tld_name1 = "nexus";
    tld_t* tld1 = register_new_tld(manager, tld_name1);
    test_case("Register new TLD 'nexus'", tld1 != NULL && strcmp(tld1->name, tld_name1) == 0);
    if (tld1) {
        test_case("TLD 'nexus' has correct creation time", tld1->created_at > 0);
        test_case("TLD 'nexus' record count is 0", tld1->record_count == 0);
    }

    tld_t* found_tld1 = find_tld_by_name(manager, tld_name1);
    test_case("Find TLD 'nexus'", found_tld1 == tld1);

    // Test registering a duplicate TLD
    tld_t* tld_dup = register_new_tld(manager, tld_name1);
    test_case("Register duplicate TLD 'nexus' (should fail or return existing)", tld_dup == NULL || tld_dup == tld1);
    // Assuming current behavior is to return NULL on duplicate rather than existing.
    // If it returns existing, the test should be `tld_dup == tld1`.
    test_case("Register duplicate TLD 'nexus' (returns NULL)", tld_dup == NULL);


    const char* tld_name2 = "hypermesh";
    tld_t* tld2 = register_new_tld(manager, tld_name2);
    test_case("Register new TLD 'hypermesh'", tld2 != NULL && strcmp(tld2->name, tld_name2) == 0);
    test_case("TLD count is 2 after registering 'nexus' and 'hypermesh'", manager->tld_count == 2);

    tld_t* found_tld2 = find_tld_by_name(manager, "hypermesh");
    test_case("Find TLD 'hypermesh'", found_tld2 == tld2);

    tld_t* not_found_tld = find_tld_by_name(manager, "notfound");
    test_case("Find non-existent TLD 'notfound'", not_found_tld == NULL);

    cleanup_tld_manager(manager);
}

// TODO: Add more tests for other tld_manager.c functions
// - test_add_remove_dns_record_to_tld
// - test_add_authoritative_node_to_tld
// - test_add_mirror_node_to_tld
// - test_tld_list_expansion (when many TLDs are added)

void ts_tld_manager_init(void) {
    printf("Initializing TLD Manager Tests...\\n");
    test_init_cleanup_tld_manager();
    test_register_and_find_tld();
    // Call other test functions here
    printf("TLD Manager Tests Finished.\\n");
} 