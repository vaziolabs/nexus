#ifndef TLD_MANAGER_H
#define TLD_MANAGER_H

#include <stdint.h>
#include <pthread.h>
#include "dns_types.h"

// Function declarations
int init_tld_manager(tld_manager_t** manager_ptr);
void cleanup_tld_manager(tld_manager_t* manager);
tld_t* register_new_tld(tld_manager_t* manager, const char* tld_name);
tld_t* find_tld_by_name(tld_manager_t* manager, const char* tld_name);
int add_dns_record_to_tld(tld_t* tld, const dns_record_t* record_in);

// TLD Mirroring and Synchronization Functions
int request_tld_mirror(tld_manager_t* manager, const char* tld_name, const char* peer_hostname, const char* peer_ip);
int sync_tld_update(tld_manager_t* manager, const char* tld_name, const dns_record_t* updated_record);
int discover_tld_peers(tld_manager_t* manager, const char* tld_name, tld_node_t** discovered_peers, size_t* peer_count);
int cleanup_stale_peers(tld_manager_t* manager, time_t stale_threshold);
int get_tld_sync_status(tld_manager_t* manager, const char* tld_name, time_t* last_sync, size_t* peer_count);

#endif // TLD_MANAGER_H 