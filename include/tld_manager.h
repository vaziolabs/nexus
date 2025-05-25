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

#endif // TLD_MANAGER_H 