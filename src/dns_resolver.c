#include "../include/dns_resolver.h"
#include "../include/debug.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

// Default configuration values
#define DEFAULT_MAX_RECURSION_DEPTH 5
#define DEFAULT_CACHE_TTL_MIN 60
#define DEFAULT_CACHE_TTL_MAX 86400
#define DEFAULT_CACHE_SIZE_MAX 1000
#define DEFAULT_ENABLE_RECURSIVE_RESOLUTION 1
#define DEFAULT_ENABLE_ITERATIVE_RESOLUTION 0
#define DEFAULT_ENABLE_NEGATIVE_CACHING 1
#define DEFAULT_NEGATIVE_CACHE_TTL 300

// Helper function to duplicate a DNS record
static dns_record_t* duplicate_dns_record(const dns_record_t* src) {
    if (!src) return NULL;
    
    dns_record_t* dup = malloc(sizeof(dns_record_t));
    if (!dup) return NULL;
    
    memset(dup, 0, sizeof(dns_record_t));
    
    dup->name = strdup(src->name);
    if (!dup->name) {
        free(dup);
        return NULL;
    }
    
    dup->rdata = strdup(src->rdata);
    if (!dup->rdata) {
        free(dup->name);
        free(dup);
        return NULL;
    }
    
    dup->type = src->type;
    dup->ttl = src->ttl;
    dup->last_updated = src->last_updated;
    
    return dup;
}

// Free a DNS record
static void free_dns_record(dns_record_t* record) {
    if (!record) return;
    
    free(record->name);
    free(record->rdata);
    free(record);
}

int init_dns_resolver(dns_resolver_t** resolver, tld_manager_t* tld_manager, dns_cache_t* cache) {
    if (!resolver || !tld_manager || !cache) return -1;
    
    *resolver = malloc(sizeof(dns_resolver_t));
    if (!*resolver) return -1;
    
    memset(*resolver, 0, sizeof(dns_resolver_t));
    
    // Set default configuration
    (*resolver)->config.max_recursion_depth = DEFAULT_MAX_RECURSION_DEPTH;
    (*resolver)->config.cache_ttl_min = DEFAULT_CACHE_TTL_MIN;
    (*resolver)->config.cache_ttl_max = DEFAULT_CACHE_TTL_MAX;
    (*resolver)->config.cache_size_max = DEFAULT_CACHE_SIZE_MAX;
    (*resolver)->config.enable_recursive_resolution = DEFAULT_ENABLE_RECURSIVE_RESOLUTION;
    (*resolver)->config.enable_iterative_resolution = DEFAULT_ENABLE_ITERATIVE_RESOLUTION;
    (*resolver)->config.enable_negative_caching = DEFAULT_ENABLE_NEGATIVE_CACHING;
    (*resolver)->config.negative_cache_ttl = DEFAULT_NEGATIVE_CACHE_TTL;
    
    (*resolver)->tld_manager = tld_manager;
    (*resolver)->cache = cache;
    
    if (pthread_mutex_init(&(*resolver)->lock, NULL) != 0) {
        free(*resolver);
        *resolver = NULL;
        return -1;
    }
    
    dlog("DNS resolver initialized");
    return 0;
}

void cleanup_dns_resolver(dns_resolver_t* resolver) {
    if (!resolver) return;
    
    pthread_mutex_destroy(&resolver->lock);
    free(resolver);
    
    dlog("DNS resolver cleaned up");
}

int configure_dns_resolver(dns_resolver_t* resolver, const dns_resolver_config_t* config) {
    if (!resolver || !config) return -1;
    
    pthread_mutex_lock(&resolver->lock);
    
    // Copy configuration
    resolver->config = *config;
    
    // Validate and adjust configuration values if needed
    if (resolver->config.max_recursion_depth <= 0) {
        resolver->config.max_recursion_depth = DEFAULT_MAX_RECURSION_DEPTH;
    } else if (resolver->config.max_recursion_depth > 10) {
        resolver->config.max_recursion_depth = 10;  // Hard limit for safety
    }
    
    if (resolver->config.cache_ttl_min <= 0) {
        resolver->config.cache_ttl_min = DEFAULT_CACHE_TTL_MIN;
    }
    
    if (resolver->config.cache_ttl_max <= resolver->config.cache_ttl_min) {
        resolver->config.cache_ttl_max = resolver->config.cache_ttl_min * 10;
    }
    
    if (resolver->config.cache_size_max <= 0) {
        resolver->config.cache_size_max = DEFAULT_CACHE_SIZE_MAX;
    }
    
    if (resolver->config.negative_cache_ttl <= 0) {
        resolver->config.negative_cache_ttl = DEFAULT_NEGATIVE_CACHE_TTL;
    }
    
    pthread_mutex_unlock(&resolver->lock);
    
    dlog("DNS resolver configured: max_recursion=%d, cache_ttl_min=%d, cache_ttl_max=%d",
         resolver->config.max_recursion_depth,
         resolver->config.cache_ttl_min,
         resolver->config.cache_ttl_max);
    
    return 0;
}

int parse_fqdn(const char* fqdn, 
              char* hostname, size_t hostname_len,
              char* domain, size_t domain_len,
              char* tld, size_t tld_len) {
    if (!fqdn || !hostname || !domain || !tld) return -1;
    
    // Initialize output buffers
    if (hostname_len > 0) hostname[0] = '\0';
    if (domain_len > 0) domain[0] = '\0';
    if (tld_len > 0) tld[0] = '\0';
    
    size_t fqdn_len = strlen(fqdn);
    if (fqdn_len == 0) return -1;
    
    // Make a copy of the FQDN to work with
    char* fqdn_copy = strdup(fqdn);
    if (!fqdn_copy) return -1;
    
    // Count the number of parts separated by dots
    int dot_count = 0;
    for (size_t i = 0; i < fqdn_len; i++) {
        if (fqdn_copy[i] == '.') dot_count++;
    }
    
    // Decide how to parse based on the number of parts
    if (dot_count == 0) {
        // Single label, treat as TLD in our system
        if (tld_len > 0) {
            strncpy(tld, fqdn_copy, tld_len - 1);
            tld[tld_len - 1] = '\0';
        }
    } else {
        // Find the last dot (rightmost)
        char* last_dot = strrchr(fqdn_copy, '.');
        if (last_dot) {
            // Extract TLD (everything after the last dot)
            if (tld_len > 0) {
                strncpy(tld, last_dot + 1, tld_len - 1);
                tld[tld_len - 1] = '\0';
            }
            
            // Null-terminate at the last dot to work with the rest
            *last_dot = '\0';
            
            // Check if there are more parts
            char* second_last_dot = strrchr(fqdn_copy, '.');
            if (second_last_dot) {
                // There are at least 3 parts (hostname.domain.tld)
                
                // Extract domain (between the second-last and last dot)
                if (domain_len > 0) {
                    strncpy(domain, second_last_dot + 1, domain_len - 1);
                    domain[domain_len - 1] = '\0';
                }
                
                // Null-terminate at the second-last dot
                *second_last_dot = '\0';
                
                // Everything before the second-last dot is the hostname
                if (hostname_len > 0) {
                    strncpy(hostname, fqdn_copy, hostname_len - 1);
                    hostname[hostname_len - 1] = '\0';
                }
            } else {
                // There are exactly 2 parts (domain.tld)
                
                // Everything before the last dot is the domain
                if (domain_len > 0) {
                    strncpy(domain, fqdn_copy, domain_len - 1);
                    domain[domain_len - 1] = '\0';
                }
                
                // No hostname in this case
                if (hostname_len > 0) hostname[0] = '\0';
            }
        }
    }
    
    free(fqdn_copy);
    return 0;
}

int add_to_dns_cache(dns_resolver_t* resolver, const char* fqdn, const dns_record_t* record) {
    if (!resolver || !fqdn || !record) return -1;
    
    // Check if the cache exists
    if (!resolver->cache) return -1;
    
    pthread_mutex_lock(&resolver->cache->lock);
    
    // Check if the cache is full
    if (resolver->cache->count >= resolver->config.cache_size_max) {
        // Remove the oldest entry (simple LRU implementation)
        // In a more sophisticated implementation, we would use a proper LRU algorithm
        
        // For now, just remove the first entry
        if (resolver->cache->head) {
            dns_cache_node_t* to_remove = resolver->cache->head;
            resolver->cache->head = to_remove->next;
            
            // Free the entry
            free(to_remove->entry.fqdn);
            free(to_remove->entry.record.name);
            free(to_remove->entry.record.rdata);
            free(to_remove);
            
            resolver->cache->count--;
        }
    }
    
    // Create a new cache entry
    dns_cache_node_t* new_node = malloc(sizeof(dns_cache_node_t));
    if (!new_node) {
        pthread_mutex_unlock(&resolver->cache->lock);
        return -1;
    }
    
    // Initialize the new node
    new_node->entry.fqdn = strdup(fqdn);
    if (!new_node->entry.fqdn) {
        free(new_node);
        pthread_mutex_unlock(&resolver->cache->lock);
        return -1;
    }
    
    new_node->entry.record.name = strdup(record->name);
    if (!new_node->entry.record.name) {
        free(new_node->entry.fqdn);
        free(new_node);
        pthread_mutex_unlock(&resolver->cache->lock);
        return -1;
    }
    
    new_node->entry.record.rdata = strdup(record->rdata);
    if (!new_node->entry.record.rdata) {
        free(new_node->entry.record.name);
        free(new_node->entry.fqdn);
        free(new_node);
        pthread_mutex_unlock(&resolver->cache->lock);
        return -1;
    }
    
    new_node->entry.record.type = record->type;
    new_node->entry.record.ttl = record->ttl;
    new_node->entry.record.last_updated = record->last_updated;
    
    new_node->entry.fetched_at = time(NULL);
    new_node->entry.expires_at = new_node->entry.fetched_at + record->ttl;
    
    // Adjust TTL if needed
    if (record->ttl < resolver->config.cache_ttl_min) {
        new_node->entry.expires_at = new_node->entry.fetched_at + resolver->config.cache_ttl_min;
    } else if (record->ttl > resolver->config.cache_ttl_max) {
        new_node->entry.expires_at = new_node->entry.fetched_at + resolver->config.cache_ttl_max;
    }
    
    // Add the new node to the cache (at the beginning for simplicity)
    new_node->next = resolver->cache->head;
    resolver->cache->head = new_node;
    resolver->cache->count++;
    
    pthread_mutex_unlock(&resolver->cache->lock);
    
    dlog("Added to DNS cache: %s (type %d), expires in %ld seconds",
         fqdn, record->type, new_node->entry.expires_at - new_node->entry.fetched_at);
    
    return 0;
}

int lookup_in_dns_cache(dns_resolver_t* resolver, 
                      const char* fqdn, 
                      dns_record_type_t query_type,
                      dns_record_t** record) {
    if (!resolver || !fqdn || !record) return -1;
    
    // Check if the cache exists
    if (!resolver->cache) return -1;
    
    *record = NULL;
    
    pthread_mutex_lock(&resolver->cache->lock);
    
    time_t now = time(NULL);
    dns_cache_node_t* current = resolver->cache->head;
    dns_cache_node_t* prev = NULL;
    
    while (current) {
        // Check if this entry matches the query
        if (strcmp(current->entry.fqdn, fqdn) == 0 && 
            current->entry.record.type == query_type) {
            
            // Check if the entry is expired
            if (current->entry.expires_at <= now) {
                // Remove the expired entry
                if (prev) {
                    prev->next = current->next;
                } else {
                    resolver->cache->head = current->next;
                }
                
                dns_cache_node_t* to_remove = current;
                current = current->next;
                
                // Free the expired entry
                free(to_remove->entry.fqdn);
                free(to_remove->entry.record.name);
                free(to_remove->entry.record.rdata);
                free(to_remove);
                
                resolver->cache->count--;
                continue;
            }
            
            // Found a valid entry, duplicate it
            *record = duplicate_dns_record(&current->entry.record);
            
            pthread_mutex_unlock(&resolver->cache->lock);
            
            dlog("Cache hit for %s (type %d), TTL remaining: %ld seconds",
                 fqdn, query_type, current->entry.expires_at - now);
            
            return *record ? 1 : -1;  // 1 = found, -1 = error duplicating
        }
        
        prev = current;
        current = current->next;
    }
    
    pthread_mutex_unlock(&resolver->cache->lock);
    
    // Not found in cache
    return 0;
}

dns_response_status_t resolve_cname(dns_resolver_t* resolver,
                                 const char* cname_target,
                                 dns_record_type_t target_type,
                                 dns_record_t** records,
                                 int* record_count,
                                 int recursion_depth) {
    if (!resolver || !cname_target || !records || !record_count) 
        return DNS_STATUS_SERVFAIL;
    
    // Check recursion depth
    if (recursion_depth >= resolver->config.max_recursion_depth) {
        dlog("Maximum CNAME recursion depth reached (%d)", recursion_depth);
        return DNS_STATUS_SERVFAIL;
    }
    
    // Initialize output parameters
    *records = NULL;
    *record_count = 0;
    
    // Resolve the CNAME target
    return resolve_dns_query(resolver, cname_target, target_type, records, record_count);
}

dns_response_status_t resolve_dns_query(dns_resolver_t* resolver, 
                                     const char* query_name, 
                                     dns_record_type_t query_type,
                                     dns_record_t** records,
                                     int* record_count) {
    if (!resolver || !query_name || !records || !record_count) 
        return DNS_STATUS_SERVFAIL;
    
    // Initialize output parameters
    *records = NULL;
    *record_count = 0;
    
    // Check cache first
    dns_record_t* cached_record = NULL;
    int cache_result = lookup_in_dns_cache(resolver, query_name, query_type, &cached_record);
    
    if (cache_result > 0 && cached_record) {
        // Cache hit
        *records = malloc(sizeof(dns_record_t));
        if (!*records) {
            free_dns_record(cached_record);
            return DNS_STATUS_SERVFAIL;
        }
        
        // Copy the record
        memcpy(*records, cached_record, sizeof(dns_record_t));
        *record_count = 1;
        
        // Don't free the copied strings, as they're now owned by *records
        free(cached_record);
        
        return DNS_STATUS_SUCCESS;
    }
    
    if (cached_record) {
        free_dns_record(cached_record);
    }
    
    // Parse the query name to extract TLD
    char hostname[MAX_DOMAIN_NAME_LEN];
    char domain[MAX_DOMAIN_NAME_LEN];
    char tld[MAX_DOMAIN_NAME_LEN];
    
    if (parse_fqdn(query_name, hostname, sizeof(hostname), domain, sizeof(domain), tld, sizeof(tld)) != 0) {
        dlog("Failed to parse FQDN: %s", query_name);
        return DNS_STATUS_FORMERR;
    }
    
    // Lock the TLD manager for reading
    pthread_rwlock_rdlock(&resolver->tld_manager->lock);
    
    // Find the TLD
    tld_t* found_tld = NULL;
    for (size_t i = 0; i < resolver->tld_manager->tld_count; ++i) {
        if (strcmp(resolver->tld_manager->tlds[i]->name, tld) == 0) {
            found_tld = resolver->tld_manager->tlds[i];
            break;
        }
    }
    
    if (!found_tld) {
        pthread_rwlock_unlock(&resolver->tld_manager->lock);
        dlog("TLD not found: %s", tld);
        return DNS_STATUS_NXDOMAIN;
    }
    
    // Construct the local part of the domain for matching
    char local_part[MAX_DOMAIN_NAME_LEN] = "";
    if (domain[0] != '\0') {
        if (hostname[0] != '\0') {
            snprintf(local_part, sizeof(local_part), "%s.%s", hostname, domain);
        } else {
            strncpy(local_part, domain, sizeof(local_part) - 1);
            local_part[sizeof(local_part) - 1] = '\0';
        }
    } else {
        if (hostname[0] != '\0') {
            strncpy(local_part, hostname, sizeof(local_part) - 1);
            local_part[sizeof(local_part) - 1] = '\0';
        } else {
            // The query is for the TLD itself
            strncpy(local_part, tld, sizeof(local_part) - 1);
            local_part[sizeof(local_part) - 1] = '\0';
        }
    }
    
    // Search for matching records in the TLD
    dns_record_t* result_records = NULL;
    int result_count = 0;
    dns_response_status_t status = DNS_STATUS_NXDOMAIN;  // Default to not found
    
    // First, look for exact matches
    for (size_t i = 0; i < found_tld->record_count; ++i) {
        // Check if the record name matches what we're looking for
        if (strcmp(found_tld->records[i].name, local_part) == 0) {
            // Found a record with matching name
            
            if (found_tld->records[i].type == query_type) {
                // Exact match for the requested type
                
                // Allocate/reallocate the result array
                dns_record_t* temp = realloc(result_records, (result_count + 1) * sizeof(dns_record_t));
                if (!temp) {
                    status = DNS_STATUS_SERVFAIL;
                    goto cleanup;
                }
                result_records = temp;
                
                // Copy the record
                dns_record_t* new_record = &result_records[result_count];
                
                new_record->name = strdup(found_tld->records[i].name);
                if (!new_record->name) {
                    status = DNS_STATUS_SERVFAIL;
                    goto cleanup;
                }
                
                new_record->rdata = strdup(found_tld->records[i].rdata);
                if (!new_record->rdata) {
                    free(new_record->name);
                    status = DNS_STATUS_SERVFAIL;
                    goto cleanup;
                }
                
                new_record->type = found_tld->records[i].type;
                new_record->ttl = found_tld->records[i].ttl;
                new_record->last_updated = found_tld->records[i].last_updated;
                
                result_count++;
                status = DNS_STATUS_SUCCESS;
                
                // Cache the result
                add_to_dns_cache(resolver, query_name, new_record);
            }
            else if (found_tld->records[i].type == DNS_RECORD_TYPE_CNAME && 
                     query_type != DNS_RECORD_TYPE_CNAME) {
                // CNAME found, need to follow it
                
                // Check if recursive resolution is enabled
                if (resolver->config.enable_recursive_resolution) {
                    // Save the CNAME record
                    dns_record_t* cname_record = malloc(sizeof(dns_record_t));
                    if (!cname_record) {
                        status = DNS_STATUS_SERVFAIL;
                        goto cleanup;
                    }
                    
                    cname_record->name = strdup(found_tld->records[i].name);
                    if (!cname_record->name) {
                        free(cname_record);
                        status = DNS_STATUS_SERVFAIL;
                        goto cleanup;
                    }
                    
                    cname_record->rdata = strdup(found_tld->records[i].rdata);
                    if (!cname_record->rdata) {
                        free(cname_record->name);
                        free(cname_record);
                        status = DNS_STATUS_SERVFAIL;
                        goto cleanup;
                    }
                    
                    cname_record->type = DNS_RECORD_TYPE_CNAME;
                    cname_record->ttl = found_tld->records[i].ttl;
                    cname_record->last_updated = found_tld->records[i].last_updated;
                    
                    // Add the CNAME record to the results
                    dns_record_t* temp = realloc(result_records, (result_count + 1) * sizeof(dns_record_t));
                    if (!temp) {
                        free(cname_record->name);
                        free(cname_record->rdata);
                        free(cname_record);
                        status = DNS_STATUS_SERVFAIL;
                        goto cleanup;
                    }
                    result_records = temp;
                    
                    // Copy the record
                    memcpy(&result_records[result_count], cname_record, sizeof(dns_record_t));
                    result_count++;
                    
                    // Free the temporary record (strings are now owned by result_records)
                    free(cname_record);
                    
                    // Cache the CNAME record
                    add_to_dns_cache(resolver, query_name, &result_records[result_count - 1]);
                    
                    // Follow the CNAME
                    dns_record_t* cname_target_records = NULL;
                    int cname_target_count = 0;
                    
                    dns_response_status_t cname_status = resolve_cname(
                        resolver,
                        result_records[result_count - 1].rdata,  // CNAME target
                        query_type,                              // Original query type
                        &cname_target_records,
                        &cname_target_count,
                        1                                        // Initial recursion depth
                    );
                    
                    if (cname_status == DNS_STATUS_SUCCESS && cname_target_records && cname_target_count > 0) {
                        // Add the target records to the results
                        temp = realloc(result_records, 
                                      (result_count + cname_target_count) * sizeof(dns_record_t));
                        if (!temp) {
                            // Free the CNAME target records
                            for (int j = 0; j < cname_target_count; j++) {
                                free(cname_target_records[j].name);
                                free(cname_target_records[j].rdata);
                            }
                            free(cname_target_records);
                            
                            status = DNS_STATUS_SERVFAIL;
                            goto cleanup;
                        }
                        
                        result_records = temp;
                        
                        // Copy the records
                        for (int j = 0; j < cname_target_count; j++) {
                            memcpy(&result_records[result_count + j], 
                                   &cname_target_records[j], 
                                   sizeof(dns_record_t));
                        }
                        
                        result_count += cname_target_count;
                        
                        // Free the array but not the strings, as they're now owned by result_records
                        free(cname_target_records);
                        
                        status = DNS_STATUS_SUCCESS;
                    } else {
                        // Failed to resolve CNAME target
                        if (cname_target_records) {
                            for (int j = 0; j < cname_target_count; j++) {
                                free(cname_target_records[j].name);
                                free(cname_target_records[j].rdata);
                            }
                            free(cname_target_records);
                        }
                        
                        // We still return the CNAME record
                        status = DNS_STATUS_SUCCESS;
                    }
                } else {
                    // Recursive resolution disabled, just return the CNAME
                    dns_record_t* temp = realloc(result_records, (result_count + 1) * sizeof(dns_record_t));
                    if (!temp) {
                        status = DNS_STATUS_SERVFAIL;
                        goto cleanup;
                    }
                    result_records = temp;
                    
                    // Copy the record
                    dns_record_t* new_record = &result_records[result_count];
                    
                    new_record->name = strdup(found_tld->records[i].name);
                    if (!new_record->name) {
                        status = DNS_STATUS_SERVFAIL;
                        goto cleanup;
                    }
                    
                    new_record->rdata = strdup(found_tld->records[i].rdata);
                    if (!new_record->rdata) {
                        free(new_record->name);
                        status = DNS_STATUS_SERVFAIL;
                        goto cleanup;
                    }
                    
                    new_record->type = DNS_RECORD_TYPE_CNAME;
                    new_record->ttl = found_tld->records[i].ttl;
                    new_record->last_updated = found_tld->records[i].last_updated;
                    
                    result_count++;
                    status = DNS_STATUS_SUCCESS;
                    
                    // Cache the result
                    add_to_dns_cache(resolver, query_name, new_record);
                }
            }
        }
    }
    
    // If we found records, we're done
    if (status == DNS_STATUS_SUCCESS && result_count > 0) {
        *records = result_records;
        *record_count = result_count;
        pthread_rwlock_unlock(&resolver->tld_manager->lock);
        return status;
    }
    
cleanup:
    // Clean up if we had an error or found no records
    if (result_records) {
        for (int i = 0; i < result_count; i++) {
            free(result_records[i].name);
            free(result_records[i].rdata);
        }
        free(result_records);
    }
    
    pthread_rwlock_unlock(&resolver->tld_manager->lock);
    
    return status;
} 