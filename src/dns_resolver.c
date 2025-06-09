#include "../include/dns_resolver.h"
#include "../include/debug.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

// Default configuration values
#define DEFAULT_MAX_RECURSION_DEPTH 5
#define DEFAULT_CACHE_TTL_MIN 60
#define DEFAULT_CACHE_TTL_MAX 86400
#define DEFAULT_CACHE_SIZE_MAX 1000
#define DEFAULT_ENABLE_RECURSIVE_RESOLUTION 1
#define DEFAULT_ENABLE_ITERATIVE_RESOLUTION 0
#define DEFAULT_ENABLE_NEGATIVE_CACHING 1
#define DEFAULT_NEGATIVE_CACHE_TTL 300

// External DNS server configuration
#define DEFAULT_EXTERNAL_DNS_SERVER "8.8.8.8"
#define DEFAULT_EXTERNAL_DNS_PORT 53
#define DNS_QUERY_TIMEOUT 5

// Structure for external DNS query
typedef struct {
    char* server;
    int port;
    int timeout;
} external_dns_config_t;

// Forward declarations for external DNS functions
static dns_response_status_t resolve_external_dns(const char* query_name, 
                                                 dns_record_type_t query_type,
                                                 dns_record_t** records,
                                                 int* record_count,
                                                 const external_dns_config_t* config);

static int is_external_domain(const char* query_name, tld_manager_t* tld_manager);

// Enhanced error handling and logging
static void log_dns_error(const char* operation, const char* domain, dns_response_status_t status) {
    const char* status_str;
    switch (status) {
        case DNS_STATUS_SUCCESS: status_str = "SUCCESS"; break;
        case DNS_STATUS_FORMERR: status_str = "FORMAT_ERROR"; break;
        case DNS_STATUS_SERVFAIL: status_str = "SERVER_FAILURE"; break;
        case DNS_STATUS_NXDOMAIN: status_str = "DOMAIN_NOT_FOUND"; break;
        case DNS_STATUS_NOTIMP: status_str = "NOT_IMPLEMENTED"; break;
        case DNS_STATUS_REFUSED: status_str = "REFUSED"; break;
        default: status_str = "UNKNOWN_ERROR"; break;
    }
    
    dlog("DNS %s failed for domain '%s': %s (%d)", operation, domain ? domain : "NULL", status_str, status);
}

// Enhanced cache management with error recovery
static int recover_dns_cache(dns_resolver_t* resolver) {
    if (!resolver || !resolver->cache) return -1;
    
    dlog("Attempting DNS cache recovery");
    
    pthread_mutex_lock(&resolver->cache->lock);
    
    // Count valid entries
    int valid_count = 0;
    dns_cache_node_t* current = resolver->cache->head;
    time_t now = time(NULL);
    
    while (current) {
        if (current->entry.expires_at > now) {
            valid_count++;
        }
        current = current->next;
    }
    
    dlog("DNS cache recovery: %d valid entries out of %d total", valid_count, (int)resolver->cache->count);
    
    // If cache is severely corrupted, clear it
    if (valid_count < (int)(resolver->cache->count / 2)) {
        dlog("DNS cache severely corrupted, clearing all entries");
        
        current = resolver->cache->head;
        while (current) {
            dns_cache_node_t* next = current->next;
            free(current->entry.fqdn);
            free(current->entry.record.name);
            free(current->entry.record.rdata);
            free(current);
            current = next;
        }
        
        resolver->cache->head = NULL;
        resolver->cache->count = 0;
    }
    
    pthread_mutex_unlock(&resolver->cache->lock);
    
    dlog("DNS cache recovery completed");
    return 0;
}

// Enhanced external DNS resolution with fallback
static dns_response_status_t resolve_external_dns_with_fallback(const char* query_name, 
                                                               dns_record_type_t query_type,
                                                               dns_record_t** records,
                                                               int* record_count) {
    if (!query_name || !records || !record_count) {
        return DNS_STATUS_SERVFAIL;
    }
    
    // Primary external DNS servers to try
    const char* dns_servers[] = {
        "8.8.8.8",      // Google DNS
        "1.1.1.1",      // Cloudflare DNS
        "208.67.222.222" // OpenDNS
    };
    const int num_servers = sizeof(dns_servers) / sizeof(dns_servers[0]);
    
    for (int i = 0; i < num_servers; i++) {
        external_dns_config_t config = {
            .server = (char*)dns_servers[i],
            .port = DEFAULT_EXTERNAL_DNS_PORT,
            .timeout = DNS_QUERY_TIMEOUT
        };
        
        dlog("Trying external DNS server %s for %s", dns_servers[i], query_name);
        
        dns_response_status_t status = resolve_external_dns(query_name, query_type, records, record_count, &config);
        
        if (status == DNS_STATUS_SUCCESS) {
            dlog("External DNS resolution successful using server %s", dns_servers[i]);
            return status;
        }
        
        log_dns_error("external resolution", query_name, status);
        
        // Clean up any partial results
        if (*records) {
            for (int j = 0; j < *record_count; j++) {
                free((*records)[j].name);
                free((*records)[j].rdata);
            }
            free(*records);
            *records = NULL;
            *record_count = 0;
        }
    }
    
    dlog("All external DNS servers failed for %s", query_name);
    return DNS_STATUS_SERVFAIL;
}

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
    if (resolver->cache->count >= (size_t)resolver->config.cache_size_max) {
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
    if ((int)record->ttl < resolver->config.cache_ttl_min) {
        new_node->entry.expires_at = new_node->entry.fetched_at + resolver->config.cache_ttl_min;
    } else if ((int)record->ttl > resolver->config.cache_ttl_max) {
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
    
    // Check if this is an external domain
    if (is_external_domain(query_name, resolver->tld_manager)) {
        // Handle external DNS resolution
        if (resolver->config.enable_recursive_resolution) {
            dlog("Resolving external domain: %s", query_name);
            
            // Use enhanced external DNS resolution with fallback
            dns_response_status_t ext_status = resolve_external_dns_with_fallback(
                query_name, query_type, records, record_count);
            
            if (ext_status != DNS_STATUS_SUCCESS) {
                log_dns_error("external resolution with fallback", query_name, ext_status);
                
                // Attempt cache recovery if external resolution fails
                if (ext_status == DNS_STATUS_SERVFAIL) {
                    dlog("External DNS failed, attempting cache recovery");
                    recover_dns_cache(resolver);
                    
                    // Try cache lookup again after recovery
                    dns_record_t* recovered_record = NULL;
                    int cache_recovery_result = lookup_in_dns_cache(resolver, query_name, query_type, &recovered_record);
                    
                    if (cache_recovery_result > 0 && recovered_record) {
                        dlog("Found cached record after cache recovery for %s", query_name);
                        *records = malloc(sizeof(dns_record_t));
                        if (*records) {
                            memcpy(*records, recovered_record, sizeof(dns_record_t));
                            *record_count = 1;
                            free(recovered_record);
                            return DNS_STATUS_SUCCESS;
                        }
                        free_dns_record(recovered_record);
                    }
                }
            } else {
                // Cache successful external results
                if (*records && *record_count > 0) {
                    for (int i = 0; i < *record_count; i++) {
                        add_to_dns_cache(resolver, query_name, &(*records)[i]);
                    }
                }
            }
            
            return ext_status;
        } else {
            dlog("External domain %s requested but recursive resolution disabled", query_name);
            log_dns_error("recursive resolution disabled", query_name, DNS_STATUS_REFUSED);
            return DNS_STATUS_REFUSED;
        }
    }
    
    // Continue with local resolution for domains managed by local TLD manager
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

// Helper function to validate record data based on type
static int validate_record_data(dns_record_type_t type, const char* rdata) {
    if (!rdata) return 0;
    
    switch (type) {
        case DNS_RECORD_TYPE_A: {
            // Validate IPv4 address format
            struct sockaddr_in sa;
            return inet_pton(AF_INET, rdata, &(sa.sin_addr)) == 1;
        }
        case DNS_RECORD_TYPE_AAAA: {
            // Validate IPv6 address format
            struct sockaddr_in6 sa;
            return inet_pton(AF_INET6, rdata, &(sa.sin6_addr)) == 1;
        }
        case DNS_RECORD_TYPE_MX: {
            // MX record format: "priority hostname"
            // Example: "10 mail.example.com"
            int priority;
            char hostname[MAX_DOMAIN_NAME_LEN];
            return sscanf(rdata, "%d %255s", &priority, hostname) == 2;
        }
        case DNS_RECORD_TYPE_SRV: {
            // SRV record format: "priority weight port target"
            // Example: "10 20 80 web.example.com"
            int priority, weight, port;
            char target[MAX_DOMAIN_NAME_LEN];
            return sscanf(rdata, "%d %d %d %255s", &priority, &weight, &port, target) == 4;
        }
        case DNS_RECORD_TYPE_TXT:
        case DNS_RECORD_TYPE_CNAME:
        case DNS_RECORD_TYPE_PTR:
            // These can contain arbitrary text, just check they're not empty
            return strlen(rdata) > 0;
        default:
            return 0;
    }
}

// Helper function to format record data for display
static const char* get_record_type_name(dns_record_type_t type) {
    switch (type) {
        case DNS_RECORD_TYPE_A: return "A";
        case DNS_RECORD_TYPE_AAAA: return "AAAA";
        case DNS_RECORD_TYPE_TXT: return "TXT";
        case DNS_RECORD_TYPE_MX: return "MX";
        case DNS_RECORD_TYPE_CNAME: return "CNAME";
        case DNS_RECORD_TYPE_SRV: return "SRV";
        case DNS_RECORD_TYPE_PTR: return "PTR";
        default: return "UNKNOWN";
    }
}

// Helper function to create a DNS record
static dns_record_t* create_dns_record(const char* name, dns_record_type_t type, 
                                      const char* rdata, uint32_t ttl) {
    if (!name || !rdata) return NULL;
    
    // Validate the record data
    if (!validate_record_data(type, rdata)) {
        dlog("Invalid record data for %s record: %s", get_record_type_name(type), rdata);
        return NULL;
    }
    
    dns_record_t* record = malloc(sizeof(dns_record_t));
    if (!record) return NULL;
    
    memset(record, 0, sizeof(dns_record_t));
    
    record->name = strdup(name);
    if (!record->name) {
        free(record);
        return NULL;
    }
    
    record->rdata = strdup(rdata);
    if (!record->rdata) {
        free(record->name);
        free(record);
        return NULL;
    }
    
    record->type = type;
    record->ttl = ttl;
    record->last_updated = time(NULL);
    
    return record;
}

// Helper function to add a record to TLD (for testing/management)
int add_record_to_tld(tld_manager_t* tld_manager, const char* tld_name, 
                     const char* record_name, dns_record_type_t type, 
                     const char* rdata, uint32_t ttl) {
    if (!tld_manager || !tld_name || !record_name || !rdata) return -1;
    
    pthread_rwlock_wrlock(&tld_manager->lock);
    
    // Find the TLD
    tld_t* found_tld = NULL;
    for (size_t i = 0; i < tld_manager->tld_count; ++i) {
        if (strcmp(tld_manager->tlds[i]->name, tld_name) == 0) {
            found_tld = tld_manager->tlds[i];
            break;
        }
    }
    
    if (!found_tld) {
        pthread_rwlock_unlock(&tld_manager->lock);
        dlog("TLD not found: %s", tld_name);
        return -1;
    }
    
    // Create the record
    dns_record_t* new_record = create_dns_record(record_name, type, rdata, ttl);
    if (!new_record) {
        pthread_rwlock_unlock(&tld_manager->lock);
        return -1;
    }
    
    // Add to TLD records array
    dns_record_t* temp = realloc(found_tld->records, 
                                (found_tld->record_count + 1) * sizeof(dns_record_t));
    if (!temp) {
        free_dns_record(new_record);
        pthread_rwlock_unlock(&tld_manager->lock);
        return -1;
    }
    
    found_tld->records = temp;
    
    // Copy the record data
    memcpy(&found_tld->records[found_tld->record_count], new_record, sizeof(dns_record_t));
    found_tld->record_count++;
    found_tld->last_modified = time(NULL);
    
    // Free the temporary record structure (strings are now owned by TLD)
    free(new_record);
    
    pthread_rwlock_unlock(&tld_manager->lock);
    
    dlog("Added %s record '%s' -> '%s' to TLD '%s'", 
         get_record_type_name(type), record_name, rdata, tld_name);
    
    return 0;
}

// Check if a domain is external (not managed by local TLD manager)
static int is_external_domain(const char* query_name, tld_manager_t* tld_manager) {
    if (!query_name || !tld_manager) return 1; // Assume external if invalid input
    
    // Parse the query name to extract TLD
    char hostname[MAX_DOMAIN_NAME_LEN];
    char domain[MAX_DOMAIN_NAME_LEN];
    char tld[MAX_DOMAIN_NAME_LEN];
    
    if (parse_fqdn(query_name, hostname, sizeof(hostname), domain, sizeof(domain), tld, sizeof(tld)) != 0) {
        return 1; // Assume external if parsing fails
    }
    
    // Check if the TLD is managed locally
    pthread_rwlock_rdlock(&tld_manager->lock);
    
    for (size_t i = 0; i < tld_manager->tld_count; ++i) {
        if (strcmp(tld_manager->tlds[i]->name, tld) == 0) {
            pthread_rwlock_unlock(&tld_manager->lock);
            return 0; // Local domain
        }
    }
    
    pthread_rwlock_unlock(&tld_manager->lock);
    return 1; // External domain
}

// Resolve external DNS queries using system resolver
static dns_response_status_t resolve_external_dns(const char* query_name, 
                                                 dns_record_type_t query_type,
                                                 dns_record_t** records,
                                                 int* record_count,
                                                 const external_dns_config_t* config) {
    if (!query_name || !records || !record_count) {
        return DNS_STATUS_SERVFAIL;
    }
    
    *records = NULL;
    *record_count = 0;
    
    // Use getaddrinfo for external DNS resolution
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    
    // Set up hints based on query type
    switch (query_type) {
        case DNS_RECORD_TYPE_A:
            hints.ai_family = AF_INET;
            break;
        case DNS_RECORD_TYPE_AAAA:
            hints.ai_family = AF_INET6;
            break;
        default:
            // For other record types, we'll use a simplified approach
            // In a full implementation, this would use raw DNS queries
            dlog("External DNS resolution for record type %d not fully implemented", query_type);
            return DNS_STATUS_NOTIMP;
    }
    
    hints.ai_socktype = SOCK_STREAM;
    
    int status = getaddrinfo(query_name, NULL, &hints, &result);
    if (status != 0) {
        dlog("External DNS resolution failed for %s: %s", query_name, gai_strerror(status));
        return DNS_STATUS_NXDOMAIN;
    }
    
    // Count the number of results
    int count = 0;
    for (struct addrinfo* rp = result; rp != NULL; rp = rp->ai_next) {
        count++;
    }
    
    if (count == 0) {
        freeaddrinfo(result);
        return DNS_STATUS_NXDOMAIN;
    }
    
    // Allocate records array
    *records = malloc(count * sizeof(dns_record_t));
    if (!*records) {
        freeaddrinfo(result);
        return DNS_STATUS_SERVFAIL;
    }
    
    // Fill in the records
    int record_index = 0;
    for (struct addrinfo* rp = result; rp != NULL && record_index < count; rp = rp->ai_next) {
        dns_record_t* record = &(*records)[record_index];
        
        record->name = strdup(query_name);
        if (!record->name) {
            // Cleanup on error
            for (int i = 0; i < record_index; i++) {
                free((*records)[i].name);
                free((*records)[i].rdata);
            }
            free(*records);
            *records = NULL;
            freeaddrinfo(result);
            return DNS_STATUS_SERVFAIL;
        }
        
        record->type = query_type;
        record->ttl = 300; // Default TTL for external records
        record->last_updated = time(NULL);
        
        // Convert address to string
        char addr_str[INET6_ADDRSTRLEN];
        const char* addr_result = NULL;
        
        if (rp->ai_family == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*)rp->ai_addr;
            addr_result = inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
        } else if (rp->ai_family == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)rp->ai_addr;
            addr_result = inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str, sizeof(addr_str));
        }
        
        if (addr_result) {
            record->rdata = strdup(addr_str);
            if (!record->rdata) {
                // Cleanup on error
                free(record->name);
                for (int i = 0; i < record_index; i++) {
                    free((*records)[i].name);
                    free((*records)[i].rdata);
                }
                free(*records);
                *records = NULL;
                freeaddrinfo(result);
                return DNS_STATUS_SERVFAIL;
            }
            record_index++;
        }
    }
    
    freeaddrinfo(result);
    *record_count = record_index;
    
    dlog("External DNS resolution for %s returned %d records", query_name, record_index);
    return record_index > 0 ? DNS_STATUS_SUCCESS : DNS_STATUS_NXDOMAIN;
} 