#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include <stdint.h>
#include <stddef.h>
#include "dns_types.h"
#include "tld_manager.h"

/**
 * @brief DNS Resolver Configuration
 * Contains settings for the DNS resolver behavior
 */
typedef struct {
    int max_recursion_depth;      // Maximum recursion depth for CNAME resolution
    int cache_ttl_min;            // Minimum TTL to cache records (seconds)
    int cache_ttl_max;            // Maximum TTL to cache records (seconds)
    int cache_size_max;           // Maximum number of entries in cache
    int enable_recursive_resolution; // Whether to perform recursive resolution
    int enable_iterative_resolution; // Whether to perform iterative resolution
    int enable_negative_caching;     // Whether to cache negative responses
    int negative_cache_ttl;          // TTL for negative cache entries (seconds)
} dns_resolver_config_t;

/**
 * @brief DNS Resolver Context
 * Contains the state of the DNS resolver
 */
typedef struct {
    dns_resolver_config_t config;  // Configuration
    dns_cache_t* cache;            // Pointer to the DNS cache
    tld_manager_t* tld_manager;    // Pointer to the TLD manager
    pthread_mutex_t lock;          // Lock for the resolver state
} dns_resolver_t;

/**
 * @brief Initialize the DNS resolver
 * 
 * @param resolver Pointer to resolver pointer to initialize
 * @param tld_manager Pointer to the TLD manager
 * @param cache Pointer to the DNS cache
 * @return int 0 on success, negative on error
 */
int init_dns_resolver(dns_resolver_t** resolver, tld_manager_t* tld_manager, dns_cache_t* cache);

/**
 * @brief Clean up the DNS resolver
 * 
 * @param resolver Pointer to the resolver to clean up
 */
void cleanup_dns_resolver(dns_resolver_t* resolver);

/**
 * @brief Configure the DNS resolver
 * 
 * @param resolver Pointer to the resolver
 * @param config Configuration structure
 * @return int 0 on success, negative on error
 */
int configure_dns_resolver(dns_resolver_t* resolver, const dns_resolver_config_t* config);

/**
 * @brief Resolve a DNS query
 * 
 * @param resolver Pointer to the resolver
 * @param query_name Name to resolve
 * @param query_type Type of record to resolve
 * @param records Pointer to store the resulting records (will be allocated)
 * @param record_count Pointer to store the number of records
 * @return dns_response_status_t Status code of the resolution
 */
dns_response_status_t resolve_dns_query(dns_resolver_t* resolver, 
                                       const char* query_name, 
                                       dns_record_type_t query_type,
                                       dns_record_t** records,
                                       int* record_count);

/**
 * @brief Parse a fully qualified domain name into components
 * 
 * @param fqdn The fully qualified domain name to parse
 * @param hostname Output buffer for the hostname part
 * @param hostname_len Length of the hostname buffer
 * @param domain Output buffer for the domain part
 * @param domain_len Length of the domain buffer
 * @param tld Output buffer for the TLD part
 * @param tld_len Length of the TLD buffer
 * @return int 0 on success, negative on error
 */
int parse_fqdn(const char* fqdn, 
               char* hostname, size_t hostname_len,
               char* domain, size_t domain_len,
               char* tld, size_t tld_len);

/**
 * @brief Add a record to the DNS cache
 * 
 * @param resolver Pointer to the resolver
 * @param fqdn The fully qualified domain name
 * @param record The record to cache
 * @return int 0 on success, negative on error
 */
int add_to_dns_cache(dns_resolver_t* resolver, const char* fqdn, const dns_record_t* record);

/**
 * @brief Look up a record in the DNS cache
 * 
 * @param resolver Pointer to the resolver
 * @param fqdn The fully qualified domain name to look up
 * @param query_type The type of record to look up
 * @param record Pointer to store the found record (will be allocated)
 * @return int 1 if found, 0 if not found, negative on error
 */
int lookup_in_dns_cache(dns_resolver_t* resolver, 
                       const char* fqdn, 
                       dns_record_type_t query_type,
                       dns_record_t** record);

/**
 * @brief Resolve CNAME records recursively
 * 
 * @param resolver Pointer to the resolver
 * @param cname_target The target of the CNAME record
 * @param target_type The type of record to resolve at the CNAME target
 * @param records Pointer to store the resulting records (will be allocated)
 * @param record_count Pointer to store the number of records
 * @param recursion_depth Current recursion depth (for limiting)
 * @return dns_response_status_t Status code of the resolution
 */
dns_response_status_t resolve_cname(dns_resolver_t* resolver,
                                  const char* cname_target,
                                  dns_record_type_t target_type,
                                  dns_record_t** records,
                                  int* record_count,
                                  int recursion_depth);

#endif // DNS_RESOLVER_H 