#include "tld_manager.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h> // For dlog or printf if needed for errors
#include "debug.h" // For dlog, if used

#define INITIAL_TLD_CAPACITY 10

// Helper function to free a single tld_t structure
static void free_single_tld(tld_t* tld) {
    if (!tld) return;

    free(tld->name);

    for (size_t i = 0; i < tld->authoritative_node_count; ++i) {
        free(tld->authoritative_nodes[i].hostname);
        free(tld->authoritative_nodes[i].ip_address);
        // free(tld->authoritative_nodes[i].public_key); // If it were allocated
    }
    free(tld->authoritative_nodes);

    for (size_t i = 0; i < tld->record_count; ++i) {
        free(tld->records[i].name);
        free(tld->records[i].rdata);
    }
    free(tld->records);

    for (size_t i = 0; i < tld->mirror_node_count; ++i) {
        free(tld->mirror_nodes[i].hostname);
        free(tld->mirror_nodes[i].ip_address);
        // free(tld->mirror_nodes[i].public_key);
    }
    free(tld->mirror_nodes);
    
    // free(tld->admin_contact); // If allocated
    free(tld);
}

int init_tld_manager(tld_manager_t** manager_ptr) {
    if (!manager_ptr) return -1;

    *manager_ptr = malloc(sizeof(tld_manager_t));
    if (!*manager_ptr) {
        // dlog_error("Failed to allocate TLD manager");
        return -1;
    }

    tld_manager_t* manager = *manager_ptr;
    manager->tlds = malloc(INITIAL_TLD_CAPACITY * sizeof(tld_t*));
    if (!manager->tlds) {
        // dlog_error("Failed to allocate TLD list for manager");
        free(manager);
        *manager_ptr = NULL;
        return -1;
    }

    manager->tld_count = 0;
    manager->tld_capacity = INITIAL_TLD_CAPACITY;
    if (pthread_rwlock_init(&manager->lock, NULL) != 0) {
        // dlog_error("Failed to initialize TLD manager rwlock");
        free(manager->tlds);
        free(manager);
        *manager_ptr = NULL;
        return -1;
    }
    return 0;
}

void cleanup_tld_manager(tld_manager_t* manager) {
    if (!manager) return;

    pthread_rwlock_wrlock(&manager->lock); // Acquire write lock to safely free
    for (size_t i = 0; i < manager->tld_count; ++i) {
        free_single_tld(manager->tlds[i]);
    }
    free(manager->tlds);
    manager->tlds = NULL;
    manager->tld_count = 0;
    manager->tld_capacity = 0;
    pthread_rwlock_unlock(&manager->lock);
    pthread_rwlock_destroy(&manager->lock);
    free(manager);
}

tld_t* register_new_tld(tld_manager_t* manager, const char* tld_name) {
    if (!manager || !tld_name) return NULL;

    pthread_rwlock_wrlock(&manager->lock);

    // Check if TLD already exists
    for (size_t i = 0; i < manager->tld_count; ++i) {
        if (strcmp(manager->tlds[i]->name, tld_name) == 0) {
            pthread_rwlock_unlock(&manager->lock);
            // dlog_warn("TLD '%s' already exists.", tld_name);
            return NULL; // Or return existing TLD: manager->tlds[i]
        }
    }

    // Expand TLD list if necessary
    if (manager->tld_count >= manager->tld_capacity) {
        size_t new_capacity = manager->tld_capacity * 2;
        tld_t** new_tlds = realloc(manager->tlds, new_capacity * sizeof(tld_t*));
        if (!new_tlds) {
            pthread_rwlock_unlock(&manager->lock);
            // dlog_error("Failed to expand TLD list capacity.");
            return NULL;
        }
        manager->tlds = new_tlds;
        manager->tld_capacity = new_capacity;
    }

    // Create new TLD structure
    tld_t* new_tld = malloc(sizeof(tld_t));
    if (!new_tld) {
        pthread_rwlock_unlock(&manager->lock);
        // dlog_error("Failed to allocate memory for new TLD '%s'.", tld_name);
        return NULL;
    }
    memset(new_tld, 0, sizeof(tld_t));

    new_tld->name = strdup(tld_name);
    if (!new_tld->name) {
        free(new_tld);
        pthread_rwlock_unlock(&manager->lock);
        // dlog_error("Failed to duplicate TLD name '%s'.", tld_name);
        return NULL;
    }
    new_tld->created_at = time(NULL);
    new_tld->last_modified = new_tld->created_at;
    // Initialize other fields (counts to 0, pointers to NULL)
    new_tld->authoritative_nodes = NULL;
    new_tld->authoritative_node_count = 0;
    new_tld->records = NULL;
    new_tld->record_count = 0;
    new_tld->mirror_nodes = NULL;
    new_tld->mirror_node_count = 0;

    manager->tlds[manager->tld_count++] = new_tld;
    
    pthread_rwlock_unlock(&manager->lock);
    // dlog_info("Registered new TLD: %s", tld_name);
    return new_tld;
}

tld_t* find_tld_by_name(tld_manager_t* manager, const char* tld_name) {
    if (!manager || !tld_name) return NULL;

    pthread_rwlock_rdlock(&manager->lock);
    for (size_t i = 0; i < manager->tld_count; ++i) {
        if (manager->tlds[i] && strcmp(manager->tlds[i]->name, tld_name) == 0) {
            tld_t* found_tld = manager->tlds[i];
            pthread_rwlock_unlock(&manager->lock);
            return found_tld;
        }
    }
    pthread_rwlock_unlock(&manager->lock);
    return NULL;
}

int add_dns_record_to_tld(tld_t* tld, const dns_record_t* record_in) {
    if (!tld || !record_in || !record_in->name || !record_in->rdata) return -1;

    // Assuming tld itself is managed by tld_manager, so its lock should be handled by caller if needed
    // or pass manager and acquire lock here.
    // For simplicity, this function will assume caller handles TLD-level locking if necessary, 
    // or that modifications to a single TLD's records are less frequent and might be protected
    // by the TLD manager's lock during operations like `register_new_tld` or full syncs.

    // Check for duplicates (optional, depends on desired behavior for updates vs new)
    // For now, we'll just add. Updates would require finding and replacing.

    dns_record_t* new_records_array = realloc(tld->records, (tld->record_count + 1) * sizeof(dns_record_t));
    if (!new_records_array) {
        // dlog_error("Failed to realloc memory for TLD records.");
        return -1;
    }
    tld->records = new_records_array;

    dns_record_t* new_record = &tld->records[tld->record_count];
    
    new_record->name = strdup(record_in->name);
    if (!new_record->name) {
        // dlog_error("Failed to strdup record name");
        // Attempt to shrink array back (or mark as invalid and handle later)
        // This error handling can get complex with realloc.
        return -1; 
    }

    new_record->rdata = strdup(record_in->rdata);
    if (!new_record->rdata) {
        free(new_record->name);
        // dlog_error("Failed to strdup record rdata");
        return -1;
    }

    new_record->type = record_in->type;
    new_record->ttl = record_in->ttl;
    new_record->last_updated = time(NULL);
    
tld->record_count++;
    tld->last_modified = time(NULL);

    return 0;
}

int remove_dns_record_from_tld(tld_t* tld, const char* record_name, dns_record_type_t type) {
    if (!tld || !record_name) return -1;

    int found_idx = -1;
    for (size_t i = 0; i < tld->record_count; ++i) {
        if (tld->records[i].type == type && strcmp(tld->records[i].name, record_name) == 0) {
            found_idx = i;
            break;
        }
    }

    if (found_idx == -1) {
        // dlog_info("Record '%s' type %d not found in TLD '%s' for removal.", record_name, type, tld->name);
        return -1; // Not found
    }

    // Free the found record's content
    free(tld->records[found_idx].name);
    free(tld->records[found_idx].rdata);

    // Shift subsequent elements down
    if (tld->record_count > 1 && (size_t)found_idx < tld->record_count - 1) {
        memmove(&tld->records[found_idx], 
                &tld->records[found_idx + 1], 
                (tld->record_count - 1 - found_idx) * sizeof(dns_record_t));
    }

    tld->record_count--;
    tld->last_modified = time(NULL);

    if (tld->record_count == 0) {
        free(tld->records);
        tld->records = NULL;
    } else {
        // Optionally, realloc to shrink, but can be costly. 
        // For now, we'll leave the allocated memory as is.
        // dns_record_t* resized_records = realloc(tld->records, tld->record_count * sizeof(dns_record_t));
        // if (resized_records || tld->record_count == 0) { // realloc returns NULL if size is 0 and ptr was not NULL
        //    tld->records = resized_records;
        // }
    }
    // dlog_info("Removed record '%s' type %d from TLD '%s'.", record_name, type, tld->name);
    return 0;
}

static int add_node_to_list(tld_node_t** list, size_t* count, const tld_node_t* node_info) {
    tld_node_t* new_list = realloc(*list, (*count + 1) * sizeof(tld_node_t));
    if (!new_list) {
        // dlog_error("Failed to realloc memory for TLD node list.");
        return -1;
    }
    *list = new_list;

    tld_node_t* new_node = &(*list)[*count];
    new_node->hostname = strdup(node_info->hostname);
    new_node->ip_address = strdup(node_info->ip_address);
    // new_node->public_key = duplicate_falcon_key(node_info->public_key); // Assuming a function to duplicate key
    new_node->last_seen = time(NULL); // Or node_info->last_seen if provided

    if (!new_node->hostname || !new_node->ip_address /* || !new_node->public_key */) {
        free(new_node->hostname);
        free(new_node->ip_address);
        // free(new_node->public_key);
        // dlog_error("Failed to duplicate node info strings.");
        // Caller might need to handle partially added node or shrink array.
        // For simplicity, current realloc means this entry is garbage but count not incremented.
        return -1;
    }

    (*count)++;
    return 0;
}

int add_authoritative_node_to_tld(tld_t* tld, const tld_node_t* node_info) {
    if (!tld || !node_info || !node_info->hostname || !node_info->ip_address) return -1;
    // TODO: Check for duplicate nodes before adding
    if (add_node_to_list(&tld->authoritative_nodes, &tld->authoritative_node_count, node_info) != 0) {
        return -1;
    }
    tld->last_modified = time(NULL);
    // dlog_info("Added authoritative node '%s' to TLD '%s'.", node_info->hostname, tld->name);
    return 0;
}

int add_mirror_node_to_tld(tld_t* tld, const tld_node_t* node_info) {
    if (!tld || !node_info || !node_info->hostname || !node_info->ip_address) return -1;
    // TODO: Check for duplicate nodes before adding
    if (add_node_to_list(&tld->mirror_nodes, &tld->mirror_node_count, node_info) != 0) {
        return -1;
    }
    tld->last_modified = time(NULL);
    // dlog_info("Added mirror node '%s' to TLD '%s'.", node_info->hostname, tld->name);
    return 0;
}

// TLD Mirroring and Synchronization Functions

int request_tld_mirror(tld_manager_t* manager, const char* tld_name, const char* peer_hostname, const char* peer_ip) {
    if (!manager || !tld_name || !peer_hostname || !peer_ip) return -1;
    
    // Check if TLD already exists locally
    tld_t* existing_tld = find_tld_by_name(manager, tld_name);
    if (existing_tld) {
        // TLD already exists, check if peer is already a mirror node
        for (size_t i = 0; i < existing_tld->mirror_node_count; i++) {
            if (strcmp(existing_tld->mirror_nodes[i].hostname, peer_hostname) == 0) {
                // Peer is already a mirror node
                return 0;
            }
        }
        
        // Add peer as mirror node
        tld_node_t peer_node = {
            .hostname = strdup(peer_hostname),
            .ip_address = strdup(peer_ip),
            .last_seen = time(NULL)
        };
        
        int result = add_mirror_node_to_tld(existing_tld, &peer_node);
        free(peer_node.hostname);
        free(peer_node.ip_address);
        return result;
    }
    
    // TLD doesn't exist locally, need to request full mirror from peer
    // This would typically involve sending a network request to the peer
    // For now, we'll create a placeholder TLD and mark the peer as authoritative
    
    tld_t* new_tld = register_new_tld(manager, tld_name);
    if (!new_tld) return -1;
    
    tld_node_t peer_node = {
        .hostname = strdup(peer_hostname),
        .ip_address = strdup(peer_ip),
        .last_seen = time(NULL)
    };
    
    int result = add_authoritative_node_to_tld(new_tld, &peer_node);
    free(peer_node.hostname);
    free(peer_node.ip_address);
    
    // TODO: Send actual network request to peer to get TLD data
    // This would be implemented with the NEXUS client API
    
    return result;
}

int sync_tld_update(tld_manager_t* manager, const char* tld_name, const dns_record_t* updated_record) {
    if (!manager || !tld_name || !updated_record) return -1;
    
    tld_t* tld = find_tld_by_name(manager, tld_name);
    if (!tld) return -1;
    
    // Update the local TLD record
    int update_result = add_dns_record_to_tld(tld, updated_record);
    if (update_result != 0) return update_result;
    
    // Propagate update to all mirror nodes
    for (size_t i = 0; i < tld->mirror_node_count; i++) {
        tld_node_t* mirror_node = &tld->mirror_nodes[i];
        
        // TODO: Send sync update to mirror node
        // This would involve:
        // 1. Creating a TLD_SYNC_UPDATE packet
        // 2. Sending it to the mirror node via NEXUS client
        // 3. Handling acknowledgment/failure
        
        // For now, just update the last_seen timestamp to indicate we attempted sync
        mirror_node->last_seen = time(NULL);
    }
    
    return 0;
}

int discover_tld_peers(tld_manager_t* manager, const char* tld_name, tld_node_t** discovered_peers, size_t* peer_count) {
    if (!manager || !tld_name || !discovered_peers || !peer_count) return -1;
    
    *discovered_peers = NULL;
    *peer_count = 0;
    
    tld_t* tld = find_tld_by_name(manager, tld_name);
    if (!tld) return -1;
    
    // Combine authoritative and mirror nodes for peer discovery
    size_t total_peers = tld->authoritative_node_count + tld->mirror_node_count;
    if (total_peers == 0) return 0;
    
    tld_node_t* peers = malloc(total_peers * sizeof(tld_node_t));
    if (!peers) return -1;
    
    size_t peer_index = 0;
    
    // Add authoritative nodes
    for (size_t i = 0; i < tld->authoritative_node_count; i++) {
        peers[peer_index].hostname = strdup(tld->authoritative_nodes[i].hostname);
        peers[peer_index].ip_address = strdup(tld->authoritative_nodes[i].ip_address);
        peers[peer_index].last_seen = tld->authoritative_nodes[i].last_seen;
        peer_index++;
    }
    
    // Add mirror nodes
    for (size_t i = 0; i < tld->mirror_node_count; i++) {
        peers[peer_index].hostname = strdup(tld->mirror_nodes[i].hostname);
        peers[peer_index].ip_address = strdup(tld->mirror_nodes[i].ip_address);
        peers[peer_index].last_seen = tld->mirror_nodes[i].last_seen;
        peer_index++;
    }
    
    *discovered_peers = peers;
    *peer_count = total_peers;
    
    return 0;
}

int cleanup_stale_peers(tld_manager_t* manager, time_t stale_threshold) {
    if (!manager) return -1;
    
    pthread_rwlock_wrlock(&manager->lock);
    
    int cleaned_count = 0;
    
    for (size_t tld_idx = 0; tld_idx < manager->tld_count; tld_idx++) {
        tld_t* tld = manager->tlds[tld_idx];
        if (!tld) continue;
        
        // Clean stale mirror nodes
        size_t new_mirror_count = 0;
        for (size_t i = 0; i < tld->mirror_node_count; i++) {
            if (tld->mirror_nodes[i].last_seen >= stale_threshold) {
                // Keep this node
                if (new_mirror_count != i) {
                    tld->mirror_nodes[new_mirror_count] = tld->mirror_nodes[i];
                }
                new_mirror_count++;
            } else {
                // Remove stale node
                free(tld->mirror_nodes[i].hostname);
                free(tld->mirror_nodes[i].ip_address);
                cleaned_count++;
            }
        }
        tld->mirror_node_count = new_mirror_count;
        
        // Clean stale authoritative nodes (more conservative)
        size_t new_auth_count = 0;
        for (size_t i = 0; i < tld->authoritative_node_count; i++) {
            if (tld->authoritative_nodes[i].last_seen >= stale_threshold) {
                // Keep this node
                if (new_auth_count != i) {
                    tld->authoritative_nodes[new_auth_count] = tld->authoritative_nodes[i];
                }
                new_auth_count++;
            } else {
                // Remove stale authoritative node
                free(tld->authoritative_nodes[i].hostname);
                free(tld->authoritative_nodes[i].ip_address);
                cleaned_count++;
            }
        }
        tld->authoritative_node_count = new_auth_count;
        
        if (cleaned_count > 0) {
            tld->last_modified = time(NULL);
        }
    }
    
    pthread_rwlock_unlock(&manager->lock);
    
    return cleaned_count;
}

int get_tld_sync_status(tld_manager_t* manager, const char* tld_name, time_t* last_sync, size_t* peer_count) {
    if (!manager || !tld_name) return -1;
    
    tld_t* tld = find_tld_by_name(manager, tld_name);
    if (!tld) return -1;
    
    if (last_sync) {
        *last_sync = tld->last_modified;
    }
    
    if (peer_count) {
        *peer_count = tld->authoritative_node_count + tld->mirror_node_count;
    }
    
    return 0;
} 