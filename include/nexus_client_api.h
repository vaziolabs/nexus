#ifndef NEXUS_CLIENT_API_H
#define NEXUS_CLIENT_API_H

#include <stddef.h> // For size_t
#include <sys/types.h> // For ssize_t
#include <stdint.h>    // For uint8_t
#include "nexus_node.h" // Include for nexus_node_t definition

// Forward declaration if nexus_client_config_t is used by the function signature
// struct nexus_client_config_s; // Assuming nexus_client_config_t is a typedef for this struct

// Forward declaration for nexus_node_t if not already included by a common header
// struct nexus_node_s; // Assuming nexus_node_t is a typedef for this
// Instead of forward declaration, let's assume nexus_node.h (which defines nexus_node_t) will be included by users of this API.

/**
 * @brief Sends a raw serialized NEXUS packet and waits for a response using a node context.
 *
 * This function handles opening a QUIC stream (or using an existing one),
 * sending the request_data, receiving the response_data, and then closing
 * the stream or preparing it for further use.
 *
 * @param node Pointer to the nexus_node_t structure, which contains client configuration and connection state.
 * @param request_data Buffer containing the serialized NEXUS request packet.
 * @param request_len Length of the request_data.
 * @param response_data_out Pointer to a uint8_t* that will be allocated by this 
 *                          function to store the received response packet data. 
 *                          The caller is responsible for freeing this memory.
 * @param target_server_addr Optional string representing the target server address.
 *                           If NULL, the client_config's default server may be used.
 *                           (This parameter might be simplified if client_config always has target)
 * @param timeout_ms Timeout in milliseconds to wait for a response.
 * @return ssize_t Length of the received response_data_out on success (>= 0).
 *                 Returns -1 on general error (e.g., connection not established, send failed).
 *                 Returns -2 on timeout.
 *                 Returns -3 on memory allocation failure for response_data_out.
 *                 Other negative values for specific ngtcp2/socket errors.
 */
ssize_t nexus_node_send_receive_packet(
    nexus_node_t *node, // Use nexus_node_t typedef
    const uint8_t *request_data, 
    size_t request_len, 
    uint8_t **response_data_out, 
    int timeout_ms
);

#endif // NEXUS_CLIENT_API_H 