#include "../include/nexus_server.h"
#include "../include/nexus_node.h"
#include "../include/debug.h"
#include "../include/packet_protocol.h"
#include "../include/dns_types.h"
#include "../include/dns_resolver.h"
#include "../include/certificate_authority.h"
#include "../include/system.h"
#include "../include/utils.h"               // For get_timestamp

// System includes
#include <unistd.h>                         // For close()
#include <errno.h>                          // For errno

// OpenSSL QUIC related headers first
#include <openssl/ssl.h>                    // For SSL_CTX_new, SSL_new etc.
#include <openssl/quic.h>                   // For OSSL_ENCRYPTION_LEVEL, SSL_set_quic_transport_params etc.
#include <openssl/err.h>
#include <openssl/rand.h>

// Then ngtcp2 headers
#include <ngtcp2/ngtcp2.h> 
#include <ngtcp2/ngtcp2_crypto.h>           // For generic crypto helper callbacks
#include <ngtcp2/ngtcp2_crypto_ossl.h>      // For OpenSSL (vanilla) specific helpers
#include "../include/network_context.h"
#include "../include/tld_manager.h"     // For TLD management functions
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h> // For pthread_mutex
#include <string.h> // For memset, strncpy, strcmp, strdup
#include <stdlib.h> // For malloc, free, realloc
#include <stdarg.h> // For va_list in log wrapper

// Define TLD registration response status codes (missing from included headers)
#define TLD_REG_RESP_SUCCESS 0
#define TLD_REG_RESP_ERROR_ALREADY_EXISTS 1
#define TLD_REG_RESP_ERROR_INTERNAL_SERVER_ERROR 2

// Define a custom get_conn function for our conn_ref
static ngtcp2_conn *get_conn_from_config(void *user_data) {
    nexus_server_config_t *config = (nexus_server_config_t *)user_data;
    if (config) {
        return config->conn;
    }
    return NULL;
}

// Wrapper for ngtcp2 log_printf to use our dlog or similar
static void ngtcp2_log_wrapper(void *user_data, const char *format, ...) {
    (void)user_data; // dlog (or current printf) doesn't use user_data
    va_list args;
    // To distinguish ngtcp2 logs, we can prefix them or use a different mechanism if dlog is complex.
    // For now, using a simple vprintf to stdout, prefixed.
    // A more robust solution would be to have a vdlog function that dlog wraps.
    fprintf(stderr, "[ngtcp2_log] "); // Log to stderr to avoid mixing with main stdout logs from dlog if it goes to stdout
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n"); // Newline after each ngtcp2 log message
}

// Forward declarations with correct return types and parameters
static int on_stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
    (void)conn;      // Suppress unused parameter warning
    (void)user_data; // Suppress unused parameter warning
    dlog("New stream opened: %ld", stream_id);
    return 0;  // Return success
}

static int on_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                         uint64_t offset_stream_data, const uint8_t *data,
                         size_t datalen, void *user_data, void *stream_user_data) {
    (void)flags;
    (void)offset_stream_data; // This offset is for the stream itself, not our buffer parsing.
    (void)stream_user_data;

    dlog("Server: Received %zu bytes on stream %ld", datalen, stream_id);

    if (!user_data) {
        dlog("ERROR: Server: No user_data (server_config) in on_stream_data callback.");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    nexus_server_config_t* server_config = (nexus_server_config_t*)user_data;
    if (!server_config->net_ctx || !server_config->net_ctx->tld_manager) {
        dlog("ERROR: Server: Network context or TLD manager not initialized in server_config.");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    nexus_packet_t received_packet;
    memset(&received_packet, 0, sizeof(nexus_packet_t));

    ssize_t bytes_read = deserialize_nexus_packet(data, datalen, &received_packet);
    if (bytes_read < 0) {
        dlog("ERROR: Server: Failed to deserialize NEXUS packet.");
        // Not freeing received_packet.data as it would be NULL or invalid on error
        return 0; // Consume data, but log error
    }
    // TODO: Potentially loop if datalen > bytes_read, indicating multiple packets in one datagram (unlikely for QUIC streams but good to consider)

    dlog("Server: Deserialized packet type %d, data_len %u", received_packet.type, received_packet.data_len);

    nexus_packet_t response_packet; // To store any response we might send
    memset(&response_packet, 0, sizeof(nexus_packet_t));
    response_packet.version = received_packet.version; // Echo version
    response_packet.session_id = received_packet.session_id; // Echo session ID

    uint8_t response_payload_buf[1024]; // Max estimated size for response payload
    ssize_t response_payload_len = 0;

    switch (received_packet.type) {
        case PACKET_TYPE_TLD_REGISTER_REQ: {
            dlog("Server: Received TLD_REGISTER_REQ");
            payload_tld_register_req_t req_payload;
            if (deserialize_payload_tld_register_req(received_packet.data, received_packet.data_len, &req_payload) < 0) {
                dlog("ERROR: Server: Failed to deserialize TLD_REGISTER_REQ payload.");
                break; // Out of switch case, will free received_packet.data later
            }

            response_packet.type = PACKET_TYPE_TLD_REGISTER_RESP;
            payload_tld_register_resp_t resp_payload;
            memset(&resp_payload, 0, sizeof(resp_payload));

            tld_t* existing_tld = find_tld_by_name(server_config->net_ctx->tld_manager, req_payload.tld_name);
            if (existing_tld) {
                resp_payload.status = TLD_REG_RESP_ERROR_ALREADY_EXISTS;
                strncpy(resp_payload.message, "TLD already exists.", sizeof(resp_payload.message) - 1);
            } else {
                tld_t* new_tld = register_new_tld(server_config->net_ctx->tld_manager, req_payload.tld_name);
                if (new_tld) {
                    resp_payload.status = TLD_REG_RESP_SUCCESS;
                    strncpy(resp_payload.message, "TLD registered successfully.", sizeof(resp_payload.message) - 1);
                } else {
                    resp_payload.status = TLD_REG_RESP_ERROR_INTERNAL_SERVER_ERROR;
                    strncpy(resp_payload.message, "Internal server error registering TLD.", sizeof(resp_payload.message) - 1);
                }
            }

            response_payload_len = serialize_payload_tld_register_resp(&resp_payload, response_payload_buf, sizeof(response_payload_buf));
            if (response_payload_len < 0) {
                dlog("ERROR: Server: Failed to serialize TLD_REGISTER_RESP payload.");
                // No specific cleanup for resp_payload needed as it's stack allocated and contains no pointers
                break; 
            }
            response_packet.data = response_payload_buf;
            response_packet.data_len = response_payload_len;
            break; // End of TLD_REGISTER_REQ case
        }

        case PACKET_TYPE_DNS_QUERY: {
            dlog("Server: Received DNS_QUERY");
            payload_dns_query_t query_payload;
            if (deserialize_payload_dns_query(received_packet.data, received_packet.data_len, &query_payload) < 0) {
                dlog("ERROR: Server: Failed to deserialize DNS_QUERY payload.");
                break;
            }

            dlog("Server: Query for Name: %s, Type: %d", query_payload.query_name, query_payload.type);

            response_packet.type = PACKET_TYPE_DNS_RESPONSE;
            payload_dns_response_t dns_resp_payload;
            memset(&dns_resp_payload, 0, sizeof(payload_dns_response_t)); // Initializes records to NULL and count to 0

            // Use the DNS resolver to handle the query
            dns_record_t* result_records = NULL;
            int result_count = 0;
            
            // Get the resolver from the network context
            dns_resolver_t* resolver = server_config->net_ctx->dns_resolver;
            
            if (!resolver) {
                dlog("ERROR: Server: DNS resolver not initialized.");
                dns_resp_payload.status = DNS_STATUS_SERVFAIL;
                goto serialize_dns_response;
            }
            
            // Resolve the query
            dns_response_status_t resolve_status = resolve_dns_query(
                resolver,
                query_payload.query_name,
                query_payload.type,
                &result_records,
                &result_count
            );
            
            // Set the response payload based on the resolver results
            dns_resp_payload.status = resolve_status;
            dns_resp_payload.record_count = result_count;
            dns_resp_payload.records = result_records;
            
            dlog("Server: DNS query resolved with status %d, found %d records", resolve_status, result_count);
            
            // Label for goto in case of errors
            serialize_dns_response:;

            response_payload_len = serialize_payload_dns_response(&dns_resp_payload, response_payload_buf, sizeof(response_payload_buf));
            
            // IMPORTANT: Free records memory if it was allocated for the response payload (name and rdata were strdup'd)
            if (dns_resp_payload.records) {
                for (int i = 0; i < dns_resp_payload.record_count; ++i) {
                    if (dns_resp_payload.records[i].name) free(dns_resp_payload.records[i].name);
                    if (dns_resp_payload.records[i].rdata) free(dns_resp_payload.records[i].rdata);
                }
                free(dns_resp_payload.records); // Free the array of records itself
                dns_resp_payload.records = NULL; // Avoid double free if error occurs after this
            }

            if (response_payload_len < 0) {
                dlog("ERROR: Server: Failed to serialize DNS_RESPONSE payload.");
                // response_packet.data will not be set, so no response sent
                break; 
            }
            response_packet.data = response_payload_buf;
            response_packet.data_len = response_payload_len;
            break; // End of DNS_QUERY case
        }

        // TODO: Handle other packet types (..., TLD_MIRROR_REQ, etc.)
        default:
            dlog("WARNING: Server: Received unhandled packet type %d on stream %ld", received_packet.type, stream_id);
            // No response will be sent for unhandled types by default
            break;
    }

    // Free data allocated by deserialize_nexus_packet for the received packet
    if (received_packet.data) {
        free(received_packet.data);
        received_packet.data = NULL;
    }

    // Send the response packet if its data field is set (i.e., a response was prepared)
    if (response_packet.data && response_packet.data_len > 0) {
        uint8_t final_response_buf[2048]; // Larger buffer for full nexus packet with DNS records
        ssize_t final_response_len = serialize_nexus_packet(&response_packet, final_response_buf, sizeof(final_response_buf));
        
        if (final_response_len < 0) {
            dlog("ERROR: Server: Failed to serialize final response NEXUS packet for type %d.", response_packet.type);
        } else {
            // ngtcp2_conn_write_stream or ngtcp2_conn_writev_stream
            // This requires knowing the stream ID is bidirectional and client is expecting a response on it.
            // For QUIC, responses are often sent on the same stream the request came on if it's client-initiated bidi.
            int rv = ngtcp2_conn_write_stream(conn, NULL, NULL, 
                                            NULL, 0, NULL, // No fin, no early_data, no early_data_ctx, no pnum_written
                                            NGTCP2_STREAM_DATA_FLAG_NONE, stream_id, final_response_buf, final_response_len, 
                                            get_timestamp()); // Use current conn timestamp
            if (rv != 0 && rv != NGTCP2_ERR_STREAM_DATA_BLOCKED && rv != NGTCP2_ERR_STREAM_SHUT_WR) { 
                dlog("ERROR: Server: Failed to write stream data for response type %d: %s (%d)", response_packet.type, ngtcp2_strerror(rv), rv);
            }
            dlog("Server: Sent response type %d, %zd bytes on stream %ld", response_packet.type, final_response_len, stream_id);
        }
    }

    return 0;  // Return success from callback
}

static int on_handshake_completed(ngtcp2_conn *conn, void *user_data) {
    (void)conn;
    nexus_server_config_t *config = (nexus_server_config_t *)user_data;
    config->handshake_completed = 1;
    dlog("Server handshake completed");
    return 0;
}

// Initialize the server's crypto context (TLS)
static int init_server_crypto_context(nexus_server_config_t *config) {
    if (!config) return -1;

    config->crypto_ctx = malloc(sizeof(nexus_server_crypto_ctx));
    if (!config->crypto_ctx) {
        dlog("ERROR: Server: Failed to allocate crypto context");
        return -1;
    }
    memset(config->crypto_ctx, 0, sizeof(nexus_server_crypto_ctx));

    config->crypto_ctx->ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!config->crypto_ctx->ssl_ctx) {
        dlog("ERROR: Server: Failed to create SSL_CTX: %s", ERR_error_string(ERR_get_error(), NULL));
        free(config->crypto_ctx);
        config->crypto_ctx = NULL;
        return -1;
    }

    // Check if CA context is available for certificate generation
    if (config->net_ctx->ca_ctx) {
        dlog("Using in-memory Falcon certificate for server");
        
        // Use the CA's certificate directly instead of issuing a new one
        // This ensures the private key matches the certificate
        config->cert = config->net_ctx->ca_ctx->ca_cert;
        
        if (SSL_CTX_use_certificate(config->crypto_ctx->ssl_ctx, config->cert->x509) != 1) {
            dlog("ERROR: Server: Failed to use certificate: %s", ERR_error_string(ERR_get_error(), NULL));
            SSL_CTX_free(config->crypto_ctx->ssl_ctx);
            free(config->crypto_ctx);
            config->crypto_ctx = NULL;
            return -1;
        }

        // Use the CA's private key (which matches the CA's certificate)
        if (SSL_CTX_use_PrivateKey(config->crypto_ctx->ssl_ctx, config->net_ctx->ca_ctx->falcon_pkey) != 1) {
            dlog("ERROR: Server: Failed to use private key: %s", ERR_error_string(ERR_get_error(), NULL));
            SSL_CTX_free(config->crypto_ctx->ssl_ctx);
            free(config->crypto_ctx);
            config->crypto_ctx = NULL;
            return -1;
        }

        if (SSL_CTX_check_private_key(config->crypto_ctx->ssl_ctx) != 1) {
            dlog("ERROR: Server: Private key does not match the public certificate: %s", ERR_error_string(ERR_get_error(), NULL));
            SSL_CTX_free(config->crypto_ctx->ssl_ctx);
            free(config->crypto_ctx);
            config->crypto_ctx = NULL;
            return -1;
        }
    } else {
        dlog("ERROR: Server: CA context not available for certificate generation.");
        SSL_CTX_free(config->crypto_ctx->ssl_ctx);
        free(config->crypto_ctx);
        config->crypto_ctx = NULL;
        return -1;
    }

    SSL_CTX_set_min_proto_version(config->crypto_ctx->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(config->crypto_ctx->ssl_ctx, TLS1_3_VERSION);

    // Comment out problematic ngtcp2 function for now
    // if (ngtcp2_crypto_ossl_configure_server_context(config->crypto_ctx->ssl_ctx) != 0) {
    //     dlog("ERROR: Server: ngtcp2_crypto_ossl_configure_server_context failed: %s", ERR_error_string(ERR_get_error(), NULL));
    //     SSL_CTX_free(config->crypto_ctx->ssl_ctx);
    //     free(config->crypto_ctx);
    //     config->crypto_ctx = NULL;
    //     return -1;
    // }

    const unsigned char alpn[] = "\x02h3";
    if (SSL_CTX_set_alpn_protos(config->crypto_ctx->ssl_ctx, alpn, sizeof(alpn) - 1) != 0) {
        dlog("ERROR: Failed to set ALPN: %s", ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(config->crypto_ctx->ssl_ctx);
        free(config->crypto_ctx);
        config->crypto_ctx = NULL;
        return -1;
    }

    uint8_t paramsbuf[256];
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);

    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 100;
    params.initial_max_data = 1 * 1024 * 1024;
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.active_connection_id_limit = 8;

    ssize_t nwrite = ngtcp2_transport_params_encode(paramsbuf, sizeof(paramsbuf), &params);
    if (nwrite < 0) {
        dlog("ERROR: Failed to encode transport parameters: %s", ngtcp2_strerror((int)nwrite));
        SSL_CTX_free(config->crypto_ctx->ssl_ctx);
        free(config->crypto_ctx);
        config->crypto_ctx = NULL;
        return -1;
    }

    // Comment out problematic SSL function for now
    // if (SSL_CTX_set_quic_transport_params(config->crypto_ctx->ssl_ctx, paramsbuf, (size_t)nwrite) != 1) {
    //     dlog("ERROR: Failed to set QUIC transport parameters on SSL_CTX: %s", ERR_error_string(ERR_get_error(), NULL));
    //     SSL_CTX_free(config->crypto_ctx->ssl_ctx);
    //     free(config->crypto_ctx);
    //     config->crypto_ctx = NULL;
    //     return -1;
    // }

    dlog("Server crypto context initialized successfully.");
    return 0;
}

static void cleanup_server_crypto_context(nexus_server_config_t *config) {
    if (!config || !config->crypto_ctx) return;
    if (config->crypto_ctx->ssl_ctx) {
        SSL_CTX_free(config->crypto_ctx->ssl_ctx);
    }
    // No SSL object to free for server context, it's created per-connection
    free(config->crypto_ctx);
    config->crypto_ctx = NULL;
}

// Add a random data generation callback
static void server_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
    (void)rand_ctx;
    
    // In a real implementation, use a secure random source
    // For now, use OpenSSL's RAND_bytes
    RAND_bytes(dest, destlen);
}

// Add a get_new_connection_id callback
static int server_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                      uint8_t *token, size_t cidlen,
                                      void *user_data) {
    (void)conn;
    (void)user_data;
    
    if (RAND_bytes(cid->data, cidlen) != 1) {
        dlog("CRITICAL: server_get_new_connection_id: RAND_bytes failed!");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    
    cid->datalen = cidlen;
    
    if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
        dlog("CRITICAL: server_get_new_connection_id: RAND_bytes for token failed!");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    
    return 0;
}

// Add an update_key callback
static int server_update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
                            ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                            ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                            const uint8_t *current_rx_secret, const uint8_t *current_tx_secret,
                            size_t secretlen, void *user_data) {
    (void)conn;
    (void)user_data;
    (void)rx_secret;
    (void)tx_secret;
    (void)rx_aead_ctx;
    (void)rx_iv;
    (void)tx_aead_ctx;
    (void)tx_iv;
    (void)current_rx_secret;
    (void)current_tx_secret;
    (void)secretlen;
    
    // This is a stub implementation to satisfy the API requirement
    dlog("Server update_key callback called (stub implementation)");
    return 0;
}

// Fix these functions with the correct signatures
static void server_delete_crypto_aead_ctx(ngtcp2_conn *conn, ngtcp2_crypto_aead_ctx *aead_ctx, void *user_data) {
    (void)conn;
    (void)user_data;
    if (aead_ctx) {
        // In a real implementation, this would free the aead_ctx
        // For now, just a stub to satisfy the API
        dlog("server_delete_crypto_aead_ctx called (stub implementation)");
    }
}

static void server_delete_crypto_cipher_ctx(ngtcp2_conn *conn, ngtcp2_crypto_cipher_ctx *cipher_ctx, void *user_data) {
    (void)conn;
    (void)user_data;
    if (cipher_ctx) {
        // In a real implementation, this would free the cipher_ctx
        // For now, just a stub to satisfy the API
        dlog("server_delete_crypto_cipher_ctx called (stub implementation)");
    }
}

// Add get_path_challenge_data callback
static int server_get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data, void *user_data) {
    (void)conn;
    (void)user_data;
    
    // Generate random data for path challenge
    if (RAND_bytes(data, NGTCP2_PATH_CHALLENGE_DATALEN) != 1) {
        dlog("ERROR: Failed to generate random data for path challenge");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    
    return 0;
}

int init_nexus_server(network_context_t *net_ctx, const char *bind_address,
                     uint16_t port, nexus_server_config_t *config) {
    if (!net_ctx || !config) {
        dlog("ERROR: Invalid parameters to init_nexus_server");
        return -1;
    }

    memset(config, 0, sizeof(nexus_server_config_t));
    config->net_ctx = net_ctx;
    config->port = port;
    config->bind_address = bind_address ? strdup(bind_address) : NULL;

    if (pthread_mutex_init(&config->lock, NULL) != 0) {
        dlog("ERROR: Server: Failed to initialize mutex");
        if(config->bind_address) free((void*)config->bind_address);
        return -1;
    }

    // Initialize server crypto context (SSL_CTX related parts)
    if (init_server_crypto_context(config) != 0) {
        dlog("ERROR: Server: Failed to initialize server crypto context (SSL_CTX)");
        pthread_mutex_destroy(&config->lock);
        if(config->bind_address) free((void*)config->bind_address);
        return -1;
    }

    ngtcp2_callbacks callbacks = {0};
    callbacks.recv_stream_data = on_stream_data;
    callbacks.handshake_completed = on_handshake_completed;
    callbacks.stream_open = on_stream_open;
    callbacks.rand = server_rand;
    callbacks.get_new_connection_id = server_get_new_connection_id;
    callbacks.update_key = server_update_key;
    callbacks.delete_crypto_aead_ctx = server_delete_crypto_aead_ctx;
    callbacks.delete_crypto_cipher_ctx = server_delete_crypto_cipher_ctx;
    callbacks.get_path_challenge_data = server_get_path_challenge_data;
    
    config->callbacks = callbacks; // Store callbacks in config

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.log_printf = ngtcp2_log_wrapper; // Use the wrapper
    settings.initial_ts = get_timestamp(); // Correct function name
    // settings.max_active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
    config->settings = settings; // Store settings in config

    // Socket creation and binding
    int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        dlog("ERROR: Failed to create server socket: %s", strerror(errno));
        return -1;
    }

    // Set socket options for better performance and reliability
    
    // Allow socket address reuse to avoid "address already in use" errors
    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        dlog("WARNING: Failed to set SO_REUSEADDR: %s", strerror(errno));
        // Continue anyway as this is just an optimization
    }
    
    // Set receive and send buffer sizes for better performance
    int buffer_size = 1024 * 1024; // 1MB buffer
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size)) < 0) {
        dlog("WARNING: Failed to set receive buffer size: %s", strerror(errno));
        // Continue anyway as this is just an optimization
    }
    
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)) < 0) {
        dlog("WARNING: Failed to set send buffer size: %s", strerror(errno));
        // Continue anyway as this is just an optimization
    }

    // Enable IPv6 only if needed, otherwise allow dual stack
    int ipv6_only = 0; // Allow both IPv4 and IPv6 by default
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only, sizeof(ipv6_only)) < 0) {
        dlog("WARNING: Failed to set IPV6_V6ONLY option: %s", strerror(errno));
        // Continue anyway as this is just an optimization
    }

    // Set socket to non-blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        dlog("ERROR: Failed to get socket flags: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        dlog("ERROR: Failed to set socket to non-blocking mode: %s", strerror(errno));
        close(sock);
        return -1;
    }

    // Create address structure for binding
    struct sockaddr_in6 addr_v6 = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(port),
        .sin6_addr = in6addr_any
    };

    // Handle bind_address properly with improved IPv6 support
    if (bind_address && *bind_address) {
        // First check if it's an IPv6 address
        if (inet_pton(AF_INET6, bind_address, &addr_v6.sin6_addr) != 1) {
            // If not a valid IPv6, check if it's an IPv4 address
            struct in_addr ipv4_addr;
            if (inet_pton(AF_INET, bind_address, &ipv4_addr) == 1) {
                // Convert IPv4 to IPv6 mapped address
                unsigned char *bytes = (unsigned char *)&addr_v6.sin6_addr;
                memset(bytes, 0, 10);
                bytes[10] = 0xff;
                bytes[11] = 0xff;
                memcpy(bytes + 12, &ipv4_addr, 4);
                dlog("Converted IPv4 address %s to IPv6 mapped address", bind_address);
            } else if (strcmp(bind_address, "localhost") == 0) {
                // Use loopback address for "localhost"
                inet_pton(AF_INET6, "::1", &addr_v6.sin6_addr);
                dlog("Using IPv6 ::1 for localhost");
            } else {
                // If it's not a valid IP address, assume it's a hostname
                // For servers, we typically want to bind to all interfaces when a hostname is specified
                // This allows the server to accept connections on any interface
                dlog("Hostname '%s' provided, binding to all IPv6 interfaces (::)", bind_address);
                addr_v6.sin6_addr = in6addr_any;
            }
        } else {
            dlog("Using IPv6 address: %s", bind_address);
        }
    } else {
        dlog("Using default IPv6 address (any)");
    }

    // Bind the socket
    if (bind(sock, (struct sockaddr*)&addr_v6, sizeof(addr_v6)) < 0) {
        dlog("ERROR: Failed to bind server socket: %s", strerror(errno));
        close(sock);
        return -1;
    }

    config->sock = sock;
    dlog("Server socket bound to port %u", config->port);
    dlog("Server initialized and listening");

    return 0;
}

int nexus_server_process_events(nexus_server_config_t *config) {
    if (!config) return -1;

    // Static variables to track connection state
    static int first_run = 1;
    static int debug_counter = 0;
    
    // Handle incoming packets
    uint8_t buf[65535];
    struct sockaddr_in6 client_addr_v6;
    socklen_t client_len = sizeof(client_addr_v6);
    
    // Print debug info about the server socket and binding
    if (first_run || debug_counter % 100 == 0) {
        char ipv6_str[INET6_ADDRSTRLEN];
        struct sockaddr_in6 server_addr;
        socklen_t server_len = sizeof(server_addr);
        
        if (getsockname(config->sock, (struct sockaddr*)&server_addr, &server_len) == 0) {
            inet_ntop(AF_INET6, &server_addr.sin6_addr, ipv6_str, sizeof(ipv6_str));
            dlog("Server socket: bound to [%s]:%d, fd=%d", 
                 ipv6_str, ntohs(server_addr.sin6_port), config->sock);
        } else {
            dlog("Failed to get socket name: %s", strerror(errno));
        }
        first_run = 0;
    }
    debug_counter++;
    
    // Try to receive a packet with a short timeout
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 10000; // 10ms timeout
    
    if (setsockopt(config->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        dlog("Failed to set socket timeout: %s", strerror(errno));
    }
    
    ssize_t nread = recvfrom(config->sock, buf, sizeof(buf), 0,
                            (struct sockaddr*)&client_addr_v6, &client_len);
    
    if (nread > 0) {
        // Convert client address to string for logging
        char client_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &client_addr_v6.sin6_addr, client_ip, sizeof(client_ip));
        dlog("Server received packet (%zd bytes) from [%s]:%d", 
             nread, client_ip, ntohs(client_addr_v6.sin6_port));
        
        // Print first few bytes of the packet for debugging
        dlog("Packet header: %02X %02X %02X %02X %02X %02X %02X %02X", 
             buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
        
        ngtcp2_path path = {
            .local = {
                .addr = (struct sockaddr*)&client_addr_v6,
                .addrlen = client_len
            },
            .remote = {
                .addr = (struct sockaddr*)&client_addr_v6,
                .addrlen = client_len
            }
        };

        ngtcp2_pkt_info pi = {0};
        
        // If we don't have a connection yet, create one
        if (!config->conn) {
            dlog("Creating new server connection for incoming packet");
            
            // First, decode the packet to get information needed for the new connection
            ngtcp2_pkt_hd hd;
            int rv;
            
            // Parse the packet header
            rv = ngtcp2_pkt_decode_hd_long(&hd, buf, nread);
            if (rv < 0) {
                dlog("Failed to decode packet header: %s", ngtcp2_strerror(rv));
                return -1;
            }
            
            dlog("Decoded QUIC packet: ver=%08x, dcid=%zu bytes, scid=%zu bytes", 
                 hd.version, hd.dcid.datalen, hd.scid.datalen);
            
            // Initialize transport parameters
            ngtcp2_transport_params params;
            ngtcp2_transport_params_default(&params);
            params.initial_max_streams_bidi = 100;
            params.initial_max_streams_uni = 100;
            params.initial_max_data = 1 * 1024 * 1024;
            params.initial_max_stream_data_bidi_local = 256 * 1024;
            params.initial_max_stream_data_bidi_remote = 256 * 1024;
            params.original_dcid = hd.dcid;
            params.original_dcid_present = 1;
            params.active_connection_id_limit = 8;
            
            // Create a new connection
            ngtcp2_cid scid = hd.dcid;
            ngtcp2_cid dcid = hd.scid;
            
            ngtcp2_conn *conn;
            rv = ngtcp2_conn_server_new(&conn, &dcid, &scid, &path, 
                                      hd.version, &config->callbacks, 
                                      &config->settings, &params, NULL, config);
            if (rv != 0) {
                dlog("Failed to create new connection: %s", ngtcp2_strerror(rv));
                return -1;
            }
            
            config->conn = conn;
            dlog("Server connection created successfully");
            
            // Create SSL object for TLS handshake
            SSL *ssl = SSL_new(config->crypto_ctx->ssl_ctx);
            if (!ssl) {
                dlog("Failed to create SSL object: %s", ERR_error_string(ERR_get_error(), NULL));
                ngtcp2_conn_del(config->conn);
                config->conn = NULL;
                return -1;
            }
            
            config->crypto_ctx->ssl = ssl;
            
            // Set SSL to accept mode
            SSL_set_accept_state(ssl);
            
            // Associate the SSL object with the QUIC connection
            ngtcp2_conn_set_tls_native_handle(config->conn, ssl);
        }
        
        // Now process the packet with the connection
        if (config->conn) {
            int rv = ngtcp2_conn_read_pkt(config->conn, &path, &pi, buf, nread, get_timestamp());
            if (rv != 0) {
                dlog("Error processing packet: %s", ngtcp2_strerror(rv));
                // Don't tear down the connection on error - let it retry
                // (some errors are expected during handshake)
            }

            // Send any pending data
            uint8_t send_buf[65535];
            ngtcp2_path_storage ps;
            ngtcp2_path_storage_zero(&ps);
            
            ngtcp2_pkt_info pktinfo = {0};
            
            // Try to send data
            ssize_t n = ngtcp2_conn_write_pkt(config->conn, &ps.path, &pktinfo,
                                             send_buf, sizeof(send_buf), get_timestamp());
            
            if (n > 0) {
                ssize_t sent = sendto(config->sock, send_buf, n, 0,
                       (struct sockaddr*)&client_addr_v6, client_len);
                dlog("Server sent %zd bytes in response to [%s]:%d", 
                     sent, client_ip, ntohs(client_addr_v6.sin6_port));
                
                // Print first few bytes of the response for debugging
                dlog("Response header: %02X %02X %02X %02X %02X %02X %02X %02X",
                     send_buf[0], send_buf[1], send_buf[2], send_buf[3],
                     send_buf[4], send_buf[5], send_buf[6], send_buf[7]);
            }
        }
    } else if (nread < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        dlog("Error receiving packet: %s", strerror(errno));
    } else if (config->conn) {
        // No new packet received, but we have an existing connection
        // Still need to process any timeouts and generate any needed packets
        
        uint8_t send_buf[65535];
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_pkt_info pktinfo = {0};
        
        // Set up path for timeout packets if needed
        struct sockaddr_in6 server_addr;
        socklen_t server_len = sizeof(server_addr);
        
        if (getsockname(config->sock, (struct sockaddr*)&server_addr, &server_len) == 0) {
            ps.path.local.addr = (struct sockaddr*)&server_addr;
            ps.path.local.addrlen = server_len;
            
            // Use last known client address for remote
            ps.path.remote.addr = (struct sockaddr*)&client_addr_v6;
            ps.path.remote.addrlen = client_len;
        }
        
        // Try to generate timeout packets
        ssize_t n = ngtcp2_conn_write_pkt(config->conn, &ps.path, &pktinfo,
                                         send_buf, sizeof(send_buf), get_timestamp());
        
        if (n > 0) {
            char client_ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &client_addr_v6.sin6_addr, client_ip, sizeof(client_ip));
            
            ssize_t sent = sendto(config->sock, send_buf, n, 0,
                   (struct sockaddr*)&client_addr_v6, client_len);
            dlog("Server sent timeout packet (%zd bytes) to [%s]:%d", 
                 sent, client_ip, ntohs(client_addr_v6.sin6_port));
        }
    }

    return 0;
}
