#include "nexus_server.h"
#include "network_context.h"
#include "certificate_authority.h"
#include "debug.h"
#include "system.h"
#include "packet_protocol.h" // For serialization/deserialization
#include "tld_manager.h"     // For TLD management functions
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h> // For pthread_mutex
#include <ngtcp2/ngtcp2_crypto.h>

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

// Forward declarations with correct return types and parameters
static int on_stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
    (void)conn;      // Suppress unused parameter warning
    (void)user_data; // Suppress unused parameter warning
    dlog("New stream opened: %ld", stream_id);
    return 0;  // Return success
}

static int on_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                         uint64_t offset, const uint8_t *data, 
                         size_t datalen, void *user_data, void *stream_user_data) {
    (void)flags;
    (void)offset;
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

    switch (received_packet.type) {
        case PACKET_TYPE_TLD_REGISTER_REQ: {
            dlog("Server: Handling TLD_REGISTER_REQ");
            payload_tld_register_req_t req_payload;
            payload_tld_register_resp_t resp_payload;
            memset(&req_payload, 0, sizeof(req_payload));
            memset(&resp_payload, 0, sizeof(resp_payload));

            if (deserialize_payload_tld_register_req(received_packet.data, received_packet.data_len, &req_payload) < 0) {
                dlog("ERROR: Server: Failed to deserialize TLD_REGISTER_REQ payload.");
                strncpy(resp_payload.message, "Malformed request payload", sizeof(resp_payload.message) - 1);
                resp_payload.status = TLD_REG_RESP_ERROR_INTERNAL_SERVER_ERROR; // Or a more specific parse error
            } else {
                dlog("Server: Attempting to register TLD: %s", req_payload.tld_name);
                tld_t* new_tld = register_new_tld(server_config->net_ctx->tld_manager, req_payload.tld_name);
                if (new_tld) {
                    resp_payload.status = TLD_REG_RESP_SUCCESS;
                    snprintf(resp_payload.message, sizeof(resp_payload.message), "TLD '%s' registered successfully.", req_payload.tld_name);
                    dlog("Server: TLD '%s' registered.", req_payload.tld_name);
                } else {
                    // find_tld_by_name could be used here to check if it was an "already_exists" case vs other error
                    if (find_tld_by_name(server_config->net_ctx->tld_manager, req_payload.tld_name)) {
                        resp_payload.status = TLD_REG_RESP_ERROR_ALREADY_EXISTS;
                        snprintf(resp_payload.message, sizeof(resp_payload.message), "TLD '%s' already exists.", req_payload.tld_name);
                        dlog("Server: TLD '%s' already exists.", req_payload.tld_name);
                    } else {
                        resp_payload.status = TLD_REG_RESP_ERROR_INTERNAL_SERVER_ERROR;
                        snprintf(resp_payload.message, sizeof(resp_payload.message), "Failed to register TLD '%s'.", req_payload.tld_name);
                        dlog("ERROR: Server: Failed to register TLD '%s'.", req_payload.tld_name);
                    }
                }
            }

            // Send response
            nexus_packet_t response_packet;
            memset(&response_packet, 0, sizeof(response_packet));
            response_packet.version = received_packet.version; // Use same version or current protocol version
            response_packet.type = PACKET_TYPE_TLD_REGISTER_RESP;
            response_packet.session_id = received_packet.session_id; // Echo session ID

            uint8_t resp_payload_buf[512]; // Estimate size; use get_serialized_... for exact
            ssize_t resp_payload_len = serialize_payload_tld_register_resp(&resp_payload, resp_payload_buf, sizeof(resp_payload_buf));
            if (resp_payload_len < 0) {
                dlog("ERROR: Server: Failed to serialize TLD_REGISTER_RESP payload.");
                break; // Out of switch case
            }
            response_packet.data = resp_payload_buf;
            response_packet.data_len = resp_payload_len;

            uint8_t final_response_buf[1024]; // Estimate for full packet
            ssize_t final_response_len = serialize_nexus_packet(&response_packet, final_response_buf, sizeof(final_response_buf));
            if (final_response_len < 0) {
                dlog("ERROR: Server: Failed to serialize final response NEXUS packet.");
                break;
            }

            // Send the data on the stream
            // ngtcp2_conn_write_stream or ngtcp2_conn_writev_stream
            // For simplicity, assuming a function like send_on_stream exists or using ngtcp2 directly.
            // This requires knowing the stream ID is bidirectional and client is expecting a response on it.
            
            int rv = ngtcp2_conn_write_stream(conn, NULL, NULL, 
                                            NULL, 0, NULL,
                                            0, stream_id, final_response_buf, final_response_len, 
                                            get_timestamp());
            if (rv != 0 && rv != NGTCP2_ERR_STREAM_DATA_BLOCKED) { // Data blocked is not a fatal error
                dlog("ERROR: Server: Failed to write stream data for TLD_REGISTER_RESP: %s", ngtcp2_strerror(rv));
            }
            dlog("Server: Sent TLD_REGISTER_RESP, %zd bytes on stream %ld", final_response_len, stream_id);
            break;
        }
        // TODO: Handle other packet types (DNS_QUERY, TLD_MIRROR_REQ, etc.)
        default:
            dlog("WARNING: Server: Received unhandled packet type %d on stream %ld", received_packet.type, stream_id);
            break;
    }

    free(received_packet.data); // Free data allocated by deserialize_nexus_packet
    // Mark data as consumed for this stream
    // ngtcp2_conn_extend_max_stream_data(conn, stream_id, datalen);
    // The return 0 from this callback usually means data is consumed.
    // ngtcp2 library might handle extending stream data offset internally based on callback processing.
    return 0;  // Return success
}

static int on_handshake_completed(ngtcp2_conn *conn, void *user_data) {
    (void)conn;
    (void)user_data;
    dlog("Server handshake completed");
    return 0;
}

static int on_receive_client_initial(ngtcp2_conn *conn, const ngtcp2_cid *dcid, void *user_data) {
    (void)user_data;
    dlog("Received client initial packet");
    
    // Generate a random initial key for testing
    uint8_t key[64];
    uint8_t iv[64];
    uint8_t hp_key[64];
    
    // Fill with random data
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));
    RAND_bytes(hp_key, sizeof(hp_key));
    
    // Create dummy AEAD context
    ngtcp2_crypto_aead_ctx aead_ctx = {0};
    ngtcp2_crypto_cipher_ctx hp_ctx = {0};
    
    // Install the keys
    if (ngtcp2_conn_install_initial_key(conn, &aead_ctx, iv, &hp_ctx,
                                      &aead_ctx, iv, &hp_ctx, 12) != 0) {
        dlog("ERROR: Failed to install initial key");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    
    dlog("Server initial keys installed");
    
    return 0;
}

// Comment out this function since it references an undefined function
/*
// Custom certificate verification that uses our Falcon certs
int verify_falcon_cert_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    (void)preverify_ok;  // Suppress unused parameter warning
    nexus_cert_t *falcon_cert = X509_STORE_CTX_get_ex_data(ctx, 0);
    ca_context_t *ca_ctx = X509_STORE_CTX_get_ex_data(ctx, 1);
    
    // Verify using Falcon instead of X509
    return verify_certificate(falcon_cert, ca_ctx);
}
*/

// Simplified crypto data handler
static int on_recv_crypto_data(ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level,
                            uint64_t offset, const uint8_t *data, size_t datalen,
                            void *user_data) {
    (void)conn;           // Suppress unused parameter warning
    (void)offset;         // Suppress unused parameter warning
    (void)data;           // Suppress unused parameter warning
    (void)encryption_level; // Suppress unused parameter warning
    
    nexus_server_config_t *config = (nexus_server_config_t *)user_data;
    
    if (!config || !config->crypto_ctx || !config->crypto_ctx->ssl) {
        dlog("ERROR: Server received crypto data but crypto context is not initialized");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    
    dlog("Server received crypto data (%zu bytes) at encryption level %d", datalen, encryption_level);
    
    // Process the handshake - in a real implementation you would need to process 
    // the SSL data properly, but for now we'll simplify
    int rv = SSL_do_handshake(config->crypto_ctx->ssl);
    if (rv > 0) {
        dlog("SSL handshake progressed");
    }
    
    return 0;
}

// Initialize crypto context for server
static int init_server_crypto_context(nexus_server_config_t *config) {
    if (!config) return -1;
    
    // Allocate crypto context
    config->crypto_ctx = malloc(sizeof(nexus_server_crypto_ctx));
    if (!config->crypto_ctx) {
        dlog("ERROR: Failed to allocate crypto context");
        return -1;
    }
    memset(config->crypto_ctx, 0, sizeof(nexus_server_crypto_ctx));
    
    // Create SSL context
    config->crypto_ctx->ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!config->crypto_ctx->ssl_ctx) {
        dlog("ERROR: Failed to create SSL context: %s", 
             ERR_error_string(ERR_get_error(), NULL));
        free(config->crypto_ctx);
        config->crypto_ctx = NULL;
        return -1;
    }
    
    // Configure TLS options for QUIC
    SSL_CTX_set_min_proto_version(config->crypto_ctx->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(config->crypto_ctx->ssl_ctx, TLS1_3_VERSION);
    
    // For testing, accept any client certificate
    SSL_CTX_set_verify(config->crypto_ctx->ssl_ctx, SSL_VERIFY_NONE, NULL);
    
    // Create SSL object for the connection
    config->crypto_ctx->ssl = SSL_new(config->crypto_ctx->ssl_ctx);
    if (!config->crypto_ctx->ssl) {
        dlog("ERROR: Failed to create SSL object: %s", 
             ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(config->crypto_ctx->ssl_ctx);
        free(config->crypto_ctx);
        config->crypto_ctx = NULL;
        return -1;
    }
    
    // Set the connection reference for the crypto callbacks
    config->crypto_ctx->conn_ref.get_conn = get_conn_from_config;
    config->crypto_ctx->conn_ref.user_data = config;
    
    // Set SSL to server mode
    SSL_set_accept_state(config->crypto_ctx->ssl);
    
    return 0;
}

// Cleanup server crypto context
static void cleanup_server_crypto_context(nexus_server_config_t *config) {
    if (!config || !config->crypto_ctx) return;
    
    if (config->crypto_ctx->ssl) {
        SSL_free(config->crypto_ctx->ssl);
    }
    
    if (config->crypto_ctx->ssl_ctx) {
        SSL_CTX_free(config->crypto_ctx->ssl_ctx);
    }
    
    free(config->crypto_ctx);
    config->crypto_ctx = NULL;
}

// Dummy encryption callback with the correct signature
static int dummy_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                      const ngtcp2_crypto_aead_ctx *aead_ctx,
                      const uint8_t *plaintext, size_t plaintextlen,
                      const uint8_t *nonce, size_t noncelen,
                      const uint8_t *ad, size_t adlen) {
    (void)aead;
    (void)aead_ctx;
    (void)nonce;
    (void)noncelen;
    (void)ad;
    (void)adlen;

    // Just copy the plaintext for simplicity
    if (plaintextlen > 0 && plaintext != NULL) {
        memcpy(dest, plaintext, plaintextlen);
    }
    return 0;
}

// Dummy decryption callback with the correct signature
static int dummy_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                      const ngtcp2_crypto_aead_ctx *aead_ctx,
                      const uint8_t *ciphertext, size_t ciphertextlen,
                      const uint8_t *nonce, size_t noncelen,
                      const uint8_t *ad, size_t adlen) {
    (void)aead;
    (void)aead_ctx;
    (void)nonce;
    (void)noncelen;
    (void)ad;
    (void)adlen;

    // Just copy the ciphertext for simplicity
    if (ciphertextlen > 0 && ciphertext != NULL) {
        memcpy(dest, ciphertext, ciphertextlen);
    }
    return 0;
}

// Dummy HP mask callback
static int dummy_hp_mask(uint8_t *mask, const ngtcp2_crypto_cipher *hp,
                      const ngtcp2_crypto_cipher_ctx *hp_ctx,
                      const uint8_t *sample) {
    (void)hp;
    (void)hp_ctx;
    (void)sample;
    
    // Just fill the mask with some fixed values for testing
    if (mask) {
        memset(mask, 0xaa, 16); // Use a recognizable pattern
    }
    return 0;
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
                                      uint8_t *token, size_t cidlen, void *user_data) {
    (void)conn;
    (void)user_data;
    
    // Generate a random CID with the requested length
    if (RAND_bytes(cid->data, cidlen) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    cid->datalen = cidlen;
    
    // Generate a random stateless reset token
    if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
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
    (void)rx_secret;
    (void)tx_secret;
    (void)rx_aead_ctx;
    (void)rx_iv;
    (void)tx_aead_ctx;
    (void)tx_iv;
    (void)current_rx_secret;
    (void)current_tx_secret;
    (void)secretlen;
    (void)user_data;
    
    // In a real implementation, this would update the keys
    // For our test, just succeed
    return 0;
}

// Fix the delete_crypto_aead_ctx callback signature
static void server_delete_crypto_aead_ctx(ngtcp2_conn *conn, ngtcp2_crypto_aead_ctx *aead_ctx, void *user_data) {
    (void)conn;
    (void)aead_ctx;
    (void)user_data;
    
    // In a real implementation, this would free resources associated with the AEAD context
    // For our test, do nothing
}

// Fix the delete_crypto_cipher_ctx callback signature
static void server_delete_crypto_cipher_ctx(ngtcp2_conn *conn, ngtcp2_crypto_cipher_ctx *cipher_ctx, void *user_data) {
    (void)conn;
    (void)cipher_ctx;
    (void)user_data;
    
    // In a real implementation, this would free resources associated with the cipher context
    // For our test, do nothing
}

// Add get_path_challenge_data callback
static int server_get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data, void *user_data) {
    (void)conn;
    (void)user_data;
    
    // Generate random data for the path challenge
    if (RAND_bytes(data, NGTCP2_PATH_CHALLENGE_DATALEN) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    
    return 0;
}

int init_nexus_server(network_context_t *net_ctx, const char *bind_address,
                     uint16_t port, nexus_server_config_t *config) {
    if (!config || !net_ctx) return -1;

    config->net_ctx = net_ctx;
    config->bind_address = (char *)bind_address;  // Note: discards const qualifier
    config->port = port;
    
    dlog("Initializing server with mode %s", net_ctx->mode);

    // Request server certificate from CA
    ca_context_t *ca_ctx = NULL;
    if (init_certificate_authority(net_ctx, &ca_ctx) != 0) {
        dlog("ERROR: Failed to initialize certificate authority");
        return -1;
    }

    nexus_cert_t *server_cert = NULL;
    if (handle_cert_request(ca_ctx, net_ctx->hostname, &server_cert) != 0) {
        dlog("ERROR: Failed to obtain server certificate");
        return -1;
    }
    
    dlog("Server certificate initialized");

    config->ca_ctx = ca_ctx;
    config->cert = server_cert;
    
    // Initialize crypto context
    if (init_server_crypto_context(config) != 0) {
        dlog("ERROR: Failed to initialize server crypto context");
        free_certificate(server_cert);
        return -1;
    }

    // Initialize ngtcp2 settings
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    
    // Set up callbacks
    ngtcp2_callbacks callbacks = {0};
    callbacks.recv_client_initial = on_receive_client_initial;
    callbacks.handshake_completed = on_handshake_completed;
    callbacks.recv_stream_data = on_stream_data;
    callbacks.stream_open = on_stream_open;
    callbacks.recv_crypto_data = on_recv_crypto_data;
    callbacks.encrypt = dummy_encrypt;
    callbacks.decrypt = dummy_decrypt;
    callbacks.hp_mask = dummy_hp_mask;
    callbacks.rand = server_rand;
    callbacks.get_new_connection_id = server_get_new_connection_id;
    callbacks.update_key = server_update_key;
    callbacks.delete_crypto_aead_ctx = server_delete_crypto_aead_ctx;
    callbacks.delete_crypto_cipher_ctx = server_delete_crypto_cipher_ctx;
    callbacks.get_path_challenge_data = server_get_path_challenge_data;
    
    // Transport parameters for server
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    
    // Initialize a dummy DCID for the original_dcid parameter
    ngtcp2_cid orig_dcid;
    memset(&orig_dcid, 0, sizeof(orig_dcid));
    orig_dcid.datalen = 8;  // Use a reasonable length
    for (size_t i = 0; i < orig_dcid.datalen; ++i) {
        orig_dcid.data[i] = (uint8_t)i;  // Simple pattern for testing
    }

    // Server needs to have original_dcid set
    params.original_dcid_present = 1;
    params.original_dcid = orig_dcid;  // Set to our dummy DCID
    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 100;
    params.initial_max_data = 1 * 1024 * 1024; // 1MB
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni = 256 * 1024;
    
    // Set up a path for the connection
    ngtcp2_path path = {0};
    struct sockaddr_in6 local_addr_v6 = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(port),
        .sin6_addr = in6addr_any
    };
    struct sockaddr_in6 remote_addr_v6 = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(0),
        .sin6_addr = in6addr_any
    };
    
    path.local.addr = (struct sockaddr*)&local_addr_v6;
    path.local.addrlen = sizeof(local_addr_v6);
    path.remote.addr = (struct sockaddr*)&remote_addr_v6;
    path.remote.addrlen = sizeof(remote_addr_v6);

    // Generate a source connection ID for the server
    ngtcp2_cid scid;
    memset(&scid, 0, sizeof(scid));
    scid.datalen = 8;  // Use a reasonable length
    for (size_t i = 0; i < scid.datalen; ++i) {
        scid.data[i] = (uint8_t)(i + 1);  // Simple pattern
    }

    // Create the ngtcp2_conn object
    ngtcp2_conn *conn = NULL;
    if (ngtcp2_conn_server_new(&conn, &scid, &scid, &path, NGTCP2_PROTO_VER_MAX,
                              &callbacks, &settings, &params, NULL, config) != 0) {
        dlog("ERROR: Failed to create QUIC connection object for server");
        cleanup_server_crypto_context(config);
        free_certificate(server_cert);
        return -1;
    }
    
    // Store the connection in config
    config->conn = conn;
    
    // Skip the problematic SSL/ngtcp2 crypto integration for now
    // We'll need to properly implement this once we have the correct versions of libraries

    // Set up the server socket
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        dlog("ERROR: Failed to create server socket");
        ngtcp2_conn_del(conn);
        cleanup_server_crypto_context(config);
        free_certificate(server_cert);
        return -1;
    }

    // Set socket to non-blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // Create address structure for binding
    struct sockaddr_in6 addr_v6 = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(port),
        .sin6_addr = in6addr_any
    };

    // If bind_address is specified, use that instead of in6addr_any
    if (bind_address && strcmp(bind_address, "0.0.0.0") != 0) {
        // Try to convert the address string to an IPv6 address
        if (inet_pton(AF_INET6, bind_address, &addr_v6.sin6_addr) != 1) {
            // If it's not a valid IPv6 address, check if it's "localhost"
            if (strcmp(bind_address, "localhost") == 0 || strcmp(bind_address, "127.0.0.1") == 0) {
                dlog("Converting localhost to IPv6 ::1");
                inet_pton(AF_INET6, "::1", &addr_v6.sin6_addr);
            } else {
                dlog("ERROR: Invalid IPv6 address: %s", bind_address);
                close(sock);
                ngtcp2_conn_del(conn);
                cleanup_server_crypto_context(config);
                free_certificate(server_cert);
                return -1;
            }
        }
    }

    // Bind the socket
    if (bind(sock, (struct sockaddr*)&addr_v6, sizeof(addr_v6)) < 0) {
        dlog("ERROR: Failed to bind server socket: %s", strerror(errno));
        close(sock);
        ngtcp2_conn_del(conn);
        cleanup_server_crypto_context(config);
        free_certificate(server_cert);
        return -1;
    }

    config->sock = sock;
    dlog("Server socket bound to port %u", config->port);
    dlog("Server initialized and listening");

    return 0;
}

int nexus_server_process_events(nexus_server_config_t *config) {
    if (!config) return -1;

    // Handle incoming packets
    uint8_t buf[65535];
    struct sockaddr_in6 client_addr_v6;
    socklen_t client_len = sizeof(client_addr_v6);
    
    ssize_t nread = recvfrom(config->sock, buf, sizeof(buf), 0,
                            (struct sockaddr*)&client_addr_v6, &client_len);
    
    if (nread > 0) {
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
        ngtcp2_conn_read_pkt(config->conn, &path, &pi, buf, nread, get_timestamp());

        // Send any pending data
        uint8_t send_buf[65535];
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        
        ngtcp2_pkt_info pktinfo = {0};
        
        // Try to send data
        ssize_t n = ngtcp2_conn_write_pkt(config->conn, &ps.path, &pktinfo,
                                         send_buf, sizeof(send_buf), get_timestamp());
        
        if (n > 0) {
            sendto(config->sock, send_buf, n, 0,
                   (struct sockaddr*)&client_addr_v6, client_len);
        }
    }

    return 0;
}
