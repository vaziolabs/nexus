#include "../include/nexus_client.h"
#include "../include/nexus_node.h"
#include "../include/debug.h"
#include "../include/packet_protocol.h"
#include "../include/dns_types.h"
#include "../include/certificate_authority.h"
#include "../include/system.h"
#include "../include/ngtcp2_compat.h"
#include "../include/nexus_client_api.h"
#include <ngtcp2/ngtcp2.h> // For ngtcp2_conn_get_ts

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

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

// Forward declare stream data callback for client
static int client_on_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                               uint64_t offset, const uint8_t *data, size_t datalen, 
                               void *user_data, void *stream_user_data);

static int client_on_stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, 
                                uint64_t app_error_code, void *user_data, void *stream_user_data) {
    (void)conn; (void)flags; (void)app_error_code; (void)user_data; (void)stream_user_data;
    dlog("Client: Stream %ld closed.", stream_id);
    // If stream_user_data was used for per-stream context, free it here.
    return 0;
}

static int client_on_stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
    (void)conn;
    (void)user_data;
    dlog("Client: Stream %ld opened by server (unexpected for client-initiated bidi).", stream_id);
    // Typically, clients open streams to servers. If server opens a stream to client, handle here.
    return 0;
}

// Add these callback declarations at the top
static int on_handshake_completed(ngtcp2_conn *conn, void *user_data) {
    (void)conn;
    (void)user_data;
    dlog("Client handshake completed");
    return 0;
}

static int on_client_initial(ngtcp2_conn *conn, void *user_data) {
    (void)user_data;
    dlog("Client initial callback");
    
    // Initialize default crypto keys
    const ngtcp2_cid *dcid = ngtcp2_conn_get_dcid(conn);
    
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
    
    // For testing purposes, we're just installing the keys
    dlog("Initial keys installed");
    
    return 0;
}

// Callback for when client receives crypto data from server
static int client_recv_crypto_data(ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level,
                                 uint64_t offset, const uint8_t *data, size_t datalen,
                                 void *user_data) {
    nexus_client_config_t *config = (nexus_client_config_t *)user_data;
    
    if (!config || !config->crypto_ctx || !config->crypto_ctx->ssl) {
        dlog("ERROR: Client received crypto data but crypto context is not initialized");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    
    dlog("Client received crypto data (%zu bytes) at encryption level %d", datalen, encryption_level);
    
    // Feed the TLS data into SSL object
    dlog("Client: SSL_provide_quic_data would be called here for encryption_level %d", encryption_level);

    // Process the handshake
    dlog("Client: SSL_do_handshake would be called here");
    
    return 0;
}

// Add recv_retry callback implementation after on_client_initial function
static int client_recv_retry(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data) {
    (void)conn;
    (void)hd;
    dlog("Client received retry packet");
    
    // This callback must be implemented for clients
    // The real implementation would regenerate keys based on the new connection ID
    // For now, just return success
    return 0;
}

// Add a random data generation callback
static void client_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
    (void)rand_ctx;
    
    // In a real implementation, use a secure random source
    // For now, use OpenSSL's RAND_bytes
    RAND_bytes(dest, destlen);
}

// Add a get_new_connection_id callback
static int client_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, 
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
static int client_update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
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
static void client_delete_crypto_aead_ctx(ngtcp2_conn *conn, ngtcp2_crypto_aead_ctx *aead_ctx, void *user_data) {
    (void)conn;
    (void)aead_ctx;
    (void)user_data;
    
    // In a real implementation, this would free resources associated with the AEAD context
    // For our test, do nothing
}

// Fix the delete_crypto_cipher_ctx callback signature
static void client_delete_crypto_cipher_ctx(ngtcp2_conn *conn, ngtcp2_crypto_cipher_ctx *cipher_ctx, void *user_data) {
    (void)conn;
    (void)cipher_ctx;
    (void)user_data;
    
    // In a real implementation, this would free resources associated with the cipher context
    // For our test, do nothing
}

// Add get_path_challenge_data callback
static int client_get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data, void *user_data) {
    (void)conn;
    (void)user_data;
    
    // Generate random data for the path challenge
    if (RAND_bytes(data, NGTCP2_PATH_CHALLENGE_DATALEN) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    
    return 0;
}

// Initialize the crypto context for TLS
static int init_client_crypto_context(nexus_client_config_t *config) {
    if (!config) return -1;
    
    // Allocate crypto context
    config->crypto_ctx = malloc(sizeof(nexus_crypto_ctx));
    if (!config->crypto_ctx) {
        dlog("ERROR: Failed to allocate crypto context");
        return -1;
    }
    memset(config->crypto_ctx, 0, sizeof(nexus_crypto_ctx));
    
    // Create SSL context
    config->crypto_ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());
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
    // SSL_CTX_set_quic_method(config->crypto_ctx->ssl_ctx, ngtcp2_crypto_ossl_quic_method);
    dlog("Client: SSL_CTX_set_quic_method would be called here");
    
    // For testing, we might need to disable certificate verification
    // SSL_CTX_set_verify(config->crypto_ctx->ssl_ctx, SSL_VERIFY_NONE, NULL);
    
    // Create SSL object
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
    config->crypto_ctx->conn_ref.get_conn = ngtcp2_crypto_conn_ref_default_get_conn;
    config->crypto_ctx->conn_ref.user_data = config;
    
    // Set server name for SNI
    SSL_set_tlsext_host_name(config->crypto_ctx->ssl, config->bind_address);
    
    // Set QUIC transport parameters
    uint8_t paramsbuf[256];
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    
    // Set parameters (ensure original_dcid_present is explicitly false for client)
    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 100;
    params.initial_max_data = 1 * 1024 * 1024; // 1MB
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.original_dcid_present = 0; // Explicitly set to false for client
    
    // Encode transport parameters using the correct function
    ssize_t nwrite = ngtcp2_transport_params_encode(
        paramsbuf, sizeof(paramsbuf), &params);
    if (nwrite < 0) {
        dlog("ERROR: Failed to encode transport parameters");
        SSL_free(config->crypto_ctx->ssl);
        SSL_CTX_free(config->crypto_ctx->ssl_ctx);
        free(config->crypto_ctx);
        config->crypto_ctx = NULL;
        return -1;
    }
    
    // Set transport parameters in SSL (updating function name)
    // if (SSL_set_quic_tls_transport_params(config->crypto_ctx->ssl, paramsbuf, nwrite) != 1) {
    //     dlog("ERROR: Failed to set QUIC transport parameters: %s", 
    //          ERR_error_string(ERR_get_error(), NULL));
    //     SSL_free(config->crypto_ctx->ssl);
    //     SSL_CTX_free(config->crypto_ctx->ssl_ctx);
    //     free(config->crypto_ctx);
    //     config->crypto_ctx = NULL;
    //     return -1;
    // }
    dlog("Client: SSL_set_quic_tls_transport_params would be called here");
    
    return 0;
}

// Free crypto context resources
static void cleanup_client_crypto_context(nexus_client_config_t *config) {
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

// Update the init_nexus_client function to use the crypto context
int init_nexus_client(network_context_t *net_ctx, const char *remote_addr, 
                    uint16_t port, nexus_client_config_t *config) {
    if (!remote_addr || !net_ctx || !config) return -1;
    dlog("Initializing client for %s:%u", remote_addr, port);

    // Initialize the provided config structure
    memset(config, 0, sizeof(nexus_client_config_t));
    config->net_ctx = net_ctx; // Store net_ctx
    config->next_stream_id = 0; // Client-initiated bidi streams are even (0, 2, 4...)

    // For private mode, clients also need a certificate
    ca_context_t *ca_ctx = NULL;
    if (init_certificate_authority(net_ctx, &ca_ctx) != 0) {
        dlog("ERROR: Failed to initialize certificate authority for client");
        return -1;
    }

    // Request client certificate from CA
    nexus_cert_t *client_cert = NULL;
    if (handle_cert_request(ca_ctx, net_ctx->hostname, &client_cert) != 0) {
        dlog("ERROR: Failed to obtain client certificate for client");
        return -1;
    }

    // Initialize QUIC settings
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);

    // Initialize crypto context
    if (init_client_crypto_context(config) != 0) {
        dlog("ERROR: Failed to initialize client crypto context");
        free_certificate(client_cert);
        return -1;
    }

    // Setup QUIC callbacks
    ngtcp2_callbacks callbacks = {0};
    callbacks.client_initial = on_client_initial;
    callbacks.handshake_completed = on_handshake_completed;
    callbacks.recv_stream_data = client_on_stream_data;
    callbacks.stream_close = client_on_stream_close;
    callbacks.stream_open = client_on_stream_open;
    callbacks.recv_crypto_data = client_recv_crypto_data;
    
    // Add encryption/decryption callbacks
    callbacks.encrypt = dummy_encrypt;
    callbacks.decrypt = dummy_decrypt;
    callbacks.hp_mask = dummy_hp_mask;
    
    // Add random data generation callback
    callbacks.rand = client_rand;
    
    // Add get_new_connection_id callback
    callbacks.get_new_connection_id = client_get_new_connection_id;
    
    // Add update_key callback
    callbacks.update_key = client_update_key;
    
    // Add delete_crypto_aead_ctx callback
    callbacks.delete_crypto_aead_ctx = client_delete_crypto_aead_ctx;
    
    // Add delete_crypto_cipher_ctx callback
    callbacks.delete_crypto_cipher_ctx = client_delete_crypto_cipher_ctx;
    
    // Add get_path_challenge_data callback
    callbacks.get_path_challenge_data = client_get_path_challenge_data;
    
    // Use the ngtcp2 crypto ossl integration
    ngtcp2_crypto_ossl_init_callbacks(&callbacks);
    
    // Generate connection IDs
    uint8_t dcid_data[NGTCP2_MAX_CIDLEN];
    uint8_t scid_data[NGTCP2_MAX_CIDLEN];
    size_t dcid_len = 18;  // Typical QUIC CID length
    size_t scid_len = 18;
    ngtcp2_cid dcid, scid;
    
    RAND_bytes(dcid_data, dcid_len);
    RAND_bytes(scid_data, scid_len);
    
    ngtcp2_cid_init(&dcid, dcid_data, dcid_len);
    ngtcp2_cid_init(&scid, scid_data, scid_len);

    // Initialize transport parameters
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    
    // Set parameters (ensure original_dcid_present is explicitly false for client)
    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 100;
    params.initial_max_data = 1 * 1024 * 1024; // 1MB
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.original_dcid_present = 0; // Explicitly set to false for client
    params.initial_max_stream_data_uni = 256 * 1024;         // 256KB
    params.initial_max_stream_data_bidi_local = 256 * 1024;  // 256KB
    params.initial_max_stream_data_bidi_remote = 256 * 1024; // 256KB
    params.initial_max_data = 1 * 1024 * 1024;              // 1MB
    params.initial_max_streams_bidi = 100;                  // Allow 100 bidirectional streams
    params.initial_max_streams_uni = 100;                   // Allow 100 unidirectional streams
    params.max_idle_timeout = 30 * NGTCP2_SECONDS;          // 30 seconds idle timeout
    params.active_connection_id_limit = 8;                  // Support 8 connection IDs

    // Set up a path for the connection
    ngtcp2_path path = {0};
    struct sockaddr_in6 local_addr_v6 = {
        .sin6_family = AF_INET6,
        .sin6_port = 0,  // Let the OS pick
        .sin6_addr = IN6ADDR_ANY_INIT
    };
    struct sockaddr_in6 remote_addr_sockaddr_v6 = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(port)
        // sin6_addr will be set by inet_pton below
    };
    
    // Convert the string address to IPv6 binary form
    if (inet_pton(AF_INET6, remote_addr, &remote_addr_sockaddr_v6.sin6_addr) != 1) {
        // If not a valid IPv6 address, try to use IPv6 localhost
        if (strcmp(remote_addr, "localhost") == 0 || strcmp(remote_addr, "127.0.0.1") == 0) {
            dlog("Converting localhost to IPv6 ::1");
            inet_pton(AF_INET6, "::1", &remote_addr_sockaddr_v6.sin6_addr);
        } else {
            dlog("ERROR: Invalid IPv6 address: %s", remote_addr);
            return -1;
        }
    }

    // Update the path addresses to use IPv6
    path.local.addr = (struct sockaddr*)&local_addr_v6;
    path.local.addrlen = sizeof(local_addr_v6);
    path.remote.addr = (struct sockaddr*)&remote_addr_sockaddr_v6;
    path.remote.addrlen = sizeof(remote_addr_sockaddr_v6);

    ngtcp2_conn *conn = NULL;
    if (ngtcp2_conn_client_new(&conn,          
                              &dcid,           
                              &scid,           
                              &path,            
                              NGTCP2_PROTO_VER_MAX, 
                              &callbacks,      
                              &settings,       
                              &params,         
                              NULL,           
                              config) != 0) {
        dlog("ERROR: Failed to create QUIC connection object for client");
        cleanup_client_crypto_context(config);
        free_certificate(client_cert);
        return -1;
    }

    // Associate ngtcp2 connection with the SSL object
    if (ngtcp2_crypto_ossl_configure_client_context(config->crypto_ctx->ssl, conn) != 0) {
        dlog("ERROR: Failed to configure client context");
        ngtcp2_conn_del(conn);
        cleanup_client_crypto_context(config);
        free_certificate(client_cert);
        return -1;
    }

    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        dlog("ERROR: Failed to create client socket");
        ngtcp2_conn_del(conn);
        cleanup_client_crypto_context(config);
        free_certificate(client_cert);
        return -1;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    if (connect(sock, (struct sockaddr*)&remote_addr_sockaddr_v6, sizeof(remote_addr_sockaddr_v6)) < 0 && errno != EINPROGRESS) {
        dlog("ERROR: Failed to connect client socket to %s:%u - %s", remote_addr, port, strerror(errno));
        close(sock);
        ngtcp2_conn_del(conn);
        cleanup_client_crypto_context(config);
        free_certificate(client_cert);
        return -1;
    }

    dlog("Client socket created, bound, and connected to %s:%d", remote_addr, port);

    config->conn = conn;
    config->sock = sock;
    config->bind_address = strdup(remote_addr);
    config->port = port;
    config->ca_ctx = ca_ctx;
    config->cert = client_cert;

    dlog("Client initialization complete for %s", net_ctx->hostname);
    return 0;
}

int nexus_client_connect(nexus_client_config_t *config) {
    if (!config) return -1;
    dlog("Starting QUIC handshake");

    uint8_t buf[65535];
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    
    ngtcp2_pkt_info pi = {0};
    
    ssize_t n = ngtcp2_conn_write_pkt(config->conn, &ps.path, &pi,
                                     buf, sizeof(buf), get_timestamp());
    
    if (n > 0) {
        struct sockaddr_in6 server_addr_connect = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(config->port)
        };
        
        // Update address conversion for IPv6
        if (inet_pton(AF_INET6, config->bind_address, &server_addr_connect.sin6_addr) != 1) {
            // If not a valid IPv6 address, try to use IPv6 localhost
            if (strcmp(config->bind_address, "localhost") == 0 || strcmp(config->bind_address, "127.0.0.1") == 0) {
                dlog("Converting localhost to IPv6 ::1");
                inet_pton(AF_INET6, "::1", &server_addr_connect.sin6_addr);
            } else {
                dlog("ERROR: Invalid IPv6 address: %s", config->bind_address);
                return -1;
            }
        }

        ssize_t sent = sendto(config->sock, buf, n, 0,
                             (struct sockaddr*)&server_addr_connect, sizeof(server_addr_connect));
        
        if (sent < 0) {
            dlog("ERROR: Failed to send initial packet");
            return -1;
        }
        
        dlog("Sent initial handshake packet (%zd bytes)", sent);
    }

    return 0;
}

int nexus_client_process_events(nexus_client_config_t *config) {
    if (!config) return -1;

    uint8_t buf[65535];
    struct sockaddr_in6 server_addr_events;
    socklen_t server_len = sizeof(server_addr_events);
    
    ssize_t nread = recvfrom(config->sock, buf, sizeof(buf), 0,
                            (struct sockaddr*)&server_addr_events, &server_len);
    
    if (nread > 0) {
        ngtcp2_path path = {
            .local = { // This might need to be the client's listening address if bound
                .addrlen = 0 // Set to client's actual local addr info if available
            },
            .remote = {
                .addr = (struct sockaddr*)&server_addr_events,
                .addrlen = server_len
            }
        };
        // If client socket is explicitly bound, path.local should be set.
        // For a connected UDP socket, getsockname can get local address.

        ngtcp2_pkt_info pi = {0};
        // Assuming get_timestamp() is available and provides ngtcp2_tstamp
        int rv = ngtcp2_conn_read_pkt(config->conn, &path, &pi, buf, nread, get_timestamp());
        if (rv != 0 && rv != NGTCP2_ERR_DECRYPT) { // Decrypt error can happen during handshake
            dlog("ERROR: ngtcp2_conn_read_pkt failed: %s", ngtcp2_strerror(rv));
        }

        // Try to send any packets ngtcp2 wants to send (acks, etc.)
        uint8_t send_buf[65535];
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_pkt_info pktinfo = {0};
        
        ssize_t n = ngtcp2_conn_write_pkt(config->conn, &ps.path, &pktinfo, 
                                         send_buf, sizeof(send_buf), get_timestamp());
        if (n > 0) {
            sendto(config->sock, send_buf, n, 0, (struct sockaddr*)&server_addr_events, server_len);
        }
    }
    return 0;
}

static int client_on_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                               uint64_t offset, const uint8_t *data, size_t datalen, 
                               void *user_data, void *stream_user_data) {
    (void)conn; (void)flags; (void)offset; (void)stream_user_data;
    dlog("Client: Received %zu bytes on stream %ld", datalen, stream_id);

    if (!user_data) {
        dlog("ERROR: Client: No user_data (client_config) in on_stream_data.");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    nexus_packet_t response_packet;
    memset(&response_packet, 0, sizeof(response_packet));

    ssize_t bytes_read = deserialize_nexus_packet(data, datalen, &response_packet);
    if (bytes_read < 0) {
        dlog("ERROR: Client: Failed to deserialize NEXUS packet on stream %ld.", stream_id);
        return 0; 
    }

    dlog("Client: Deserialized packet type %d from stream %ld", response_packet.type, stream_id);

    switch (response_packet.type) {
        case PACKET_TYPE_TLD_REGISTER_RESP: {
            payload_tld_register_resp_t resp_payload;
            if (deserialize_payload_tld_register_resp(response_packet.data, response_packet.data_len, &resp_payload) < 0) {
                dlog("ERROR: Client: Failed to deserialize TLD_REGISTER_RESP payload on stream %ld.", stream_id);
            } else {
                dlog("Client: TLD Registration Response on stream %ld: Status %d, Message: '%s'", 
                        stream_id, resp_payload.status, resp_payload.message);
            }
            break;
        }
        default:
            dlog("WARNING: Client: Received unhandled packet type %d on stream %ld.", response_packet.type, stream_id);
            break;
    }
    free(response_packet.data); 
    return 0; 
}

int64_t nexus_client_send_tld_register_request(nexus_client_config_t* client_config, const char* tld_name) {
    if (!client_config || !client_config->conn || !tld_name) {
        dlog("ERROR: Client: Invalid arguments for send_tld_register_request.");
        return -1;
    }

    payload_tld_register_req_t req_payload;
    memset(&req_payload, 0, sizeof(req_payload));
    strncpy(req_payload.tld_name, tld_name, sizeof(req_payload.tld_name) - 1);

    uint8_t payload_buf[sizeof(payload_tld_register_req_t) + 1]; 
    ssize_t payload_len = serialize_payload_tld_register_req(&req_payload, payload_buf, sizeof(payload_buf));
    if (payload_len < 0) {
        dlog("ERROR: Client: Failed to serialize TLD_REGISTER_REQ payload.");
        return -2;
    }

    nexus_packet_t request_packet;
    memset(&request_packet, 0, sizeof(request_packet));
    request_packet.version = 1; 
    request_packet.type = PACKET_TYPE_TLD_REGISTER_REQ;
    request_packet.session_id = 0; 
    request_packet.data = payload_buf;
    request_packet.data_len = payload_len;

    uint8_t final_request_buf[1024]; 
    ssize_t final_request_len = serialize_nexus_packet(&request_packet, final_request_buf, sizeof(final_request_buf));
    if (final_request_len < 0) {
        dlog("ERROR: Client: Failed to serialize final NEXUS packet for TLD registration.");
        return -3;
    }

    int64_t stream_id = -1;
    int rv = ngtcp2_conn_open_bidi_stream(client_config->conn, &stream_id, NULL);
    if (rv != 0) {
        dlog("ERROR: Client: Failed to open bidirectional stream: %s", ngtcp2_strerror(rv));
        return -4;
    }
    dlog("Client: Opened bidirectional stream %ld for TLD registration.", stream_id);

    // Attempt to send the data directly using ngtcp2_conn_write_stream
    ssize_t bytes_written_or_code = 0; 

    // The 6th argument (pnum_written) will receive the number of bytes written,
    // or a negative error code if the stream is blocked or another stream-level error occurs.
    // The function itself returns 0 on success (meaning it attempted to write), 
    // or a connection-level error code.
    rv = ngtcp2_conn_write_stream(client_config->conn, NULL, NULL, 
                                 NULL, 0, &bytes_written_or_code,
                                 0, stream_id, final_request_buf, final_request_len, 
                                 get_timestamp());

    if (rv == 0) { // Call to ngtcp2_conn_write_stream was successful (attempted to process the send)
        if (bytes_written_or_code < 0) { // Stream-level error (e.g., blocked)
            if (bytes_written_or_code == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                 dlog("WARNING: Client: TLD_REGISTER_REQ for '%s' on stream %ld (%zd bytes) was blocked by ngtcp2. Data not sent. Implement queueing or retry.", 
                     tld_name, stream_id, final_request_len);
                 return -5; // Indicate data was blocked
            } else {
                dlog("ERROR: Client: Stream error while writing TLD_REGISTER_REQ to stream %ld: %s (code %zd)", 
                    stream_id, ngtcp2_strerror(bytes_written_or_code), bytes_written_or_code);
                return -7; // Generic stream write error
            }
        } else {
            dlog("Client: TLD_REGISTER_REQ for '%s' on stream %ld: %zd bytes accepted by ngtcp2 (total %zd).", 
                 tld_name, stream_id, bytes_written_or_code, final_request_len);
            if (bytes_written_or_code >= 0 && final_request_len > 0 && (size_t)bytes_written_or_code < (size_t)final_request_len) {
                 dlog("WARNING: Client: Only %zd of %zd bytes were accepted by ngtcp2 for stream %ld. Full request may not have been buffered. Implement partial send handling.", 
                      bytes_written_or_code, final_request_len, stream_id);
                 // For now, we'll return the stream_id, but this indicates a need for more robust handling
            }
        }
    } else { // Error from ngtcp2_conn_write_stream call itself (e.g. bad connection state)
        dlog("ERROR: Client: Failed to call ngtcp2_conn_write_stream for TLD_REGISTER_REQ to stream %ld: %s", stream_id, ngtcp2_strerror(rv));
        return -6;
    }
    
    // Need to make sure ngtcp2 has a chance to send this data out on the wire.
    // This is typically done by calling ngtcp2_conn_write_pkt in the event loop.
    // The nexus_client_process_events function should handle this.

    return stream_id;
}

// Add a client_initial callback to properly set up the crypto key material

static int client_initial(ngtcp2_conn *conn, void *user_data) {
    (void)conn;
    (void)user_data;
    
    dlog("Client initial callback invoked");
    
    // In a real implementation, this would initialize the crypto key material
    // For testing purposes we'll just return success
    
    return 0;
}

// Helper structure to manage stream-specific data for request/response
typedef struct {
    uint8_t* response_buffer;    // Dynamically allocated buffer for response data
    size_t response_buffer_size; // Current allocated size of response_buffer
    size_t response_data_len;    // Actual length of received response data
    int request_sent;            // Flag: 0 = not sent, 1 = sent
    int response_received;       // Flag: 0 = not received, 1 = fully received (e.g., FIN on stream)
    int error_occurred;          // Flag: non-zero if an error happened on this stream
    int64_t stream_id;           // The ID of this stream
} client_stream_context_t;

// This callback will need to be modified or a new one created to handle data for specific request/response streams.
// The existing client_on_stream_data might be too generic.
// For now, let's assume we can associate client_stream_context_t with the stream_user_data.

static int client_request_response_on_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                               uint64_t offset, const uint8_t *data, size_t datalen, 
                               void *user_data, void *stream_user_data) {
    (void)conn; (void)flags; (void)offset; (void)user_data;
    dlog("Client RR Stream %lld: Received %zu bytes", stream_id, datalen);

    if (!stream_user_data) {
        dlog("Client RR Stream %lld: ERROR - No stream_user_data context!", stream_id);
        return NGTCP2_ERR_CALLBACK_FAILURE; // Critical error
    }
    client_stream_context_t* stream_ctx = (client_stream_context_t*)stream_user_data;

    if (stream_ctx->response_received) { // Already got FIN or error
        dlog("Client RR Stream %lld: Data received after stream considered closed/errored.", stream_id);
        return 0; // Just consume it
    }

    // Append data to buffer
    if (stream_ctx->response_buffer_size < stream_ctx->response_data_len + datalen) {
        size_t new_size = stream_ctx->response_buffer_size == 0 ? datalen : stream_ctx->response_buffer_size * 2;
        if (new_size < stream_ctx->response_data_len + datalen) new_size = stream_ctx->response_data_len + datalen;
        
        uint8_t* new_buf = realloc(stream_ctx->response_buffer, new_size);
        if (!new_buf) {
            dlog("Client RR Stream %lld: ERROR - Failed to realloc response buffer.", stream_id);
            stream_ctx->error_occurred = 1;
            // No NGTCP2_ERR_CALLBACK_FAILURE here, just mark error, allow ngtcp2 to handle stream flow
            return 0; 
        }
        stream_ctx->response_buffer = new_buf;
        stream_ctx->response_buffer_size = new_size;
    }
    memcpy(stream_ctx->response_buffer + stream_ctx->response_data_len, data, datalen);
    stream_ctx->response_data_len += datalen;
    dlog("Client RR Stream %lld: Appended %zu bytes. Total buffered: %zu", stream_id, datalen, stream_ctx->response_data_len);

    return 0; // Indicate data consumed
}

static int client_request_response_on_stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, 
                                uint64_t app_error_code, void *user_data, void *stream_user_data) {
    (void)conn; (void)flags; (void)app_error_code; (void)user_data;
    dlog("Client RR Stream %lld: Closed. App Error Code: %llu", stream_id, app_error_code);
    if (stream_user_data) {
        client_stream_context_t* stream_ctx = (client_stream_context_t*)stream_user_data;
        stream_ctx->response_received = 1; // Mark as closed/complete or errored
        if (app_error_code != 0) {
            stream_ctx->error_occurred = 1; // Or specific error code
        }
        // The actual freeing of stream_ctx and its buffer will be handled by nexus_node_send_receive_packet
    }
    return 0;
}

// Main function to implement for nexus_client_api.h
// This is a simplified conceptual implementation. A robust one needs careful state management,
// especially around ngtcp2_conn_get_stream_user_data and ngtcp2_conn_set_stream_user_data if streams are multiplexed.
ssize_t nexus_node_send_receive_packet(
    nexus_node_t* node,
    const uint8_t *request_data, 
    size_t request_len, 
    uint8_t **response_data_out, 
    int timeout_ms
) {
    if (!node || !node->client_config.conn || !request_data || !response_data_out) {
        if (response_data_out) *response_data_out = NULL;
        return -1; // Invalid arguments or not connected
    }
    *response_data_out = NULL;

    client_stream_context_t stream_ctx;
    memset(&stream_ctx, 0, sizeof(client_stream_context_t));

    // 1. Open a new bi-directional stream
    int rv = ngtcp2_conn_open_bidi_stream(node->client_config.conn, &stream_ctx.stream_id, &stream_ctx);
    if (rv != 0) {
        dlog("ERROR: Failed to open bi-directional stream: %s", ngtcp2_strerror(rv));
        return -1; 
    }
    dlog("Client: Opened new bi-directional stream ID %lld for request/response", stream_ctx.stream_id);

    // Associate our context with the stream (if not already done by open_bidi_stream)
    // ngtcp2_conn_set_stream_user_data(node->client_config.conn, stream_ctx.stream_id, &stream_ctx); 
    // This seems to be done by open_bidi_stream if the last arg is non-NULL.

    // Modify client callbacks to use our new stream-specific handlers for this stream.
    // This is tricky. ngtcp2 uses global callbacks. For stream-specific logic, 
    // the callbacks must inspect stream_id or stream_user_data to dispatch.
    // For this example, let's assume the global callbacks (client_on_stream_data, client_on_stream_close)
    // are modified to check if stream_user_data is a client_stream_context_t and act accordingly, or we use a different set of callbacks.
    // This part of design is CRITICAL. For now, we'll assume the callbacks are set up to use stream_user_data.
    // Ideally, the main nexus_client_process_events would use the general callbacks, and those callbacks
    // would check stream_user_data to see if it's a special context like client_stream_context_t.
    // If so, they'd call client_request_response_on_stream_data or client_request_response_on_stream_close.

    // 2. Send the request_data on this stream
    // Need to queue the data to be written by ngtcp2_conn_writev_stream in nexus_client_process_events
    // This part is simplified. A real implementation would add to a send buffer for the stream.
    // ngtcp2_vec datav = { (uint8_t*)request_data, request_len };
    // rv = ngtcp2_conn_writev_stream(node->client_config.conn, NULL, NULL, NULL, 0, NULL, 0, stream_ctx.stream_id, &datav, 1, ngtcp2_conn_get_ts(node->client_config.conn));
    // A more common pattern is to use ngtcp2_conn_send_early_data or ngtcp2_conn_write_stream and let the event loop handle it.
    // For simplicity of this API function, let's try to send it directly and then rely on the event loop.
    
    // This function would buffer data and ngtcp2_client_process_events() would send it.
    ssize_t stream_data_consumed = 0; // For ngtcp2_conn_write_stream's pnum_written argument
    rv = ngtcp2_conn_write_stream(node->client_config.conn, NULL, NULL, NULL, 0, &stream_data_consumed, NGTCP2_STREAM_DATA_FLAG_NONE, stream_ctx.stream_id, (uint8_t*)request_data, request_len, get_timestamp());
    if (rv != 0 && rv != NGTCP2_ERR_STREAM_DATA_BLOCKED) {
        dlog("ERROR: Failed to write initial stream data for request: %s (%d)", ngtcp2_strerror(rv), rv);
        // We might not want to close the stream here, ngtcp2 might handle it.
        // Cleanup stream_ctx? No, that belongs to ngtcp2 until stream_close callback.
        return -1;
    }
    stream_ctx.request_sent = 1;
    dlog("Client Stream %lld: Queued %zu bytes for sending.", stream_ctx.stream_id, request_len);

    // 3. Loop to process events and check for response / timeout
    struct timeval start_time, current_time;
    gettimeofday(&start_time, NULL);
    long elapsed_ms = 0;

    while (!stream_ctx.response_received && !stream_ctx.error_occurred && elapsed_ms < timeout_ms) {
        // Process client events (this drives sending and receiving)
        // This assumes nexus_client_process_events is being called elsewhere too, 
        // or this function takes over event processing for its duration.
        // For a synchronous API like this, it must drive the event loop.
        if (nexus_client_process_events(&node->client_config) < 0) {
             dlog("ERROR: Client Stream %lld: Error in nexus_client_process_events.", stream_ctx.stream_id);
             stream_ctx.error_occurred = 1; // Mark error to exit loop
             break;
        }

        // Check for timeout
        gettimeofday(&current_time, NULL);
        elapsed_ms = (current_time.tv_sec - start_time.tv_sec) * 1000 +
                       (current_time.tv_usec - start_time.tv_usec) / 1000;
        
        if (stream_ctx.response_received || stream_ctx.error_occurred) break;

        // Small sleep to prevent busy-waiting if no events are immediately available
        // but allow quick reaction. The actual timing depends on ngtcp2_conn_get_expiry.
        usleep(10000); // 10ms - adjust as needed
    }

    if (stream_ctx.error_occurred) {
        dlog("Client Stream %lld: Error occurred during request/response.", stream_ctx.stream_id);
        if (stream_ctx.response_buffer) free(stream_ctx.response_buffer);
        // Stream context itself will be cleaned up by ngtcp2 if ngtcp2_conn_open_bidi_stream used it directly.
        // If we manually set it with ngtcp2_conn_set_stream_user_data, we might need to clear it in stream_close.
        return -1; // General error
    }

    if (!stream_ctx.response_received) { // Timeout
        dlog("Client Stream %lld: Timeout waiting for response (%ld ms).", stream_ctx.stream_id, elapsed_ms);
        if (stream_ctx.response_buffer) free(stream_ctx.response_buffer);
        return -2; // Timeout error
    }

    // 4. Response received successfully
    if (stream_ctx.response_data_len > 0 && stream_ctx.response_buffer) {
        *response_data_out = malloc(stream_ctx.response_data_len);
        if (!*response_data_out) {
            dlog("Client Stream %lld: ERROR - Failed to allocate memory for final response_data_out.", stream_ctx.stream_id);
            free(stream_ctx.response_buffer);
            return -3; // Memory allocation failure
        }
        memcpy(*response_data_out, stream_ctx.response_buffer, stream_ctx.response_data_len);
        free(stream_ctx.response_buffer); // Free the temporary buffer
        return (ssize_t)stream_ctx.response_data_len;
    } else {
        // No data in response, but stream closed successfully without error (e.g. empty response)
        if (stream_ctx.response_buffer) free(stream_ctx.response_buffer);
        *response_data_out = NULL;
        return 0; // Success, but no data
    }
}

// Ensure existing functions like init_nexus_client, nexus_client_connect, nexus_client_process_events are compatible
// with the stream_user_data mechanism if this new send/receive is to coexist.
// Specifically, the global callbacks in init_nexus_client (callbacks.recv_stream_data, callbacks.stream_close)
// would need to be aware of client_stream_context_t in stream_user_data.

