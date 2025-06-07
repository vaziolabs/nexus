#include "../include/nexus_client.h"
#include "../include/nexus_node.h"
#include "../include/debug.h"
#include "../include/packet_protocol.h"
#include "../include/dns_types.h"
#include "../include/certificate_authority.h"
#include "../include/system.h"
#include "../include/nexus_client_api.h"
#include "../include/utils.h"           // For get_timestamp

// System includes first
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdarg.h>       // For va_list in log wrapper
#include <unistd.h>       // For close() and usleep()

// OpenSSL headers
#include <openssl/ssl.h>                // For SSL_CTX_new, SSL_new etc.
#include <openssl/err.h>
#include <openssl/rand.h>

// ngtcp2 headers - include main header first, then crypto headers
#include <ngtcp2/ngtcp2.h> 
#include <ngtcp2/ngtcp2_crypto.h>         // For generic crypto helper callbacks
#include <ngtcp2/ngtcp2_crypto_ossl.h>    // For OpenSSL (vanilla) specific helpers
#include "../include/ngtcp2_compat.h"       // Compatibility layer for ngtcp2 v1.12.0

// OpenSSL QUIC header after ngtcp2 to avoid conflicts
#include <openssl/quic.h>               // For OSSL_ENCRYPTION_LEVEL, SSL_set_quic_transport_params etc.

// Forward declarations of other static functions if client_rand_callback_wrapper is moved very early
static int client_on_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                               uint64_t offset, const uint8_t *data, size_t datalen, 
                               void *user_data, void *stream_user_data);
static int client_on_stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, 
                                uint64_t app_error_code, void *user_data, void *stream_user_data);
static int client_on_stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data);
static int on_handshake_completed(ngtcp2_conn *conn, void *user_data);
static int client_recv_retry(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data);
static int client_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                     uint8_t *token, size_t cidlen,
                                     void *user_data);
static int client_update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
                           ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                           ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                           const uint8_t *current_rx_secret, const uint8_t *current_tx_secret,
                           size_t secretlen, void *user_data);
static void client_delete_crypto_aead_ctx(ngtcp2_conn *conn, ngtcp2_crypto_aead_ctx *aead_ctx, void *user_data);
static void client_delete_crypto_cipher_ctx(ngtcp2_conn *conn, ngtcp2_crypto_cipher_ctx *cipher_ctx, void *user_data);
static int init_client_crypto_context(nexus_client_config_t *config);
static void cleanup_client_crypto_context(nexus_client_config_t *config);
static void client_log_wrapper(void *user_data, const char *format, ...);
static int client_get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data, void *user_data);
static int client_acked_stream_data_offset(ngtcp2_conn *conn,
                                           int64_t stream_id, uint64_t offset,
                                           uint64_t datalen, void *user_data,
                                           void *stream_user_data);
static int client_stream_reset(ngtcp2_conn *conn, int64_t stream_id,
                               uint64_t final_size, uint64_t app_error_code,
                               void *user_data, void *stream_user_data);

void nexus_client_cleanup(nexus_client_config_t *config);

// Function to get ngtcp2_conn* from ngtcp2_crypto_conn_ref
static ngtcp2_conn *client_get_conn_from_ref(ngtcp2_crypto_conn_ref *conn_ref) {
    if (conn_ref && conn_ref->user_data) {
        nexus_client_config_t *config = (nexus_client_config_t *)conn_ref->user_data;
        return config->conn;
    }
    return NULL;
}

// Custom rand callback wrapper for ngtcp2_callbacks.rand
static void client_rand_callback_wrapper(uint8_t *dest, size_t destlen,
                                    const ngtcp2_rand_ctx *rand_ctx) {
    (void)rand_ctx;
    if (RAND_bytes(dest, destlen) != 1) {
        dlog("CRITICAL: client_rand_callback_wrapper: RAND_bytes failed!");
        memset(dest, 0, destlen);
    }
}

static int client_on_stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, 
                                uint64_t app_error_code, void *user_data, void *stream_user_data) {
    (void)conn; (void)flags; (void)app_error_code; (void)user_data; (void)stream_user_data;
    dlog("Client: Stream %ld closed.", stream_id);
    return 0;
}

static int client_on_stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
    (void)conn;
    (void)user_data;
    dlog("Client: Stream %ld opened by server (unexpected for client-initiated bidi).", stream_id);
    return 0;
}

static int on_handshake_completed(ngtcp2_conn *conn, void *user_data) {
    (void)conn;
    nexus_client_config_t *config = (nexus_client_config_t *)user_data;
    if (config) {
        config->handshake_completed = 1;
    }
    dlog("Client handshake completed");
    return 0;
}

static int client_recv_retry(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data) {
    (void)conn; (void)hd; (void)user_data; 
    dlog("Client received retry packet");
    return 0;
}

// Initialize the crypto context for TLS
static int init_client_crypto_context(nexus_client_config_t *config) {
    if (!config) return -1;
    
    config->crypto_ctx = malloc(sizeof(nexus_crypto_ctx));
    if (!config->crypto_ctx) {
        dlog("ERROR: Failed to allocate crypto context");
        return -1;
    }
    memset(config->crypto_ctx, 0, sizeof(nexus_crypto_ctx));
    
    // Initialize conn_ref
    config->crypto_ctx->conn_ref.get_conn = client_get_conn_from_ref;
    config->crypto_ctx->conn_ref.user_data = config; // conn_ref's user_data points to the main client_config

    config->crypto_ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!config->crypto_ctx->ssl_ctx) {
        dlog("ERROR: Failed to create SSL context: %s", ERR_error_string(ERR_get_error(), NULL));
        goto err_ssl_ctx_new;
    }
    
    // Standard OpenSSL 3+ QUIC setup:
    SSL_CTX_set_min_proto_version(config->crypto_ctx->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(config->crypto_ctx->ssl_ctx, TLS1_3_VERSION);
    // ngtcp2_crypto_ossl_configure_client_session will handle SSL_CTX_set_quic_method for SSL*

    config->crypto_ctx->ssl = SSL_new(config->crypto_ctx->ssl_ctx);
    if (!config->crypto_ctx->ssl) {
        dlog("ERROR: Failed to create SSL object: %s", ERR_error_string(ERR_get_error(), NULL));
        goto err_configure_ctx;
    }
    
    // Configure SSL object for QUIC client session using ngtcp2 OSSL helper
    if (ngtcp2_crypto_ossl_configure_client_session(config->crypto_ctx->ssl) != 0) {
        dlog("ERROR: ngtcp2_crypto_ossl_configure_client_session failed: %s", ERR_error_string(ERR_get_error(), NULL));
        goto err_ssl_new;
    }

    // Set app data for OpenSSL QUIC callbacks to find ngtcp2_crypto_conn_ref
    SSL_set_app_data(config->crypto_ctx->ssl, &config->crypto_ctx->conn_ref); 
    SSL_set_connect_state(config->crypto_ctx->ssl);

    const unsigned char alpn[] = "\x02h3"; // Example ALPN
    if (SSL_set_alpn_protos(config->crypto_ctx->ssl, alpn, sizeof(alpn) -1) != 0) {
        dlog("ERROR: Failed to set ALPN: %s", ERR_error_string(ERR_get_error(), NULL));
        // Non-fatal for now
    }

    if (config->bind_address && SSL_set_tlsext_host_name(config->crypto_ctx->ssl, config->bind_address) != 1) {
        dlog("Warning: Failed to set SNI: %s", ERR_error_string(ERR_get_error(), NULL));
        // Non-fatal
    }
    
    uint8_t paramsbuf[256];
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    
    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 100;
    params.initial_max_data = 1 * 1024 * 1024;
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.original_dcid_present = 0; 
    params.active_connection_id_limit = 8;
    
    ssize_t nwrite = ngtcp2_transport_params_encode(paramsbuf, sizeof(paramsbuf), &params);
    if (nwrite < 0) {
        dlog("ERROR: Failed to encode transport parameters: %s", ngtcp2_strerror((int)nwrite));
        goto err_ssl_new;
    }
    
    // Use SSL_set_quic_tls_transport_params as indicated by ngtcp2's OpenSSL integration approach
    if (SSL_set_quic_tls_transport_params(config->crypto_ctx->ssl, paramsbuf, (size_t)nwrite) != 1) {
        dlog("ERROR: Failed to set QUIC TLS transport parameters on SSL object: %s", ERR_error_string(ERR_get_error(), NULL));
        goto err_ssl_new;
    }
    
    return 0;

err_ssl_new:
    SSL_free(config->crypto_ctx->ssl);
err_configure_ctx:
    SSL_CTX_free(config->crypto_ctx->ssl_ctx);
err_ssl_ctx_new:
    free(config->crypto_ctx);
    config->crypto_ctx = NULL;
    return -1;
}

static void cleanup_client_crypto_context(nexus_client_config_t *config) {
    if (!config || !config->crypto_ctx) return;
    if (config->crypto_ctx->ssl) SSL_free(config->crypto_ctx->ssl);
    if (config->crypto_ctx->ssl_ctx) SSL_CTX_free(config->crypto_ctx->ssl_ctx);
    free(config->crypto_ctx);
    config->crypto_ctx = NULL;
}

int init_nexus_client(network_context_t *ctx, const char *server_addr, uint16_t server_port, nexus_client_config_t *config) {
    if (!ctx || !server_addr || !config) {
        return -1;
    }
    
    dlog("Initializing client for %s:%d", server_addr, server_port);
    
    // Store server address
    if (config->bind_address) {
        free(config->bind_address);
    }
    config->bind_address = strdup(server_addr);
    config->port = server_port;
    
    // Create IPv6 UDP socket
    config->sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (config->sock < 0) {
        perror("socket");
        return -1;
    }
    
    // Configure socket for non-blocking operation
    int flags = fcntl(config->sock, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl(F_GETFL)");
        close(config->sock);
        return -1;
    }
    if (fcntl(config->sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(F_SETFL)");
        close(config->sock);
        return -1;
    }
    
    // Bind to a specific local port if specified in the config
    if (ctx->client_port > 0) {
        struct sockaddr_in6 local_addr = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(ctx->client_port),
            .sin6_addr = in6addr_any
        };
        
        if (bind(config->sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) != 0) {
            perror("bind");
            // Non-fatal, we'll get a random port
            dlog("Warning: Failed to bind to client port %d", ctx->client_port);
        } else {
            dlog("Successfully bound to client port %d", ctx->client_port);
        }
    }
    
    // Set up client settings for QUIC
    ngtcp2_settings_default(&config->settings);  // Initialize all default settings first
    config->settings.initial_ts = get_timestamp();
    config->settings.log_printf = NULL;
    
    // Set up QUIC callbacks
    config->callbacks.client_initial = ngtcp2_crypto_client_initial_cb;  // Required for client connections
    config->callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;  // Required for crypto handshake
    config->callbacks.encrypt = ngtcp2_crypto_encrypt_cb;  // Required for encryption
    config->callbacks.decrypt = ngtcp2_crypto_decrypt_cb;  // Required for decryption
    config->callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;  // Required for header protection
    config->callbacks.update_key = ngtcp2_crypto_update_key_cb;  // Required for key updates
    config->callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;  // Required for cleanup
    config->callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;  // Required for cleanup
    config->callbacks.recv_stream_data = client_on_stream_data;
    config->callbacks.acked_stream_data_offset = client_acked_stream_data_offset;
    config->callbacks.stream_open = client_on_stream_open;
    config->callbacks.stream_close = client_on_stream_close;
    config->callbacks.rand = client_rand_callback_wrapper;
    config->callbacks.get_new_connection_id = client_get_new_connection_id;
    config->callbacks.stream_reset = client_stream_reset;
    config->callbacks.handshake_completed = on_handshake_completed;
    config->callbacks.recv_retry = client_recv_retry;
    config->callbacks.get_path_challenge_data = client_get_path_challenge_data;
    
    // Initialize client parameters
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 100;
    params.initial_max_data = 1 * 1024 * 1024;
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    
    // Generate random source and destination connection IDs
    uint8_t scid_buf[32], dcid_buf[32];
    ngtcp2_cid scid, dcid;
    
    if (RAND_bytes(scid_buf, 32) != 1) {
        return -1;
    }
    if (RAND_bytes(dcid_buf, 32) != 1) {
        return -1;
    }
    
    ngtcp2_cid_init(&scid, scid_buf, 16);
    ngtcp2_cid_init(&dcid, dcid_buf, 16);
    
    // Set up path information for the client
    struct sockaddr_in6 path_addr = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(server_port)
    };
    
    if (inet_pton(AF_INET6, server_addr, &path_addr.sin6_addr) != 1) {
        if (strcmp(server_addr, "localhost") == 0 || strcmp(server_addr, "127.0.0.1") == 0) {
            inet_pton(AF_INET6, "::1", &path_addr.sin6_addr);
            dlog("Using IPv6 ::1 for localhost");
        } else {
            dlog("ERROR: Invalid IPv6 address: %s", server_addr);
            close(config->sock);
            return -1;
        }
    }
    
    ngtcp2_path path = {
        .local = {
            .addrlen = sizeof(struct sockaddr_in6),
            .addr = (struct sockaddr *)&path_addr
        },
        .remote = {
            .addrlen = sizeof(struct sockaddr_in6),
            .addr = (struct sockaddr *)&path_addr
        }
    };
    
    // Create QUIC client connection
    int ret = ngtcp2_conn_client_new(&config->conn, &dcid, &scid, &path,
                                    NGTCP2_PROTO_VER_V1, &config->callbacks,
                                    &config->settings, &params, NULL, config);
    
    if (ret != 0) {
        dlog("ERROR: Failed to create QUIC client connection: %s", ngtcp2_strerror(ret));
        close(config->sock);
        return -1;
    }
    
    // Initialize TLS context for client
    if (init_client_crypto_context(config) != 0) {
        dlog("ERROR: Failed to initialize client crypto context");
        ngtcp2_conn_del(config->conn);
        close(config->sock);
        return -1;
    }
    
    // Connect the SSL context to the ngtcp2 connection
    if (!config->crypto_ctx || !config->crypto_ctx->ssl) {
        dlog("ERROR: Invalid SSL context before setting TLS native handle");
        ngtcp2_conn_del(config->conn);
        close(config->sock);
        return -1;
    }
    
    dlog("Setting TLS native handle with SSL context %p", config->crypto_ctx->ssl);
    ngtcp2_conn_set_tls_native_handle(config->conn, config->crypto_ctx->ssl);
    
    // Initialize handshake state
    config->handshake_completed = 0;
    
    dlog("Client initialization complete for %s", server_addr);
    
    // Start the connection process
    if (nexus_client_connect(config) != 0) {
        dlog("ERROR: Failed to start client connection");
        nexus_client_cleanup(config);
        return -1;
    }
    
    dlog("Client connection initiated");
    
    return 0;
}

// Establish connection to remote server
int nexus_client_connect(nexus_client_config_t *config) {
    if (!config) return -1;
    
    // Print client socket info for debugging
    char local_ip[INET6_ADDRSTRLEN];
    struct sockaddr_in6 local_addr;
    socklen_t local_len = sizeof(local_addr);
    
    if (getsockname(config->sock, (struct sockaddr*)&local_addr, &local_len) == 0) {
        inet_ntop(AF_INET6, &local_addr.sin6_addr, local_ip, sizeof(local_ip));
        dlog("Client socket: local [%s]:%d, connecting to server port %d, fd=%d", 
             local_ip, ntohs(local_addr.sin6_port), config->port, config->sock);
    } else {
        dlog("Failed to get client socket name: %s", strerror(errno));
    }
    
    dlog("Starting QUIC handshake");

    // Generate and send initial packet
    uint8_t buf[65535];
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    
    ngtcp2_pkt_info pi = {0};
    
    // Try to generate initial packet
    ssize_t n = ngtcp2_conn_write_pkt(config->conn, &ps.path, &pi,
                                     buf, sizeof(buf), get_timestamp());
    
    if (n > 0) {
        // Set up destination address
        struct sockaddr_in6 server_addr = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(config->port)
        };
        
        // Convert hostname to IP address if needed
        if (inet_pton(AF_INET6, config->bind_address, &server_addr.sin6_addr) != 1) {
            if (strcmp(config->bind_address, "localhost") == 0 || strcmp(config->bind_address, "127.0.0.1") == 0) {
                inet_pton(AF_INET6, "::1", &server_addr.sin6_addr);
                dlog("Using IPv6 ::1 for localhost");
            } else {
                dlog("ERROR: Invalid IPv6 address: %s", config->bind_address);
                return -1;
            }
        }
        
        char server_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &server_addr.sin6_addr, server_ip, sizeof(server_ip));
        dlog("Client sending initial packet to server [%s]:%d", 
             server_ip, ntohs(server_addr.sin6_port));

        // Print first few bytes of the packet for debugging
        if (n >= 8) {
            dlog("Initial packet: %02X %02X %02X %02X %02X %02X %02X %02X", 
                 buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
        }

        // Send the packet
        ssize_t sent = sendto(config->sock, buf, n, 0,
                             (struct sockaddr*)&server_addr, sizeof(server_addr));
        
        if (sent < 0) {
            dlog("ERROR: Failed to send initial packet: %s", strerror(errno));
            return -1;
        }
        dlog("Sent initial handshake packet (%zd bytes)", sent);
    } else if (n < 0) {
        dlog("ERROR: Failed to generate initial packet: %s", ngtcp2_strerror((int)n));
        return -1;
    }

    return 0;
}

int nexus_client_process_events(nexus_client_config_t *config) {
    if (!config || config->sock < 0) {
        return -1;
    }
    
    uint8_t buf[65535];
    struct sockaddr_in6 server_addr_events;
    socklen_t server_len = sizeof(server_addr_events);
    
    ssize_t nread = recvfrom(config->sock, buf, sizeof(buf), 0,
                            (struct sockaddr*)&server_addr_events, &server_len);
    
    if (nread > 0) {
        ngtcp2_path path = { {0}, {0}, NULL }; // Initialize with NULL user_data
        path.remote.addr = (struct sockaddr*)&server_addr_events;
        path.remote.addrlen = server_len;

        ngtcp2_pkt_info pi = {0};
        int rv = ngtcp2_conn_read_pkt(config->conn, &path, &pi, buf, nread, get_timestamp());
        if (rv != 0 && rv != NGTCP2_ERR_DECRYPT) { 
            dlog("ERROR: ngtcp2_conn_read_pkt failed: %s", ngtcp2_strerror(rv));
        }

        uint8_t send_buf[65535];
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_pkt_info pktinfo = {0};
        
        ssize_t n = ngtcp2_conn_write_pkt(config->conn, &ps.path, &pktinfo, 
                                         send_buf, sizeof(send_buf), get_timestamp());
        if (n > 0) {
            sendto(config->sock, send_buf, n, 0, (struct sockaddr*)&server_addr_events, server_len);
        } else if (n < 0 && n != NGTCP2_ERR_NOBUF && n != NGTCP2_ERR_CALLBACK_FAILURE) {
            dlog("ERROR: ngtcp2_conn_write_pkt after read failed: %s", ngtcp2_strerror((int)n));
        }
    } else if (nread < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        dlog("ERROR: recvfrom failed: %s", strerror(errno));
        return -1; 
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
    
    ssize_t bytes_written_or_code = 0; 
    rv = ngtcp2_conn_write_stream(client_config->conn, NULL, NULL, 
                                 NULL, 0, &bytes_written_or_code,
                                 NGTCP2_STREAM_DATA_FLAG_FIN, stream_id, final_request_buf, final_request_len, 
                                 get_timestamp());

    if (rv == 0) { 
        if (bytes_written_or_code < 0) { 
            if (bytes_written_or_code == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                 dlog("WARNING: Client: TLD_REGISTER_REQ for '%s' on stream %ld (%zd bytes) was blocked. Data not sent. Implement queueing.", 
                     tld_name, stream_id, final_request_len);
                 return -5; 
            } else {
                dlog("ERROR: Client: Stream error while writing TLD_REGISTER_REQ to stream %ld: %s (code %zd)", 
                    stream_id, ngtcp2_strerror(bytes_written_or_code), bytes_written_or_code);
                return -7; 
            }
        } else {
            dlog("Client: TLD_REGISTER_REQ for '%s' on stream %ld: %zd bytes accepted by ngtcp2 (total %zd).", 
                 tld_name, stream_id, bytes_written_or_code, final_request_len);
            if ((size_t)bytes_written_or_code < (size_t)final_request_len) {
                 dlog("WARNING: Client: Only %zd of %zd bytes were accepted by ngtcp2. Implement partial send handling.", 
                      bytes_written_or_code, final_request_len);
            }
        }
    } else { 
        dlog("ERROR: Client: Failed to call ngtcp2_conn_write_stream for TLD_REGISTER_REQ: %s", ngtcp2_strerror(rv));
        return -6;
    }
    return stream_id;
}

typedef struct {
    uint8_t* response_buffer;   
    size_t response_buffer_size; 
    size_t response_data_len;    
    int request_sent;            
    int response_received;       
    int error_occurred;          
    int64_t stream_id;           
} client_stream_context_t;

ssize_t nexus_node_send_receive_packet(
    nexus_node_t* node,
    const uint8_t *request_data, 
    size_t request_len, 
    uint8_t **response_data_out, 
    int timeout_ms
) {
    if (!node || !node->client_config.conn || !request_data || !response_data_out) {
        if (response_data_out) *response_data_out = NULL;
        return -1; 
    }
    *response_data_out = NULL;

    client_stream_context_t stream_ctx; 
    memset(&stream_ctx, 0, sizeof(client_stream_context_t));

    int rv = ngtcp2_conn_open_bidi_stream(node->client_config.conn, &stream_ctx.stream_id, NULL );
    if (rv != 0) {
        dlog("ERROR: Failed to open bi-directional stream: %s", ngtcp2_strerror(rv));
        return -1; 
    }
    dlog("Client: Opened new bi-directional stream ID %lld for request/response", stream_ctx.stream_id);
    
    ssize_t stream_data_consumed = 0; 
    rv = ngtcp2_conn_write_stream(node->client_config.conn, NULL, NULL, NULL, 0, &stream_data_consumed, NGTCP2_STREAM_DATA_FLAG_FIN, stream_ctx.stream_id, (uint8_t*)request_data, request_len, get_timestamp());
    if (rv != 0 && rv != NGTCP2_ERR_STREAM_DATA_BLOCKED) { 
        dlog("ERROR: Failed to write initial stream data for request: %s (%d)", ngtcp2_strerror(rv), rv);
        return -1;
    }
     if (rv == NGTCP2_ERR_STREAM_DATA_BLOCKED || (stream_data_consumed >=0 && (size_t)stream_data_consumed < request_len)) {
        dlog("WARNING: Stream %lld data send blocked or partial (%zd/%zu). Synchronous send incomplete.", stream_ctx.stream_id, stream_data_consumed, request_len);
    }
    stream_ctx.request_sent = 1;
    dlog("Client Stream %lld: Queued/Sent %zd of %zu bytes for sending.", stream_ctx.stream_id, stream_data_consumed > 0 ? stream_data_consumed : 0, request_len);

    if (nexus_client_process_events(&node->client_config) < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
         dlog("ERROR: Client Stream %lld: Error in nexus_client_process_events after send.", stream_ctx.stream_id);
    }

    struct timeval start_time, current_time;
    gettimeofday(&start_time, NULL);
    long elapsed_ms = 0;

    while (!stream_ctx.response_received && !stream_ctx.error_occurred && elapsed_ms < timeout_ms) {
        if (nexus_client_process_events(&node->client_config) < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
             dlog("ERROR: Client Stream %lld: Error in nexus_client_process_events during wait.", stream_ctx.stream_id);
             stream_ctx.error_occurred = 1; 
             break;
        }

        gettimeofday(&current_time, NULL);
        elapsed_ms = (current_time.tv_sec - start_time.tv_sec) * 1000 +
                       (current_time.tv_usec - start_time.tv_usec) / 1000;
        
        if (stream_ctx.response_received || stream_ctx.error_occurred) break;
        usleep(10000); 
    }

    if (stream_ctx.error_occurred) {
        dlog("Client Stream %lld: Error occurred during request/response.", stream_ctx.stream_id);
        if (stream_ctx.response_buffer) free(stream_ctx.response_buffer);
        return -1; 
    }

    if (!stream_ctx.response_received) { 
        dlog("Client Stream %lld: Timeout waiting for response (%ld ms).", stream_ctx.stream_id, elapsed_ms);
        if (stream_ctx.response_buffer) free(stream_ctx.response_buffer);
        // TODO: Fix ngtcp2_conn_shutdown_stream API compatibility
        // ngtcp2_conn_shutdown_stream(node->client_config.conn, 0, stream_ctx.stream_id, NGTCP2_INTERNAL_ERROR);
        return -2; 
    }

    if (stream_ctx.response_data_len > 0 && stream_ctx.response_buffer) {
        *response_data_out = malloc(stream_ctx.response_data_len);
        if (!*response_data_out) {
            dlog("Client Stream %lld: ERROR - Failed to allocate for final response_data_out.", stream_ctx.stream_id);
            free(stream_ctx.response_buffer);
            return -3; 
        }
        memcpy(*response_data_out, stream_ctx.response_buffer, stream_ctx.response_data_len);
        free(stream_ctx.response_buffer); 
        return (ssize_t)stream_ctx.response_data_len;
    } else {
        if (stream_ctx.response_buffer) free(stream_ctx.response_buffer);
        *response_data_out = NULL;
        return 0; 
    }
}

static void client_log_wrapper(void *user_data, const char *format, ...) {
    (void)user_data;
    va_list args;
    fprintf(stderr, "[ngtcp2_client_log] ");
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
}

// Add this function after client_rand_callback_wrapper
static int client_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                      uint8_t *token, size_t cidlen,
                                      void *user_data) {
    (void)conn;
    (void)user_data;
    
    if (RAND_bytes(cid->data, cidlen) != 1) {
        dlog("CRITICAL: client_get_new_connection_id: RAND_bytes failed!");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    
    cid->datalen = cidlen;
    
    if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
        dlog("CRITICAL: client_get_new_connection_id: RAND_bytes for token failed!");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    
    return 0;
}

// Add this function after client_get_new_connection_id
static int client_update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
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
    dlog("Client update_key callback called (stub implementation)");
    return 0;
}

// Add these functions after client_update_key
static void client_delete_crypto_aead_ctx(ngtcp2_conn *conn, ngtcp2_crypto_aead_ctx *aead_ctx, void *user_data) {
    (void)conn;
    (void)user_data;
    if (aead_ctx) {
        // In a real implementation, this would free the aead_ctx
        // For now, just a stub to satisfy the API
        dlog("client_delete_crypto_aead_ctx called (stub implementation)");
    }
}

static void client_delete_crypto_cipher_ctx(ngtcp2_conn *conn, ngtcp2_crypto_cipher_ctx *cipher_ctx, void *user_data) {
    (void)conn;
    (void)user_data;
    if (cipher_ctx) {
        // In a real implementation, this would free the cipher_ctx
        // For now, just a stub to satisfy the API
        dlog("client_delete_crypto_cipher_ctx called (stub implementation)");
    }
}

// Add the missing path challenge data callback
static int client_get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data, void *user_data) {
    (void)conn;
    (void)user_data;
    
    // Generate random data for path challenge
    if (RAND_bytes(data, NGTCP2_PATH_CHALLENGE_DATALEN) != 1) {
        dlog("ERROR: Failed to generate random data for path challenge");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    
    return 0;
}

// Function to send a raw NEXUS packet and receive a response
// THIS IS A STUB IMPLEMENTATION
ssize_t nexus_client_send_receive_raw_packet(
    const char *server_address, 
    uint16_t server_port, 
    const uint8_t *request_packet_data, 
    size_t request_packet_len, 
    uint8_t **response_packet_data
) {
    dlog("STUB: nexus_client_send_receive_raw_packet called for server %s:%u", server_address, server_port);
    dlog("STUB: Would send %zu bytes.", request_packet_len);

    // Suppress unused parameter warnings for the stub
    (void)request_packet_data;

    if (response_packet_data) {
        *response_packet_data = NULL; // Ensure it's NULL if we fail
    }

    // Simulate failure: no response received
    fprintf(stderr, "STUB: Simulating failure in nexus_client_send_receive_raw_packet. No response.\n");
    return -1; 
}

static int client_acked_stream_data_offset(ngtcp2_conn *conn,
                                           int64_t stream_id, uint64_t offset,
                                           uint64_t datalen, void *user_data,
                                           void *stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)offset;
  (void)datalen;
  (void)user_data;
  (void)stream_user_data;
  return 0;
}

static int client_stream_reset(ngtcp2_conn *conn, int64_t stream_id,
                               uint64_t final_size, uint64_t app_error_code,
                               void *user_data, void *stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)final_size;
  (void)app_error_code;
  (void)user_data;
  (void)stream_user_data;
  return 0;
}

void nexus_client_cleanup(nexus_client_config_t *config) {
    if (!config) {
        return;
    }

    if (config->conn) {
        ngtcp2_conn_del(config->conn);
        config->conn = NULL;
    }

    if (config->sock >= 0) {
        close(config->sock);
        config->sock = -1;
    }

    cleanup_client_crypto_context(config);

    if (config->bind_address) {
        free(config->bind_address);
        config->bind_address = NULL;
    }
}

