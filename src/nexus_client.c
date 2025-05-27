#include "../include/nexus_client.h"
#include "../include/nexus_node.h"
#include "../include/debug.h"
#include "../include/packet_protocol.h"
#include "../include/dns_types.h"
#include "../include/certificate_authority.h"
#include "../include/system.h"
#include "../include/nexus_client_api.h"
#include "../include/utils.h"           // For get_timestamp

// OpenSSL QUIC related headers first
#include <openssl/ssl.h>                // For SSL_CTX_new, SSL_new etc.
#include <openssl/quic.h>               // For OSSL_ENCRYPTION_LEVEL, SSL_set_quic_transport_params etc.
#include <openssl/err.h>
#include <openssl/rand.h>

// Then ngtcp2 headers
#include <ngtcp2/ngtcp2.h> 
#include <ngtcp2/ngtcp2_crypto.h>         // For generic crypto helper callbacks
#include <ngtcp2/ngtcp2_crypto_ossl.h>    // For OpenSSL (vanilla) specific helpers

// Project specific includes (should come after system/lib headers generally)
#include "../include/nexus_client.h"
#include "../include/nexus_node.h"
#include "../include/debug.h"
#include "../include/packet_protocol.h"
#include "../include/dns_types.h"
#include "../include/certificate_authority.h"
#include "../include/system.h"
#include "../include/nexus_client_api.h"
#include "../include/utils.h"           // For get_timestamp

// Other system headers
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

int init_nexus_client(network_context_t *net_ctx, const char *remote_addr, 
                    uint16_t port, nexus_client_config_t *config) {
    if (!remote_addr || !net_ctx || !config) return -1;
    dlog("Initializing client for %s:%u", remote_addr, port);

    memset(config, 0, sizeof(nexus_client_config_t));
    config->net_ctx = net_ctx;
    config->next_stream_id = 0; 

    ca_context_t *ca_ctx = NULL;
    if (init_certificate_authority(net_ctx, &ca_ctx) != 0) {
        dlog("ERROR: Failed to initialize certificate authority for client");
        return -1;
    }

    nexus_cert_t *client_cert = NULL;
    if (handle_cert_request(ca_ctx, net_ctx->hostname, &client_cert) != 0) {
        dlog("ERROR: Failed to obtain client certificate for client");
        // Consider freeing ca_ctx if it was successfully initialized
        return -1;
    }
    config->ca_ctx = ca_ctx; 
    config->cert = client_cert;

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.log_printf = client_log_wrapper; 
    settings.initial_ts = get_timestamp();    
    // settings.max_active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT; // This is a transport param now
    config->settings = settings; 

    if (init_client_crypto_context(config) != 0) {
        dlog("ERROR: Failed to initialize client crypto context");
        goto err_crypto_init;
    }

    ngtcp2_callbacks callbacks = {0};
    callbacks.handshake_completed = on_handshake_completed;
    callbacks.recv_stream_data = client_on_stream_data;
    callbacks.stream_close = client_on_stream_close;
    callbacks.stream_open = client_on_stream_open;
    callbacks.recv_retry = client_recv_retry;
    
    // Attempt to set the core crypto callbacks. If these are undeclared by compiler,
    // it means ngtcp2_crypto.h is not providing them as expected.
    callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.rand = client_rand_callback_wrapper; // Custom wrapper
    
    // Add the missing callback
    callbacks.get_new_connection_id = client_get_new_connection_id;
    callbacks.update_key = client_update_key;
    callbacks.delete_crypto_aead_ctx = client_delete_crypto_aead_ctx;
    callbacks.delete_crypto_cipher_ctx = client_delete_crypto_cipher_ctx;
    callbacks.get_path_challenge_data = client_get_path_challenge_data;
    
    // Leave other _cb suffixed ones NULL for now, to see if build passes or what asserts next.
    // callbacks.remove_connection_id = ngtcp2_crypto_remove_connection_id_cb;
    // callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    config->callbacks = callbacks; 
    
    uint8_t dcid_data[NGTCP2_MAX_CIDLEN], scid_data[NGTCP2_MAX_CIDLEN];
    size_t dcid_len = 18, scid_len = 18;
    ngtcp2_cid dcid, scid;
    RAND_bytes(dcid_data, dcid_len); RAND_bytes(scid_data, scid_len);
    ngtcp2_cid_init(&dcid, dcid_data, dcid_len); ngtcp2_cid_init(&scid, scid_data, scid_len);

    ngtcp2_transport_params conn_params;
    ngtcp2_transport_params_default(&conn_params);
    conn_params.initial_max_streams_bidi = 100;
    conn_params.initial_max_streams_uni = 100;
    conn_params.initial_max_data = 1 * 1024 * 1024; 
    conn_params.initial_max_stream_data_bidi_local = 256 * 1024;
    conn_params.initial_max_stream_data_bidi_remote = 256 * 1024;
    conn_params.original_dcid_present = 0;
    conn_params.active_connection_id_limit = 8;

    ngtcp2_path path_struct = {0};
    struct sockaddr_in6 local_addr_v6 = {.sin6_family = AF_INET6, .sin6_port = 0, .sin6_addr = IN6ADDR_ANY_INIT};
    struct sockaddr_in6 remote_addr_sockaddr_v6 = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
    
    if (inet_pton(AF_INET6, remote_addr, &remote_addr_sockaddr_v6.sin6_addr) != 1) {
        if (strcmp(remote_addr, "localhost") == 0 || strcmp(remote_addr, "127.0.0.1") == 0) {
            inet_pton(AF_INET6, "::1", &remote_addr_sockaddr_v6.sin6_addr);
        } else {
            dlog("ERROR: Invalid IPv6 address: %s", remote_addr);
            goto err_crypto_init; 
        }
    }
    path_struct.local.addr = (struct sockaddr*)&local_addr_v6;
    path_struct.local.addrlen = sizeof(local_addr_v6);
    path_struct.remote.addr = (struct sockaddr*)&remote_addr_sockaddr_v6;
    path_struct.remote.addrlen = sizeof(remote_addr_sockaddr_v6);

    ngtcp2_conn *conn_ptr = NULL;
    if (ngtcp2_conn_client_new(&conn_ptr, &dcid, &scid, &path_struct, NGTCP2_PROTO_VER_MAX, 
                               &config->callbacks, &config->settings, &conn_params, NULL, config) != 0) {
        dlog("ERROR: Failed to create QUIC connection object for client");
        goto err_crypto_init;
    }
    config->conn = conn_ptr;

    ngtcp2_conn_set_tls_native_handle(config->conn, config->crypto_ctx->ssl);

    config->sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (config->sock < 0) {
        dlog("ERROR: Failed to create client socket");
        goto err_conn_new;
    }
    int flags = fcntl(config->sock, F_GETFL, 0);
    fcntl(config->sock, F_SETFL, flags | O_NONBLOCK);

    if (connect(config->sock, (struct sockaddr*)&remote_addr_sockaddr_v6, sizeof(remote_addr_sockaddr_v6)) < 0 && errno != EINPROGRESS) {
        dlog("ERROR: Failed to connect client socket to %s:%u - %s", remote_addr, port, strerror(errno));
        goto err_socket;
    }

    config->bind_address = strdup(remote_addr);
    config->port = port;
    config->handshake_completed = 0;

    dlog("Client initialization complete for %s", net_ctx->hostname);
    return 0;

err_socket:
    close(config->sock);
err_conn_new:
    ngtcp2_conn_del(config->conn);
err_crypto_init:
    cleanup_client_crypto_context(config);
    free_certificate(config->cert); 
    if (config->ca_ctx) free_ca_context(config->ca_ctx); 
    if (config->bind_address && (strcmp(config->bind_address, remote_addr) == 0) ) { 
        // Only free if it's the one strdup'd by this function
        free((void*)config->bind_address); config->bind_address = NULL;
    } else if (config->bind_address) {
        // If bind_address was from somewhere else, don't free. This logic is tricky.
        // Best to ensure bind_address is always managed by this config struct or always passed in.
    }
    return -1;
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
        
        if (inet_pton(AF_INET6, config->bind_address, &server_addr_connect.sin6_addr) != 1) {
            if (strcmp(config->bind_address, "localhost") == 0 || strcmp(config->bind_address, "127.0.0.1") == 0) {
                inet_pton(AF_INET6, "::1", &server_addr_connect.sin6_addr);
            } else {
                dlog("ERROR: Invalid IPv6 address: %s", config->bind_address);
                return -1;
            }
        }

        ssize_t sent = sendto(config->sock, buf, n, 0,
                             (struct sockaddr*)&server_addr_connect, sizeof(server_addr_connect));
        
        if (sent < 0) {
            dlog("ERROR: Failed to send initial packet: %s", strerror(errno));
            return -1;
        }
        dlog("Sent initial handshake packet (%zd bytes)", sent);
    } else if (n < 0 && n != NGTCP2_ERR_CALLBACK_FAILURE) { 
        dlog("ERROR: ngtcp2_conn_write_pkt failed to generate initial packet: %s", ngtcp2_strerror((int)n));
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
        ngtcp2_conn_shutdown_stream(node->client_config.conn, 0, stream_ctx.stream_id, NGTCP2_INTERNAL_ERROR);
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

