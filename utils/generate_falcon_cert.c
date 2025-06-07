#include <stdio.h>
#include <stdlib.h>
#include "../include/network_context.h"
#include "../include/certificate_authority.h"
#include <openssl/pem.h>
#include <openssl/evp.h>

int main() {
    ca_context_t *ca_ctx = NULL;
    network_context_t net_ctx = {
        .hostname = "localhost",
    };

    if (init_certificate_authority(&net_ctx, &ca_ctx) != 0) {
        fprintf(stderr, "Failed to initialize certificate authority\\n");
        return 1;
    }

    nexus_cert_t *cert = NULL;
    if (ca_issue_certificate(ca_ctx, "localhost", &cert) != 0) {
        fprintf(stderr, "Failed to issue certificate\\n");
        cleanup_certificate_authority(ca_ctx);
        return 1;
    }

    FILE *cert_file = fopen("server.cert", "w");
    if (!cert_file) {
        fprintf(stderr, "Failed to open server.cert for writing\\n");
        free_certificate(cert);
        cleanup_certificate_authority(ca_ctx);
        return 1;
    }
    PEM_write_X509(cert_file, cert->x509);
    fclose(cert_file);

    FILE *key_file = fopen("server.key", "w");
    if (!key_file) {
        fprintf(stderr, "Failed to open server.key for writing\\n");
        free_certificate(cert);
        cleanup_certificate_authority(ca_ctx);
        return 1;
    }
    PEM_write_PrivateKey(key_file, ca_ctx->falcon_pkey, NULL, NULL, 0, NULL, NULL);
    fclose(key_file);

    printf("Successfully generated server.cert and server.key\\n");

    free_certificate(cert);
    cleanup_certificate_authority(ca_ctx);

    return 0;
} 