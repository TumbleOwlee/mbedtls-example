#pragma once

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"

namespace net {

namespace tls {

struct context {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt own_cert;
    mbedtls_pk_context own_key;

    context() {
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_x509_crt_init(&cacert);
        mbedtls_x509_crt_init(&own_cert);
        mbedtls_pk_init(&own_key);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);
    }

    ~context() {
        mbedtls_ssl_close_notify(&ssl);
        mbedtls_x509_crt_free(&cacert);
        mbedtls_x509_crt_free(&own_cert);
        mbedtls_pk_free(&own_key);
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_psa_crypto_free();
    }
};

} // namespace tls

} // namespace net
