#pragma once

#ifdef DEBUG
#include "mbedtls/debug.h"
#endif

#include "../error.h"
#include "../tls/context.h"

#include "stream.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"

#include <boost/url.hpp>
#include <sys/socket.h>

namespace net::client {

using namespace ::net::errors;

template <typename S = stream>
class tls_stream : public stream {
public:
    static auto create(S &&stream, char const *own_cert, char const *own_key) -> tls_stream {
        return std::move(tls_stream(std::move(stream), own_cert, own_key));
    }

    tls_stream(tls_stream &&) = default;
    tls_stream(tls_stream const &) = delete;

    auto operator=(tls_stream &&) -> tls_stream & = default;
    auto operator=(tls_stream const &) -> tls_stream & = delete;

    ~tls_stream() { close(); }

    auto close() -> void override {
        _ctx.reset();
        _stream.close();
    }

    auto connect() -> result<void, error> override {
        char const *pers = "ssl_client1";

        if (!_stream.is_connected()) {
            auto res = _stream.connect();
            if (res.is_err()) {
                return res;
            }
        }

#ifdef DEBUG
        mbedtls_debug_set_threshold(3);
#endif

        _ctx.reset(new ::net::tls::context());

        if (psa_crypto_init() != PSA_SUCCESS) {
            _ctx.reset();
            return {{.code = PSA_CRYPTO_INIT_FAILED, .msg = PSA_CRYPTO_INIT_FAILED_MSG}};
        }

        if (mbedtls_ctr_drbg_seed(&_ctx->ctr_drbg, mbedtls_entropy_func, &_ctx->entropy,
                                  reinterpret_cast<const unsigned char *>(pers), strlen(pers)) != 0) {
            _ctx.reset();
            return {{.code = DRBG_SEEDING_FAILED, .msg = DRBG_SEEDING_FAILED_MSG}};
        }

        mbedtls_x509_crt_parse_path(&_ctx->cacert, "/etc/ssl/certs");

        if ((_own.key != nullptr && _own.cert == nullptr) || (_own.key == nullptr && _own.cert != nullptr)) {
            _ctx.reset();
            return {{.code = OWN_CERT_OR_KEY_MISSING, .msg = OWN_CERT_OR_KEY_MISSING_MSG}};
        }

        if (_own.cert != nullptr && mbedtls_x509_crt_parse_file(&_ctx->own_cert, _own.cert) < 0) {
            _ctx.reset();
            return {{.code = OWN_CERT_PARSING_FAILED, .msg = OWN_CERT_PARSING_FAILED_MSG}};
        }

        if (_own.key != nullptr && mbedtls_pk_parse_keyfile(&_ctx->own_key, _own.key, nullptr) < 0) {
            _ctx.reset();
            return {{.code = OWN_KEY_PARSING_FAILED, .msg = OWN_KEY_PARSING_FAILED_MSG}};
        }

        if (0 != mbedtls_ssl_config_defaults(&_ctx->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT)) {
            _ctx.reset();
            return {{.code = SSL_CONF_INIT_FAILED, .msg = SSL_CONF_INIT_FAILED_MSG}};
        }

        mbedtls_ssl_conf_authmode(&_ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_ssl_conf_ca_chain(&_ctx->conf, &_ctx->cacert, nullptr);
        mbedtls_ssl_conf_dbg(&_ctx->conf, &tls_stream::mbedtls_debug, stdout);

        if (_own.cert != nullptr && _own.key != nullptr) {
            if (0 != mbedtls_ssl_conf_own_cert(&_ctx->conf, &_ctx->own_cert, &_ctx->own_key)) {
                _ctx.reset();
                return {{.code = SSL_OWN_CERT_CONF_FAILED, .msg = SSL_OWN_CERT_CONF_FAILED_MSG}};
            }
        }

        if (0 != mbedtls_ssl_setup(&_ctx->ssl, &_ctx->conf)) {
            _ctx.reset();
            return {{.code = SSL_SETUP_FAILED, .msg = SSL_SETUP_FAILED_MSG}};
        }

        if (0 != mbedtls_ssl_set_hostname(&_ctx->ssl, _stream._ctx.uri.hostname.c_str())) {
            _ctx.reset();
            return {{.code = SSL_SET_HOSTNAME_FAILED, .msg = SSL_SET_HOSTNAME_FAILED_MSG}};
        }

        mbedtls_ssl_set_bio(&_ctx->ssl, this, &tls_stream::mbedtls_send, &tls_stream::mbedtls_recv, nullptr);

        while (true) {
            auto ret = mbedtls_ssl_handshake(&_ctx->ssl);
            if (ret == 0) {
                break;
            }

            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                _ctx.reset();
                return {{.code = TLS_HANDSHAKE_FAILED, .msg = TLS_HANDSHAKE_FAILED_MSG}};
            }
        }

        auto flags = mbedtls_ssl_get_verify_result(&_ctx->ssl);
        if (flags != 0) {
            _ctx.reset();
            return {{.code = SSL_RESULT_VERIFY_FAILED, .msg = SSL_RESULT_VERIFY_FAILED_MSG}};
        }

        return {};
    }

    auto send(uint8_t const *const buf, size_t len) -> result<int, int> override {
        if (!is_connected()) {
            return {-1, true};
        }
        int ret = mbedtls_ssl_write(&_ctx->ssl, buf, len);
        if (ret < 0) {
            return {std::move(ret), true};
        } else {
            return {std::move(ret), false};
        }
    }

    auto send(std::vector<uint8_t> const &buf) -> result<int, int> override {
        if (!is_connected()) {
            return {-1, true};
        }
        int ret = mbedtls_ssl_write(&_ctx->ssl, buf.data(), buf.size());
        if (ret < 0) {
            return {std::move(ret), true};
        } else {
            return {std::move(ret), false};
        }
    }

    auto recv(uint8_t *const buf, size_t len) -> result<int, int> override {
        if (!is_connected()) {
            return {-1, true};
        }
        int ret = mbedtls_ssl_read(&_ctx->ssl, buf, len);
        if (ret < 0) {
            return {std::move(ret), true};
        } else {
            return {std::move(ret), false};
        }
    }

    auto recv(std::vector<uint8_t> &buf) -> result<int, int> override {
        if (!is_connected()) {
            return {-1, true};
        }
        buf.resize(buf.capacity());
        int ret = mbedtls_ssl_read(&_ctx->ssl, buf.data(), buf.capacity());
        if (ret < 0) {
            return {std::move(ret), true};
        } else {
            buf.resize(ret);
            return {std::move(ret), false};
        }
    }

    auto is_connected() -> bool override { return _stream.is_connected() && !!_ctx; }

private:
    template <typename T>
    using ptr = std::unique_ptr<T>;

    S _stream;

    struct {
        char const *const cert;
        char const *const key;
    } _own;

    ptr<::net::tls::context> _ctx;

    tls_stream(class tcp_stream &&stream) : _stream(std::move(stream)) {}

    static auto mbedtls_send(void *ctx, const unsigned char *buf, size_t len) -> int {
        class tls_stream *tls_stream = reinterpret_cast<class tls_stream *>(ctx);
        return ::send(tls_stream->_stream._ctx.fd, buf, len, 0);
    }

    static auto mbedtls_recv(void *ctx, unsigned char *buf, size_t len) -> int {
        class tls_stream *tls_stream = reinterpret_cast<class tls_stream *>(ctx);
        return ::recv(tls_stream->_stream._ctx.fd, buf, len, 0);
    }

    static void mbedtls_debug(void *ctx, int level, const char *file, int line, const char *str) {
        fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
        fflush((FILE *)ctx);
    }

    tls_stream(S &&stream, char const *const cert, char const *const key)
        : _stream(std::move(stream)), _own({cert, key}), _ctx() {}
};

} // namespace net::client
