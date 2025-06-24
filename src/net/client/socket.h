#pragma once

#ifdef DEBUG
#include "mbedtls/debug.h"
#endif

#include "../resolver.h"
#include "../tls/context.h"
#include "../uri.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/ssl.h"

#include <arpa/inet.h>
#include <boost/url.hpp>
#include <cstring>
#include <memory>
#include <netdb.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace net {

namespace client {

class socket {
public:
    static constexpr int FD_INVALID = -1;

    socket() = default;

    socket(socket &&other) {
        _fd = other._fd;
        _uri = std::move(other._uri);
        _addr = other._addr;
        _ctx = std::move(other._ctx);
        other._fd = FD_INVALID;
    };
    socket(socket const &) = delete;

    auto operator=(socket &&other) -> socket & {
        _fd = other._fd;
        _uri = std::move(other._uri);
        _addr = other._addr;
        _ctx = std::move(other._ctx);
        other._fd = FD_INVALID;
        return *this;
    }
    auto operator=(socket const &) -> socket & = delete;

    ~socket() { close(); }

    auto close() -> void {
        _ctx.reset();
        _uri.reset();
        if (_fd != FD_INVALID) {
            ::close(_fd);
        }
        _fd = FD_INVALID;
    }

    auto connect(std::string uri, uint16_t port, bool throw_exception = false) -> bool {
        static constexpr int SUCCESS = 0;

        if (_fd != FD_INVALID) {
            if (throw_exception) {
                throw std::runtime_error(std::string("Socket already created (") + strerror(errno) + ")");
            } else {
                return false;
            }
        }

        auto u = ::net::resolver::parse_uri(uri, throw_exception);
        if (!u.has_value()) {
            if (throw_exception) {
                throw std::runtime_error("Failed to parse URI");
            } else {
                return false;
            }
        }

        _uri.reset(new ::net::uri(std::move(u.value())));

        _fd = ::socket(AF_INET, SOCK_STREAM, 0);

        if (_fd == FD_INVALID) {
            if (throw_exception) {
                throw std::runtime_error(std::string("Socket creation failed (") + strerror(errno) + ")");
            } else {
                return false;
            }
        }

        _addr.sin_family = AF_INET;
        _addr.sin_port = ::htons(port);

        if (::inet_pton(AF_INET, _uri->ip.c_str(), &_addr.sin_addr.s_addr) <= 0) {
            close();
            if (throw_exception) {
                throw std::runtime_error(std::string("Parse of IP failed (") + strerror(errno) + ")");
            } else {
                return false;
            }
        }

        auto ret = ::connect(_fd, reinterpret_cast<struct sockaddr *>(&_addr), sizeof(_addr));
        if (ret != SUCCESS) {
            close();
            if (throw_exception) {
                throw std::runtime_error(std::string("Failed to connect (") + strerror(errno) + ")");
            } else {
                return false;
            }
        }

        return true;
    }

    auto handshake(char const *pem_file, bool throw_exception = false) -> bool {
        char const *pers = "ssl_client1";

        if (_ctx) {
            if (throw_exception) {
                throw std::runtime_error(std::string("Handshake already performed"));
            } else {
                return false;
            }
        }

        if (!_uri) {
            if (throw_exception) {
                throw std::runtime_error(std::string("Parsed URI not present (logic error)"));
            } else {
                return false;
            }
        }

        _ctx.reset(new ::net::tls::context());

#ifdef DEBUG
        mbedtls_debug_set_threshold(3);
#endif

        if (psa_crypto_init() != PSA_SUCCESS) {
            _ctx.reset();
            if (throw_exception) {
                throw std::runtime_error(std::string("Failed to initialize PSA crypto"));
            } else {
                return false;
            }
        }

        if (mbedtls_ctr_drbg_seed(&_ctx->ctr_drbg, mbedtls_entropy_func, &_ctx->entropy,
                                  reinterpret_cast<const unsigned char *>(pers), strlen(pers)) != 0) {
            _ctx.reset();
            if (throw_exception) {
                throw std::runtime_error(std::string("Failed to seed"));
            } else {
                return false;
            }
        }

        mbedtls_x509_crt_parse_path(&_ctx->cacert, "/etc/ssl/certs");
        if (pem_file != nullptr && mbedtls_x509_crt_parse_file(&_ctx->cacert, pem_file) < 0) {
            _ctx.reset();
            if (throw_exception) {
                throw std::runtime_error(std::string("Failed to parse CRT"));
            } else {
                return false;
            }
        }

        if (0 != mbedtls_ssl_config_defaults(&_ctx->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT)) {
            _ctx.reset();
            if (throw_exception) {
                throw std::runtime_error(std::string("Failed to setup config"));
            } else {
                return false;
            }
        }

        mbedtls_ssl_conf_authmode(&_ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_ssl_conf_ca_chain(&_ctx->conf, &_ctx->cacert, nullptr);
        mbedtls_ssl_conf_dbg(&_ctx->conf, &socket::mbedtls_debug, stdout);

        if (0 != mbedtls_ssl_setup(&_ctx->ssl, &_ctx->conf)) {
            _ctx.reset();
            if (throw_exception) {
                throw std::runtime_error(std::string("Failed to setup ssl"));
            } else {
                return false;
            }
        }

        if (0 != mbedtls_ssl_set_hostname(&_ctx->ssl, _uri->hostname.c_str())) {
            _ctx.reset();
            if (throw_exception) {
                throw std::runtime_error(std::string("Failed to set hostname"));
            } else {
                return false;
            }
        }

        mbedtls_ssl_set_bio(&_ctx->ssl, this, &socket::mbedtls_send, &socket::mbedtls_recv, nullptr);

        while (true) {
            auto ret = mbedtls_ssl_handshake(&_ctx->ssl);
            if (ret == 0) {
                break;
            }

            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                _ctx.reset();
                if (throw_exception) {
                    throw std::runtime_error(std::string("Failed to perform handshake (") + std::to_string(ret) + ")");
                } else {
                    return false;
                }
            }
        }

        auto flags = mbedtls_ssl_get_verify_result(&_ctx->ssl);
        if (flags != 0) {
            _ctx.reset();
            if (throw_exception) {
                char buf[2000];
                mbedtls_strerror(flags, buf, sizeof(buf));
                throw std::runtime_error(std::string("Failed to verify result (") + buf + ")");
            } else {
                return false;
            }
        }

        return !!_ctx;
    }

    auto send(const unsigned char *buf, size_t len) -> int {
        if (_ctx) {
            return mbedtls_ssl_write(&_ctx->ssl, buf, len);
        } else {
            return ::send(_fd, buf, len, 0);
        }
    }

    auto recv(unsigned char *buf, size_t len) -> int {
        if (_ctx) {
            return mbedtls_ssl_read(&_ctx->ssl, buf, len);
        } else {
            return ::recv(_fd, buf, len, 0);
        }
    }

private:
    int _fd = FD_INVALID;
    std::unique_ptr<::net::uri> _uri;
    sockaddr_in _addr;
    std::unique_ptr<::net::tls::context> _ctx;

    static auto mbedtls_send(void *ctx, const unsigned char *buf, size_t len) -> int {
        class socket *socket = reinterpret_cast<class socket *>(ctx);
        return ::send(socket->_fd, buf, len, 0);
    }

    static auto mbedtls_recv(void *ctx, unsigned char *buf, size_t len) -> int {
        class socket *socket = reinterpret_cast<class socket *>(ctx);
        return ::recv(socket->_fd, buf, len, 0);
    }

    static void mbedtls_debug(void *ctx, int level, const char *file, int line, const char *str) {
        fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
        fflush((FILE *)ctx);
    }
};

} // namespace client

} // namespace net
