#pragma once

#ifdef DEBUG
#include "mbedtls/debug.h"
#endif

#include "../resolver.h"
#include "../tls/context.h"
#include "../uri.h"
#include "../util.h"

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

/*!
 * \brief Client socket with optional TLS support
 *
 * This class provides a simple interface for creating a client socket that can connect to a server
 */
class socket {
public:
    static constexpr int FD_INVALID = -1;

    /*!
     * \brief Default constructor
     *
     * Creates a socket object without initializing it.
     */
    socket() = default;

    /*!
     * \brief Move constructor
     *
     * Transfers ownership of the socket from another instance to this one.
     */
    socket(socket &&other) {
        _fd = other._fd;
        _uri = std::move(other._uri);
        _addr = other._addr;
        _ctx = std::move(other._ctx);
        other._fd = FD_INVALID;
    };

    /*!
     * \brief Deleted copy constructor
     *
     * Copying a socket is not allowed, as it would lead to resource management issues.
     */
    socket(socket const &) = delete;

    /*!
     * \brief Move assignment operator
     *
     * Transfers ownership of the socket from another instance to this one.
     */
    auto operator=(socket &&other) -> socket & {
        _fd = other._fd;
        _uri = std::move(other._uri);
        _addr = other._addr;
        _ctx = std::move(other._ctx);
        other._fd = FD_INVALID;
        return *this;
    }

    /*!
     * \brief Deleted copy assignment operator
     *
     * Copying a socket is not allowed, as it would lead to resource management issues.
     */
    auto operator=(socket const &) -> socket & = delete;

    /*!
     * \brief Destructor
     *
     * Cleans up the socket resources.
     */
    ~socket() { close(); }

    /*!
     * \brief Closes the socket and releases resources
     *
     * This method resets the context and URI, and closes the file descriptor if it is valid.
     */
    auto close() -> void {
        _ctx.reset();
        _uri.reset();
        if (_fd != FD_INVALID) {
            ::close(_fd);
        }
        _fd = FD_INVALID;
    }

    /*!
     * \brief Connects to a server using the specified URI and port
     *
     * This method parses the URI, creates a socket, and connects to the server.
     * If the socket is already created, it throws an exception or returns false based on the throw_exception flag.
     *
     * \param uri The URI of the server to connect to
     * \param port The port number to connect to
     * \param throw_exception If true, throws an exception on error; otherwise, returns false
     *
     * \throws std::runtime_error if an error occurs and throw_exception is true
     *
     * \return true if the connection was successful, false otherwise
     */
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

    /*!
     * \brief Performs a TLS handshake with the server
     *
     * This method initializes the TLS context, sets up the SSL configuration, and performs the handshake.
     * If the handshake is already performed or if there is an error, it throws an exception or returns false based on
     * the throw_exception flag.
     *
     * \param own_cert Path to the own certificate file (optional)
     * \param own_key Path to the own private key file (optional)
     * \param throw_exception If true, throws an exception on error; otherwise, returns false
     *
     * \throws std::runtime_error if an error occurs and throw_exception is true
     *
     * \return true if the handshake was successful, false otherwise
     */
    auto handshake(char const *own_cert, char const *own_key, bool throw_exception = false) -> bool {
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

        if ((own_key != nullptr && own_cert == nullptr) || (own_key == nullptr && own_cert != nullptr)) {
            _ctx.reset();
            if (throw_exception) {
                throw std::runtime_error("Certificate or private key is missing");
            } else {
                return false;
            }
        }

        if (own_cert != nullptr && mbedtls_x509_crt_parse_file(&_ctx->own_cert, own_cert) < 0) {
            _ctx.reset();
            if (throw_exception) {
                throw std::runtime_error(std::string("Failed to parse CRT"));
            } else {
                return false;
            }
        }

        if (own_key != nullptr && mbedtls_pk_parse_keyfile(&_ctx->own_key, own_key, nullptr) < 0) {
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

        if (own_cert != nullptr && own_key != nullptr) {
            if (0 != mbedtls_ssl_conf_own_cert(&_ctx->conf, &_ctx->own_cert, &_ctx->own_key)) {
                _ctx.reset();
                if (throw_exception) {
                    throw std::runtime_error(std::string("Failed to setup own certificate"));
                } else {
                    return false;
                }
            }
            LOG("Use own certificate and private key.");
        }

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

        LOG("Start TLS handshake ...");
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

        LOG("Verify TLS result ...");
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

    /*!
     * \brief Sends data over the socket
     *
     * This method sends data over the socket. If the socket is using TLS, it uses the mbedtls_ssl_write function;
     * otherwise, it uses the standard send function.
     *
     * \param buf Pointer to the data buffer to send
     * \param len Length of the data to send
     *
     * \return The number of bytes sent, or a negative error code on failure
     */
    auto send(const unsigned char *buf, size_t len) -> int {
        if (_ctx) {
            return mbedtls_ssl_write(&_ctx->ssl, buf, len);
        } else {
            return ::send(_fd, buf, len, 0);
        }
    }

    /*!
     * \brief Receives data from the socket
     *
     * This method receives data from the socket. If the socket is using TLS, it uses the mbedtls_ssl_read function;
     * otherwise, it uses the standard recv function.
     *
     * \param buf Pointer to the buffer to store received data
     * \param len Length of the buffer
     *
     * \return The number of bytes received, or a negative error code on failure
     */
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
