#pragma once

#ifdef DEBUG
#include "mbedtls/debug.h"
#endif

#include "../error.h"
#include "../resolver.h"
#include "../uri.h"

#include "stream.h"
#include "tls_stream.h"

#include <fcntl.h>

namespace net::client {

using namespace ::net::errors;

class tcp_stream : public stream {
    friend class tls_stream<tcp_stream>;

private:
    static constexpr int FD_INVALID = -1;

public:
    static auto create(std::string uri, uint16_t port) -> result<tcp_stream, error> {
        auto u = ::net::resolver::parse_uri(uri);
        if (!u.has_value()) {
            return {error{.code = URI_PARSE_FAILED, .msg = URI_PARSE_FAILED_MSG}};
        }

        return {std::move(tcp_stream(std::move(u.value()), port))};
    }

    tcp_stream(tcp_stream &&other) : _ctx(other._ctx) { other._ctx.fd = FD_INVALID; }

    auto operator=(tcp_stream &&other) -> tcp_stream & {
        _ctx = other._ctx;
        other._ctx.fd = FD_INVALID;
        return *this;
    }

    ~tcp_stream() { tcp_stream::close(); }

    auto close() -> void override {
        if (_ctx.fd != FD_INVALID) {
            ::close(_ctx.fd);
        }
        _ctx.fd = FD_INVALID;
    }

    auto connect() -> result<void, error> override {
        static constexpr int SUCCESS = 0;

        if (_ctx.fd != FD_INVALID) {
            return {error{.code = ALREADY_CONNECTED, .msg = "TCP stream is already connected"}};
        }

        _ctx.fd = ::socket(AF_INET, SOCK_STREAM, 0);

        if (_ctx.fd == FD_INVALID) {
            return {error{.code = TCP_CONNECT_FAILED, .msg = "TCP stream is already connected"}};
        }

        if (0 != fcntl(_ctx.fd, F_SETFL, O_NONBLOCK)) {
            return {error{.code = NONBLOCK_SET_FAILED, .msg = NONBLOCK_SET_FAILED_MSG}};
        }

        if (::inet_pton(AF_INET, _ctx.uri.ip.c_str(), &_ctx.addr.sin_addr.s_addr) <= 0) {
            close();
            return {error{.code = PORT_REPR_CONV_FAILED, .msg = PORT_REPR_CONV_FAILED_MSG}};
        }

        auto ret = ::connect(_ctx.fd, reinterpret_cast<struct sockaddr *>(&_ctx.addr), sizeof(_ctx.addr));
        if (ret != SUCCESS && errno != EAGAIN && errno != EINPROGRESS) {
            close();
            return {error{.code = TCP_CONNECT_FAILED, .msg = TCP_CONNECT_FAILED_MSG}};
        }

        if (errno == EAGAIN || errno == EINPROGRESS) {
            fd_set fdset;
            struct timeval tv;

            FD_ZERO(&fdset);
            FD_SET(_ctx.fd, &fdset);

            tv.tv_sec = 3;
            tv.tv_usec = 0;

            if (select(_ctx.fd + 1, nullptr, &fdset, nullptr, &tv) < 1) {
                close();
                return {error{.code = TCP_CONNECT_FAILED, .msg = TCP_CONNECT_FAILED_MSG}};
            }

            int so_error;
            socklen_t len = sizeof(so_error);

            if (getsockopt(_ctx.fd, SOL_SOCKET, SO_ERROR, &so_error, &len) != 0) {
                close();
                return {error{.code = TCP_CONNECT_FAILED, .msg = TCP_CONNECT_FAILED_MSG}};
            }

            if (so_error != SUCCESS) {
                close();
                return {error{.code = TCP_CONNECT_FAILED, .msg = TCP_CONNECT_FAILED_MSG}};
            }
        }

        int flags = fcntl(_ctx.fd, F_SETFL, O_NONBLOCK);
        if (flags < 0) {
            close();
            return {error{.code = NONBLOCK_SET_FAILED, .msg = NONBLOCK_SET_FAILED_MSG}};
        }

        flags &= ~O_NONBLOCK;
        if (0 != fcntl(_ctx.fd, F_SETFL, flags)) {
            close();
            return {error{.code = NONBLOCK_SET_FAILED, .msg = NONBLOCK_SET_FAILED_MSG}};
        }

        return {};
    }

    auto send(uint8_t const *const buf, size_t len) -> result<int, int> override {
        if (!tcp_stream::is_connected()) {
            return {-1, true};
        }
        int ret = ::send(_ctx.fd, buf, len, 0);
        if (ret < 0) {
            return {std::move(ret), true};
        } else {
            return {std::move(ret), false};
        }
    }

    auto send(std::vector<uint8_t> const &buf) -> result<int, int> override {
        if (!tcp_stream::is_connected()) {
            return {-1, true};
        }
        int ret = ::send(_ctx.fd, buf.data(), buf.size(), 0);
        if (ret < 0) {
            return {std::move(ret), true};
        } else {
            return {std::move(ret), false};
        }
    }

    auto recv(uint8_t *const buf, size_t len) -> result<int, int> override {
        if (!tcp_stream::is_connected()) {
            return {-1, true};
        }
        int ret = ::recv(_ctx.fd, buf, len, 0);
        if (ret < 0) {
            return {std::move(ret), true};
        } else {
            return {std::move(ret), false};
        }
    }

    auto recv(std::vector<uint8_t> &buf) -> result<int, int> override {
        if (!tcp_stream::is_connected()) {
            return {-1, true};
        }
        buf.resize(buf.capacity());
        int ret = ::recv(_ctx.fd, buf.data(), buf.capacity(), 0);
        if (ret < 0) {
            return {std::move(ret), true};
        } else {
            buf.resize(ret);
            return {std::move(ret), false};
        }
    }

    auto is_connected() -> bool override { return _ctx.fd != FD_INVALID; }

private:
    struct {
        int fd = FD_INVALID;
        sockaddr_in addr;
        ::net::uri uri;
    } _ctx;

    tcp_stream(::net::uri uri, uint16_t port) {
        _ctx.uri = uri;
        _ctx.addr.sin_family = AF_INET;
        _ctx.addr.sin_port = ::htons(port);
    }

    tcp_stream(tcp_stream const &) = delete;

    auto operator=(tcp_stream const &) -> tcp_stream & = delete;
};

} // namespace net::client
