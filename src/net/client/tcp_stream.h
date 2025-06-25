#pragma once

#ifdef DEBUG
#include "mbedtls/debug.h"
#endif

#include "../resolver.h"
#include "../uri.h"

#include "stream.h"
#include "tls_stream.h"

namespace net::client {

class tcp_stream : public stream {
    friend class tls_stream<tcp_stream>;

private:
    static constexpr int FD_INVALID = -1;

public:
    static auto create(std::string uri, uint16_t port) -> std::optional<tcp_stream> {
        auto u = ::net::resolver::parse_uri(uri);
        if (!u.has_value()) {
            return {};
        }

        return tcp_stream(std::move(u.value()), port);
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

    auto connect() -> bool override {
        static constexpr int SUCCESS = 0;

        if (_ctx.fd != FD_INVALID) {
            return false;
        }

        _ctx.fd = ::socket(AF_INET, SOCK_STREAM, 0);

        if (_ctx.fd == FD_INVALID) {
            return false;
        }

        if (::inet_pton(AF_INET, _ctx.uri.ip.c_str(), &_ctx.addr.sin_addr.s_addr) <= 0) {
            close();
            return false;
        }

        auto ret = ::connect(_ctx.fd, reinterpret_cast<struct sockaddr *>(&_ctx.addr), sizeof(_ctx.addr));
        if (ret != SUCCESS) {
            close();
            return false;
        }

        return true;
    }

    auto send(uint8_t const *const buf, size_t len) -> int override {
        if (!tcp_stream::is_connected()) {
            return -1;
        }
        return ::send(_ctx.fd, buf, len, 0);
    }

    auto send(std::vector<uint8_t> const &buf) -> int override {
        if (!tcp_stream::is_connected()) {
            return -1;
        }
        return ::send(_ctx.fd, buf.data(), buf.size(), 0);
    }

    auto recv(uint8_t *const buf, size_t len) -> int override {
        if (!tcp_stream::is_connected()) {
            return -1;
        }
        return ::recv(_ctx.fd, buf, len, 0);
    }

    auto recv(std::vector<uint8_t> &buf) -> int override {
        if (!tcp_stream::is_connected()) {
            return -1;
        }
        return ::recv(_ctx.fd, buf.data(), buf.capacity(), 0);
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
