#pragma once

#include <arpa/inet.h>
#include <cstring>
#include <netinet/ip.h>
#include <optional>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

namespace net {

namespace server {

class connection {
public:
    connection(int fd) : _fd(fd) {}
    ~connection() { ::close(_fd); }

    connection(connection &&) = delete;
    connection(connection const &) = delete;

    auto operator=(connection &&) -> connection & = delete;
    auto operator=(connection const &) -> connection & = delete;

private:
    int _fd = -1;
};

class socket {
public:
    static constexpr int FD_INVALID = -1;

    socket() = default;

    socket(socket &&other) {
        _fd = other._fd;
        other._fd = FD_INVALID;
    };
    socket(socket const &) = delete;

    auto operator=(socket &&other) -> socket & {
        _fd = other._fd;
        other._fd = FD_INVALID;
        return *this;
    }
    auto operator=(socket const &) -> socket & = delete;

    ~socket() {
        if (_fd != FD_INVALID) {
            ::close(_fd);
        }
    }

    auto close() -> void {
        if (_fd != FD_INVALID) {
            ::close(_fd);
        }
        _fd = FD_INVALID;
    }

    auto listen(bool throw_exception = false) -> bool {
        if (::listen(_fd, 3) < 0) {
            close();
            if (throw_exception) {
                throw std::runtime_error(std::string("Failed to listen (") + strerror(errno) + ")");
            } else {
                return false;
            }
        }
        return true;
    }

    auto accept(bool throw_exception = false) -> std::optional<connection> {
        socklen_t len = sizeof(_addr);
        auto s = ::accept(_fd, reinterpret_cast<struct sockaddr *>(&_addr), &len);
        if (s < 0) {
            if (throw_exception) {
                throw std::runtime_error(std::string("Failed to accept (") + strerror(errno) + ")");
            } else {
                return {};
            }
        }

        return {s};
    }

    auto bind(char const *const ip, uint16_t port, bool throw_exception = false) -> bool {
        static constexpr int SUCCESS = 0;

        if (_fd != FD_INVALID) {
            if (throw_exception) {
                throw std::runtime_error(std::string("Socket already created (") + strerror(errno) + ")");
            } else {
                return false;
            }
        }

        _fd = ::socket(AF_INET, SOCK_STREAM, 0);

        if (_fd == FD_INVALID) {
            throw std::runtime_error(std::string("Socket creation failed (") + strerror(errno) + ")");
        }

        int opt = 1;
        if (setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
            close();
            if (throw_exception) {
                throw std::runtime_error(strerror(errno));
            } else {
                return false;
            }
        }

        _addr.sin_family = AF_INET;
        _addr.sin_port = ::htons(port);

        if (ip != nullptr) {
            if (::inet_pton(AF_INET, ip, &_addr.sin_addr.s_addr) <= 0) {
                close();
                if (throw_exception) {
                    throw std::runtime_error(std::string("Parse of IP failed (") + strerror(errno) + ")");
                } else {
                    return false;
                }
            }
        } else {
            _addr.sin_addr.s_addr = INADDR_ANY;
        }

        auto ret = ::bind(_fd, reinterpret_cast<struct sockaddr *>(&_addr), sizeof(_addr));
        if (ret != SUCCESS) {
            close();
            if (throw_exception) {
                throw std::runtime_error(std::string("Failed to bind (") + strerror(errno) + ")");
            } else {
                return false;
            }
        }

        return true;
    }

private:
    int _fd = FD_INVALID;
    sockaddr_in _addr;
};

} // namespace server

} // namespace net
