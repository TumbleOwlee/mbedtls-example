#pragma once

#include <arpa/inet.h>
#include <boost/url/parse.hpp>
#include <netdb.h>
#include <netinet/ip.h>
#include <optional>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>

namespace net {

struct uri {
    std::string ip;
    std::string hostname;
};

class resolver {
public:
    static auto parse_uri(std::string const &uri, bool throw_exception = false) -> std::optional<::net::uri> {
        auto url_view = boost::urls::parse_uri(uri);
        if (!url_view.has_value()) {
            if (throw_exception) {
                throw std::runtime_error("Parse of URI failed");
            } else {
                return {};
            }
        }
        auto value = url_view.value();

        struct addrinfo hints;
        struct addrinfo *result = nullptr;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (0 != getaddrinfo(value.host().c_str(), nullptr, &hints, &result)) {
            if (throw_exception) {
                throw std::runtime_error(std::string("Failed to resolve URL (") + strerror(errno) + ")");
            } else {
                return {};
            }
        }

        std::string ip;
        for (struct addrinfo *rp = result; rp != nullptr; rp = rp->ai_next) {
            auto *ipv4 = reinterpret_cast<struct sockaddr_in *>(rp->ai_addr);
            auto *addr = &(ipv4->sin_addr);

            constexpr size_t LEN = 255;
            char buf[LEN] = {'\0'};
            if (inet_ntop(AF_INET, addr, &buf[0], LEN - 1) != nullptr) {
                ip = buf;
                break;
            }
        }

        if (ip.empty()) {
            if (throw_exception) {
                throw std::runtime_error("Failed to resolve IP ");
            } else {
                return {};
            }
        }

        return net::uri{
            .ip = ip,
            .hostname = value.host(),
        };
    }

private:
};

} // namespace net
