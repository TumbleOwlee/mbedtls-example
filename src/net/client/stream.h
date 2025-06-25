#pragma once

#include <cstdint>
#include <vector>

namespace net::client {

class stream {
public:
    virtual auto is_connected() -> bool = 0;

    virtual auto connect() -> bool = 0;

    virtual auto send(uint8_t const *const buf, size_t len) -> int = 0;

    virtual auto send(std::vector<uint8_t> const &buf) -> int = 0;

    virtual auto recv(uint8_t *const buf, size_t len) -> int = 0;

    virtual auto recv(std::vector<uint8_t> &buf) -> int = 0;

    virtual auto close() -> void = 0;
};

} // namespace net::client
