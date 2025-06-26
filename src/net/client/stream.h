#pragma once

#include <cstdint>
#include <vector>

#include "../error.h"
#include "../result.h"

namespace net::client {

class stream {
public:
    virtual auto is_connected() -> bool = 0;

    virtual auto connect() -> result<void, error> = 0;

    virtual auto send(uint8_t const *const buf, size_t len) -> result<int, int> = 0;

    virtual auto send(std::vector<uint8_t> const &buf) -> result<int, int> = 0;

    virtual auto recv(uint8_t *const buf, size_t len) -> result<int, int> = 0;

    virtual auto recv(std::vector<uint8_t> &buf) -> result<int, int> = 0;

    virtual auto close() -> void = 0;
};

} // namespace net::client
