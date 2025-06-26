#pragma once

#include <cstdlib>
#include <utility>
#include <variant>

namespace net {

template <typename S, typename E>
class result {
public:
    result(S &&s) : _v(std::move(s)) {}
    result(E &&e) : _v(std::move(e)) {}

    result(result &&) = default;
    result(result const &) = delete;

    ~result() = default;

    auto operator=(result &&) -> result & = default;
    auto operator=(result const &) -> result & = delete;

    auto err() -> E {
        auto ptr = std::get_if<E>(&_v);
        if (ptr == nullptr) {
            abort();
        }
        return std::move(*ptr);
    }

    auto ok() -> S {
        auto ptr = std::get_if<S>(&_v);
        if (ptr == nullptr) {
            abort();
        }
        return std::move(*ptr);
    }

    auto is_ok() -> bool { return std::get_if<S>(&_v) != nullptr; }

    auto is_err() -> bool { return std::get_if<E>(&_v) != nullptr; }

private:
    std::variant<std::monostate, E, S> _v;
};

template <typename E>
class result<void, E> {
public:
    result(E &&e) : _v(std::move(e)) {}
    result() {}
    ~result() = default;

    result(result &&) = default;
    result(result const &) = delete;

    auto err() -> E {
        auto ptr = std::get_if<E>(&_v);
        if (ptr == nullptr) {
            abort();
        }
        return std::move(*ptr);
    }

    auto operator=(result &&other) -> result & = default;
    auto operator=(result const &) -> result & = delete;

    auto is_ok() -> bool { return std::get_if<E>(&_v) == nullptr; }

    auto is_err() -> bool { return std::get_if<E>(&_v) != nullptr; }

private:
    std::variant<std::monostate, E> _v;
};

template <typename S>
class result<S, void> {
public:
    result(S &&s) : _v(std::move(s)) {}
    result() {}

    result(result &&) = default;
    result(result const &) = delete;

    auto operator=(result &&other) -> result & = default;
    auto operator=(result const &) -> result & = delete;

    auto ok() -> S {
        auto ptr = std::get_if<S>(&_v);
        if (ptr == nullptr) {
            abort();
        }
        return std::move(*ptr);
    }

    auto is_ok() -> bool { return std::get_if<S>(&_v) != nullptr; }

    auto is_err() -> bool { return std::get_if<S>(&_v) == nullptr; }

private:
    std::variant<std::monostate, S> _v;
};

template <typename S>
class result<S, S> {
public:
    result(S &&s, bool err) : _v(std::move(s)), _err(err) {}
    result() {}

    result(result &&) = default;
    result(result const &) = delete;

    auto operator=(result &&other) -> result & = default;
    auto operator=(result const &) -> result & = delete;

    auto ok() -> S {
        auto ptr = std::get_if<S>(&_v);
        if (ptr == nullptr) {
            abort();
        }
        return std::move(*ptr);
    }

    auto is_ok() -> bool { return std::get_if<S>(&_v) != nullptr && !_err; }

    auto is_err() -> bool { return std::get_if<S>(&_v) != nullptr && _err; }

private:
    std::variant<std::monostate, S> _v;
    bool _err : 1;
};

} // namespace net
