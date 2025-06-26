#pragma once

#include <cstdint>

namespace net {

namespace errors {

/*!
 * TCP error codes and messages
 */

static constexpr uint32_t ALREADY_CONNECTED = 0x0001U;
static constexpr uint32_t TCP_SOCKET_CREATION_FAILED = 0x0002U;
static constexpr uint32_t PORT_REPR_CONV_FAILED = 0x0004U;
static constexpr uint32_t TCP_CONNECT_FAILED = 0x0008U;
static constexpr uint32_t URI_PARSE_FAILED = 0x0010U;
static constexpr uint32_t NONBLOCK_SET_FAILED = 0x0011U;

static constexpr char const *const ALREADY_CONNECTED_MSG = "TCP stream is already connected";
static constexpr char const *const TCP_SOCKET_CREATION_FAILED_MSG = "TCP stream socket creation failed";
static constexpr char const *const PORT_REPR_CONV_FAILED_MSG = "Port representation conversion failed";
static constexpr char const *const TCP_CONNECT_FAILED_MSG = "TCP stream connect failed";
static constexpr char const *const URI_PARSE_FAILED_MSG = "Failed to parse URI";
static constexpr char const *const NONBLOCK_SET_FAILED_MSG = "Failed to set nonblock mode";

/*!
 * TLS error codes and messages
 */

static constexpr uint32_t PSA_CRYPTO_INIT_FAILED = 0x0101U;
static constexpr uint32_t DRBG_SEEDING_FAILED = 0x0102U;
static constexpr uint32_t OWN_CERT_OR_KEY_MISSING = 0x0104U;
static constexpr uint32_t OWN_CERT_PARSING_FAILED = 0x0108U;
static constexpr uint32_t OWN_KEY_PARSING_FAILED = 0x0110U;
static constexpr uint32_t SSL_CONF_INIT_FAILED = 0x0111U;
static constexpr uint32_t SSL_OWN_CERT_CONF_FAILED = 0x0112U;
static constexpr uint32_t SSL_SETUP_FAILED = 0x0114U;
static constexpr uint32_t SSL_SET_HOSTNAME_FAILED = 0x0118U;
static constexpr uint32_t TLS_HANDSHAKE_FAILED = 0x0120U;
static constexpr uint32_t SSL_RESULT_VERIFY_FAILED = 0x0121U;

static constexpr char const *const PSA_CRYPTO_INIT_FAILED_MSG = "PSA crypto initialization failed";
static constexpr char const *const DRBG_SEEDING_FAILED_MSG = "DRBG seeding failed";
static constexpr char const *const OWN_CERT_OR_KEY_MISSING_MSG = "Own certificate or key missing";
static constexpr char const *const OWN_CERT_PARSING_FAILED_MSG = "Failed to parse own certificate";
static constexpr char const *const OWN_KEY_PARSING_FAILED_MSG = "Failed to parse own key";
static constexpr char const *const SSL_CONF_INIT_FAILED_MSG = "Failed to initialize SSL config";
static constexpr char const *const SSL_OWN_CERT_CONF_FAILED_MSG = "Failed to set own key and certificate";
static constexpr char const *const SSL_SETUP_FAILED_MSG = "Failed to setup SSL context";
static constexpr char const *const SSL_SET_HOSTNAME_FAILED_MSG = "Failed to set hostname";
static constexpr char const *const TLS_HANDSHAKE_FAILED_MSG = "Failed to perform handshake";
static constexpr char const *const SSL_RESULT_VERIFY_FAILED_MSG = "Handshake result verification failed";

} // namespace errors

struct error {
    uint32_t const code = 0;
    char const *const msg = nullptr;
};

} // namespace net
