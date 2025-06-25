#include "net/client/tcp_stream.h"
#include "net/client/tls_stream.h"
#include "net/server/socket.h"
#include "net/util.h"

using namespace ::net::client;

/*!
 * Simple client/server application for Mbed-TLS testing
 */
int main(int argc, char **argv) {
    try {
        // Start simple server (currently without TLS)
        if (argc > 3 && strcmp(argv[1], "server") == 0) {
            net::server::socket socket;

            if (!socket.bind(argv[2], ::atoi(argv[3]))) {
                ERR("Failed to bind ...");
                return 1;
            }

            if (!socket.listen()) {
                ERR("Failed to listen ...");
                return 1;
            }

            while (true) {
                auto connection = socket.accept();
                if (!connection) {
                    ERR("Failed to accept ...");
                    return 1;
                }
                LOG("Handle connection ...");
            }

        }
        // Start simple client with TLS handshake
        else if (argc > 3 && strcmp(argv[1], "client") == 0) {
            auto tcp = tcp_stream::create(argv[2], ::atoi(argv[3])).value();
            if (!tcp.connect()) {
                ERR("Failed to connect ...");
                return 1;
            }

            auto own_cert = argc > 4 ? argv[4] : nullptr;
            auto own_key = argc > 5 ? argv[5] : nullptr;

            tls_stream tls = tls_stream<tcp_stream>::create(std::move(tcp), own_cert, own_key);
            if (!tls.connect()) {
                ERR("Failed to perform TLS handshake ...");
                return 1;
            }

            LOG("Handshake successful!");
        }

    } catch (std::runtime_error &ex) {
        ERR(ex.what());
    }

    return 0;
}
