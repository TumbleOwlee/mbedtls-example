#include "net/client/socket.h"
#include "net/server/socket.h"

int main(int argc, char **argv) {
    try {
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

        } else if (argc > 3 && strcmp(argv[1], "client") == 0) {
            net::client::socket socket;

            if (!socket.connect(argv[2], ::atoi(argv[3]), true)) {
                ERR("Failed to connect ...");
                return 1;
            }

            auto own_cert = argc > 4 ? argv[4] : nullptr;
            auto own_key = argc > 5 ? argv[5] : nullptr;

            if (!socket.handshake(own_cert, own_key, true)) {
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
