#include <iostream>

#include "client.h"
#include "server.h"

int main(int argc, char **argv) {
    if (argc > 3 && strcmp(argv[1], "server") == 0) {
        net::server::socket socket;

        if (!socket.bind(argv[2], ::atoi(argv[3]))) {
            std::cerr << "Failed to bind ..." << std::endl;
            return 1;
        }

        if (!socket.listen()) {
            std::cerr << "Failed to listen ..." << std::endl;
            return 1;
        }

        while (true) {
            auto connection = socket.accept();
            if (!connection) {
                std::cerr << "Failed to accept ..." << std::endl;
                return 1;
            }
            std::cerr << "Handle connection ..." << std::endl;
        }

    } else if (argc > 3 && strcmp(argv[1], "client") == 0) {
        net::client::socket socket;

        if (!socket.connect(argv[2], ::atoi(argv[3]), true)) {
            std::cerr << "Failed to connect ..." << std::endl;
            return 1;
        }

        auto pem_file = nullptr;
        if (!socket.handshake(pem_file, true)) {
            std::cerr << "Failed to perform TLS handshake ..." << std::endl;
            return 1;
        }

        std::cerr << "Handshake successful!" << std::endl;
    }

    return 0;
}
