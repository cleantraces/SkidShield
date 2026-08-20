// skidshield-client: listens on a local plaintext port and forwards each
// connection through a TLS tunnel to a skidshield-server instance.
//
// Usage: skidshield-client <local_port> <server_host> <server_port> <server_ca.pem> <client_cert.pem> <client_key.pem>

#include "common.hpp"

using namespace skidshield;

static SSL_CTX* g_ctx = nullptr;
static std::string g_server_host;
static int g_server_port = 0;

static void handle_connection(SOCKET local) {
    SOCKET remote = connect_socket(g_server_host, g_server_port);

    SSL* tls = SSL_new(g_ctx);
    SSL_set_fd(tls, (int)remote);

    if (SSL_connect(tls) != 1) {
        std::fprintf(stderr, "TLS handshake to server failed\n");
        print_ssl_errors();
        SSL_free(tls);
        closesocket(remote);
        closesocket(local);
        return;
    }

    relay(local, tls);
}

int main(int argc, char** argv) {
    if (argc != 7) {
        std::fprintf(stderr,
            "usage: %s <local_port> <server_host> <server_port> <server_ca.pem> <client_cert.pem> <client_key.pem>\n",
            argv[0]);
        return 1;
    }

    int local_port = std::atoi(argv[1]);
    g_server_host = argv[2];
    g_server_port = std::atoi(argv[3]);
    const char* server_ca = argv[4];
    const char* client_cert = argv[5];
    const char* client_key = argv[6];

    winsock_init();
    openssl_init();

    g_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ctx) { print_ssl_errors(); return 1; }

    // Require a valid chain to the given CA. There is no insecure fallback:
    // a tunnel that silently accepts any certificate isn't a tunnel.
    if (SSL_CTX_load_verify_locations(g_ctx, server_ca, nullptr) != 1) {
        std::fprintf(stderr, "failed to load server CA cert: %s\n", server_ca);
        print_ssl_errors();
        return 1;
    }
    SSL_CTX_set_verify(g_ctx, SSL_VERIFY_PEER, nullptr);

    // Present our own cert/key so the server can verify us back. Without
    // this, anyone who finds the server's address can connect through it,
    // even though they'd never be able to prove the server is who it says
    // it is. Auth needs to go both ways or it isn't really auth.
    if (SSL_CTX_use_certificate_file(g_ctx, client_cert, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(g_ctx, client_key, SSL_FILETYPE_PEM) != 1) {
        std::fprintf(stderr, "failed to load client cert/key\n");
        print_ssl_errors();
        return 1;
    }
    if (SSL_CTX_check_private_key(g_ctx) != 1) {
        std::fprintf(stderr, "client certificate/key mismatch\n");
        return 1;
    }

    SOCKET listener = listen_socket(local_port);
    std::printf("skidshield-client listening on 127.0.0.1:%d -> tls://%s:%d\n",
                local_port, g_server_host.c_str(), g_server_port);

    for (;;) {
        SOCKET conn = accept(listener, nullptr, nullptr);
        if (conn == INVALID_SOCKET) continue;
        std::thread(handle_connection, conn).detach();
    }
}
