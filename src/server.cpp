// skidshield-server: accepts TLS connections and forwards decrypted traffic
// to a plaintext destination.
//
// Usage: skidshield-server <listen_port> <dest_host> <dest_port> <server_cert.pem> <server_key.pem> <client_ca.pem>

#include "common.hpp"

using namespace skidshield;

static SSL_CTX* g_ctx = nullptr;
static std::string g_dest_host;
static int g_dest_port = 0;

static void handle_connection(SOCKET client) {
    SSL* tls = SSL_new(g_ctx);
    SSL_set_fd(tls, (int)client);

    if (SSL_accept(tls) != 1) {
        std::fprintf(stderr, "TLS handshake from client failed\n");
        print_ssl_errors();
        SSL_free(tls);
        closesocket(client);
        return;
    }

    SOCKET dest = connect_socket(g_dest_host, g_dest_port);
    relay(dest, tls);
}

int main(int argc, char** argv) {
    if (argc != 7) {
        std::fprintf(stderr,
            "usage: %s <listen_port> <dest_host> <dest_port> <server_cert.pem> <server_key.pem> <client_ca.pem>\n",
            argv[0]);
        return 1;
    }

    int listen_port = std::atoi(argv[1]);
    g_dest_host = argv[2];
    g_dest_port = std::atoi(argv[3]);
    const char* cert_file = argv[4];
    const char* key_file = argv[5];
    const char* client_ca = argv[6];

    winsock_init();
    openssl_init();

    g_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ctx) { print_ssl_errors(); return 1; }

    if (SSL_CTX_use_certificate_file(g_ctx, cert_file, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(g_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        std::fprintf(stderr, "failed to load cert/key\n");
        print_ssl_errors();
        return 1;
    }
    if (SSL_CTX_check_private_key(g_ctx) != 1) {
        std::fprintf(stderr, "certificate/key mismatch\n");
        return 1;
    }

    // Only trust connections that present a cert signed by our own client
    // CA, and refuse the handshake outright if they don't bring one. This
    // is what actually makes it client-to-server auth instead of just
    // server-to-client: without it, the server will happily tunnel traffic
    // for anyone who can reach the port.
    if (SSL_CTX_load_verify_locations(g_ctx, client_ca, nullptr) != 1) {
        std::fprintf(stderr, "failed to load client CA cert: %s\n", client_ca);
        print_ssl_errors();
        return 1;
    }
    SSL_CTX_set_verify(g_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

    SOCKET listener = listen_socket(listen_port);
    std::printf("skidshield-server listening on 0.0.0.0:%d -> %s:%d\n",
                listen_port, g_dest_host.c_str(), g_dest_port);

    for (;;) {
        SOCKET conn = accept(listener, nullptr, nullptr);
        if (conn == INVALID_SOCKET) continue;
        std::thread(handle_connection, conn).detach();
    }
}
