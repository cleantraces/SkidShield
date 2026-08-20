#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

namespace skidshield {

inline void winsock_init() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::fprintf(stderr, "WSAStartup failed\n");
        std::exit(1);
    }
}

inline void openssl_init() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

inline void print_ssl_errors() {
    ERR_print_errors_fp(stderr);
}

inline SOCKET listen_socket(int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { std::fprintf(stderr, "socket() failed\n"); std::exit(1); }

    BOOL yes = TRUE;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((u_short)port);

    if (bind(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::fprintf(stderr, "bind() failed on port %d\n", port);
        std::exit(1);
    }
    if (listen(s, SOMAXCONN) == SOCKET_ERROR) {
        std::fprintf(stderr, "listen() failed\n");
        std::exit(1);
    }
    return s;
}

inline SOCKET connect_socket(const std::string& host, int port) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result) != 0) {
        std::fprintf(stderr, "getaddrinfo() failed for %s\n", host.c_str());
        std::exit(1);
    }

    SOCKET s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (s == INVALID_SOCKET || connect(s, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        std::fprintf(stderr, "connect() failed to %s:%d\n", host.c_str(), port);
        freeaddrinfo(result);
        std::exit(1);
    }
    freeaddrinfo(result);
    return s;
}

// Pumps data both ways between a plaintext socket and a TLS connection until
// both sides are done. One thread, not two: OpenSSL doesn't let you call
// SSL_read/SSL_write on the same SSL* from two threads at once, so we can't
// just spin up a thread per direction like you would with plain sockets.
//
// The two directions are tracked separately and only close when their own
// side hits EOF. First version of this just bailed out on the first EOF it
// saw, which killed request/response traffic (app sends its request, shuts
// down its write side, then waits for the reply... and the reply never
// showed up because we'd already torn the whole thing down).
inline void relay(SOCKET plain, SSL* tls) {
    SOCKET tls_fd = (SOCKET)SSL_get_fd(tls);
    char buf[8192];
    bool plain_open = true; // still worth reading from the plaintext side
    bool tls_open = true;   // still worth reading from the TLS side

    while (plain_open || tls_open) {
        fd_set readfds;
        FD_ZERO(&readfds);
        SOCKET maxfd = 0;
        if (plain_open) { FD_SET(plain, &readfds); maxfd = plain; }
        if (tls_open) { FD_SET(tls_fd, &readfds); if (tls_fd > maxfd) maxfd = tls_fd; }

        if (select((int)maxfd + 1, &readfds, nullptr, nullptr, nullptr) <= 0) break;

        if (plain_open && FD_ISSET(plain, &readfds)) {
            int n = recv(plain, buf, sizeof(buf), 0);
            if (n <= 0) {
                plain_open = false;
            } else if (SSL_write(tls, buf, n) <= 0) {
                plain_open = false;
                tls_open = false;
            }
        }

        if (tls_open && FD_ISSET(tls_fd, &readfds)) {
            do {
                int n = SSL_read(tls, buf, sizeof(buf));
                if (n <= 0) { tls_open = false; break; }
                if (send(plain, buf, n, 0) == SOCKET_ERROR) { tls_open = false; plain_open = false; break; }
            } while (SSL_pending(tls) > 0); // drain data already buffered by OpenSSL
        }
    }

    SSL_shutdown(tls);
    SSL_free(tls);
    shutdown(plain, SD_BOTH);
    closesocket(plain);
}

} // namespace skidshield
