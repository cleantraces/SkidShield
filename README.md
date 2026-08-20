# SkidShield

A minimal TLS tunnel for encrypting TCP traffic between two points, built on
OpenSSL. Point any TCP client at a local `skidshield-client` port instead of
its real destination, and the traffic between `skidshield-client` and
`skidshield-server` is TLS-encrypted with mutual auth. Everything else about
the app stays unaware.

```
your app -> skidshield-client (plaintext, localhost) -> [TLS, mutual auth] -> skidshield-server -> real destination (plaintext)
```

No custom crypto, just OpenSSL doing TLS, wired up as a forwarding proxy.
TCP only for now.

## Build

You need CMake, a C++17 compiler, and [vcpkg](https://vcpkg.io) for OpenSSL.

```sh
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=<path-to-vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

## Usage

The server checks the client's cert and the client checks the server's cert,
so you need two cert/key pairs: one for the server, one for the client.

Server cert:

```sh
openssl req -x509 -newkey rsa:4096 -nodes -keyout server.key -out server.pem -days 365 -subj "/CN=skidshield-server"
```

Client cert:

```sh
openssl req -x509 -newkey rsa:4096 -nodes -keyout client.key -out client.pem -days 365 -subj "/CN=skidshield-client"
```

Copy `client.pem` to wherever the server runs (it's the CA the server trusts
client connections against) and `server.pem` to wherever the client runs (the
CA the client trusts the server against). Keep the `.key` files where they
were generated, don't ship them around.

Run the server:

```sh
skidshield-server <listen_port> <dest_host> <dest_port> server.pem server.key client.pem
```

Run the client:

```sh
skidshield-client <local_port> <server_host> <server_port> server.pem client.pem client.key
```

Point your app at `127.0.0.1:<local_port>` instead of the real destination.

## Notes

- Both sides verify each other's cert. The server refuses any connection
  that doesn't present a cert signed by the client CA you gave it, and the
  client refuses to talk to a server whose cert doesn't chain to the CA you
  gave it. Neither side has an insecure/skip-verification mode.
- This encrypts and authenticates the hop between client and server. It
  doesn't make traffic anonymous, and it doesn't replace TLS the destination
  service terminates itself, if it has any.
