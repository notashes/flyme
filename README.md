# FlyMe: Secure IPC with Mutual TLS in Rust

**FlyMe** is a demonstration project that showcases a **secure, local inter-process communication (IPC)** mechanism in Rust. It uses **mutual TLS (mTLS)** to ensure **strong authentication** and **encrypted communication** between a **privileged server** and **unprivileged clients**.

This architecture is ideal for scenarios where a root-level process must expose a tightly scoped API to user-mode processes, without relying on TCP networking or external authentication services.

---

## 🧩 Workspace Overview

The repository is organized as a Rust Cargo workspace with the following crates:

| Crate         | Description                                                                 |
|---------------|-----------------------------------------------------------------------------|
| `server`      | Privileged process that listens on a local socket and enforces mTLS.       |
| `client`      | Command-line client that interacts securely with the server.               |
| `client-lib`  | Reusable library for securely connecting to the server.                    |
| `shared`      | Shared types and utilities used across all components.                     |
| `fake-client` | A test client that connects without valid certificates (expected to fail). |

---

## 🔒 Security Model: Mutual TLS (mTLS)

FlyMe enforces **mutual TLS**, where both parties must present valid X.509 certificates issued by a shared trusted Certificate Authority (CA).

- ✅ **Server Authentication**: The client verifies that the server presents a certificate signed by the CA.
- ✅ **Client Authentication**: The server accepts only clients with certificates signed by the same CA.
- 🔐 **Secure Channel**: All traffic is encrypted via TLS over the local socket.

---

## 📁 Certificate Layout

You must create a `certs/` directory in the project root containing:

```

certs/
├── root-ca.pem
├── server.pem
├── server.key.pem
├── client.pem
└── client.key.pem

````

You can generate these using [`openssl`](https://www.openssl.org/) or [`mkcert`](https://github.com/FiloSottile/mkcert). See [`scripts/generate-certs.sh`](./scripts/) if provided.

---

## 🚀 Getting Started

### 1. Build Everything

```sh
cargo build --release
````

### 2. Run the Server (Privileged)

The server must be run first, and with root privileges:

```sh
sudo cargo run --bin server
```

It will bind to a secure local socket and start listening for connections.

### 3. Run the Authorized Client (Unprivileged)

```sh
cargo run --bin client ping "hello secure world"
cargo run --bin client status
cargo run --bin client list /tmp /var
```

You can explore more subcommands in [`client/README.md`](./client/README.md).

### 4. Test Security Enforcement

To confirm unauthorized clients are rejected:

```sh
cargo run --bin fake-client
```

This should fail with a TLS handshake error, validating mTLS is enforced.

---

## 🧱 Project Layout

```txt
flyme/
├── certs/             # TLS certificates (you must generate)
├── server/            # Privileged server process
├── client/            # CLI for unprivileged users
├── client-lib/        # Library used by clients to connect securely
├── fake-client/       # Client without proper certs (expected to fail)
├── shared/            # Common IPC data structures and socket logic
├── scripts/           # (Optional) Scripts for cert generation, setup
└── Cargo.toml         # Workspace configuration
```

---

## 📜 Example Use Cases

* Secure admin interfaces for background daemons
* Local privilege separation between services
* System health check tools with fine-grained access control
* Embedded system control between secure bootstrapped processes

---

## ⚠️ Notes

* Certificate paths are currently hardcoded to `certs/`. For production, consider configurable paths or using system directories like `/etc/flyme/certs`.
* Only Unix systems are currently supported (via Unix domain sockets). Cross-platform IPC via `interprocess` is a possible future enhancement.

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.

---

## 👨‍💻 Authors

Built with ❤️ in Rust by the FlyMe contributors.

---

## 📚 More Documentation

* [`server/README.md`](./server/README.md) — Design and usage of the privileged server
* [`client/README.md`](./client/README.md) — CLI usage and commands
* [`client-lib/README.md`](./client-lib/README.md) — Secure IPC client library
* [`shared/README.md`](./shared/README.md) — Shared definitions for protocol and socket naming

