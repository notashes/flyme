# Flyme IPC

A cross-platform Inter-Process Communication (IPC) library written in Rust with built-in anti-tampering protection against fake clients. This library provides secure, mutual TLS-authenticated communication between privileged server processes and unprivileged client applications.

## Features

- 🔒 **Mutual TLS Authentication**: Certificate-based security for both client and server
- 🛡️ **Anti-Tampering Protection**: Process credential verification and binary hash validation
- 🌐 **Cross-Platform**: Unix domain sockets on Unix-like systems, named pipes on Windows
- 🔧 **Clean Architecture**: Multi-crate workspace with clear separation of concerns
- ⚡ **High Performance**: Async-first design with tokio for concurrent client handling
- 🔄 **Thread-Safe**: Safe concurrent access with proper synchronization primitives

## Architecture

This workspace is organized into three main crates:

### 📦 Crates

| Crate | Description | Purpose |
|-------|-------------|---------|
| **`common/`** | Shared protocols and utilities | Platform-specific socket implementations, TLS streams, message definitions |
| **`client/`** | Client library | Secure IPC client for connecting to servers |
| **`server/`** | Server library | Secure IPC server with client validation |

### 🔧 Key Components

- **Platform Abstraction**: Unified interface for Unix domain sockets and Windows named pipes
- **TLS Integration**: Rustls-based mutual TLS with certificate management
- **Process Validation**: Client binary hash verification and user credential checking
- **Message Protocol**: Efficient binary serialization with structured message types

## Quick Start

### Prerequisites

- Rust 1.70+ (2021 edition)
- Valid TLS certificates for mutual authentication

### Building

```bash
# Build the entire workspace
cargo build

# Build with optimizations
cargo build --release

# Check all crates
cargo check
```

### Running Examples

```bash
# Client examples
cargo run --example basic                    # Basic client example
cargo run --example cli interactive         # Interactive CLI client
cargo run --example cli ping                # Quick connection test

# Server examples
cargo run --example basic -p flyme-server    # Basic server setup
cargo run --example daemon -p flyme-server   # Daemon server with signal handling
cargo run --example echo -p flyme-server     # Echo server with custom commands
```

## Usage

### Client Library

```rust
use flyme_client::{ClientConfig, SecureIpcClient};
use std::time::Duration;

// Create client with custom configuration
let config = ClientConfig::new()
    .with_timeout(Duration::from_secs(10))
    .with_verbose(true);

// Connect and send requests
let mut client = SecureIpcClient::new(config)?;
client.connect()?;

let response = client.send_request("status")?;
println!("Server response: {}", response);

client.disconnect()?;
```

### Server Library

```rust
use flyme_server::SecureIpcServer;
use flyme_common::config::ServerCertPath;

// Initialize server with TLS certificates
let cert_path = ServerCertPath::new();
let server = SecureIpcServer::new(cert_path, "my-socket".to_string())?;

// Start accepting connections (blocking)
server.run()?;
```

### Server Examples

The server crate includes several examples demonstrating different use cases:

- **Basic Server** (`examples/basic.rs`): Simple server setup with certificate management
- **Daemon Server** (`examples/daemon.rs`): Long-running server with signal handling and graceful shutdown
- **Echo Server** (`examples/echo.rs`): Custom server implementation with command processing

## Security Model

### Authentication Flow

1. **Socket Connection**: Client connects to platform-specific socket
2. **TLS Handshake**: Mutual TLS authentication with certificate verification
3. **Process Validation**: Server verifies client user credentials and process information
4. **Binary Verification**: Optional client binary hash validation
5. **Secure Communication**: Encrypted message exchange over established TLS channel

### Certificate Management

The library expects the following certificate structure:

```
certificates/
├── ca.pem              # Certificate Authority
├── server-cert.pem     # Server certificate  
├── server-key.pem      # Server private key
├── client-cert.pem     # Client certificate
└── client-key.pem      # Client private key
```

### Anti-Tampering Features

- **Process Credential Verification**: Ensures client runs with expected user privileges
- **Binary Hash Validation**: Verifies client executable integrity (configurable)
- **Certificate Pinning**: Mutual TLS prevents man-in-the-middle attacks
- **Abstract Namespace Sockets**: On Linux, uses abstract sockets to prevent filesystem-based attacks

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLYME_CLIENT_BINARY_HASH` | Expected SHA256 hash of client binary | Empty (validation disabled) |
| `FLYME_CLIENT_BINARY_HASHES` | Comma-separated list of allowed hashes | Empty |
| `FLYME_ENFORCE_CLIENT_HASH_VALIDATION` | Enable/disable hash validation | `false` |

### Socket Configuration

- **Unix**: Abstract namespace socket `/tmp/flyme`
- **Windows**: Named pipe `\\.\pipe\flyme`

## Development

### Project Structure

```
flyme/
├── Cargo.toml          # Workspace configuration
├── common/             # Shared protocols and utilities
│   ├── src/
│   │   ├── config.rs       # Message and cert path definitions
│   │   ├── platform_socket.rs  # Cross-platform socket abstraction
│   │   ├── tls_stream.rs   # TLS wrapper for sockets

│   │   └── lib.rs          # Common library entry point
│   └── Cargo.toml
├── client/             # Client library
│   ├── src/
│   │   ├── client.rs       # Main client implementation
│   │   └── lib.rs          # Client library entry point
│   ├── examples/           # Client usage examples
│   │   ├── basic.rs        # Basic client example
│   │   └── cli.rs          # Interactive CLI client
│   └── Cargo.toml
├── server/             # Server library  
│   ├── src/
│   │   └── lib.rs          # Server implementation
│   ├── examples/           # Server usage examples
│   │   ├── basic.rs        # Basic server setup
│   │   ├── daemon.rs       # Daemon server with signal handling
│   │   └── echo.rs         # Echo server with custom commands
│   └── Cargo.toml
└── README.md
```

### Testing

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Test specific crate
cargo test -p secure-ipc-client

# Run integration test (requires certificates)
./scripts/test_integration.sh
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `cargo test`
5. Check formatting: `cargo fmt`
6. Run clippy: `cargo clippy`
7. Submit a pull request

## Platform Support

| Platform | Socket Type | Status |
|----------|-------------|--------|
| Linux | Unix Domain Sockets (Abstract) | ✅ Supported |
| macOS | Unix Domain Sockets | ✅ Supported |
| Windows | Named Pipes | ✅ Supported |
| BSD | Unix Domain Sockets | 🔄 Should work |

## Dependencies

### Core Dependencies

- **rustls**: TLS implementation
- **tokio**: Async runtime
- **serde**: Serialization framework
- **anyhow**: Error handling
- **nix**: Unix systems programming (Unix only)
- **windows**: Windows API bindings (Windows only)

### Platform-Specific Notes

- **Unix**: Uses `libc` and `nix` for socket operations and process information
- **Windows**: Uses `windows` crate for named pipes and process APIs
- **Cross-platform**: Runtime detection of platform capabilities

## Changelog

### v0.1.0 (Initial Release)

- ✨ Multi-crate workspace architecture
- ✨ Mutual TLS authentication
- ✨ Cross-platform socket support
- ✨ Process credential verification
- ✨ Binary hash validation
- ✨ Comprehensive examples and documentation

---

**Built with ❤️ in Rust for secure system-level communication** 
