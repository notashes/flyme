/// Secure IPC communication system with mutual TLS authentication and client
/// validation
pub mod config;
pub mod old;
/// Platform-specific socket implementations (Unix domain sockets, Windows named
/// pipes)
pub mod platform_socket;
/// TLS stream wrapper for encrypted IPC communication
pub mod tls_stream;
