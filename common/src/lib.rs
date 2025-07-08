//! Secure IPC Common Library
//!
//! This crate provides shared protocols, data structures, and utilities used by both
//! the Secure IPC client and server. It includes:
//!
//! - Protocol definitions and message types
//! - Platform-specific socket implementations (Unix domain sockets, Windows named pipes)
//! - TLS stream wrappers for encrypted communication
//! - Configuration structures and utilities
//!
//! # Features
//!
//! - **Cross-platform IPC**: Unified interface for Unix domain sockets and Windows named pipes
//! - **Mutual TLS**: Secure communication with certificate-based authentication
//! - **Client validation**: Process credential verification and binary hash validation
//! - **Protocol definitions**: Standardized message formats for client-server communication

/// Configuration structures and protocol definitions
pub mod config;



/// Platform-specific socket implementations
pub mod platform_socket;

/// TLS stream wrapper for encrypted IPC communication  
pub mod tls_stream;

// Re-export commonly used types for convenience
pub use config::{ClientCertPath, IpcMessage, ServerCertPath, SOCKET_NAME};
pub use platform_socket::{ClientCredentials, PlatformListener, PlatformSocket};
pub use tls_stream::TlsStream; 