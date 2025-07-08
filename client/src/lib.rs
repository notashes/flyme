//! Secure IPC Client Library
//!
//! This crate provides a secure IPC client for communicating with secure
//! servers. It uses TLS over platform-specific sockets (Unix domain sockets on
//! Unix-like systems, named pipes on Windows) for secure inter-process
//! communication.
//!
//! # Example
//!
//! ```no_run
//! use std::time::Duration;
//!
//! use flyme_client::{ClientConfig, SecureIpcClient};
//!
//! # fn main() -> anyhow::Result<()> {
//! let config = ClientConfig::new()
//!     .with_timeout(Duration::from_secs(10))
//!     .with_verbose(true);
//!
//! let mut client = SecureIpcClient::new(config)?;
//! client.connect()?;
//!
//! let response = client.send_request("status")?;
//! println!("Server status: {}", response);
//!
//! client.disconnect()?;
//! # Ok(())
//! # }
//! ```

mod client;

pub use client::*;
// Re-export important types from secure-ipc-common for convenience  
pub use flyme_common::{ClientCertPath, IpcMessage, SOCKET_NAME};
