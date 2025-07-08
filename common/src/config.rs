use std::{env, path::PathBuf};

use serde::{Deserialize, Serialize};

/// The socket our server and clients communicate over
pub const SOCKET_NAME: &str = "flyme.sock";

const CERTS_DIR_ENV: &str = "FLYME_CERTS_DIR";
const DEFAULT_CERTS_DIR: &str = "certs";

// New constants for server and client subdirectories
const SERVER_CERTS_SUBDIR: &str = "agent";
const CLIENT_CERTS_SUBDIR: &str = "app";

fn get_certs_dir() -> PathBuf {
    let dir = env::var(CERTS_DIR_ENV).unwrap_or(DEFAULT_CERTS_DIR.to_string());
    PathBuf::from(dir)
}

/// Server certificate paths for TLS authentication
pub struct ServerCertPath {
    /// Path to the server certificate file
    pub cert_path: PathBuf,
    /// Path to the server private key file
    pub key_path:  PathBuf,
    /// Path to the certificate authority file
    pub ca_path:   PathBuf,
}

impl ServerCertPath {
    /// Creates ServerCertPath with default certificate locations
    /// Certificates are expected in a 'server' subdirectory within the base
    /// certs directory.
    pub fn new() -> Self {
        let base = get_certs_dir().join(SERVER_CERTS_SUBDIR); // Join with server subdirectory
        Self {
            cert_path: base.join("server.pem"),
            key_path:  base.join("server.key.pem"),
            ca_path:   get_certs_dir().join("root-ca.pem"), // CA remains in the base certs dir
        }
    }
}

impl Default for ServerCertPath {
    fn default() -> Self {
        Self::new()
    }
}

/// Certificate paths for client authentication
pub struct ClientCertPath {
    /// Path to the client certificate file
    pub cert_path: PathBuf,
    /// Path to the client private key file
    pub key_path:  PathBuf,
    /// Path to the certificate authority file
    pub ca_path:   PathBuf,
}

impl ClientCertPath {
    /// Creates ClientCertPath with default certificate locations
    /// Certificates are expected in a 'client' subdirectory within the base
    /// certs directory.
    pub fn new() -> Self {
        let base = get_certs_dir().join(CLIENT_CERTS_SUBDIR); // Join with client subdirectory
        Self {
            cert_path: base.join("client.pem"),
            key_path:  base.join("client.key.pem"),
            ca_path:   get_certs_dir().join("root-ca.pem"), // CA remains in the base certs dir
        }
    }
}

impl Default for ClientCertPath {
    fn default() -> Self {
        Self::new()
    }
}

/// Messages exchanged over IPC channels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    /// Ping message to check connection health
    Ping,
    /// Pong response to ping
    Pong,
    /// Request containing a command to execute
    Request {
        /// Unique identifier for the request
        id:      u32,
        /// Command string to execute
        command: String,
    },
    /// Response to a request
    Response {
        /// Unique identifier matching the request
        id:      u32,
        /// Whether the command succeeded
        success: bool,
        /// Response data or result
        data:    String,
    },
    /// Error response to a request
    Error {
        /// Unique identifier matching the request
        id:      u32,
        /// Error message describing what went wrong
        message: String,
    },
    /// Signal to shutdown the connection
    Shutdown,
}
