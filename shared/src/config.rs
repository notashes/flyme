use std::env;
use std::path::PathBuf;

// The base directory for certs can be overridden by this env var.
const CERTS_DIR_ENV: &str = "FLYME_CERTS_DIR";
// The default directory relative to the project root for development.
const DEFAULT_CERTS_DIR: &str = "certs";

fn get_certs_dir() -> PathBuf {
    //println!("{CERTS_DIR_ENV}");
    env::var(CERTS_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CERTS_DIR))
}

pub struct ServerCertPaths {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_path: PathBuf,
}

impl ServerCertPaths {
    pub fn new() -> Self {
        let base = get_certs_dir();
        Self {
            cert_path: base.join("server.pem"),
            key_path: base.join("server.key.pem"),
            ca_path: base.join("root-ca.pem"),
        }
    }
}

impl Default for ServerCertPaths {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ClientCertPaths {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_path: PathBuf,
}

impl ClientCertPaths {
    pub fn new() -> Self {
        let base = get_certs_dir();
        Self {
            cert_path: base.join("client.pem"),
            key_path: base.join("client.key.pem"),
            ca_path: base.join("root-ca.pem"),
        }
    }
}

impl Default for ClientCertPaths {
    fn default() -> Self {
        Self::new()
    }
}
