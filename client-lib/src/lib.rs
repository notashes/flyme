use anyhow::{anyhow, Context, Result};
use interprocess::local_socket::prelude::*;
use log::{debug, info};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls_pemfile::{certs, private_key};
use shared::{config::ClientCertPaths, IpcMessage};
use std::io::{BufReader, Read, Write};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

pub struct SecureIpcClient {
    tls_config: Arc<ClientConfig>,
    request_id: AtomicU32,
}

impl SecureIpcClient {
    pub fn new(paths: ClientCertPaths) -> Result<Self> {
        info!(
            "Loading client certs from: {:?}",
            paths.cert_path.parent().unwrap()
        );
        let ca_pem = std::fs::read(&paths.ca_path).with_context(|| {
            format!(
                "Failed to read root CA certificate from {:?}",
                paths.ca_path
            )
        })?;
        let mut root_store = RootCertStore::empty();
        let mut ca_pem_reader = BufReader::new(&*ca_pem);
        let ca_certs_vec = certs(&mut ca_pem_reader)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse root CA certificate")?;

        root_store.add_parsable_certificates(ca_certs_vec);

        if root_store.is_empty() {
            return Err(anyhow!(
                "No valid CA certificates found in {:?}",
                paths.ca_path
            ));
        }

        let client_cert_pem = std::fs::read(&paths.cert_path).with_context(|| {
            format!(
                "Failed to read client certificate from {:?}",
                paths.cert_path
            )
        })?;
        let client_key_pem = std::fs::read(&paths.key_path)
            .with_context(|| format!("Failed to read client key from {:?}", paths.key_path))?;

        let client_cert_chain: Vec<CertificateDer> = certs(&mut BufReader::new(&*client_cert_pem))
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse client certificate")?;

        let client_private_key: PrivateKeyDer<'static> =
            private_key(&mut BufReader::new(&*client_key_pem))
                .context("Failed to parse client private key")?
                .ok_or_else(|| anyhow!("No private key found in {:?}", paths.key_path))?;

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_cert_chain, client_private_key)
            .context("Failed to configure client authentication")?;

        Ok(Self {
            tls_config: Arc::new(config),
            request_id: AtomicU32::new(1),
        })
    }

    pub fn connect(&self) -> Result<SecureIpcConnection> {
        let name = shared::get_socket_name().context("Failed to create socket name")?;
        println!("Here is the socket name: {name:?}");
        let stream =
            LocalSocketStream::connect(name).context("Failed to connect to server IPC socket")?;
        info!("Connected to server via IPC");
        let server_name = "localhost"
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid server name"))?;
        let tls_conn = ClientConnection::new(Arc::clone(&self.tls_config), server_name)?;
        Ok(SecureIpcConnection { stream, tls_conn })
    }

    pub fn ping(&self, message: &str) -> Result<String> {
        let mut conn = self.connect()?;
        let ping_msg = IpcMessage::Ping(message.to_string());
        match conn.send_message(ping_msg)? {
            IpcMessage::Pong(response) => Ok(response),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }

    pub fn send_request(&self, command: &str, args: Vec<String>) -> Result<String> {
        let mut conn = self.connect()?;
        let id = self.request_id.fetch_add(1, Ordering::SeqCst);
        let request = IpcMessage::Request {
            id,
            command: command.to_string(),
            args,
        };
        match conn.send_message(request)? {
            IpcMessage::Response {
                success: true,
                data,
                ..
            } => Ok(data),
            IpcMessage::Response {
                success: false,
                data,
                ..
            } => Err(anyhow::anyhow!("Request failed: {}", data)),
            IpcMessage::Error { message, .. } => Err(anyhow::anyhow!("Server error: {}", message)),
            other => Err(anyhow::anyhow!("Unexpected response: {:?}", other)),
        }
    }
}

pub struct SecureIpcConnection {
    stream: LocalSocketStream,
    tls_conn: ClientConnection,
}

impl SecureIpcConnection {
    pub fn send_message(&mut self, message: IpcMessage) -> Result<IpcMessage> {
        let mut tls_stream = rustls::Stream::new(&mut self.tls_conn, &mut self.stream);

        debug!("Sending message: {message:?}");
        let request_data = bincode::serialize(&message)?;
        tls_stream.write_all(&request_data)?;
        tls_stream.flush()?;

        tls_stream.conn.send_close_notify();
        tls_stream.flush()?;

        let mut response_data = Vec::new();
        tls_stream
            .read_to_end(&mut response_data)
            .context("Failed to read response from TLS stream")?;

        if response_data.is_empty() {
            return Err(anyhow::anyhow!(
                "Connection closed by server without a response"
            ));
        }

        let response = bincode::deserialize::<IpcMessage>(&response_data)
            .context("Failed to deserialize response")?;

        debug!("Received response: {response:?}");
        Ok(response)
    }
}

// Helper function to create a client with default path loading.
fn default_client() -> Result<SecureIpcClient> {
    let paths = shared::config::ClientCertPaths::new();
    SecureIpcClient::new(paths)
}

pub fn quick_ping(message: &str) -> Result<String> {
    let client = default_client()?;
    client.ping(message)
}
pub fn execute_command(command: &str, args: Vec<String>) -> Result<String> {
    let client = default_client()?;
    client.send_request(command, args)
}
pub fn get_server_status() -> Result<String> {
    execute_command("status", vec![])
}
pub fn list_files(paths: Vec<String>) -> Result<String> {
    execute_command("list", paths)
}
pub fn run_privileged_operation() -> Result<String> {
    execute_command("privileged_op", vec![])
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore]
    fn test_client_creation() {
        let client = default_client();
        assert!(client.is_ok());
    }
}
