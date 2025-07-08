use std::{fs, io::BufReader, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use rustls::{ClientConfig as RustlsClientConfig, ClientConnection, RootCertStore};
use rustls_pemfile::{certs, private_key};
use flyme_common::{
    config::{ClientCertPath, IpcMessage, SOCKET_NAME},
    platform_socket::connect_socket,
    tls_stream::TlsStream,
};

/// Configuration for the secure IPC client
pub struct ClientConfig {
    /// Path to client certificate files
    pub cert_path:   ClientCertPath,
    /// Socket name to connect to
    pub socket_name: String,
    /// Operation timeout
    pub timeout:     Duration,
    /// Enable verbose logging
    pub verbose:     bool,
}

impl Clone for ClientConfig {
    fn clone(&self) -> Self {
        Self {
            cert_path:   ClientCertPath::new(), // ClientCertPath doesn't implement Clone
            socket_name: self.socket_name.clone(),
            timeout:     self.timeout,
            verbose:     self.verbose,
        }
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            cert_path:   ClientCertPath::new(),
            socket_name: SOCKET_NAME.to_string(),
            timeout:     Duration::from_secs(30),
            verbose:     false,
        }
    }
}

impl ClientConfig {
    /// Creates a client configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the certificate path
    pub fn with_cert_path(mut self, cert_path: ClientCertPath) -> Self {
        self.cert_path = cert_path;
        self
    }

    /// Set the socket name
    pub fn with_socket_name<S: Into<String>>(mut self, socket_name: S) -> Self {
        self.socket_name = socket_name.into();
        self
    }

    /// Set the operation timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Enable verbose logging
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }
}

/// A secure IPC client for communicating with secure servers
pub struct SecureIpcClient {
    tls_config:      Arc<RustlsClientConfig>,
    socket_name:     String,
    connection:      Option<TlsStream>,
    request_counter: u32,
    timeout:         Duration,
    verbose:         bool,
}

impl SecureIpcClient {
    /// Creates a secure IPC client with the given configuration
    pub fn new(config: ClientConfig) -> Result<Self> {
        Self::with_config(config)
    }

    /// Creates a secure IPC client with default configuration
    pub fn with_defaults() -> Result<Self> {
        Self::with_config(ClientConfig::default())
    }

    /// Creates a secure IPC client from configuration
    pub fn with_config(config: ClientConfig) -> Result<Self> {
        if config.verbose {
            println!("Loading client certificates...");
            println!("  - Client cert: {:?}", config.cert_path.cert_path);
            println!("  - Client key: {:?}", config.cert_path.key_path);
            println!("  - CA cert: {:?}", config.cert_path.ca_path);
        }

        let cert_pem = fs::read(&config.cert_path.cert_path).with_context(|| {
            format!(
                "Failed to read client certificate from {:?}",
                config.cert_path.cert_path
            )
        })?;

        let key_pem = fs::read(&config.cert_path.key_path).with_context(|| {
            format!(
                "Failed to read client private key from {:?}",
                config.cert_path.key_path
            )
        })?;

        let ca_pem = fs::read(&config.cert_path.ca_path).with_context(|| {
            format!(
                "Failed to read CA certificate from {:?}",
                config.cert_path.ca_path
            )
        })?;

        // Parse client certificate and key
        if config.verbose {
            println!("Parsing client certificate...");
        }
        let cert_chain = certs(&mut BufReader::new(&*cert_pem))
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse client certificate PEM data")?;

        if config.verbose {
            println!("Parsing client private key...");
        }
        let private_key = private_key(&mut BufReader::new(&*key_pem))
            .context("Failed to parse client private key PEM data")?
            .ok_or_else(|| anyhow!("No private key found in client key file"))?;

        // Set up server certificate verification
        if config.verbose {
            println!("Setting up CA certificate verification...");
        }
        let mut root_store = RootCertStore::empty();
        let ca_certs = certs(&mut BufReader::new(&*ca_pem))
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse CA certificate PEM data")?;

        root_store.add_parsable_certificates(ca_certs);

        if root_store.is_empty() {
            return Err(anyhow!(
                "No valid CA certificates found in {:?}. Please check the CA certificate file.",
                config.cert_path.ca_path
            ));
        }

        if config.verbose {
            println!("Building TLS client configuration...");
        }
        let tls_config = RustlsClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, private_key)
            .context("Failed to build TLS client configuration")?;

        if config.verbose {
            println!("✓ Client created successfully");
        }

        Ok(Self {
            tls_config:      Arc::new(tls_config),
            socket_name:     config.socket_name,
            connection:      None,
            request_counter: 0,
            timeout:         config.timeout,
            verbose:         config.verbose,
        })
    }

    /// Connect to the secure IPC server
    pub fn connect(&mut self) -> Result<()> {
        if self.verbose {
            println!("Connecting to secure IPC server: {}", self.socket_name);
        }

        let socket =
            connect_socket(&self.socket_name).context("Failed to connect to server socket")?;

        if self.verbose {
            println!("Socket connected, establishing TLS...");
        }

        let server_name = "secure-ipc-server"
            .try_into()
            .map_err(|_| anyhow!("Invalid server name"))?;

        let client_conn = ClientConnection::new(self.tls_config.clone(), server_name)?;
        let tls_stream = TlsStream::from_client(socket, client_conn)?;

        self.connection = Some(tls_stream);

        if self.verbose {
            println!("✓ Secure connection established");
        }

        Ok(())
    }

    /// Disconnect from the server
    pub fn disconnect(&mut self) -> Result<()> {
        if self.connection.is_some() {
            if self.verbose {
                println!("Disconnecting from server...");
            }
            self.connection = None;
            if self.verbose {
                println!("✓ Disconnected");
            }
        }
        Ok(())
    }

    /// Check if client is connected to the server
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    /// Send a ping message and wait for pong response
    pub fn ping(&mut self) -> Result<()> {
        let stream = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow!("Not connected to server"))?;

        if self.verbose {
            println!("Sending ping...");
        }
        stream.send_message(&IpcMessage::Ping)?;

        match self.receive_response()? {
            IpcMessage::Pong => {
                if self.verbose {
                    println!("✓ Received pong");
                }
                Ok(())
            }
            IpcMessage::Error { id: _, message } => {
                Err(anyhow!("Server returned error for ping: {}", message))
            }
            msg => Err(anyhow!("Expected pong, got: {:?}", msg)),
        }
    }

    /// Send a command request and wait for the response
    pub fn send_request(&mut self, command: &str) -> Result<String> {
        let stream = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow!("Not connected to server"))?;

        self.request_counter += 1;
        let request_id = self.request_counter;

        if self.verbose {
            println!("Sending request {request_id}: {command}");
        }

        let request = IpcMessage::Request {
            id:      request_id,
            command: command.to_string(),
        };

        stream.send_message(&request)?;

        match self.receive_response()? {
            IpcMessage::Response { id, success, data } => {
                if id != request_id {
                    return Err(anyhow!(
                        "Response ID mismatch: expected {}, got {}",
                        request_id,
                        id
                    ));
                }

                if success {
                    if self.verbose {
                        println!("✓ Request {id} completed successfully");
                    }
                    Ok(data)
                } else {
                    Err(anyhow!("Request {} failed: {}", id, data))
                }
            }
            IpcMessage::Error { id, message } => {
                if id != request_id {
                    return Err(anyhow!(
                        "Error response ID mismatch: expected {}, got {}",
                        request_id,
                        id
                    ));
                }
                Err(anyhow!("Request {} error: {}", id, message))
            }
            msg => Err(anyhow!("Expected response or error, got: {:?}", msg)),
        }
    }

    /// Send a shutdown command to gracefully stop the server
    pub fn shutdown_server(&mut self) -> Result<()> {
        let stream = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow!("Not connected to server"))?;

        if self.verbose {
            println!("Sending shutdown command...");
        }
        stream.send_message(&IpcMessage::Shutdown)?;

        // Server will close connection after shutdown, no response expected
        if self.verbose {
            println!("✓ Shutdown command sent");
        }

        // Clear connection since server will close it
        self.connection = None;
        Ok(())
    }

    /// Send a custom message and return the server's response
    pub fn send_message(&mut self, message: &IpcMessage) -> Result<IpcMessage> {
        let stream = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow!("Not connected to server"))?;

        if self.verbose {
            println!("Sending message: {message:?}");
        }
        stream.send_message(message)?;

        let response = self.receive_response()?;
        if self.verbose {
            println!("Received response: {response:?}");
        }
        Ok(response)
    }

    /// Get connection and usage statistics
    pub fn get_stats(&self) -> ClientStats {
        ClientStats {
            connected:     self.is_connected(),
            socket_name:   self.socket_name.clone(),
            requests_sent: self.request_counter,
            timeout:       self.timeout,
        }
    }

    /// Test connection with a series of basic operations
    pub fn test_connection(&mut self) -> Result<()> {
        if self.verbose {
            println!("Testing connection...");
        }

        if !self.is_connected() {
            self.connect()?;
        }

        self.ping()?;

        let test_commands = vec!["status", "version", "echo Hello"];

        for cmd in test_commands {
            let _response = self.send_request(cmd)?;
        }

        if self.verbose {
            println!("✓ All tests passed!");
        }
        Ok(())
    }

    /// Receive a response from the server
    fn receive_response(&mut self) -> Result<IpcMessage> {
        let stream = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow!("Not connected to server"))?;

        stream.recv_message()
    }
}

/// Statistics about the client connection
pub struct ClientStats {
    pub connected:     bool,
    pub socket_name:   String,
    pub requests_sent: u32,
    pub timeout:       Duration,
}

impl Drop for SecureIpcClient {
    fn drop(&mut self) {
        if self.is_connected() {
            let _ = self.disconnect();
        }
    }
}

// Convenience functions for common operations
impl SecureIpcClient {
    /// Execute a single command (connect, execute, disconnect)
    pub fn execute_command(config: ClientConfig, command: &str) -> Result<String> {
        let mut client = Self::new(config)?;
        client.connect()?;
        let result = client.send_request(command);
        client.disconnect()?;
        result
    }

    /// Quick ping test (connect, ping, disconnect)
    pub fn quick_ping(config: ClientConfig) -> Result<()> {
        let mut client = Self::new(config)?;

        client.connect()?;
        let result = client.ping();
        client.disconnect()?;

        result
    }

    /// Health check - tests basic connectivity and commands
    pub fn health_check(config: ClientConfig) -> Result<()> {
        let mut client = Self::new(config)?;
        client.test_connection()
    }
}
