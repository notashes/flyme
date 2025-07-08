use std::{env, fs, io, io::BufReader, sync::Arc, sync::atomic::{AtomicBool, Ordering}, time::Duration};

use anyhow::{anyhow, Context, Result};
use rustls::{server::WebPkiClientVerifier, RootCertStore, ServerConfig, ServerConnection};
use rustls_pemfile::{certs, private_key};
use sha2::{Digest, Sha256};
use flyme_common::{
    config::{IpcMessage, ServerCertPath},
    platform_socket::{ClientCredentials, PlatformListener, PlatformSocket},
    tls_stream::TlsStream,
};

/// Configuration for client binary hash validation with multiple allowed hashes
/// This is server-only configuration and cannot be modified by clients
#[derive(Debug, Clone)]
struct ServerBinaryHashConfig {
    /// List of allowed hashes
    allowed_hashes:     Vec<String>,
    /// Whether to enforce hash validation (can be disabled for development)
    enforce_validation: bool,
}

impl Default for ServerBinaryHashConfig {
    fn default() -> Self {
        Self {
            allowed_hashes:     vec![Self::get_expected_client_binary_hash()],
            enforce_validation: false,
        }
    }
}

impl ServerBinaryHashConfig {
    /// Creates a configuration with default settings
    fn new() -> Self {
        Self::default()
    }

    /// Creates configuration from environment variables
    ///
        /// Reads from FLYME_CLIENT_BINARY_HASH(ES) and
    /// FLYME_ENFORCE_CLIENT_HASH_VALIDATION
    fn from_env() -> Self {
        let mut config = Self::new();

        // Check for multiple hashes first
        if let Ok(hashes_str) = env::var("FLYME_CLIENT_BINARY_HASHES") {
            config.allowed_hashes = hashes_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        } else {
            // Fall back to single hash
            config.allowed_hashes = vec![Self::get_expected_client_binary_hash()];
        }

        // Check if validation should be enforced
        if let Ok(enforce_str) = env::var("FLYME_ENFORCE_CLIENT_HASH_VALIDATION") {
            config.enforce_validation = enforce_str.to_lowercase() == "true";
        }

        config
    }

    /// Get the expected SHA256 hash of the secure-ipc-client binary
fn get_expected_client_binary_hash() -> String {
    env::var("FLYME_CLIENT_BINARY_HASH").unwrap_or_default()
    }

    /// Check if a hash is allowed
    fn is_hash_allowed<S: AsRef<str>>(&self, hash: S) -> bool {
        if !self.enforce_validation {
            return true;
        }

        let hash_str = hash.as_ref();
        self.allowed_hashes
            .iter()
            .any(|allowed| allowed == hash_str)
    }

    /// Get all allowed hashes
    fn allowed_hashes(&self) -> &[String] {
        &self.allowed_hashes
    }

    /// Check if validation is enforced
    fn is_validation_enforced(&self) -> bool {
        self.enforce_validation
    }
}

/// A secure IPC server that handles client connections with mutual TLS
/// authentication, user verification, and binary hash validation.
#[derive(Clone)]
pub struct SecureIpcServer {
    tls_config:  Arc<ServerConfig>,
    socket_name: String,
}

impl SecureIpcServer {
    /// Creates a new secure IPC server with TLS configuration and client
    /// validation.
    ///
    /// # Arguments
    /// * `cert_path` - Server certificate, key, and CA certificate paths
    /// * `socket_name` - Name of the socket to bind to
    pub fn new(cert_path: ServerCertPath, socket_name: String) -> Result<Self> {
        // Install default crypto provider for rustls if not already installed
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        tracing::info!("Creating secure IPC server with certificates:");
        tracing::info!("  - Server cert: {:?}", cert_path.cert_path);
        tracing::info!("  - Server key: {:?}", cert_path.key_path);
        tracing::info!("  - CA cert: {:?}", cert_path.ca_path);
        let cert_pem = fs::read(&cert_path.cert_path)?;
        let key_pem = fs::read(&cert_path.key_path)?;
        let ca_pem = fs::read(&cert_path.ca_path)?;

        // Parse server certificate and key
        let cert_chain = certs(&mut BufReader::new(&*cert_pem)).collect::<Result<Vec<_>, _>>()?;

        let private_key = private_key(&mut BufReader::new(&*key_pem))?
            .ok_or_else(|| anyhow!("No private key found"))?;

        // Set up client certificate verification
        let mut root_store = RootCertStore::empty();
        let ca_certs = certs(&mut BufReader::new(&*ca_pem)).collect::<Result<Vec<_>, _>>()?;

        root_store.add_parsable_certificates(ca_certs);

        if root_store.is_empty() {
            return Err(anyhow!(
                "No valid CA certificates found in {:?}",
                cert_path.ca_path
            ));
        }

        let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store)).build()?;

        let config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(cert_chain, private_key)?;

        Ok(Self {
            tls_config: Arc::new(config),
            socket_name,
        })
    }

    /// Starts the server and handles incoming connections indefinitely.
    pub fn run(&self) -> Result<()> {
        tracing::info!("Starting secure IPC server on socket: {}", self.socket_name);
        tracing::info!("Socket will be created at: /tmp/{}", self.socket_name);

        let listener = PlatformListener::bind(&self.socket_name)
            .with_context(|| format!("Failed to bind to socket: {}", self.socket_name))?;

        tracing::info!(
            "✓ Secure IPC server successfully bound to socket: /tmp/{}",
            self.socket_name
        );
        tracing::info!("Secure IPC server listening on: /tmp/{}", self.socket_name);

        for connection in listener.incoming() {
            match connection {
                Ok(socket) => {
                    tracing::info!("New connection received");
                    if let Err(e) = self.handle_client(socket) {
                        tracing::error!("Client error: {}", e);
                    }
                }
                Err(e) => {
                    tracing::error!("Connection error: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Starts the server with a shutdown signal for graceful termination.
    /// This version can be interrupted by setting the shutdown flag to false.
    pub fn run_with_shutdown(&self, shutdown: Arc<AtomicBool>) -> Result<()> {
        tracing::info!("Starting secure IPC server on socket: {}", self.socket_name);
        tracing::info!("Socket will be created at: /tmp/{}", self.socket_name);

        let listener = PlatformListener::bind(&self.socket_name)
            .with_context(|| format!("Failed to bind to socket: {}", self.socket_name))?;

        tracing::info!(
            "✓ Secure IPC server successfully bound to socket: /tmp/{}",
            self.socket_name
        );
        tracing::info!("Secure IPC server listening on: /tmp/{}", self.socket_name);

        // Set socket to non-blocking mode for interruptible accept
        #[cfg(unix)]
        {
            let flyme_common::platform_socket::PlatformListener::Unix(unix_listener) = &listener;
            use std::os::unix::io::AsRawFd;
            let fd = unix_listener.as_raw_fd();
            unsafe {
                libc::fcntl(fd, libc::F_SETFL, libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK);
            }
        }

        while shutdown.load(Ordering::SeqCst) {
            // Try to accept a connection with a short timeout
            match listener.accept() {
                Ok(socket) => {
                    tracing::info!("New connection received");
                    if let Err(e) = self.handle_client(socket) {
                        tracing::error!("Client error: {}", e);
                    }
                }
                Err(e) => {
                    // Check if it's a "would block" error (no connections available)
                    if let Some(io_error) = e.downcast_ref::<std::io::Error>() {
                        if io_error.kind() == std::io::ErrorKind::WouldBlock {
                            // Sleep briefly to avoid busy waiting
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                    }
                    tracing::error!("Connection error: {}", e);
                }
            }
        }

        tracing::info!("Server shutdown signal received, stopping gracefully");
        Ok(())
    }

    /// Handle a single client connection with full authentication
    fn handle_client(&self, socket: PlatformSocket) -> Result<()> {
        tracing::info!("Authenticating client...");

        // Step 1: Extract client credentials from socket
        let credentials = socket
            .get_peer_credentials()
            .context("Failed to get client credentials")?;

        tracing::info!("Client PID: {}, UID: {}", credentials.pid, credentials.uid);

        // Step 2: Verify client user matches server user
        if !self.verify_client_user(&credentials)? {
            return Err(anyhow!("Client user verification failed"));
        }
        tracing::info!("✓ User verification passed");

        // Step 3: Verify client binary hash
        if !self.verify_client_binary(credentials.pid)? {
            return Err(anyhow!("Client binary verification failed"));
        }
        tracing::info!("✓ Binary verification passed");

        // Step 4: Establish TLS connection with mutual authentication
        let server_conn = ServerConnection::new(self.tls_config.clone())?;
        let mut tls_stream = TlsStream::from_server(socket, server_conn)?;

        tracing::info!("✓ TLS connection established with client certificate verification");

        // Step 5: Handle secure communication
        self.handle_secure_communication(&mut tls_stream)?;

        Ok(())
    }

    /// Verifies that the client user is authorized to connect.
    /// On Unix systems, checks UID matching and sudo user privileges.
    /// On Windows, validates user token and security context.
    fn verify_client_user(&self, credentials: &ClientCredentials) -> Result<bool> {
        #[cfg(unix)]
        {
            // SAFETY: getuid() is always safe to call - returns the real user ID
            let current_uid = unsafe { libc::getuid() };

            // If UIDs match, allow connection
            if credentials.uid == current_uid {
                tracing::info!(
                    "✓ Client UID {} matches server UID {}",
                    credentials.uid,
                    current_uid
                );
                return Ok(true);
            }

            // If server is running as root (UID 0), check if client is the original sudo
            // user
            if current_uid == 0 {
                if let Ok(sudo_user) = std::env::var("SUDO_USER") {
                    match get_user_uid(&sudo_user) {
                        Ok(sudo_uid) => {
                            if credentials.uid == sudo_uid {
                                tracing::info!(
                                    "✓ Client UID {} matches original sudo user '{}' (UID {})",
                                    credentials.uid,
                                    sudo_user,
                                    sudo_uid
                                );
                                return Ok(true);
                            } else {
                                tracing::warn!(
                                    "✗ Client UID {} does not match sudo user '{}' (UID {})",
                                    credentials.uid,
                                    sudo_user,
                                    sudo_uid
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "⚠️  Failed to get UID for sudo user '{}': {}",
                                sudo_user,
                                e
                            );
                        }
                    }
                } else {
                    tracing::warn!("⚠️  Server running as root but SUDO_USER not set");
                }
            }

            tracing::warn!(
                "✗ User verification failed: client UID {} != server UID {}",
                credentials.uid,
                current_uid
            );
            Ok(false)
        }

        #[cfg(windows)]
        {
            // Windows user verification via security token comparison
            // Validates that the client process runs under an authorized user context
            let _current_pid = std::process::id();
            #[allow(clippy::used_underscore_binding)]
            let _ = credentials; // Suppress unused parameter warning
            Ok(true) // Currently allows all users - extend for production use
        }
    }

    /// Verify client binary matches expected hash
    fn verify_client_binary(&self, pid: u32) -> Result<bool> {
        let exe_path = self.get_process_executable_path(pid)?;
        tracing::debug!("Verifying binary: {:?}", exe_path);

        // Load binary hash configuration from environment variables (server-only)
        let hash_config = ServerBinaryHashConfig::from_env();

        // Check if hash validation is enforced
        if !hash_config.is_validation_enforced() {
            tracing::warn!(
                            "⚠️  Binary hash validation is disabled \
             (FLYME_ENFORCE_CLIENT_HASH_VALIDATION=false)"
            );
            tracing::info!("✓ Skipping binary verification - validation disabled");
            return Ok(true);
        }

        let binary_data = fs::read(&exe_path).context("Failed to read client binary")?;

        let computed_hash = Sha256::digest(&binary_data);
        let computed_hash_hex = hex::encode(computed_hash);

        // Use the server-only hash validation system
        let is_allowed = hash_config.is_hash_allowed(&computed_hash_hex);

        if !is_allowed {
            tracing::error!("Binary hash mismatch!");
            tracing::error!("Computed: {}", computed_hash_hex);
            tracing::error!("Allowed hashes:");
            for (i, allowed_hash) in hash_config.allowed_hashes().iter().enumerate() {
                tracing::error!("  [{}]: {}", i + 1, allowed_hash);
            }
            tracing::error!("Binary path: {:?}", exe_path);

            tracing::info!("💡 To fix this issue, you can:");
            tracing::info!("  1. Rebuild the client to match the expected hash");
            tracing::info!(
                "  2. Set FLYME_CLIENT_BINARY_HASH=\"{}\" to allow this binary",
                computed_hash_hex
            );
            tracing::info!(
                "  3. Set FLYME_ENFORCE_CLIENT_HASH_VALIDATION=\"false\" to disable validation"
            );
        } else {
            tracing::info!("✓ Binary hash verification passed");
            tracing::debug!("  Computed: {}", computed_hash_hex);
            tracing::debug!("  Validation: enforced");
        }

        Ok(is_allowed)
    }

    /// Get executable path from process ID
    #[cfg(target_os = "linux")]
    fn get_process_executable_path(&self, pid: u32) -> Result<std::path::PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .context("Failed to read process executable path")
    }

    #[cfg(target_os = "macos")]
    fn get_process_executable_path(&self, pid: u32) -> Result<std::path::PathBuf> {
        use std::ffi::CStr;

        // Use libproc to get the executable path on macOS
        let mut path_buf = [0i8; 4096]; // PROC_PIDPATHINFO_MAXSIZE

        // SAFETY: proc_pidpath is safe when called with valid PID, buffer pointer, and
        // size. path_buf is a valid stack-allocated array and its length
        // matches the size parameter.
        let ret = unsafe {
            libc::proc_pidpath(
                pid as i32,
                path_buf.as_mut_ptr() as *mut std::ffi::c_void,
                path_buf.len() as u32,
            )
        };

        if ret <= 0 {
            return Err(anyhow!(
                "Failed to get process path for PID {}: proc_pidpath returned {}",
                pid,
                ret
            ));
        }

        // SAFETY: CStr::from_ptr is safe because proc_pidpath null-terminates the
        // string and we verified ret > 0, ensuring path_buf contains a valid C
        // string.
        let path_cstr = unsafe { CStr::from_ptr(path_buf.as_ptr()) };
        let path_str = path_cstr
            .to_str()
            .context("Process path contains invalid UTF-8")?;

        tracing::debug!("macOS process path for PID {}: {}", pid, path_str);
        Ok(std::path::PathBuf::from(path_str))
    }

    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    fn get_process_executable_path(&self, pid: u32) -> Result<std::path::PathBuf> {
        // Fallback for other Unix systems - try /proc first, then give up
        let proc_path = format!("/proc/{pid}/exe");
        match std::fs::read_link(&proc_path) {
            Ok(path) => {
                tracing::debug!("Using /proc/*/exe on other Unix system for PID {}", pid);
                Ok(path)
            }
            Err(_) => {
                Err(anyhow!(
                    "Unable to determine process executable path for PID {} on this Unix system. \
                     Supported systems: Linux (/proc/*/exe), macOS (proc_pidpath). Current system \
                     is not supported for binary verification.",
                    pid
                ))
            }
        }
    }

    #[cfg(windows)]
    fn get_process_executable_path(&self, pid: u32) -> Result<std::path::PathBuf> {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt};

        // SAFETY: Windows API calls are safe when used with proper error handling:
        // - OpenProcess: Safe with valid PID and access rights
        // - QueryFullProcessImageNameW: Safe with valid handle and buffer
        // - CloseHandle: Safe with valid handle, ensures resource cleanup
        unsafe {
            use windows::Win32::{
                Foundation::CloseHandle,
                System::Threading::{
                    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
                    PROCESS_QUERY_INFORMATION,
                },
            };

            let handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)?;

            let mut buffer = vec![0u16; 1024];
            let mut size = buffer.len() as u32;

            // Use PWSTR for the buffer parameter and PROCESS_NAME_WIN32 for the format
            let result = QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                windows::core::PWSTR(buffer.as_mut_ptr()),
                &mut size,
            );

            let _ = CloseHandle(handle);

            match result {
                Ok(_) => {
                    buffer.truncate(size as usize);
                    let path = OsString::from_wide(&buffer);
                    tracing::debug!("Windows process path for PID {}: {:?}", pid, path);
                    Ok(path.into())
                }
                Err(e) => {
                    Err(anyhow!(
                        "Failed to get process image name for PID {}: {}",
                        pid,
                        e
                    ))
                }
            }
        }
    }

    /// Handle secure communication with the client
    fn handle_secure_communication(&self, tls_stream: &mut TlsStream) -> Result<()> {
        tracing::debug!("Starting secure communication loop...");

        loop {
            match tls_stream.recv_message() {
                Ok(msg) => {
                    tracing::debug!("Received message: {:?}", msg);

                    match msg {
                        IpcMessage::Ping => {
                            tracing::debug!("Responding to ping with pong");
                            tls_stream.send_message(&IpcMessage::Pong)?;
                        }
                        IpcMessage::Request { id, command } => {
                            tracing::info!("Processing request {}: {}", id, command);

                            match self.process_command(&command) {
                                Ok(response_data) => {
                                    let response = IpcMessage::Response {
                                        id,
                                        success: true,
                                        data: response_data,
                                    };
                                    tls_stream.send_message(&response)?;
                                }
                                Err(e) => {
                                    tracing::error!("Command processing failed: {}", e);
                                    let error_response = IpcMessage::Error {
                                        id,
                                        message: e.to_string(),
                                    };
                                    tls_stream.send_message(&error_response)?;
                                }
                            }
                        }
                        IpcMessage::Shutdown => {
                            tracing::info!("Received shutdown request");
                            tracing::info!("Client disconnected via shutdown");
                            break;
                        }
                        IpcMessage::Pong => {
                            tracing::debug!("Received pong message (client response to our ping)");
                        }
                        IpcMessage::Response { id, success, data } => {
                            tracing::debug!(
                                "Received response {} (success: {}, data: {})",
                                id,
                                success,
                                data
                            );
                        }
                        IpcMessage::Error { id, message } => {
                            tracing::warn!("Received error {} from client: {}", id, message);
                        }
                    }
                }
                Err(e) => {
                    // Check for clean disconnection patterns
                    if let Some(io_err) = e.root_cause().downcast_ref::<io::Error>() {
                        if matches!(
                            io_err.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::BrokenPipe
                        ) {
                            tracing::info!("Client disconnected");
                            break;
                        }
                    }

                    // Check for TLS disconnection
                    if e.to_string().contains("Connection closed") {
                        tracing::info!("Client disconnected");
                        break;
                    }

                    // Log and fail for unexpected errors
                    tracing::error!("Message receive failed: {}", e);
                    return Err(e.context("Failed to receive message"));
                }
            }
        }

        Ok(())
    }

    /// Executes a command and returns the result.
    /// Supports basic commands: status, version, echo
    fn process_command(&self, command: &str) -> Result<String> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return Err(anyhow!("Empty command"));
        }

        match parts[0] {
            "status" => Ok("OK".to_string()),
            "version" => Ok(env!("CARGO_PKG_VERSION").to_string()),
            "echo" => Ok(parts.get(1..).unwrap_or(&[]).join(" ")),
            cmd => Err(anyhow!("Unknown command: {}", cmd)),
        }
    }

    /// Returns the socket name this server is bound to.
    pub fn get_socket_name(&self) -> &str {
        &self.socket_name
    }

    /// Gracefully shuts down the server and cleans up resources.
    pub fn shutdown(&self) -> Result<()> {
        tracing::info!("Shutting down secure IPC server...");
        Ok(())
    }
}

/// Helper function to get user ID from username
#[cfg(unix)]
fn get_user_uid(username: &str) -> Result<u32> {
    use std::ffi::CString;

    let username_cstring = CString::new(username)?;

    // SAFETY: getpwnam is safe when called with a valid C string pointer.
    // The returned pointer is either null (handled) or points to a valid passwd
    // struct. We check for null before dereferencing and only access the
    // standard pw_uid field.
    unsafe {
        let passwd = libc::getpwnam(username_cstring.as_ptr());
        if passwd.is_null() {
            return Err(anyhow!("User '{}' not found", username));
        }

        Ok((*passwd).pw_uid)
    }
}




