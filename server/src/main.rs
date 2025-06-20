use anyhow::{anyhow, Context, Result};
use clap::Parser;
use log::{error, info, warn};
use rustls::server::{ServerConfig, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConnection};
use rustls_pemfile::{certs, private_key};
use sha2::{Digest, Sha256};
use shared::{config::ServerCertPaths, IpcMessage};
use std::io::{self, BufReader, Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::thread;
use std::{fs, mem};

pub mod peer_creds;

/// Wrapper to make UnixStream work with rustls
struct UnixStreamWrapper {
    stream: UnixStream,
}

impl UnixStreamWrapper {
    fn new(stream: UnixStream) -> Self {
        Self { stream }
    }
}

impl Read for UnixStreamWrapper {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for UnixStreamWrapper {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[derive(Parser)]
#[command(name = "server")]
#[command(about = "Secure IPC Server")]
struct Args {
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

struct SecureIpcServer {
    tls_config: Arc<ServerConfig>,
}

/// Binds a UnixListener to a name in the Linux abstract socket namespace.
///
/// This requires unsafe code because it manually constructs the `sockaddr_un`
/// struct required by the `bind` syscall for abstract sockets.
fn bind_abstract_socket(name: &str) -> io::Result<UnixListener> {
    // The full path for an abstract socket starts with a null byte.
    let full_name = format!("\0{}", name);
    let name_bytes = full_name.as_bytes();

    unsafe {
        // 1. Create a raw socket file descriptor.
        let socket_fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if socket_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // 2. Construct the special address structure for abstract sockets.
        let mut addr: libc::sockaddr_un = mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;

        // Ensure the name fits, including the leading null byte.
        if name_bytes.len() > addr.sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket name is too long",
            ));
        }

        // Copy the name into the sun_path field.
        // This is the core "unsafe" part.
        let path_slice = &mut addr.sun_path[..name_bytes.len()];
        path_slice.copy_from_slice(std::mem::transmute(name_bytes));

        // 3. Bind the socket to the address.
        // The length calculation is critical for abstract sockets.
        let addr_len = mem::size_of::<libc::sa_family_t>() + name_bytes.len();
        let result = libc::bind(
            socket_fd,
            &addr as *const _ as *const libc::sockaddr,
            addr_len as libc::socklen_t,
        );
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        // 4. Put the socket into listening mode.
        if libc::listen(socket_fd, 128) < 0 {
            // 128 is a common backlog size
            return Err(io::Error::last_os_error());
        }

        // 5. Wrap the raw file descriptor in a safe UnixListener.
        // From this point on, all operations are safe.
        Ok(UnixListener::from_raw_fd(socket_fd))
    }
}

impl SecureIpcServer {
    fn new(paths: ServerCertPaths) -> Result<Self> {
        info!(
            "Loading server certs from: {:?}",
            paths.cert_path.parent().unwrap()
        );
        let cert_pem = std::fs::read(&paths.cert_path)
            .with_context(|| format!("Failed to read certificate from {:?}", paths.cert_path))?;
        let key_pem = std::fs::read(&paths.key_path)
            .with_context(|| format!("Failed to read private key from {:?}", paths.key_path))?;

        let cert_chain = certs(&mut BufReader::new(&*cert_pem))
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse certificate")?;
        let private_key = private_key(&mut BufReader::new(&*key_pem))
            .context("Failed to parse private key")?
            .ok_or_else(|| anyhow!("No private key found in {:?}", paths.key_path))?;

        // --- Load Root CA to verify clients ---
        let ca_pem = std::fs::read(&paths.ca_path)
            .with_context(|| format!("Failed to read root CA from {:?}", paths.ca_path))?;
        let mut root_store = RootCertStore::empty();
        let ca_certs = certs(&mut BufReader::new(&*ca_pem))
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse root CA certificate")?;
        root_store.add_parsable_certificates(ca_certs);

        if root_store.is_empty() {
            return Err(anyhow!(
                "No valid CA certificates found in {:?}",
                paths.ca_path
            ));
        }

        // --- Create a client certificate verifier ---
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .context("Failed to build client verifier")?;

        // --- Create TLS server config with client authentication ---
        let config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier) // Require and verify a client cert
            .with_single_cert(cert_chain, private_key)
            .context("Failed to create TLS config")?;

        Ok(Self {
            tls_config: Arc::new(config),
        })
    }

    fn run(&self) -> Result<()> {
        // Use UnixListener instead of interprocess listener for better control
        let socket_path = "flyme.sock";

        let listener =
            bind_abstract_socket(socket_path).context("Failed to bind abstract Unix socket")?;

        // The name shown in logs will have a leading @ on Linux
        info!(
            "Server listening for connections on abstract socket: {}...",
            socket_path
        );

        for stream in listener.incoming() {
            match stream {
                Ok(unix_stream) => {
                    let config = Arc::clone(&self.tls_config);
                    thread::spawn(move || {
                        if let Err(e) = Self::handle_client_unix(unix_stream, config) {
                            if let Some(io_err) = e.downcast_ref::<io::Error>() {
                                if io_err.kind() == io::ErrorKind::UnexpectedEof {
                                    info!("Client closed connection cleanly.");
                                    return;
                                }
                            }
                            error!("Client handler error: {e:?}");
                        }
                    });
                }
                Err(e) => {
                    error!("Incoming connection failed: {e}");
                }
            }
        }

        Ok(())
    }

    /// Get the binary hash of a process given its PID
    fn get_process_binary_hash(pid: u32) -> Result<String> {
        // Read the executable path from /proc/PID/exe
        let exe_path = format!("/proc/{}/exe", pid);
        let exe_path = fs::read_link(&exe_path)
            .with_context(|| format!("Failed to read executable path for PID {}", pid))?;

        info!("Client binary path: {:?}", exe_path);

        // --- HASHING LOGIC CHANGED HERE ---

        // 1. Create a new SHA-256 hasher instance.
        let mut hasher = Sha256::new();

        // 2. Open the binary file for reading.
        let mut file = fs::File::open(&exe_path)
            .with_context(|| format!("Failed to open binary file for hashing: {:?}", exe_path))?;

        // 3. Copy the file's contents into the hasher. This is memory-efficient.
        io::copy(&mut file, &mut hasher)
            .with_context(|| format!("Failed to hash binary file: {:?}", exe_path))?;

        // 4. Finalize the hash and get the result as a byte array.
        let hash_bytes = hasher.finalize();

        // 5. Format the byte array as a lowercase hexadecimal string.
        let hash_string = format!("{:x}", hash_bytes);

        Ok(hash_string)
    }

    fn handle_client_unix(unix_stream: UnixStream, config: Arc<ServerConfig>) -> Result<()> {
        // Get client PID before TLS handshake
        let client_pid = peer_creds::get_peer_pid_from_unix_stream(&unix_stream)
            .context("Failed to get client PID")?;

        info!("New client connected with PID: {}", client_pid);

        // Compute client binary hash
        match Self::get_process_binary_hash(client_pid) {
            Ok(hash) => {
                info!("Client binary hash: {}", hash);
            }
            Err(e) => {
                warn!("Failed to compute client binary hash: {}", e);
            }
        }

        info!("Performing TLS handshake...");
        let mut tls_conn = ServerConnection::new(config)?;

        // Convert UnixStream to something rustls can work with
        let mut stream_wrapper = UnixStreamWrapper::new(unix_stream);
        let mut tls_stream = rustls::Stream::new(&mut tls_conn, &mut stream_wrapper);

        let mut request_buf = Vec::new();
        tls_stream
            .read_to_end(&mut request_buf)
            .context("Failed to read request from TLS stream")?;

        if request_buf.is_empty() {
            info!("Client connected but sent no data.");
            return Ok(());
        }

        match bincode::deserialize::<IpcMessage>(&request_buf) {
            Ok(message) => {
                info!("Received message: {message:?}");
                let response = Self::process_message(message, client_pid);
                let response_data = bincode::serialize(&response)?;
                tls_stream.write_all(&response_data)?;
                tls_stream.flush()?;
                tls_stream.conn.send_close_notify();
                tls_stream.flush()?;
            }
            Err(e) => {
                warn!("Failed to deserialize client message: {e}");
            }
        }

        info!("Request handled. Closing connection cleanly.");
        Ok(())
    }

    fn process_message(msg: IpcMessage, client_pid: u32) -> IpcMessage {
        match msg {
            IpcMessage::Ping(data) => {
                info!("Processing ping from PID {}: {}", client_pid, data);
                IpcMessage::Pong(format!("Echo from PID {}: {}", client_pid, data))
            }
            IpcMessage::Request { id, command, args } => {
                info!(
                    "Processing request {id} from PID {client_pid}: {command} with args {args:?}"
                );
                match command.as_str() {
                    "status" => IpcMessage::Response {
                        id,
                        success: true,
                        data: format!(
                            "Server is running with root privileges. Client PID: {}",
                            client_pid
                        ),
                    },
                    "list" => IpcMessage::Response {
                        id,
                        success: true,
                        data: format!("Files: {args:?} (requested by PID {})", client_pid),
                    },
                    "privileged_op" => {
                        // You can add client binary verification here
                        match Self::get_process_binary_hash(client_pid) {
                            Ok(hash) => {
                                info!("Verifying client binary hash: {}", hash);
                                // Add your hash verification logic here
                                // For now, just proceed with the operation
                                IpcMessage::Response {
                                    id,
                                    success: true,
                                    data: format!("Privileged operation completed successfully for verified client (PID: {}, Hash: {})", client_pid, hash),
                                }
                            }
                            Err(e) => {
                                warn!("Failed to verify client binary: {}", e);
                                IpcMessage::Error {
                                    id,
                                    message: "Failed to verify client binary".to_string(),
                                }
                            }
                        }
                    }
                    _ => IpcMessage::Error {
                        id,
                        message: format!("Unknown command: {command}"),
                    },
                }
            }
            other => {
                warn!("Unhandled message type from PID {client_pid}: {other:?}");
                IpcMessage::Error {
                    id: 0,
                    message: "Unhandled message type".to_string(),
                }
            }
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&args.log_level))
        .init();
    info!("Starting secure IPC server...");
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        if uid != 0 {
            warn!("Server not running as root - some operations may fail");
        } else {
            info!("Server running with root privileges");
        }
    }
    let cert_paths = ServerCertPaths::new();
    let server = SecureIpcServer::new(cert_paths).context("Failed to create server")?;
    server.run().context("Server error")?;
    Ok(())
}
