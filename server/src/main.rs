use anyhow::{anyhow, Context, Result};
use clap::Parser;
use interprocess::local_socket::{prelude::*, ListenerOptions};
use log::{error, info, warn};
use rustls::server::{ServerConfig, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConnection};
use rustls_pemfile::{certs, private_key};
use shared::{config::ServerCertPaths, IpcMessage};
use std::io::{self, BufReader, Read, Write};
use std::sync::Arc;
use std::thread;

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
        fn handle_error(conn: io::Result<LocalSocketStream>) -> Option<LocalSocketStream> {
            match conn {
                Ok(c) => Some(c),
                Err(e) => {
                    error!("Incoming connection failed: {e}");
                    None
                }
            }
        }

        let name = shared::get_socket_name().context("Failed to create socket name")?;

        let listener = ListenerOptions::new()
            .name(name.clone())
            .create_sync()
            .map_err(|e| {
                if e.kind() == io::ErrorKind::AddrInUse {
                    error!("Error: Could not start server because the socket name is occupied: {name:?}");
                    warn!("This might mean another server instance is running, or a socket file from a crashed instance was left behind.");
                }
                anyhow::Error::new(e)
            })
            .context("Failed to create listener")?;

        info!("Server listening for connections on {name:?}...");

        for stream in listener.incoming().filter_map(handle_error) {
            let config = Arc::clone(&self.tls_config);
            thread::spawn(move || {
                if let Err(e) = Self::handle_client(stream, config) {
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

        Ok(())
    }

    fn handle_client(mut stream: LocalSocketStream, config: Arc<ServerConfig>) -> Result<()> {
        info!("New client connected, performing TLS handshake...");
        let mut tls_conn = ServerConnection::new(config)?;
        let mut tls_stream = rustls::Stream::new(&mut tls_conn, &mut stream);

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
                let response = Self::process_message(message);
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

    fn process_message(msg: IpcMessage) -> IpcMessage {
        match msg {
            IpcMessage::Ping(data) => {
                info!("Processing ping: {data}");
                IpcMessage::Pong(format!("Echo: {data}"))
            }
            IpcMessage::Request { id, command, args } => {
                info!("Processing request {id}: {command} with args {args:?}");
                match command.as_str() {
                    "status" => IpcMessage::Response {
                        id,
                        success: true,
                        data: "Server is running with root privileges".to_string(),
                    },
                    "list" => IpcMessage::Response {
                        id,
                        success: true,
                        data: format!("Files: {args:?}"),
                    },
                    "privileged_op" => IpcMessage::Response {
                        id,
                        success: true,
                        data: "Privileged operation completed successfully".to_string(),
                    },
                    _ => IpcMessage::Error {
                        id,
                        message: format!("Unknown command: {command}"),
                    },
                }
            }
            other => {
                warn!("Unhandled message type: {other:?}");
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
