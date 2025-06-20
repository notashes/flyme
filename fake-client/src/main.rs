use anyhow::{Context, Result};
use interprocess::local_socket::prelude::*;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls_pemfile::certs;
use shared::config::ClientCertPaths;
use std::io::{BufReader, Write};
use std::sync::Arc;

fn main() -> Result<()> {
    println!("--- Starting Fake Client ---");
    println!("This client will attempt to connect WITHOUT a valid client certificate.");
    println!("The connection is expected to fail during the TLS handshake.");

    // --- Certificate Loading (only the Root CA to verify the server) ---
    let paths = ClientCertPaths::new();
    println!("Loading Root CA from: {:?}", paths.ca_path);

    // Load Root CA to verify the server's certificate.
    let ca_pem = std::fs::read(&paths.ca_path)
        .with_context(|| format!("Failed to read root CA from {:?}", paths.ca_path))?;
    let mut root_store = RootCertStore::empty();
    let ca_certs_vec = certs(&mut BufReader::new(&*ca_pem))
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse root CA certificate")?;
    root_store.add_parsable_certificates(ca_certs_vec);

    // --- Create a TLS client config WITHOUT client authentication ---
    // This is the key difference. We don't call `.with_client_auth_cert()`.
    // The server requires a client cert, so this configuration is invalid for our server.
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth(); // Explicitly configure no client certificate.

    let tls_config = Arc::new(config);

    // --- Connect to the server's socket ---
    println!("\nAttempting to connect to the server socket...");
    let name = shared::get_socket_name().context("Failed to create socket name")?;
    let mut stream = LocalSocketStream::connect(name.clone())
        .context(format!("Failed to connect to server IPC socket: {name:?}"))?;
    println!("Socket connection established. Starting TLS handshake...");

    let server_name = "localhost"
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid server name"))?;
    let mut tls_conn = ClientConnection::new(tls_config, server_name)?;
    let mut tls_stream = rustls::Stream::new(&mut tls_conn, &mut stream);

    // --- Attempt to communicate ---
    // The handshake happens implicitly during the first read/write.
    // The server will request a client certificate. Since our config doesn't have one,
    // the handshake will fail. The `write_all` call will return an error.
    let message_to_send = b"hello from the fake client";
    println!("Attempting to write to the TLS stream (this should fail)...");

    match tls_stream.write_all(message_to_send) {
        Ok(_) => {
            eprintln!("\nERROR: FAKE CLIENT UNEXPECTEDLY SUCCEEDED!");
            eprintln!(
                "The server should have rejected the connection. Check server TLS configuration."
            );
            anyhow::bail!("Connection was expected to fail but it succeeded.");
        }
        Err(e) => {
            println!("\nSUCCESS: The write operation failed as expected!");
            println!("Error details: {e}");
            println!("\nThis demonstrates that the server correctly rejected the connection because the client did not provide a required certificate.");
        }
    }

    Ok(())
}
