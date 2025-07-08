use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use flyme_server::SecureIpcServer;
use flyme_common::{config::ServerCertPath, SOCKET_NAME};
use tracing::{error, info, warn};

/// Daemon server example with signal handling and graceful shutdown
fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("=== Secure IPC Daemon Server Example ===");
    println!("This example demonstrates a long-running server with signal handling");

    // Set up signal handling for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        info!("Received shutdown signal, stopping server...");
        r.store(false, Ordering::SeqCst);
    })
    .context("Failed to set signal handler")?;

    // Create server certificate paths
    let cert_path = ServerCertPath::new();
    
    println!("Certificate paths:");
    println!("  - Server cert: {:?}", cert_path.cert_path);
    println!("  - Server key: {:?}", cert_path.key_path);
    println!("  - CA cert: {:?}", cert_path.ca_path);

    // Check if certificates exist
    if !cert_path.cert_path.exists() {
        warn!("Server certificate not found at {:?}", cert_path.cert_path);
        println!("Please generate certificates first using:");
        println!("  ./scripts/generate_test_certs.sh");
        println!("Exiting...");
        return Ok(());
    }

    // Create the server
    let socket_name = SOCKET_NAME.to_string();
    let server = SecureIpcServer::new(cert_path, socket_name.clone())
        .context("Failed to create secure IPC server")?;

    println!("✓ Server created successfully");
    println!("Socket name: {}", socket_name);
    println!("Server will listen on: /tmp/{}", socket_name);
    println!("Press Ctrl+C to stop the server gracefully");
    println!();

    // Start the server in a separate thread so we can handle signals
    let server_handle = {
        let server = server.clone();
        let running = running.clone();
        std::thread::spawn(move || {
            info!("Starting secure IPC server...");
            match server.run_with_shutdown(running) {
                Ok(()) => info!("Server stopped normally"),
                Err(e) => error!("Server error: {}", e),
            }
        })
    };

    // Main loop - wait for shutdown signal
    let mut connection_count = 0;
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(5));
        
        // Simulate some server activity
        connection_count += 1;
        if connection_count % 6 == 0 { // Every 30 seconds
            info!("Server running for {} seconds...", connection_count * 5);
        }
    }

    // Graceful shutdown
    info!("Shutting down server gracefully...");
    
    // Give the server a moment to finish any ongoing operations
    std::thread::sleep(Duration::from_secs(1));
    
    // Wait for server thread to finish (with timeout)
    let timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();
    
    while !server_handle.is_finished() && start.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(100));
    }
    
    if !server_handle.is_finished() {
        warn!("Server thread did not finish within timeout, forcing shutdown");
    }
    
    match server_handle.join() {
        Ok(_) => info!("Server thread finished successfully"),
        Err(_) => error!("Server thread panicked"),
    }

    println!("✓ Server shutdown completed");
    Ok(())
} 