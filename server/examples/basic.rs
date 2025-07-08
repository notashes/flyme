use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use flyme_server::SecureIpcServer;
use flyme_common::{config::ServerCertPath, SOCKET_NAME};
use tracing::warn;

/// Basic example of running a secure IPC server
fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("=== Secure IPC Server Basic Example ===");

    // Example 1: Using default certificate paths
    println!("\n1. Starting server with default certificate paths:");
    example_with_default_certs()?;

    // Example 2: Using custom certificate paths
    println!("\n2. Starting server with custom certificate paths:");
    example_with_custom_certs()?;

    println!("\n✓ All server examples completed successfully!");
    Ok(())
}

fn example_with_default_certs() -> Result<()> {
    println!("Setting up server with default certificate paths...");

    // Create server certificate paths with default locations
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
        println!("Skipping this example...");
        return Ok(());
    }

    // Create and start the server
    let socket_name = SOCKET_NAME.to_string();
    let _server = SecureIpcServer::new(cert_path, socket_name.clone())
        .context("Failed to create secure IPC server")?;

    println!("✓ Server created successfully");
    println!("Socket name: {}", socket_name);
    println!("Server will listen on: /tmp/{}", socket_name);
    
    // Note: In a real application, you would call server.run() here
    // For this example, we'll just show the setup
    println!("Server is ready to accept connections!");
    println!("(Press Ctrl+C to stop the server)");

    // Simulate server running for a short time
    std::thread::sleep(Duration::from_secs(2));
    
    println!("✓ Default certificate example completed");
    Ok(())
}

fn example_with_custom_certs() -> Result<()> {
    println!("Setting up server with custom certificate paths...");

    // Create custom certificate paths
    let cert_path = ServerCertPath {
        cert_path: PathBuf::from("certs/agent/server.pem"),
        key_path: PathBuf::from("certs/agent/server.key.pem"),
        ca_path: PathBuf::from("certs/root-ca.pem"),
    };

    println!("Custom certificate paths:");
    println!("  - Server cert: {:?}", cert_path.cert_path);
    println!("  - Server key: {:?}", cert_path.key_path);
    println!("  - CA cert: {:?}", cert_path.ca_path);

    // Check if certificates exist
    if !cert_path.cert_path.exists() {
        warn!("Server certificate not found at {:?}", cert_path.cert_path);
        println!("Please generate certificates first using:");
        println!("  ./scripts/generate_test_certs.sh");
        println!("Skipping this example...");
        return Ok(());
    }

    // Create server with custom socket name
    let socket_name = "custom-secure-ipc".to_string();
    let _server = SecureIpcServer::new(cert_path, socket_name.clone())
        .context("Failed to create secure IPC server with custom certificates")?;

    println!("✓ Server created successfully with custom certificates");
    println!("Socket name: {}", socket_name);
    println!("Server will listen on: /tmp/{}", socket_name);

    // Show server configuration
    println!("Server configuration:");
    println!("  - Socket: /tmp/{}", socket_name);
    println!("  - TLS: Enabled with mutual authentication");
    println!("  - Client validation: Enabled");
    println!("  - Binary hash validation: Configurable via environment");

    // Simulate server running for a short time
    std::thread::sleep(Duration::from_secs(2));

    println!("✓ Custom certificate example completed");
    Ok(())
} 