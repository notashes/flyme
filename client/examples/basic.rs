use std::time::Duration;

use anyhow::Result;
use flyme_client::{ClientCertPath, ClientConfig, SecureIpcClient, SOCKET_NAME};

fn main() -> Result<()> {
    // Install default crypto provider for rustls
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install crypto provider"))?;

    println!("=== Secure IPC Client Basic Example ===");

    // Example 1: Using default configuration
    println!("\n1. Using default configuration:");
    example_with_defaults()?;

    // Example 2: Using custom configuration
    println!("\n2. Using custom configuration:");
    example_with_custom_config()?;

    // Example 3: One-shot operations
    println!("\n3. One-shot operations:");
    example_one_shot_operations()?;

    println!("\n✓ All examples completed successfully!");
    Ok(())
}

fn example_with_defaults() -> Result<()> {
    println!("Creating client with default configuration...");

    let mut client = SecureIpcClient::with_defaults()?;

    println!("Connecting...");
    client.connect()?;

    println!("Sending ping...");
    client.ping()?;

    println!("Getting server status...");
    let status = client.send_request("status")?;
    println!("Server status: {status}");

    println!("Disconnecting...");
    client.disconnect()?;

    println!("✓ Default configuration example completed");
    Ok(())
}

fn example_with_custom_config() -> Result<()> {
    println!("Creating client with custom configuration...");

    let config = ClientConfig::new()
        .with_cert_path(ClientCertPath::new())
        .with_socket_name(SOCKET_NAME)
        .with_timeout(Duration::from_secs(5))
        .with_verbose(false); // Disable verbose logging for this example

    let mut client = SecureIpcClient::new(config)?;

    println!("Testing connection...");
    client.test_connection()?;

    println!("Getting client stats...");
    let stats = client.get_stats();
    println!("Client connected: {}", stats.connected);
    println!("Requests sent: {}", stats.requests_sent);
    println!("Timeout: {:?}", stats.timeout);

    println!("✓ Custom configuration example completed");
    Ok(())
}

fn example_one_shot_operations() -> Result<()> {
    println!("Performing one-shot operations...");

    let config = ClientConfig::new();

    // Quick ping
    println!("Quick ping test...");
    SecureIpcClient::quick_ping(config.clone())?;
    println!("✓ Ping successful");

    // Execute single command
    println!("Executing single command...");
    let response = SecureIpcClient::execute_command(config.clone(), "version")?;
    println!("Server version: {response}");

    // Health check
    println!("Running health check...");
    SecureIpcClient::health_check(config)?;
    println!("✓ Health check passed");

    println!("✓ One-shot operations completed");
    Ok(())
}
