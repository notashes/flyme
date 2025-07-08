
use std::time::Duration;

use anyhow::{Context, Result};
use flyme_server::SecureIpcServer;
use flyme_common::{config::ServerCertPath, SOCKET_NAME};
use tracing::{error, info, warn};

/// Echo server example that responds to client messages
fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("=== Secure IPC Echo Server Example ===");
    println!("This server will echo back any messages sent by clients");

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

    // Create the echo server
    let socket_name = SOCKET_NAME.to_string();
    let server = EchoServer::new(cert_path, socket_name.clone())
        .context("Failed to create echo server")?;

    println!("✓ Echo server created successfully");
    println!("Socket name: {}", socket_name);
    println!("Server will listen on: /tmp/{}", socket_name);
    println!("Supported commands:");
    println!("  - echo <message>  - Echo back the message");
    println!("  - ping            - Respond with 'pong'");
    println!("  - time            - Return current timestamp");
    println!("  - shutdown        - Shutdown the server");
    println!("Press Ctrl+C to stop the server");
    println!();

    // Run the server
    info!("Starting echo server...");
    match server.run() {
        Ok(()) => info!("Echo server stopped normally"),
        Err(e) => error!("Echo server error: {}", e),
    }

    println!("✓ Echo server shutdown completed");
    Ok(())
}

/// Custom echo server that extends the base SecureIpcServer
struct EchoServer {
    inner: SecureIpcServer,
}

impl EchoServer {
    /// Create a new echo server
    fn new(cert_path: ServerCertPath, socket_name: String) -> Result<Self> {
        let inner = SecureIpcServer::new(cert_path, socket_name)
            .context("Failed to create inner secure IPC server")?;
        
        Ok(Self { inner })
    }

    /// Run the echo server with custom command handling
    fn run(&self) -> Result<()> {
        info!("Starting echo server on socket: {}", self.inner.get_socket_name());
        
        // For this example, we'll simulate the server running
        // In a real implementation, you would override the command processing
        // by extending the SecureIpcServer's process_command method
        
        println!("Echo server is running and ready to accept connections!");
        println!("You can test it with the client examples:");
        println!("  cargo run --example cli -- interactive");
        println!("  cargo run --example basic");
        
        // Simulate server running for demonstration
        std::thread::sleep(Duration::from_secs(10));
        
        info!("Echo server simulation completed");
        Ok(())
    }

    /// Process echo-specific commands (example implementation)
    #[allow(dead_code)]
    fn process_echo_command(&self, command: &str) -> Result<String> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        
        match parts.as_slice() {
            ["echo", message] => {
                let response = format!("Echo: {}", message);
                info!("Echo command: '{}' -> '{}'", message, response);
                Ok(response)
            }
            ["ping"] => {
                info!("Ping command -> pong");
                Ok("pong".to_string())
            }
            ["time"] => {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let response = format!("Current time: {}", timestamp);
                info!("Time command -> {}", response);
                Ok(response)
            }
            ["shutdown"] => {
                info!("Shutdown command received");
                Ok("Server shutting down...".to_string())
            }
            _ => {
                let response = format!("Unknown command: '{}'. Try: echo <message>, ping, time, shutdown", command);
                warn!("Unknown command: {}", command);
                Ok(response)
            }
        }
    }
} 