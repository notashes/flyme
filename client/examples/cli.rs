use anyhow::{anyhow, Context, Result};
use flyme_client::{ClientCertPath, ClientConfig, SecureIpcClient, SOCKET_NAME};

/// Interactive CLI for testing the Secure IPC server
struct InteractiveCli {
    client: SecureIpcClient,
}

impl InteractiveCli {
    /// Create a new interactive CLI with the given configuration
    fn new(config: ClientConfig) -> Result<Self> {
        let client = SecureIpcClient::new(config)?;
        Ok(Self { client })
    }

    /// Run the interactive session
    fn run(&mut self) -> Result<()> {
        if !self.client.is_connected() {
            self.client.connect()?;
        }

        println!("Starting interactive session. Type 'help' for commands, 'quit' to exit.");
        println!("Special commands:");
        println!("  ping              - Send ping and wait for pong");
        println!("  shutdown-server   - Send shutdown command to server");
        println!("  disconnect        - Disconnect from server");
        println!("  connect           - Connect to server");
        println!("  status-client     - Show client connection status");
        println!("  help              - Show this help");
        println!("  quit/exit         - Exit interactive mode");
        println!();

        loop {
            print!("secure-ipc> ");
            std::io::Write::flush(&mut std::io::stdout())?;

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let command = input.trim();

            if command.is_empty() {
                continue;
            }

            match command {
                "quit" | "exit" => {
                    println!("Goodbye!");
                    break;
                }
                "ping" => {
                    if let Err(e) = self.client.ping() {
                        eprintln!("Ping failed: {e}");
                    }
                }
                "shutdown-server" => {
                    match self.client.shutdown_server() {
                        Ok(()) => {
                            println!("Server shutdown successful");
                            if !self.client.is_connected() {
                                println!("Connection closed by server");
                            }
                        }
                        Err(e) => eprintln!("Shutdown failed: {e}"),
                    }
                }
                "disconnect" => {
                    self.client.disconnect()?;
                    println!("Disconnected. Use 'connect' to reconnect.");
                }
                "connect" => {
                    if self.client.is_connected() {
                        println!("Already connected.");
                    } else {
                        match self.client.connect() {
                            Ok(()) => println!("Connected successfully."),
                            Err(e) => eprintln!("Connection failed: {e}"),
                        }
                    }
                }
                "status-client" => {
                    let stats = self.client.get_stats();
                    if stats.connected {
                        println!("Status: Connected to {}", stats.socket_name);
                        println!("Timeout: {:?}", stats.timeout);
                        println!("Requests sent: {}", stats.requests_sent);
                    } else {
                        println!("Status: Not connected");
                    }
                }
                "help" => {
                    println!("Available commands:");
                    println!("  Server commands:");
                    println!("    status         - Get server status");
                    println!("    version        - Get server version");
                    println!("    echo <text>    - Echo text back");
                    println!();
                    println!("  Client commands:");
                    println!("    ping              - Send ping and wait for pong");
                    println!("    shutdown-server   - Send shutdown command to server");
                    println!("    disconnect        - Disconnect from server");
                    println!("    connect           - Connect to server");
                    println!("    status-client     - Show client connection status");
                    println!("    quit/exit         - Exit interactive mode");
                }
                cmd => {
                    if !self.client.is_connected() {
                        eprintln!("Not connected. Use 'connect' first.");
                        continue;
                    }

                    match self.client.send_request(cmd) {
                        Ok(response) => {
                            println!("Response: {response}");
                        }
                        Err(e) => {
                            eprintln!("Request failed: {e}");
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    // Install default crypto provider for rustls
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow!("Failed to install crypto provider"))?;

    println!("=== Secure IPC Client CLI ===");

    let args: Vec<String> = std::env::args().collect();

    println!("Initializing certificate paths...");
    let cert_path = ClientCertPath::new();
    let socket_name = SOCKET_NAME.to_string();

    println!("Socket name: {socket_name}");

    if args.len() < 2 {
        println!("Secure IPC Client CLI");
        println!("Usage:");
        println!(
            "  {} interactive         - Start interactive session",
            args[0]
        );
        println!("  {} test               - Run connection test", args[0]);
        println!("  {} ping               - Quick ping test", args[0]);
        println!("  {} shutdown           - Send shutdown to server", args[0]);
        println!("  {} <command>          - Execute single command", args[0]);
        println!();
        println!("Example commands: status, version, echo");
        println!("Special message types: ping, shutdown");
        return Ok(());
    }

    match args[1].as_str() {
        "interactive" => {
            println!("Starting interactive mode...");
            let config = ClientConfig::new()
                .with_cert_path(cert_path)
                .with_socket_name(socket_name)
                .with_verbose(true);

            let mut cli =
                InteractiveCli::new(config).context("Failed to create interactive CLI")?;
            cli.run().context("Interactive session failed")?;
        }
        "test" => {
            println!("Running connection test...");
            let config = ClientConfig::new()
                .with_cert_path(cert_path)
                .with_socket_name(socket_name)
                .with_verbose(true);

            SecureIpcClient::health_check(config).context("Connection test failed")?;
        }
        "ping" => {
            println!("Testing connection...");
            let config = ClientConfig::new()
                .with_cert_path(cert_path)
                .with_socket_name(socket_name)
                .with_verbose(true); // Add verbose output

            SecureIpcClient::quick_ping(config).context("Ping test failed")?;
            println!("✓ Ping successful");
        }
        "shutdown" => {
            println!("Sending shutdown command to server...");
            let config = ClientConfig::new()
                .with_cert_path(cert_path)
                .with_socket_name(socket_name)
                .with_verbose(true);

            let mut client = SecureIpcClient::new(config)
                .context("Failed to create secure IPC client for shutdown")?;
            client.connect().context("Failed to connect for shutdown")?;
            client
                .shutdown_server()
                .context("Shutdown command failed")?;
            println!("✓ Shutdown command sent successfully");
        }
        cmd => {
            println!("Executing command: {cmd}");
            let config = ClientConfig::new()
                .with_cert_path(cert_path)
                .with_socket_name(socket_name);

            let response = SecureIpcClient::execute_command(config, cmd)
                .with_context(|| format!("Failed to execute command: {cmd}"))?;
            println!("Response: {response}");
        }
    }

    Ok(())
}
