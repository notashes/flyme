use anyhow::Result;
use client_lib::{execute_command, get_server_status, quick_ping, SecureIpcClient};
use log::info;

fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();

    println!("=== Secure IPC Client Library Usage Examples ===\n");

    // Example 1: Simple ping using convenience function
    println!("1. Simple ping:");
    match quick_ping("Hello from example!") {
        Ok(response) => println!("   Response: {response}"),
        Err(e) => println!("   Error: {e}"),
    }

    // Example 2: Get server status
    println!("\n2. Server status:");
    match get_server_status() {
        Ok(status) => println!("   Status: {status}"),
        Err(e) => println!("   Error: {e}"),
    }

    // Example 3: Execute custom command
    println!("\n3. Custom command:");
    match execute_command("list", vec!["/tmp".to_string(), "/var".to_string()]) {
        Ok(result) => println!("   Result: {result}"),
        Err(e) => println!("   Error: {e}"),
    }

    // Example 4: Using the client directly for multiple operations
    println!("\n4. Multiple operations with persistent client:");
    match SecureIpcClient::new() {
        Ok(client) => {
            // Multiple pings
            for i in 1..=3 {
                match client.ping(&format!("Message {i}")) {
                    Ok(response) => println!("   Ping {i}: {response}"),
                    Err(e) => println!("   Ping {i} failed: {e}"),
                }
            }

            // Multiple requests
            let commands = vec![
                ("status", vec![]),
                ("privileged_op", vec![]),
                ("unknown_command", vec!["arg1".to_string()]),
            ];

            for (cmd, args) in commands {
                match client.send_request(cmd, args) {
                    Ok(result) => println!("   Command '{cmd}': {result}"),
                    Err(e) => println!("   Command '{cmd}' failed: {e}"),
                }
            }
        }
        Err(e) => println!("   Failed to create client: {e}"),
    }

    println!("\n=== Examples completed ===");
    Ok(())
}

// Example of integrating the client library into a larger application
pub struct MyApplication {
    ipc_client: SecureIpcClient,
}

impl MyApplication {
    pub fn new() -> Result<Self> {
        let ipc_client = SecureIpcClient::new()?;
        Ok(Self { ipc_client })
    }

    pub fn perform_privileged_task(&self, task_name: &str) -> Result<String> {
        info!("Requesting privileged task: {task_name}");

        // Send request to server running with root privileges
        let result = self
            .ipc_client
            .send_request("privileged_op", vec![task_name.to_string()])?;

        info!("Privileged task completed: {result}");
        Ok(result)
    }

    pub fn check_system_status(&self) -> Result<bool> {
        let status = self.ipc_client.send_request("status", vec![])?;
        Ok(status.contains("running"))
    }

    pub fn ping_server(&self) -> Result<bool> {
        match self.ipc_client.ping("health_check") {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
