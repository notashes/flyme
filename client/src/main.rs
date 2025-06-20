use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use client_lib::{
    execute_command, get_server_status, list_files, quick_ping, run_privileged_operation,
};
use log::info;

#[derive(Parser)]
#[command(name = "client")]
#[command(about = "Secure IPC Client")]
struct Args {
    #[arg(short, long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a ping message to the server
    Ping {
        /// Message to send
        message: String,
    },
    /// Get server status
    Status,
    /// List files (simulate)
    List {
        /// Paths to list
        paths: Vec<String>,
    },
    /// Run a privileged operation
    Privileged,
    /// Send a custom command
    Custom {
        /// Command to execute
        command: String,
        /// Command arguments
        #[arg(short, long)]
        args: Vec<String>,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&args.log_level))
        .init();

    info!("Starting secure IPC client...");

    // Check that we're not running as root (for security)
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            eprintln!("Warning: Client should not run as root for security reasons");
        }
    }

    match args.command {
        Commands::Ping { message } => {
            let response = quick_ping(&message).context("Failed to ping server")?;
            println!("Server response: {response}");
        }

        Commands::Status => {
            let status = get_server_status().context("Failed to get server status")?;
            println!("Server status: {status}");
        }

        Commands::List { paths } => {
            let result = list_files(paths).context("Failed to list files")?;
            println!("List result: {result}");
        }

        Commands::Privileged => {
            let result =
                run_privileged_operation().context("Failed to run privileged operation")?;
            println!("Privileged operation result: {result}");
        }

        Commands::Custom { command, args } => {
            let result =
                execute_command(&command, args).context("Failed to execute custom command")?;
            println!("Command result: {result}");
        }
    }

    Ok(())
}
