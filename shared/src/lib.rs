use interprocess::local_socket::{GenericNamespaced, ToNsName};
use serde::{Deserialize, Serialize};
use std::io;

pub mod config;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    Ping(String),
    Pong(String),
    Request {
        id: u32,
        command: String,
        args: Vec<String>,
    },
    Response {
        id: u32,
        success: bool,
        data: String,
    },
    Error {
        id: u32,
        message: String,
    },
}
// Using a .sock extension is a common convention that works well with GenericNamespaced.
pub const SERVER_SOCKET_NAME: &str = "flyme.sock";

/// Returns a platform-agnostic, namespaced socket name.
/// This uses the abstract namespace on Linux and a file path in /tmp on other Unixes.
/// On Windows, it uses the named pipe namespace.
pub fn get_socket_name() -> io::Result<interprocess::local_socket::Name<'static>> {
    SERVER_SOCKET_NAME.to_ns_name::<GenericNamespaced>()
}
