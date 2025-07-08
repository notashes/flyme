use std::io::{self, Read, Write};

use anyhow::{Context, Result};
use rustls::{ClientConnection, Connection, ServerConnection};

use crate::{config::IpcMessage, platform_socket::PlatformSocket};

/// Synchronous TLS wrapper for platform-specific sockets
pub struct TlsStream {
    socket: PlatformSocket,
    tls:    Connection,
}

impl TlsStream {
    /// Create a new TLS stream from a server connection and complete the
    /// handshake
    pub fn from_server(socket: PlatformSocket, tls: ServerConnection) -> Result<Self> {
        let mut stream = Self {
            socket,
            tls: Connection::Server(tls),
        };
        stream.complete_handshake()?;
        Ok(stream)
    }

    /// Create a new TLS stream from a client connection and complete the
    /// handshake
    pub fn from_client(socket: PlatformSocket, tls: ClientConnection) -> Result<Self> {
        let mut stream = Self {
            socket,
            tls: Connection::Client(tls),
        };
        stream.complete_handshake()?;
        Ok(stream)
    }

    /// Complete the TLS handshake
    fn complete_handshake(&mut self) -> Result<()> {
        while self.tls.is_handshaking() {
            if self.tls.wants_write() {
                self.tls.write_tls(&mut self.socket)?;
            }
            if self.tls.wants_read() {
                self.tls.read_tls(&mut self.socket)?;
                self.tls
                    .process_new_packets()
                    .map_err(|e| anyhow::anyhow!("TLS handshake error: {}", e))?;
            }
        }
        Ok(())
    }

    /// Send an IPC message over the secure connection
    pub fn send_message(&mut self, msg: &IpcMessage) -> Result<()> {
        let serialized = bincode::serialize(msg).context("Failed to serialize message")?;
        let len = serialized.len() as u32;

        self.write_all(&len.to_le_bytes())
            .context("Failed to send message length")?;

        self.write_all(&serialized)
            .context("Failed to send message data")?;

        self.flush().context("Failed to flush stream")?;
        Ok(())
    }

    /// Receive an IPC message from the secure connection
    pub fn recv_message(&mut self) -> Result<IpcMessage> {
        let mut len_buf = [0u8; 4];
        self.read_exact(&mut len_buf)
            .context("Failed to read message length")?;
        let len = u32::from_le_bytes(len_buf) as usize;

        if len > 1024 * 1024 {
            // 1MB limit
            return Err(anyhow::anyhow!("Message too large: {} bytes", len));
        }

        let mut msg_buf = vec![0u8; len];
        self.read_exact(&mut msg_buf)
            .context("Failed to read message data")?;

        let msg = bincode::deserialize(&msg_buf).context("Failed to deserialize message")?;
        Ok(msg)
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Try to read buffered plaintext first
        if let Ok(n) = self.tls.reader().read(buf) {
            return Ok(n);
        }

        // Need more TLS data - check if we can read more
        if !self.tls.wants_read() {
            return Ok(0); // EOF
        }

        // Read and process new TLS data
        match self.tls.read_tls(&mut self.socket) {
            Ok(0) => Ok(0), // Clean shutdown
            Ok(_) => {
                // Process TLS packets and try reading again
                self.tls
                    .process_new_packets()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                self.tls.reader().read(buf)
            }
            Err(e) => Err(e),
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.tls.writer().write(buf)?;

        // Flush TLS data to socket (ignore WouldBlock in blocking mode)
        while self.tls.wants_write() {
            if let Err(e) = self.tls.write_tls(&mut self.socket) {
                if e.kind() != io::ErrorKind::WouldBlock {
                    return Err(e);
                }
                break;
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Ensure any buffered plaintext is passed to the TLS session
        self.tls.writer().flush()?;

        // Try to send all pending buffered TLS data to the socket
        while self.tls.wants_write() {
            match self.tls.write_tls(&mut self.socket) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        // Finally, flush the underlying socket
        self.socket.flush()
    }
}
