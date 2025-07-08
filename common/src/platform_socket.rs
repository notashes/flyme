#[cfg(windows)]
use std::ffi::CString;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
use std::ptr;

use anyhow::{anyhow, Context, Result};
// Platform-specific imports
// cfg for unix except macos
#[cfg(all(unix, not(target_os = "macos")))]
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use tracing;
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::*, Storage::FileSystem::*, System::Pipes::*, System::Threading::*,
};

/// Cross-platform socket wrapper
pub enum PlatformSocket {
    #[cfg(unix)]
    /// Unix domain socket
    Unix(UnixStream),
    #[cfg(windows)]
    /// Windows named pipe handle
    NamedPipe(HANDLE),
}

/// Cross-platform socket listener
pub enum PlatformListener {
    #[cfg(unix)]
    /// Unix domain socket listener
    Unix(UnixListener),
    #[cfg(windows)]
    /// Windows named pipe name
    NamedPipe(String), // Pipe name for Windows
}

/// Client credentials extracted from socket
#[derive(Debug)]
pub struct ClientCredentials {
    /// Process ID of the client
    pub pid: u32,
    /// User ID of the client
    pub uid: u32,
}

impl PlatformSocket {
    /// Set the socket to blocking or non-blocking mode
    pub fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            PlatformSocket::Unix(stream) => stream.set_nonblocking(nonblocking),
            #[cfg(windows)]
            PlatformSocket::NamedPipe(handle) => {
                // For named pipes on Windows, we need to use SetNamedPipeHandleState
                let mode = if nonblocking { PIPE_NOWAIT } else { PIPE_WAIT };

                // SAFETY: SetNamedPipeHandleState is safe with valid handle and mode
                // parameters. Handle is guaranteed valid by enum variant.
                let result = unsafe {
                    SetNamedPipeHandleState(*handle, &mode, ptr::null_mut(), ptr::null_mut())
                };

                if result == 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Set read timeout for the socket
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            PlatformSocket::Unix(stream) => stream.set_read_timeout(timeout),
            #[cfg(windows)]
            PlatformSocket::NamedPipe(_handle) => {
                // Named pipes don't support read timeouts in the same way
                // You'd need to implement this with overlapped I/O or threads
                // For now, we'll just return Ok to avoid breaking existing code
                #[allow(clippy::used_underscore_binding)] // Or #[allow(unused_variables)]
                let _ = timeout; // Explicitly use it to suppress the warning, but effectively ignore it
                Ok(())
            }
        }
    }

    /// Set write timeout for the socket
    pub fn set_write_timeout(&self, _timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            PlatformSocket::Unix(stream) => stream.set_write_timeout(_timeout),
            #[cfg(windows)]
            PlatformSocket::NamedPipe(_handle) => {
                // Named pipes don't support write timeouts in the same way
                // You'd need to implement this with overlapped I/O or threads
                // For now, we'll just return Ok to avoid breaking existing code
                Ok(())
            }
        }
    }

    /// Extract client credentials from the socket connection
    pub fn get_peer_credentials(&self) -> Result<ClientCredentials> {
        match self {
            #[cfg(unix)]
            PlatformSocket::Unix(stream) => {
                #[cfg(target_os = "linux")]
                {
                    let creds = getsockopt(stream, PeerCredentials)
                        .context("Failed to get peer credentials")?;

                    return Ok(ClientCredentials {
                        pid: creds.pid() as u32,
                        uid: creds.uid(),
                    });
                }

                #[cfg(target_os = "macos")]
                {
                    use std::os::unix::io::AsRawFd;

                    // Get UID using getpeereid - macOS specific
                    let mut uid: libc::uid_t = 0;
                    let mut gid: libc::gid_t = 0;

                    // SAFETY: getpeereid is safe to call with valid file descriptor and mutable
                    // references to uid_t and gid_t. stream.as_raw_fd() returns
                    // a valid fd, and uid/gid are properly initialized
                    // variables on the stack.
                    let result =
                        unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };

                    if result != 0 {
                        return Err(anyhow!(
                            "Failed to get peer UID on macOS: {}",
                            std::io::Error::last_os_error()
                        ));
                    }

                    // Get PID using LOCAL_PEERPID socket option - macOS specific
                    let mut pid: libc::pid_t = 0;
                    let mut pid_len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;

                    // SAFETY: getsockopt is safe when called with:
                    // - Valid file descriptor (stream.as_raw_fd())
                    // - Valid socket level and option (SOL_LOCAL, LOCAL_PEERPID)
                    // - Proper buffer pointer and size (pid is valid stack variable, pid_len
                    //   matches)
                    let result = unsafe {
                        libc::getsockopt(
                            stream.as_raw_fd(),
                            libc::SOL_LOCAL,
                            libc::LOCAL_PEERPID,
                            &mut pid as *mut _ as *mut libc::c_void,
                            &mut pid_len,
                        )
                    };

                    if result != 0 {
                        return Err(anyhow!(
                            "Failed to get peer PID on macOS: {}",
                            std::io::Error::last_os_error()
                        ));
                    }

                    tracing::debug!("macOS peer credentials: PID={}, UID={}", pid, uid);

                    return Ok(ClientCredentials {
                        pid: pid as u32,
                        uid,
                    });
                }

                #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
                {
                    // For other Unix systems, try SO_PEERCRED first, then give up
                    match getsockopt(stream, PeerCredentials) {
                        Ok(creds) => {
                            tracing::debug!("Using SO_PEERCRED on other Unix system");
                            return Ok(ClientCredentials {
                                pid: creds.pid() as u32,
                                uid: creds.uid(),
                            });
                        }
                        Err(_) => {
                            return Err(anyhow!(
                                "Peer credentials extraction not supported on this Unix platform. \
                                 Supported platforms: Linux (SO_PEERCRED), macOS \
                                 (getpeereid/LOCAL_PEERPID). This platform doesn't support \
                                 SO_PEERCRED."
                            ));
                        }
                    }
                }

                // This should never be reached due to cfg blocks above
                #[allow(unreachable_code)]
                Err(anyhow!("Unsupported Unix platform for peer credentials"))
            }
            #[cfg(windows)]
            PlatformSocket::NamedPipe(handle) => {
                let mut client_pid = 0u32;
                // SAFETY: GetNamedPipeClientProcessId is safe when called with a valid pipe
                // handle and a mutable reference to u32. The handle is
                // guaranteed valid by the enum variant.
                let result = unsafe { GetNamedPipeClientProcessId(*handle, &mut client_pid) };

                if result == 0 {
                    return Err(anyhow!("Failed to get client process ID"));
                }

                // Get process owner (simplified - you may want more robust user verification)
                let uid = Self::get_process_owner(client_pid)?;

                Ok(ClientCredentials {
                    pid: client_pid,
                    uid,
                })
            }
        }
    }

    #[cfg(windows)]
    fn get_process_owner(pid: u32) -> Result<u32> {
        // SAFETY: This function uses multiple Windows API calls that require careful
        // handle management:
        // - OpenProcess: Safe with valid PID and appropriate access rights
        // - OpenProcessToken: Safe with valid process handle
        // - GetTokenInformation: Safe with valid token handle and properly sized buffer
        // - CloseHandle: Safe with valid handles, called to prevent resource leaks
        // All handles are checked for validity before use and properly closed on all
        // paths.
        unsafe {
            use windows_sys::Win32::{Security::*, System::Threading::OpenProcessToken};

            let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
            if process_handle.is_null() {
                return Err(anyhow!("Failed to open process"));
            }

            let mut token_handle = std::ptr::null_mut();
            let result = OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle);

            CloseHandle(process_handle);

            if result == 0 {
                return Err(anyhow!("Failed to open process token"));
            }

            // Get token user information
            let mut return_length = 0u32;
            GetTokenInformation(
                token_handle,
                TokenUser,
                ptr::null_mut(),
                0,
                &mut return_length,
            );

            if return_length == 0 {
                CloseHandle(token_handle);
                return Err(anyhow!("Failed to get token information size"));
            }

            let mut buffer = vec![0u8; return_length as usize];
            let result = GetTokenInformation(
                token_handle,
                TokenUser,
                buffer.as_mut_ptr() as *mut _,
                return_length,
                &mut return_length,
            );

            CloseHandle(token_handle);

            if result == 0 {
                return Err(anyhow!("Failed to get token information"));
            }

            // For simplicity, return the PID as UID (you'd normally parse the SID)
            Ok(pid)
        }
    }
}

impl Read for PlatformSocket {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            PlatformSocket::Unix(stream) => stream.read(buf),
            #[cfg(windows)]
            PlatformSocket::NamedPipe(handle) => {
                let mut bytes_read = 0u32;
                // SAFETY: ReadFile is safe when called with:
                // - Valid handle (guaranteed by enum variant)
                // - Valid buffer pointer and size (buf is a valid slice)
                // - Valid pointer to bytes_read (stack variable)
                // - null overlapped pointer for synchronous operation
                let result = unsafe {
                    use windows_sys::Win32::Storage::FileSystem::ReadFile;
                    ReadFile(
                        *handle,
                        buf.as_mut_ptr() as *mut _,
                        buf.len() as u32,
                        &mut bytes_read,
                        ptr::null_mut(),
                    )
                };

                if result == 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(bytes_read as usize)
                }
            }
        }
    }
}

impl Write for PlatformSocket {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            PlatformSocket::Unix(stream) => stream.write(buf),
            #[cfg(windows)]
            PlatformSocket::NamedPipe(handle) => {
                let mut bytes_written = 0u32;
                // SAFETY: WriteFile is safe when called with:
                // - Valid handle (guaranteed by enum variant)
                // - Valid buffer pointer and size (buf is a valid slice)
                // - Valid pointer to bytes_written (stack variable)
                // - null overlapped pointer for synchronous operation
                let result = unsafe {
                    use windows_sys::Win32::Storage::FileSystem::WriteFile;
                    WriteFile(
                        *handle,
                        buf.as_ptr() as *const _,
                        buf.len() as u32,
                        &mut bytes_written,
                        ptr::null_mut(),
                    )
                };

                if result == 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(bytes_written as usize)
                }
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            PlatformSocket::Unix(stream) => stream.flush(),
            #[cfg(windows)]
            PlatformSocket::NamedPipe(handle) => {
                // SAFETY: FlushFileBuffers is safe when called with a valid handle.
                // The handle is guaranteed valid by the enum variant.
                let result = unsafe {
                    use windows_sys::Win32::Storage::FileSystem::FlushFileBuffers;
                    FlushFileBuffers(*handle)
                };
                if result == 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl PlatformListener {
    /// Create a new platform-specific listener
    pub fn bind(socket_name: &str) -> Result<Self> {
        #[cfg(unix)]
        {
            let socket_path = format!("/tmp/{socket_name}");

            tracing::info!(
                "Setting up Unix socket server: {} -> {}",
                socket_name,
                socket_path
            );

            // Check if socket file already exists
            if std::path::Path::new(&socket_path).exists() {
                tracing::warn!("Existing socket file found, removing it...");
                match std::fs::remove_file(&socket_path) {
                    Ok(_) => tracing::info!("Old socket file removed successfully"),
                    Err(e) => {
                        tracing::error!("Failed to remove old socket file: {}", e);
                        return Err(anyhow!(
                            "Could not remove existing socket file '{}': {}. You may need to stop \
                             the existing server or remove the file manually.",
                            socket_path,
                            e
                        ));
                    }
                }
            } else {
                tracing::debug!("No existing socket file found");
            }

            // Check parent directory
            if let Some(parent) = std::path::Path::new(&socket_path).parent() {
                match std::fs::metadata(parent) {
                    Ok(metadata) => {
                        tracing::debug!("Parent directory exists and is accessible");
                        if !metadata.is_dir() {
                            return Err(anyhow!(
                                "Parent path '{}' exists but is not a directory",
                                parent.display()
                            ));
                        }
                    }
                    Err(e) => {
                        return Err(anyhow!(
                            "Cannot access parent directory '{}': {}",
                            parent.display(),
                            e
                        ));
                    }
                }
            }

            // Try to bind
            tracing::debug!("Binding to socket...");
            let listener = match UnixListener::bind(&socket_path) {
                Ok(listener) => {
                    tracing::info!("Successfully bound to Unix socket!");
                    listener
                }
                Err(e) => {
                    tracing::error!("Failed to bind to socket: {} (kind: {:?})", e, e.kind());

                    let detailed_error = match e.kind() {
                        std::io::ErrorKind::PermissionDenied => {
                            format!(
                                "Permission denied creating socket '{socket_path}'. You may need \
                                 to:\n- Run as root/administrator\n- Check parent directory \
                                 permissions\n- Ensure you have write access to /tmp"
                            )
                        }
                        std::io::ErrorKind::AlreadyExists => {
                            format!(
                                "Socket '{socket_path}' already exists. Another server instance \
                                 may be running.\nTry stopping the existing server or removing \
                                 the socket file manually."
                            )
                        }
                        std::io::ErrorKind::InvalidInput => {
                            format!(
                                "Invalid socket path '{socket_path}'. Check that the path is \
                                 valid and not too long."
                            )
                        }
                        _ => {
                            format!(
                                "Unexpected error binding to socket '{}': {} (kind: {:?})",
                                socket_path,
                                e,
                                e.kind()
                            )
                        }
                    };

                    return Err(anyhow!(
                        "{}\n\nOS Error Code: {}",
                        detailed_error,
                        e.raw_os_error().unwrap_or(-1)
                    ));
                }
            };

            // Set restrictive permissions and proper ownership
            tracing::debug!("Setting socket permissions and ownership...");
            use std::os::unix::fs::PermissionsExt;

            // Set permissions to 600 (owner read/write only)
            match std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)) {
                Ok(_) => {
                    tracing::debug!("Socket permissions set to 600 (owner read/write only)");
                }
                Err(e) => {
                    tracing::warn!("Failed to set socket permissions: {}", e);
                    // Don't fail the entire operation for permission setting
                    // failure
                }
            }

            // If running as root (via sudo), change ownership to the original user
            // SAFETY: geteuid() is always safe to call - it simply returns the effective
            // user ID
            if unsafe { libc::geteuid() } == 0 {
                if let Ok(sudo_user) = std::env::var("SUDO_USER") {
                    tracing::info!(
                        "Detected sudo execution, changing socket ownership to user: {}",
                        sudo_user
                    );

                    // Get the original user's UID and GID
                    match get_user_ids(&sudo_user) {
                        Ok((uid, gid)) => {
                            let socket_path_cstring =
                                match std::ffi::CString::new(socket_path.clone()) {
                                    Ok(cstring) => cstring,
                                    Err(e) => {
                                        tracing::warn!(
                                            "Failed to convert socket path to C string: {}",
                                            e
                                        );
                                        return Ok(PlatformListener::Unix(listener));
                                    }
                                };

                            // SAFETY: chown is safe when called with a valid C string pointer
                            // and valid uid/gid values. The CString is guaranteed valid and
                            // uid/gid come from getpwnam which returns valid system values.
                            let result =
                                unsafe { libc::chown(socket_path_cstring.as_ptr(), uid, gid) };

                            if result == 0 {
                                tracing::info!(
                                    "Socket ownership changed to {}:{} ({})",
                                    uid,
                                    gid,
                                    sudo_user
                                );
                            } else {
                                let error = std::io::Error::last_os_error();
                                tracing::warn!("Failed to change socket ownership: {}", error);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to get user IDs for {}: {}", sudo_user, e);
                        }
                    }
                } else {
                    tracing::info!("Running as root but SUDO_USER not set, keeping root ownership");
                }
            } else {
                tracing::debug!("Running as regular user, no ownership change needed");
            }

            tracing::info!("Unix socket server setup complete!");
            Ok(PlatformListener::Unix(listener))
        }

        #[cfg(windows)]
        {
            let pipe_name = format!(r"\\.\pipe\{socket_name}");
            Ok(PlatformListener::NamedPipe(pipe_name))
        }
    }

    /// Accept incoming connections
    /// Accept incoming connections with proper blocking configuration
    pub fn accept(&self) -> Result<PlatformSocket> {
        match self {
            #[cfg(unix)]
            PlatformListener::Unix(listener) => {
                let (stream, _) = listener
                    .accept()
                    .context("Failed to accept Unix socket connection")?;

                let socket = PlatformSocket::Unix(stream);

                // Ensure the socket is blocking
                socket
                    .set_nonblocking(false)
                    .context("Failed to set socket to blocking mode")?;

                // Set reasonable timeouts to prevent hanging
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(30)))
                    .context("Failed to set read timeout")?;
                socket
                    .set_write_timeout(Some(std::time::Duration::from_secs(30)))
                    .context("Failed to set write timeout")?;

                Ok(socket)
            }
            #[cfg(windows)]
            PlatformListener::NamedPipe(pipe_name) => {
                let pipe_name_cstr = CString::new(pipe_name.as_bytes())?;

                // SAFETY: This block contains multiple Windows security API calls:
                // - InitializeSecurityDescriptor: Safe with valid buffer and revision
                // - SetSecurityDescriptorDacl: Safe with valid descriptor pointer
                // - CreateNamedPipeA: Safe with valid pipe name and parameters
                // All pointers are to valid stack-allocated data or null where appropriate
                let pipe_handle = unsafe {
                    use windows_sys::Win32::{
                        Security::*, Storage::FileSystem::PIPE_ACCESS_DUPLEX,
                    };

                    // Create a security descriptor that allows Everyone full access
                    // This is for testing purposes - in production you'd want more restrictive ACLs
                    let mut security_descriptor = [0u8; 1024]; // Buffer for security descriptor
                    let mut security_attrs = SECURITY_ATTRIBUTES {
                        nLength:              std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                        lpSecurityDescriptor: ptr::null_mut(),
                        bInheritHandle:       0,
                    };

                    // Initialize security descriptor
                    if InitializeSecurityDescriptor(
                        security_descriptor.as_mut_ptr() as *mut _,
                        1, // SECURITY_DESCRIPTOR_REVISION
                    ) != 0
                    {
                        // Set DACL to NULL to allow everyone access (for testing)
                        if SetSecurityDescriptorDacl(
                            security_descriptor.as_mut_ptr() as *mut _,
                            1,               // DACL present
                            ptr::null_mut(), // NULL DACL = allow everyone
                            0,               // Not defaulted
                        ) != 0
                        {
                            security_attrs.lpSecurityDescriptor =
                                security_descriptor.as_mut_ptr() as *mut _;
                        }
                    }

                    CreateNamedPipeA(
                        pipe_name_cstr.as_ptr() as *const u8,
                        PIPE_ACCESS_DUPLEX,
                        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, /* Ensure PIPE_WAIT
                                                                          * (blocking) */
                        1,               // Max instances
                        4096,            // Out buffer size
                        4096,            // In buffer size
                        30000,           // 30 second timeout
                        &security_attrs, // Security attributes with Everyone access
                    )
                };

                if pipe_handle == INVALID_HANDLE_VALUE {
                    return Err(anyhow!("Failed to create named pipe"));
                }

                // Wait for client connection
                // SAFETY: ConnectNamedPipe is safe with valid pipe handle and null overlapped
                // pointer
                let connected = unsafe {
                    windows_sys::Win32::System::Pipes::ConnectNamedPipe(
                        pipe_handle,
                        ptr::null_mut(),
                    )
                };

                if connected == 0 {
                    // SAFETY: GetLastError() is always safe to call
                    let error = unsafe { GetLastError() };
                    if error != ERROR_PIPE_CONNECTED {
                        // SAFETY: CloseHandle is safe with valid handle to prevent resource leak
                        unsafe {
                            CloseHandle(pipe_handle);
                        }
                        return Err(anyhow!("Failed to connect named pipe: {}", error));
                    }
                }

                let socket = PlatformSocket::NamedPipe(pipe_handle);

                // Ensure blocking mode (this should already be set with PIPE_WAIT above)
                socket
                    .set_nonblocking(false)
                    .context("Failed to set named pipe to blocking mode")?;

                Ok(socket)
            }
        }
    }

    /// Get iterator over incoming connections
    pub fn incoming(&self) -> IncomingConnections {
        IncomingConnections { listener: self }
    }
}

/// Iterator over incoming connections
pub struct IncomingConnections<'a> {
    listener: &'a PlatformListener,
}

impl Iterator for IncomingConnections<'_> {
    type Item = Result<PlatformSocket>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.listener.accept())
    }
}

/// Connect to a platform-specific socket with blocking configuration
pub fn connect_socket(socket_name: &str) -> Result<PlatformSocket> {
    #[cfg(unix)]
    {
        let socket_path = format!("/tmp/{socket_name}");

        tracing::debug!(
            "Attempting to connect to Unix socket: {} -> {}",
            socket_name,
            socket_path
        );

        // Check if socket file exists first
        match std::fs::metadata(&socket_path) {
            Ok(metadata) => {
                tracing::debug!("Socket file exists");
                if metadata.file_type().is_socket() {
                    tracing::debug!("File is a socket");
                } else {
                    tracing::warn!(
                        "File exists but is not a socket! File type: {:?}",
                        metadata.file_type()
                    );
                }

                // Check permissions
                use std::os::unix::fs::{FileTypeExt, PermissionsExt};
                let mode = metadata.permissions().mode();
                tracing::debug!("Socket permissions: {:o}", mode);

                if mode & 0o600 == 0o600 {
                    tracing::debug!("Socket has read/write permissions for owner");
                } else {
                    tracing::warn!("Socket permissions may be restrictive");
                }
            }
            Err(e) => {
                tracing::error!(
                    "Socket file does not exist or is inaccessible: {} (OS error: {:?})",
                    e,
                    e.kind()
                );

                // Check if directory exists
                if let Some(parent) = std::path::Path::new(&socket_path).parent() {
                    match std::fs::metadata(parent) {
                        Ok(_) => tracing::debug!("Parent directory (/tmp) exists"),
                        Err(dir_err) => tracing::error!("Parent directory error: {}", dir_err),
                    }
                }

                return Err(anyhow!(
                    "Socket file '{}' does not exist. This usually means:\n1. The server is not \
                     running\n2. The server failed to start (check server logs)\n3. The server is \
                     binding to a different socket path\n\nOriginal error: {}",
                    socket_path,
                    e
                ));
            }
        }

        // Try to connect
        tracing::debug!("Attempting connection...");
        match UnixStream::connect(&socket_path) {
            Ok(stream) => {
                tracing::info!("Successfully connected to Unix socket!");

                let socket = PlatformSocket::Unix(stream);

                // Ensure the socket is blocking
                socket
                    .set_nonblocking(false)
                    .context("Failed to set socket to blocking mode")?;

                // Set reasonable timeouts
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(30)))
                    .context("Failed to set read timeout")?;
                socket
                    .set_write_timeout(Some(std::time::Duration::from_secs(30)))
                    .context("Failed to set write timeout")?;

                tracing::debug!("Socket configured for blocking I/O with 30s timeouts");

                Ok(socket)
            }
            Err(e) => {
                tracing::error!("Connection failed: {} (kind: {:?})", e, e.kind());

                // Provide specific error analysis
                let detailed_error = match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        format!(
                            "Socket file not found at '{socket_path}'. The server may have \
                             stopped or never started."
                        )
                    }
                    std::io::ErrorKind::PermissionDenied => {
                        format!(
                            "Permission denied accessing socket '{socket_path}'. You may need to \
                             run with sudo or check socket permissions."
                        )
                    }
                    std::io::ErrorKind::ConnectionRefused => {
                        format!(
                            "Connection refused to socket '{socket_path}'. The server may be \
                             starting up or shutting down."
                        )
                    }
                    std::io::ErrorKind::TimedOut => {
                        format!(
                            "Connection to socket '{socket_path}' timed out. The server may be \
                             overloaded or unresponsive."
                        )
                    }
                    std::io::ErrorKind::InvalidInput => {
                        format!(
                            "Invalid socket path '{socket_path}'. Check that the path is correct."
                        )
                    }
                    _ => {
                        format!(
                            "Unexpected error connecting to socket '{}': {} (kind: {:?})",
                            socket_path,
                            e,
                            e.kind()
                        )
                    }
                };

                Err(anyhow!(
                    "{}\n\nOS Error Code: {}",
                    detailed_error,
                    e.raw_os_error().unwrap_or(-1)
                ))
            }
        }
    }

    #[cfg(windows)]
    {
        let pipe_name = format!(r"\\.\pipe\{socket_name}");
        tracing::debug!("Attempting to connect to Windows named pipe: {}", pipe_name);

        let pipe_name_cstr = CString::new(pipe_name.as_bytes())?;

        // Wait for pipe to become available
        tracing::debug!("Waiting for named pipe to become available...");
        // SAFETY: WaitNamedPipeA is safe with valid pipe name C string and timeout
        // value
        let wait_result =
            unsafe { WaitNamedPipeA(pipe_name_cstr.as_ptr() as *const u8, NMPWAIT_WAIT_FOREVER) };

        if wait_result == 0 {
            // SAFETY: GetLastError() is always safe to call
            let error = unsafe { GetLastError() };
            tracing::error!("WaitNamedPipeA failed with error: {}", error);
            return Err(anyhow!(
                "Failed to wait for named pipe. Error code: {}",
                error
            ));
        }

        tracing::debug!("Named pipe is available, attempting to connect...");

        // SAFETY: CreateFileA is safe when called with:
        // - Valid pipe name C string
        // - Valid access flags (GENERIC_READ | GENERIC_WRITE)
        // - Null security attributes and template handle for named pipes
        let pipe_handle = unsafe {
            CreateFileA(
                pipe_name_cstr.as_ptr() as *const u8,
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null_mut(),
                OPEN_EXISTING,
                0, // No special flags - this will be blocking by default
                std::ptr::null_mut(),
            )
        };

        if pipe_handle == INVALID_HANDLE_VALUE {
            // SAFETY: GetLastError() is always safe to call
            let error = unsafe { GetLastError() };
            tracing::error!("CreateFileA failed with error: {}", error);
            return Err(anyhow!(
                "Failed to connect to named pipe '{}'. Error code: {}",
                pipe_name,
                error
            ));
        }

        tracing::debug!("Successfully connected to named pipe!");

        let socket = PlatformSocket::NamedPipe(pipe_handle);

        // Ensure blocking mode
        socket
            .set_nonblocking(false)
            .context("Failed to set named pipe to blocking mode")?;

        tracing::debug!("Named pipe connection established and configured");
        Ok(socket)
    }
}

#[cfg(windows)]
impl Drop for PlatformSocket {
    fn drop(&mut self) {
        let PlatformSocket::NamedPipe(handle) = self;
        // SAFETY: CloseHandle is safe with valid handle to clean up resources.
        // Handle is guaranteed valid by enum variant construction.
        unsafe {
            CloseHandle(*handle);
        }
    }
}

/// Helper function to get user ID and group ID from username
#[cfg(unix)]
fn get_user_ids(username: &str) -> Result<(u32, u32)> {
    use std::ffi::CString;

    let username_cstring = CString::new(username)?;

    // SAFETY: getpwnam is safe when called with a valid C string pointer.
    // The returned pointer is either null (handled) or points to a valid passwd
    // struct. We check for null before dereferencing and only access standard
    // fields.
    unsafe {
        let passwd = libc::getpwnam(username_cstring.as_ptr());
        if passwd.is_null() {
            return Err(anyhow!("User '{}' not found", username));
        }

        let uid = (*passwd).pw_uid;
        let gid = (*passwd).pw_gid;

        Ok((uid, gid))
    }
}
