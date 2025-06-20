use anyhow::Result;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

/// Get the PID of the peer process connected to the Unix socket
pub fn get_peer_pid_from_unix_stream(stream: &UnixStream) -> Result<u32> {
    let fd = stream.as_raw_fd();

    #[cfg(target_os = "linux")]
    {
        get_peer_pid_linux(fd)
    }

    #[cfg(target_os = "macos")]
    {
        get_peer_pid_macos(fd)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(anyhow::anyhow!(
            "Peer PID extraction not supported on this platform"
        ))
    }
}

#[cfg(target_os = "linux")]
fn get_peer_pid_linux(fd: i32) -> Result<u32> {
    use std::mem;

    let mut ucred: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;

    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if result == 0 {
        Ok(ucred.pid as u32)
    } else {
        Err(anyhow::anyhow!(
            "Failed to get peer credentials: {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(target_os = "macos")]
fn get_peer_pid_macos(fd: i32) -> Result<u32> {
    use std::mem;

    let mut pid: libc::pid_t = 0;
    let mut len = mem::size_of::<libc::pid_t>() as libc::socklen_t;

    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if result == 0 {
        Ok(pid as u32)
    } else {
        Err(anyhow::anyhow!(
            "Failed to get peer PID: {}",
            std::io::Error::last_os_error()
        ))
    }
}

/// Get full peer credentials (PID, UID, GID) - Linux only
#[cfg(target_os = "linux")]
pub fn get_peer_credentials(stream: &UnixStream) -> Result<(u32, u32, u32)> {
    use std::mem;

    let fd = stream.as_raw_fd();
    let mut ucred: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;

    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if result == 0 {
        Ok((ucred.pid as u32, ucred.uid as u32, ucred.gid as u32))
    } else {
        Err(anyhow::anyhow!(
            "Failed to get peer credentials: {}",
            std::io::Error::last_os_error()
        ))
    }
}
