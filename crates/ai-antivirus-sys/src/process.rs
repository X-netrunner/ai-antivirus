//! Process handles and socket peer credentials for the responder (M4).
//!
//! A pidfd names one process for as long as it is open, so a signal sent through it can never reach a later process
//! that reused the PID. Callers open the pidfd first and then check the process's start time; if the start time still
//! matches, the descriptor refers to the process they meant.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Credentials of the process on the other end of a Unix socket, as the kernel recorded them at `connect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// Open a pidfd for `pid` (`pidfd_open(2)`, kernel 5.3+). The descriptor is close-on-exec.
#[allow(unsafe_code)]
pub fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    let pid = libc::pid_t::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))?;
    if pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pid must be positive",
        ));
    }
    // SAFETY: `pidfd_open` takes a pid and a flags word (0) by value and reads no caller memory. It returns a new
    // descriptor or -1.
    let rc = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = i32::try_from(rc)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "descriptor out of range"))?;
    // SAFETY: the kernel just created `fd` for this process; nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Send `signal` to the process `pidfd` refers to (`pidfd_send_signal(2)`, kernel 5.1+).
#[allow(unsafe_code)]
pub fn pidfd_send_signal<F: AsRawFd>(pidfd: &F, signal: i32) -> io::Result<()> {
    // SAFETY: the descriptor is borrowed, so it stays open for the call; `info` is NULL (the kernel fills in a
    // default siginfo) and flags are 0. No caller memory is read or written.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `SO_PEERCRED` of a connected Unix socket.
#[allow(unsafe_code)]
pub fn peer_cred<F: AsRawFd>(socket: &F) -> io::Result<PeerCred> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ucred size"))?;
    // SAFETY: `cred` is a valid, writable `ucred` and `len` holds its exact size; both outlive the call. The socket
    // is borrowed, so it stays open.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCred {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::process::Command;

    #[test]
    fn peer_cred_is_our_own_process() {
        let (a, _b) = UnixStream::pair().unwrap();
        let c = peer_cred(&a).unwrap();
        assert_eq!(c.pid, i32::try_from(std::process::id()).unwrap());
        assert_eq!(
            c.uid,
            std::fs::metadata("/proc/self")
                .map(|m| {
                    use std::os::unix::fs::MetadataExt;
                    m.uid()
                })
                .unwrap()
        );
    }

    #[test]
    fn pidfd_signals_a_child_and_reports_gone_processes() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let fd = pidfd_open(child.id()).unwrap();
        pidfd_send_signal(&fd, 0).unwrap();
        pidfd_send_signal(&fd, libc::SIGKILL).unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success());
        // reaped: the pidfd stays valid but the process is gone (ESRCH)
        assert!(pidfd_send_signal(&fd, 0).is_err());
        assert!(pidfd_open(0).is_err());
    }
}
