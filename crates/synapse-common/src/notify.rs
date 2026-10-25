//! systemd readiness and watchdog notifications (`sd_notify`), in safe Rust: one datagram to `$NOTIFY_SOCKET`.
//!
//! A daemon calls [`Heartbeat::ready`] once it is working and [`Heartbeat::tick`] from its main loop. `tick` sends
//! `WATCHDOG=1` at half the interval systemd asked for (`$WATCHDOG_USEC`), so a daemon whose main loop hangs stops
//! pinging and systemd restarts it (spec 10). Without systemd none of this does anything.

use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::time::{Duration, Instant};

/// Send one notification message to the socket named by `socket` (`/path` or `@abstract`).
pub fn send_to(socket: &str, message: &str) -> std::io::Result<()> {
    let sock = UnixDatagram::unbound()?;
    if let Some(name) = socket.strip_prefix('@') {
        sock.send_to_addr(
            message.as_bytes(),
            &SocketAddr::from_abstract_name(name.as_bytes())?,
        )?;
    } else {
        sock.send_to(message.as_bytes(), socket)?;
    }
    Ok(())
}

/// Parse `$WATCHDOG_USEC` into the interval at which to ping: half of it, at least 100 ms.
pub fn watchdog_interval(usec: Option<&str>) -> Option<Duration> {
    let us: u64 = usec?.trim().parse().ok()?;
    (us > 0).then(|| Duration::from_micros(us / 2).max(Duration::from_millis(100)))
}

#[derive(Debug)]
pub struct Heartbeat {
    socket: Option<String>,
    every: Option<Duration>,
    last: Instant,
}

impl Heartbeat {
    /// From the environment systemd gives a service.
    pub fn from_env() -> Heartbeat {
        Heartbeat::new(
            std::env::var("NOTIFY_SOCKET").ok(),
            std::env::var("WATCHDOG_USEC").ok().as_deref(),
        )
    }

    pub fn new(socket: Option<String>, watchdog_usec: Option<&str>) -> Heartbeat {
        Heartbeat {
            socket: socket.filter(|s| !s.is_empty()),
            every: watchdog_interval(watchdog_usec),
            last: Instant::now(),
        }
    }

    fn send(&self, msg: &str) {
        if let Some(s) = &self.socket {
            // best effort: a failed notification must never stop the daemon
            let _ = send_to(s, msg);
        }
    }

    pub fn ready(&self, status: &str) {
        self.send(&format!("READY=1\nSTATUS={}", status.replace('\n', " ")));
    }

    /// Call often from the main loop; pings the watchdog when it is due.
    pub fn tick(&mut self) {
        if let Some(every) = self.every {
            if self.last.elapsed() >= every {
                self.send("WATCHDOG=1");
                self.last = Instant::now();
            }
        }
    }

    pub fn stopping(&self) {
        self.send("STOPPING=1");
    }

    pub fn active(&self) -> bool {
        self.socket.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_watchdog_interval_is_half_and_bounded() {
        assert_eq!(
            watchdog_interval(Some("30000000")),
            Some(Duration::from_secs(15))
        );
        assert_eq!(
            watchdog_interval(Some("1000")),
            Some(Duration::from_millis(100))
        );
        assert_eq!(watchdog_interval(Some("0")), None);
        assert_eq!(watchdog_interval(Some("soon")), None);
        assert_eq!(watchdog_interval(None), None);
    }

    #[test]
    fn messages_reach_a_socket_and_pings_are_paced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let server = UnixDatagram::bind(&path).unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut hb = Heartbeat::new(Some(path.to_string_lossy().into_owned()), Some("200000"));
        hb.ready("running\nfine");
        let mut buf = [0u8; 256];
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1\nSTATUS=running fine");
        hb.tick(); // not due yet (100 ms interval)
        std::thread::sleep(Duration::from_millis(150));
        hb.tick();
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"WATCHDOG=1");
        // not under systemd: silent no-ops
        let mut none = Heartbeat::new(None, None);
        none.ready("x");
        none.tick();
        none.stopping();
        assert!(!none.active());
    }

    #[test]
    fn a_missing_socket_is_not_an_error_for_the_daemon() {
        let hb = Heartbeat::new(Some("/nonexistent/notify".into()), None);
        hb.ready("x");
        hb.stopping();
    }
}
