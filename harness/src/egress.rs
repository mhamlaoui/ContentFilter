//! Egress-deny assertion helpers, standing in for `svc-egress-wfp` until
//! that component exists. Applies a real, temporary OS firewall rule so the
//! assertion is genuine rather than mocked, then removes it on drop.
//!
//! Mutates live OS firewall state, so [`block_outbound_tcp`] refuses to run
//! outside CI (no `CI` env var) to avoid touching a developer's machine.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

pub struct BlockGuard {
    #[cfg(windows)]
    rule_name: String,
    #[cfg(unix)]
    port: u16,
}

/// Blocks outbound TCP to `port` on loopback until the returned guard drops.
/// Returns an error if not running in CI (`CI` env var unset).
pub fn block_outbound_tcp(port: u16) -> io::Result<BlockGuard> {
    if std::env::var_os("CI").is_none() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to modify the local firewall outside CI (CI env var not set)",
        ));
    }
    imp::block_outbound_tcp(port)
}

pub fn assert_egress_denied(addr: SocketAddr) {
    let result = TcpStream::connect_timeout(&addr, Duration::from_millis(500));
    assert!(
        result.is_err(),
        "expected egress to {addr} to be denied, but it succeeded"
    );
}

pub fn assert_egress_allowed(addr: SocketAddr) {
    TcpStream::connect_timeout(&addr, Duration::from_millis(500))
        .unwrap_or_else(|e| panic!("expected egress to {addr} to be allowed, got {e}"));
}

#[cfg(windows)]
mod imp {
    use super::BlockGuard;
    use std::io;
    use std::process::Command;

    pub fn block_outbound_tcp(port: u16) -> io::Result<BlockGuard> {
        let rule_name = format!("cf-test-harness-block-{port}");
        let status = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={rule_name}"),
                "dir=out",
                "action=block",
                "protocol=TCP",
                // "remoteport" is the destination port for an outbound
                // rule; "localport" would match the client's ephemeral
                // source port instead and never block anything.
                &format!("remoteport={port}"),
            ])
            .status()?;
        if !status.success() {
            return Err(io::Error::other("netsh add rule failed"));
        }
        Ok(BlockGuard { rule_name })
    }

    impl Drop for BlockGuard {
        fn drop(&mut self) {
            let _ = Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={}", self.rule_name),
                ])
                .status();
        }
    }
}

#[cfg(unix)]
mod imp {
    use super::BlockGuard;
    use std::io;
    use std::process::Command;

    pub fn block_outbound_tcp(port: u16) -> io::Result<BlockGuard> {
        let status = Command::new("sudo")
            .args([
                "iptables",
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                &port.to_string(),
                "-j",
                "REJECT",
            ])
            .status()?;
        if !status.success() {
            return Err(io::Error::other("iptables insert failed"));
        }
        Ok(BlockGuard { port })
    }

    impl Drop for BlockGuard {
        fn drop(&mut self) {
            let _ = Command::new("sudo")
                .args([
                    "iptables",
                    "-D",
                    "OUTPUT",
                    "-p",
                    "tcp",
                    "--dport",
                    &self.port.to_string(),
                    "-j",
                    "REJECT",
                ])
                .status();
        }
    }
}
