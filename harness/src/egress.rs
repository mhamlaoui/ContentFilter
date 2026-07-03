//! Egress-deny assertion helpers, standing in for `svc-egress-wfp` until
//! that component exists. Applies a real, temporary OS firewall rule so the
//! assertion is genuine rather than mocked, then removes it on drop.
//!
//! Mutates live OS firewall state, so [`block_outbound_tcp`] refuses to run
//! outside CI (no `CI` env var) to avoid touching a developer's machine.

use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

/// Returns a real, non-loopback local IP by asking the OS which interface
/// it would route through to reach an arbitrary external address (no
/// packets are actually sent — UDP `connect` just does a routing lookup).
pub fn local_nonloopback_ip() -> io::Result<IpAddr> {
    let probe = UdpSocket::bind("0.0.0.0:0")?;
    probe.connect("8.8.8.8:80")?;
    Ok(probe.local_addr()?.ip())
}

pub struct BlockGuard {
    #[cfg(windows)]
    rule_name: String,
    #[cfg(unix)]
    port: u16,
}

/// Blocks outbound TCP to `port` until the returned guard drops. Returns an
/// error if not running in CI (`CI` env var unset).
pub fn block_outbound_tcp(port: u16) -> io::Result<BlockGuard> {
    if std::env::var_os("CI").is_none() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to modify the local firewall outside CI (CI env var not set)",
        ));
    }
    imp::block_outbound_tcp(port)
}

/// Confirmed empirically to be unreliable on Windows for a same-host
/// connection, even against a real (non-loopback) interface address:
/// Windows appears to route same-host TCP connections through a fast path
/// that bypasses the outbound filter regardless of a correctly-scoped
/// block rule being active (verified via `netsh ... show rule verbose`
/// reporting `Action: Block` while the connection still succeeded). On
/// Windows, use [`rule_blocks_port`] to verify the rule itself instead.
/// Linux's `iptables OUTPUT` chain does not have this problem.
pub fn assert_egress_denied(addr: SocketAddr) {
    let result = TcpStream::connect_timeout(&addr, Duration::from_millis(500));
    assert!(
        result.is_err(),
        "expected egress to {addr} to be denied, but it succeeded"
    );
}

/// Windows-only: checks the block rule for `port` (created by
/// [`block_outbound_tcp`]) is present and actually configured to block, as
/// a substitute for a live connection attempt. See [`assert_egress_denied`].
#[cfg(windows)]
pub fn rule_blocks_port(port: u16) -> io::Result<bool> {
    imp::rule_blocks_port(port)
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
                "profile=any",
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

    pub fn rule_blocks_port(port: u16) -> io::Result<bool> {
        let rule_name = format!("cf-test-harness-block-{port}");
        let output = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "show",
                "rule",
                &format!("name={rule_name}"),
                "verbose",
            ])
            .output()?;
        if !output.status.success() {
            return Ok(false);
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let field = |key: &str| -> Option<String> {
            text.lines()
                .find(|l| l.trim_start().starts_with(key))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
        };
        Ok(field("Enabled").as_deref() == Some("Yes")
            && field("Action").as_deref() == Some("Block")
            && field("RemotePort").as_deref() == Some(port.to_string().as_str()))
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
