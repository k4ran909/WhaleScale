//! Tunnel backends that apply rendered WireGuard configuration to the OS.
//!
//! - [`LogBackend`]: prints the config (dev / unsupported platforms).
//! - [`WgQuickBackend`]: drives `wg-quick` + `wg syncconf` on Linux/macOS.
//!
//! `WgQuickBackend` takes a [`CommandRunner`] so the command sequence can be
//! unit-tested without actually configuring a network interface.

use std::path::PathBuf;
use std::process::Command;

use anyhow::Context;

/// Applies WireGuard configuration to an OS interface.
pub trait TunnelBackend {
    /// `quick_config` is wg-quick format (used to bring the interface up);
    /// `sync_config` is `wg setconf` format (used to update it in place).
    fn apply(&mut self, quick_config: &str, sync_config: &str) -> anyhow::Result<()>;

    /// Cumulative `(rx_bytes, tx_bytes)` for the interface, if available.
    /// Default: unavailable (`None`).
    fn transfer(&mut self) -> Option<(u64, u64)> {
        None
    }
}

impl TunnelBackend for Box<dyn TunnelBackend> {
    fn apply(&mut self, quick_config: &str, sync_config: &str) -> anyhow::Result<()> {
        (**self).apply(quick_config, sync_config)
    }
    fn transfer(&mut self) -> Option<(u64, u64)> {
        (**self).transfer()
    }
}

/// Parse `wg show <iface> transfer` output, summing per-peer counters into a
/// total `(rx_bytes, tx_bytes)`. Each line is `<pubkey>\t<rx>\t<tx>`.
pub fn parse_wg_transfer(output: &str) -> (u64, u64) {
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in output.lines() {
        let mut cols = line.split('\t');
        let _pubkey = cols.next();
        if let (Some(r), Some(t)) = (cols.next(), cols.next()) {
            rx += r.trim().parse::<u64>().unwrap_or(0);
            tx += t.trim().parse::<u64>().unwrap_or(0);
        }
    }
    (rx, tx)
}

/// A no-op backend that logs the config — for dev or platforms without a
/// WireGuard backend yet (e.g. Windows during development).
#[derive(Default)]
pub struct LogBackend;

impl TunnelBackend for LogBackend {
    fn apply(&mut self, quick_config: &str, _sync_config: &str) -> anyhow::Result<()> {
        tracing::info!("would apply WireGuard config:\n{quick_config}");
        Ok(())
    }
}

/// Abstraction over running external commands (so backends are testable).
pub trait CommandRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> anyhow::Result<()>;
}

/// Runs commands via `std::process::Command`.
#[derive(Default)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> anyhow::Result<()> {
        let status = Command::new(program)
            .args(args)
            .status()
            .with_context(|| format!("failed to spawn {program}"))?;
        if !status.success() {
            anyhow::bail!("{program} {args:?} exited with {status}");
        }
        Ok(())
    }
}

/// Configures a kernel WireGuard interface via `wireguard-tools`.
///
/// First `apply` writes the wg-quick config and runs `wg-quick up`; subsequent
/// applies write the stripped config and run `wg syncconf`, updating peers
/// without tearing down the tunnel.
pub struct WgQuickBackend<R: CommandRunner = SystemRunner> {
    iface: String,
    dir: PathBuf,
    up: bool,
    runner: R,
}

impl WgQuickBackend<SystemRunner> {
    /// Create a backend for interface `iface` (e.g. `whale0`), writing config
    /// files under the system temp directory.
    pub fn new(iface: impl Into<String>) -> Self {
        Self::with_runner(iface, std::env::temp_dir(), SystemRunner)
    }
}

impl<R: CommandRunner> WgQuickBackend<R> {
    pub fn with_runner(iface: impl Into<String>, dir: PathBuf, runner: R) -> Self {
        Self {
            iface: iface.into(),
            dir,
            up: false,
            runner,
        }
    }

    fn quick_path(&self) -> PathBuf {
        self.dir.join(format!("{}.conf", self.iface))
    }

    fn sync_path(&self) -> PathBuf {
        self.dir.join(format!("{}.sync.conf", self.iface))
    }
}

impl<R: CommandRunner> TunnelBackend for WgQuickBackend<R> {
    fn apply(&mut self, quick_config: &str, sync_config: &str) -> anyhow::Result<()> {
        let quick_path = self.quick_path();
        std::fs::write(&quick_path, quick_config).context("failed to write wg-quick config")?;

        if !self.up {
            self.runner
                .run("wg-quick", &["up", &quick_path.to_string_lossy()])?;
            self.up = true;
            tracing::info!(iface = %self.iface, "WireGuard interface up");
        } else {
            let sync_path = self.sync_path();
            std::fs::write(&sync_path, sync_config).context("failed to write sync config")?;
            self.runner.run(
                "wg",
                &["syncconf", &self.iface, &sync_path.to_string_lossy()],
            )?;
            tracing::debug!(iface = %self.iface, "WireGuard peers synced");
        }
        Ok(())
    }

    fn transfer(&mut self) -> Option<(u64, u64)> {
        if !self.up {
            return None;
        }
        let output = Command::new("wg")
            .args(["show", &self.iface, "transfer"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        Some(parse_wg_transfer(&String::from_utf8_lossy(&output.stdout)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingRunner {
        calls: Vec<String>,
    }
    impl CommandRunner for RecordingRunner {
        fn run(&mut self, program: &str, args: &[&str]) -> anyhow::Result<()> {
            self.calls.push(format!("{program} {}", args.join(" ")));
            Ok(())
        }
    }

    #[test]
    fn first_apply_brings_up_then_syncs() {
        let dir = std::env::temp_dir().join(format!("ws-wgtest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut be = WgQuickBackend::with_runner("whale0", dir.clone(), RecordingRunner::default());

        be.apply("quick-cfg-1", "sync-cfg-1").unwrap();
        be.apply("quick-cfg-2", "sync-cfg-2").unwrap();

        let calls = &be.runner.calls;
        assert_eq!(calls.len(), 2);
        assert!(calls[0].starts_with("wg-quick up"), "first: {}", calls[0]);
        assert!(
            calls[1].starts_with("wg syncconf whale0"),
            "second: {}",
            calls[1]
        );

        // The sync config was written for the in-place update.
        let synced = std::fs::read_to_string(dir.join("whale0.sync.conf")).unwrap();
        assert_eq!(synced, "sync-cfg-2");
    }

    #[test]
    fn parses_and_sums_wg_transfer() {
        let output = "PEERA\t1000\t2000\nPEERB\t30\t40\n";
        assert_eq!(parse_wg_transfer(output), (1030, 2040));
        assert_eq!(parse_wg_transfer(""), (0, 0));
    }
}
