//! Small process/runtime helpers shared by the binaries (server, client)
//! and the iOS FFI: logger init, a multi-thread Tokio runtime, a version banner,
//! and a graceful-shutdown signal future. These are pure boilerplate that every
//! entry point needs; keeping one copy here avoids drift between crates.

use anyhow::{Context, Result};

/// Default `env_logger` filter for the binaries: flextunnel's own crates at
/// `info`, the noisy transport deps (iroh and its tracing bridge) at `warn`.
/// Overridable at runtime via `RUST_LOG`. The FFI passes its own filter instead.
pub const DEFAULT_LOG_FILTER: &str = "info,iroh=warn,tracing=warn";

/// Initialize `env_logger` with `default_filter` unless `RUST_LOG` overrides it.
/// Uses `try_init` so it is idempotent and safe to call more than once (the FFI
/// entry point may be invoked repeatedly).
pub fn init_logger(default_filter: &str) {
    let _ =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
            .try_init();
}

/// Raise this process's soft `RLIMIT_NOFILE` to its hard limit (on
/// macOS/iOS, capped at `kern.maxfilesperproc` as Darwin's `setrlimit`
/// requires).
///
/// Strictly per-process: only the calling process's own soft limit moves, and
/// never above the hard limit the OS already granted it — no other process or
/// system setting is affected, and no privileges are needed. Matters most on
/// macOS, whose default soft limit of 256 fds a proxy holding one socket per
/// connection (two on the direct split-tunnel path) exhausts quickly.
/// Best-effort: on failure the process just keeps its current limit.
#[cfg(unix)]
pub fn raise_fd_limit() {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        log::warn!(
            "getrlimit(RLIMIT_NOFILE) failed: {}",
            std::io::Error::last_os_error()
        );
        return;
    }
    // Darwin rejects a soft limit above `kern.maxfilesperproc` even when the
    // hard limit reports RLIM_INFINITY (`libc` exposes no `OPEN_MAX` on
    // Darwin, and the sysctl is the value the kernel actually enforces).
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let target = match darwin_maxfilesperproc() {
        Some(max) => lim.rlim_max.min(max),
        None => return, // can't learn the cap; leave the soft limit untouched
    };
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let target = lim.rlim_max;
    if lim.rlim_cur >= target {
        return; // already at the highest value we may request
    }
    let raised = libc::rlimit {
        rlim_cur: target,
        rlim_max: lim.rlim_max,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } != 0 {
        log::warn!(
            "setrlimit(RLIMIT_NOFILE, {target}) failed: {}; keeping soft limit {}",
            std::io::Error::last_os_error(),
            lim.rlim_cur
        );
    } else {
        log::info!("Raised open-file limit: {} -> {target}", lim.rlim_cur);
    }
}

/// Read `kern.maxfilesperproc`, the ceiling Darwin's `setrlimit` enforces on
/// the `RLIMIT_NOFILE` soft limit. Returns `None` if the sysctl fails or
/// reports a non-positive value.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn darwin_maxfilesperproc() -> Option<libc::rlim_t> {
    let mut mib = [libc::CTL_KERN, libc::KERN_MAXFILESPERPROC];
    let mut maxfiles: libc::c_int = 0;
    let mut size = std::mem::size_of_val(&maxfiles);
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            &mut maxfiles as *mut _ as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        log::warn!(
            "sysctl(kern.maxfilesperproc) failed: {}",
            std::io::Error::last_os_error()
        );
        return None;
    }
    (maxfiles > 0).then_some(maxfiles as libc::rlim_t)
}

/// Raise the open-file limit (non-Unix: nothing to do — Windows has no
/// `RLIMIT_NOFILE`; socket handles are not constrained by a per-process fd
/// table the way Unix fds are).
#[cfg(not(unix))]
pub fn raise_fd_limit() {}

/// Worker threads of the runtime a client or server runs on, on a machine with
/// at least that many cores.
///
/// One connection's data path is a chain of tasks (the splice of each stream,
/// the connection's driver, the endpoint's driver) that hand data on through
/// the connection's lock, so it cannot use more cores at once, and on Tokio's
/// default of one worker per core the chain spreads over idle workers, where
/// each handoff is a cross-thread wake. Between two 6-vCPU Linux VMs one
/// stream moved 1.86 Gbit/s down and 1.89 up on six workers, 1.93 and 2.04 on
/// two, and 2.24 and 1.99 on one, and four streams on one connection moved no
/// more than one did, at any count. Connections are what spread over workers:
/// with those hosts set up for a higher rate, a server with three busy clients
/// moved 5.1 Gbit/s down and 4.8 up in aggregate on two workers, the same on
/// three, 4.7 and 4.6 on six, and 3.8 and 4.1 on one. Two rather than one, so
/// a saturated connection cannot hold up the control streams and the
/// listeners, and a server still has a second core for a second client.
/// Numbers and method are in `docs/benchmarks.md`.
pub const RUNTIME_WORKER_THREADS: usize = 2;

/// A builder for the multi-threaded Tokio runtime of a client or server, with
/// its worker count set. `TOKIO_WORKER_THREADS` overrides the count, for
/// measurement: Tokio reads the variable only when no count is set, so the
/// count is left unset when the variable is.
pub fn runtime_builder() -> tokio::runtime::Builder {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if std::env::var_os("TOKIO_WORKER_THREADS").is_none() {
        let cores = std::thread::available_parallelism().map_or(1, usize::from);
        builder.worker_threads(cores.min(RUNTIME_WORKER_THREADS));
    }
    builder.enable_all();
    builder
}

/// Build the multi-threaded Tokio runtime the entry points block on.
pub fn build_runtime() -> Result<tokio::runtime::Runtime> {
    runtime_builder().build().map_err(Into::into)
}

/// Log the running binary's name and version. Callers pass their own crate's
/// `env!("CARGO_PKG_NAME")` / `env!("CARGO_PKG_VERSION")`, since those must be
/// resolved in the binary crate, not here.
pub fn log_version(pkg_name: &str, pkg_version: &str) {
    log::info!("{pkg_name} v{pkg_version}");
}

/// Resolve when a shutdown signal arrives: SIGTERM or SIGINT on Unix, Ctrl-C
/// elsewhere. Await this alongside the main task in a `tokio::select!`. Returns
/// an error if the signal handlers can't be registered, so the caller can log
/// and exit cleanly instead of the process panicking.
#[cfg(unix)]
pub async fn shutdown_signal() -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut int = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    Ok(())
}

/// Resolve when a shutdown signal arrives (non-Unix: Ctrl-C only).
#[cfg(not(unix))]
pub async fn shutdown_signal() -> Result<()> {
    tokio::signal::ctrl_c()
        .await
        .context("installing Ctrl-C handler")?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    /// Raising the limit must bring the soft limit to at least the target we
    /// request (the hard limit off Darwin, `kern.maxfilesperproc` on it) and
    /// be a stable no-op when called again. `raise_fd_limit` only ever raises,
    /// so an ambient soft limit already above the target is left in place —
    /// hence `>=`, not `==`. Only touches the process's own soft limit, so
    /// running alongside other tests is harmless.
    #[test]
    fn raise_fd_limit_reaches_cap_and_is_idempotent() {
        super::raise_fd_limit();
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) }, 0);
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let target = lim
            .rlim_max
            .min(super::darwin_maxfilesperproc().expect("kern.maxfilesperproc must be readable"));
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        let target = lim.rlim_max;
        assert!(
            lim.rlim_cur >= target,
            "soft limit {} below target {target}",
            lim.rlim_cur
        );
        let after_first = lim.rlim_cur;
        super::raise_fd_limit();
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) }, 0);
        assert_eq!(lim.rlim_cur, after_first);
    }
}
