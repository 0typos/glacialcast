//! Local Unix-socket lifecycle helpers for GlacialCast binaries.
//!
//! The control protocol is intentionally small and local: one newline-
//! terminated command receives one newline-terminated response. It supports
//! status inspection and graceful shutdown, while process daemonization
//! re-executes the current binary in a detached session.

use anyhow::{Context, Result, bail};
use std::{
    env,
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::watch,
};

#[cfg(unix)]
use std::os::unix::{fs::OpenOptionsExt, process::CommandExt};

/// Converts a user-facing value into a conservative Unix-socket path component.
pub fn sanitize_socket_component(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    sanitized.trim_matches('-').to_string()
}

/// Re-executes the current process as a detached daemon when requested.
///
/// Returns `true` in the parent after spawning the daemon child, which tells
/// the caller to exit successfully. Returns `false` when the current process
/// should continue normal startup.
///
/// When `log_path` is set, the child's standard output and error are appended
/// to that file, which is created with mode `0600` because process logs can
/// contain operational detail. Without it, both streams are discarded.
pub fn daemonize_if_requested(
    daemon: bool,
    daemon_child: bool,
    socket_path: &Path,
    socket_flag: &str,
    child_flag: &str,
    log_path: Option<&Path>,
) -> Result<bool> {
    if !daemon || daemon_child {
        return Ok(false);
    }

    let current_exe = env::current_exe().context("resolving current executable")?;
    let mut args = filtered_daemon_args(socket_path, socket_flag, child_flag)?;
    args.push(OsString::from(child_flag));
    args.push(OsString::from(socket_flag));
    args.push(socket_path.as_os_str().to_os_string());

    let (stdout, stderr) = match log_path {
        Some(path) => {
            let file = open_daemon_log(path)?;
            let duplicate = file
                .try_clone()
                .with_context(|| format!("duplicating daemon log {}", path.display()))?;
            (Stdio::from(file), Stdio::from(duplicate))
        }
        None => (Stdio::null(), Stdio::null()),
    };
    let mut command = Command::new(current_exe);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);

    #[cfg(unix)]
    // SAFETY: the post-fork closure performs only the async-signal-safe
    // `setsid(2)` syscall and reads `errno` when that syscall fails.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = command.spawn().context("spawning daemon child")?;
    println!(
        "started daemon pid={} socket={}",
        child.id(),
        socket_path.display()
    );
    Ok(true)
}

/// Opens the daemon log for appending, creating it private when absent.
fn open_daemon_log(path: &Path) -> Result<std::fs::File> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating daemon log directory {}", parent.display()))?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening daemon log {}", path.display()))
}

fn filtered_daemon_args(
    socket_path: &Path,
    socket_flag: &str,
    child_flag: &str,
) -> Result<Vec<OsString>> {
    let mut out = Vec::new();
    let mut args = env::args_os().skip(1).peekable();
    while let Some(arg) = args.next() {
        if arg == "--daemon" || arg == child_flag {
            continue;
        }
        if arg == socket_flag {
            let _ = args.next();
            continue;
        }
        let arg_string = arg.to_string_lossy();
        if arg_string.starts_with("--daemon=")
            || arg_string.starts_with(&format!("{socket_flag}="))
            || arg_string.starts_with(&format!("{child_flag}="))
        {
            continue;
        }
        out.push(arg);
    }
    if socket_path.as_os_str().is_empty() {
        bail!("daemon socket path must not be empty");
    }
    Ok(out)
}

/// Sends one command to a local daemon control socket and returns its response.
pub async fn manager_command(socket_path: &Path, command: &str) -> Result<String> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connecting daemon socket {}", socket_path.display()))?;
    stream
        .write_all(command.as_bytes())
        .await
        .context("writing daemon command")?;
    if !command.ends_with('\n') {
        stream
            .write_all(b"\n")
            .await
            .context("terminating daemon command")?;
    }
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .await
        .context("reading daemon response")?;
    Ok(response)
}

/// Serves status and shutdown commands until shutdown is requested.
///
/// Startup refuses to replace an active socket and removes only a stale socket
/// at the exact requested path. The socket is removed on graceful exit.
pub async fn serve_control_socket(
    socket_path: PathBuf,
    shutdown_tx: watch::Sender<bool>,
) -> Result<()> {
    prepare_socket_path(&socket_path).await?;
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("binding daemon socket {}", socket_path.display()))?;
    let mut shutdown_rx = shutdown_tx.subscribe();

    loop {
        tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown_rx) => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accepting daemon control connection")?;
                let shutdown_tx = shutdown_tx.clone();
                tokio::spawn(async move {
                    let _ = handle_control_connection(stream, shutdown_tx).await;
                });
            }
        }
    }

    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

async fn prepare_socket_path(socket_path: &Path) -> Result<()> {
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating daemon socket dir {}", parent.display()))?;
    }
    if UnixStream::connect(socket_path).await.is_ok() {
        bail!("daemon socket already active at {}", socket_path.display());
    }
    if socket_path.exists() {
        tokio::fs::remove_file(socket_path)
            .await
            .with_context(|| format!("removing stale daemon socket {}", socket_path.display()))?;
    }
    Ok(())
}

async fn handle_control_connection(
    stream: UnixStream,
    shutdown_tx: watch::Sender<bool>,
) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut command = String::new();
    reader.read_line(&mut command).await?;
    let command = command.trim();
    let response = match command {
        "pid" | "status" => format!("pid {}\n", std::process::id()),
        "shutdown" | "stop" => {
            let _ = shutdown_tx.send(true);
            "ok shutting down\n".to_string()
        }
        "signal TERM" | "signal SIGTERM" => {
            #[cfg(unix)]
            // SAFETY: the target is this live process ID and SIGTERM is a
            // valid signal number; no pointer or borrowed memory crosses FFI.
            unsafe {
                libc::kill(
                    // Linux process IDs fit in `pid_t` by construction; this is
                    // this process's own ID, not a value from anywhere else.
                    #[allow(clippy::cast_possible_wrap, reason = "a pid always fits in pid_t")]
                    {
                        std::process::id() as libc::pid_t
                    },
                    libc::SIGTERM,
                );
            }
            #[cfg(not(unix))]
            {
                let _ = shutdown_tx.send(true);
            }
            "ok signalled\n".to_string()
        }
        _ => "error unknown command\n".to_string(),
    };
    reader.get_mut().write_all(response.as_bytes()).await?;
    Ok(())
}

/// Waits for `Ctrl+C` or `SIGTERM`, then broadcasts graceful shutdown.
pub async fn install_signal_handlers(shutdown_tx: watch::Sender<bool>) -> Result<()> {
    let mut sigterm = {
        #[cfg(unix)]
        {
            Some(tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            )?)
        }
        #[cfg(not(unix))]
        {
            None::<()>
        }
    };

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.context("listening for Ctrl-C")?;
        }
        _ = async {
            #[cfg(unix)]
            if let Some(signal) = sigterm.as_mut() {
                signal.recv().await;
            }
            #[cfg(not(unix))]
            std::future::pending::<()>().await;
        } => {}
    }
    let _ = shutdown_tx.send(true);
    Ok(())
}

/// Waits until shutdown was requested or all watch senders were dropped.
pub async fn wait_for_shutdown(shutdown_rx: &mut watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }
    while shutdown_rx.changed().await.is_ok() {
        if *shutdown_rx.borrow() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn socket_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "glacialcast-daemon-{label}-{}.sock",
            Uuid::new_v4()
        ))
    }

    async fn wait_for_path(path: &Path) {
        for _ in 0..100 {
            if path.exists() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("socket did not appear at {}", path.display());
    }

    #[test]
    fn socket_components_are_filesystem_safe() {
        assert_eq!(
            sanitize_socket_component("Glacial Cast/one"),
            "Glacial-Cast-one"
        );
        assert_eq!(sanitize_socket_component("--a__b--"), "a__b");
        assert_eq!(sanitize_socket_component("☃"), "");
        assert_eq!(sanitize_socket_component("abc-123_DEF"), "abc-123_DEF");
    }

    #[tokio::test]
    async fn control_socket_handles_status_unknown_and_shutdown_commands() {
        let path = socket_path("commands");
        let (shutdown_tx, _) = watch::channel(false);
        let server_path = path.clone();
        let server_tx = shutdown_tx.clone();
        let server =
            tokio::spawn(async move { serve_control_socket(server_path, server_tx).await });
        wait_for_path(&path).await;

        let status = manager_command(&path, "status").await.unwrap();
        assert_eq!(status, format!("pid {}\n", std::process::id()));
        assert_eq!(
            manager_command(&path, "not-a-command\n").await.unwrap(),
            "error unknown command\n"
        );
        assert_eq!(
            manager_command(&path, "shutdown").await.unwrap(),
            "ok shutting down\n"
        );

        server.await.unwrap().unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn socket_preparation_removes_stale_file_but_preserves_active_socket() {
        let stale = socket_path("stale");
        std::fs::write(&stale, b"stale").unwrap();
        prepare_socket_path(&stale).await.unwrap();
        assert!(!stale.exists());

        let active = socket_path("active");
        let listener = UnixListener::bind(&active).unwrap();
        let error = prepare_socket_path(&active).await.unwrap_err();
        assert!(error.to_string().contains("already active"));
        assert!(active.exists());
        drop(listener);
        std::fs::remove_file(active).unwrap();
    }

    #[tokio::test]
    async fn shutdown_waiter_handles_preexisting_signal_and_sender_close() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(true);
        wait_for_shutdown(&mut shutdown_rx).await;
        drop(shutdown_rx);
        drop(shutdown_tx);

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        drop(shutdown_tx);
        wait_for_shutdown(&mut shutdown_rx).await;
    }

    #[tokio::test]
    async fn manager_command_reports_missing_socket() {
        let error = manager_command(&socket_path("missing"), "status")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("connecting daemon socket"));
    }
}
