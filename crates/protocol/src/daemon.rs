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
use std::os::unix::process::CommandExt;

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

pub fn daemonize_if_requested(
    daemon: bool,
    daemon_child: bool,
    socket_path: &Path,
    socket_flag: &str,
    child_flag: &str,
) -> Result<bool> {
    if !daemon || daemon_child {
        return Ok(false);
    }

    let current_exe = env::current_exe().context("resolving current executable")?;
    let mut args = filtered_daemon_args(socket_path, socket_flag, child_flag)?;
    args.push(OsString::from(child_flag));
    args.push(OsString::from(socket_flag));
    args.push(socket_path.as_os_str().to_os_string());

    let mut command = Command::new(current_exe);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(unix)]
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
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGTERM);
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
