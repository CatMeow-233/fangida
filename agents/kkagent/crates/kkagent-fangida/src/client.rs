//! Persistent local transport. It never implements loaders or instruction decoding.
use anyhow::{bail, Context, Result};
use kkagent_tools::ToolContext;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const PROTOCOL: &str = "2025-11-25";

#[derive(Clone, Debug)]
pub struct BridgeConfig {
    pub python: OsString,
    pub repository: Option<PathBuf>,
    pub timeout: Duration,
}

impl BridgeConfig {
    pub fn discover(working_dir: &Path) -> Result<Self> {
        let repository = if let Some(root) = std::env::var_os("FANGIDA_ROOT") {
            let root = PathBuf::from(root)
                .canonicalize()
                .context("Invalid FANGIDA_ROOT")?;
            if !root.join("fangida/mcp_server.py").is_file() {
                bail!("FANGIDA_ROOT must point to the Fangida repository");
            }
            Some(root)
        } else {
            let executable = std::env::current_exe().ok();
            let found = [
                Some(working_dir),
                executable.as_deref(),
                Some(Path::new(env!("CARGO_MANIFEST_DIR"))),
            ]
            .into_iter()
            .flatten()
            .find_map(|start| {
                start
                    .ancestors()
                    .find(|parent| parent.join("fangida/mcp_server.py").is_file())
                    .map(Path::to_path_buf)
            });
            found
        };
        let python = std::env::var_os("FANGIDA_PYTHON")
            .or_else(|| {
                let root = repository.as_ref()?;
                let relative = if cfg!(windows) {
                    ".venv/Scripts/python.exe"
                } else {
                    ".venv/bin/python"
                };
                let candidate = root.join(relative);
                candidate.is_file().then(|| candidate.into_os_string())
            })
            .unwrap_or_else(|| {
                if cfg!(windows) {
                    "python".into()
                } else {
                    "python3".into()
                }
            });
        let seconds = match std::env::var("FANGIDA_TIMEOUT_SECONDS") {
            Ok(value) => value
                .parse::<u64>()
                .context("FANGIDA_TIMEOUT_SECONDS must be an integer")?,
            Err(_) => 120,
        };
        if !(1..=3600).contains(&seconds) {
            bail!("FANGIDA_TIMEOUT_SECONDS must be between 1 and 3600");
        }
        Ok(Self {
            python,
            repository,
            timeout: Duration::from_secs(seconds),
        })
    }
}

struct Bridge {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    pending: bool,
}

async fn read_frame<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    loop {
        let buffer = reader.fill_buf().await?;
        if buffer.is_empty() {
            bail!("Fangida backend closed its output");
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(buffer.len(), |position| position + 1);
        if count > MAX_FRAME_BYTES.saturating_sub(frame.len()) {
            bail!("Fangida response exceeds 4 MiB; request a smaller page");
        }
        frame.extend_from_slice(&buffer[..count]);
        reader.consume(count);
        if newline.is_some() {
            return Ok(frame);
        }
    }
}

async fn interrupted(flag: &Option<Arc<AtomicBool>>) {
    let Some(flag) = flag else {
        std::future::pending::<()>().await;
        return;
    };
    while !flag.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

impl Bridge {
    async fn start(config: &BridgeConfig, working_dir: &Path) -> Result<Self> {
        let mut command = Command::new(&config.python);
        command
            .args([
                "-m",
                "fangida.mcp_server",
                "--allow-writes",
                "--own-completed-results",
            ])
            .current_dir(working_dir)
            .kill_on_drop(true)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .env("PYTHONUNBUFFERED", "1");
        if let Some(root) = &config.repository {
            let mut paths = vec![root.clone()];
            if let Some(existing) = std::env::var_os("PYTHONPATH") {
                paths.extend(std::env::split_paths(&existing));
            }
            command.env("PYTHONPATH", std::env::join_paths(paths)?);
        }
        let mut child = command.spawn().with_context(|| {
            format!(
                "Cannot start {:?}; set FANGIDA_PYTHON to the Python with Fangida installed",
                config.python
            )
        })?;
        let stdin = child.stdin.take().context("Missing backend stdin")?;
        let stdout = BufReader::new(child.stdout.take().context("Missing backend stdout")?);
        let mut bridge = Self {
            child,
            stdin,
            stdout,
            next_id: 1,
            pending: false,
        };
        let response = bridge.request("initialize", json!({"protocolVersion":PROTOCOL,"capabilities":{},"clientInfo":{"name":"kkagent-fangida","version":env!("CARGO_PKG_VERSION")}})).await?;
        if response.get("protocolVersion").and_then(Value::as_str) != Some(PROTOCOL) {
            bail!("Unsupported Fangida protocol version");
        }
        bridge.notify("notifications/initialized").await?;
        Ok(bridge)
    }

    async fn notify(&mut self, method: &str) -> Result<()> {
        let mut bytes = serde_json::to_vec(&json!({"jsonrpc":"2.0","method":method}))?;
        bytes.push(b'\n');
        self.stdin.write_all(&bytes).await?;
        self.stdin.flush().await?;
        Ok(())
    }

    async fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let mut bytes =
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))?;
        bytes.push(b'\n');
        self.pending = true;
        self.stdin.write_all(&bytes).await?;
        self.stdin.flush().await?;
        let response: Value = serde_json::from_slice(&read_frame(&mut self.stdout).await?)?;
        if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || response.get("id").and_then(Value::as_u64) != Some(id)
        {
            bail!("Fangida response does not match the current request");
        }
        self.pending = false;
        if let Some(error) = response.get("error") {
            bail!("Fangida protocol error: {error}");
        }
        response
            .get("result")
            .cloned()
            .context("Missing Fangida result")
    }
}

#[derive(Default)]
pub(crate) struct Session {
    bridge: Option<Bridge>,
    pub files: HashMap<String, PathBuf>,
    pub databases: HashMap<String, PathBuf>,
}

impl Session {
    pub async fn close_temporary_database(
        &mut self,
        config: &BridgeConfig,
        ctx: &ToolContext,
        database: &str,
    ) -> Result<()> {
        if self.bridge.is_some() {
            self.call(config, ctx, "close_database", json!({"database":database}))
                .await?;
        }
        Ok(())
    }
    pub fn reset(&mut self) {
        if let Some(mut bridge) = self.bridge.take() {
            let _ = bridge.child.start_kill();
        }
        self.files.clear();
        self.databases.clear();
    }

    pub async fn call(
        &mut self,
        config: &BridgeConfig,
        ctx: &ToolContext,
        name: &str,
        arguments: Value,
    ) -> Result<Value> {
        if ctx
            .interrupted
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            bail!("Fangida request cancelled before dispatch");
        }
        if self.bridge.as_ref().is_some_and(|bridge| bridge.pending) {
            self.reset();
            bail!("Previous Fangida request was interrupted; handles expired. Reopen the file/database. Writes are never replayed automatically.");
        }
        let operation = async {
            if self.bridge.is_none() {
                self.bridge = Some(Bridge::start(config, &ctx.working_dir).await?);
            }
            self.bridge
                .as_mut()
                .unwrap()
                .request("tools/call", json!({"name":name,"arguments":arguments}))
                .await
        };
        let response = tokio::select! {
            value = tokio::time::timeout(config.timeout, operation) => match value {
                Ok(result) => result,
                Err(_) => Err(anyhow::anyhow!("Fangida request timed out")),
            },
            _ = interrupted(&ctx.interrupted) => Err(anyhow::anyhow!("Fangida request cancelled")),
        };
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                self.reset();
                return Err(error
                    .context("Fangida transport lost; handles expired. Writes were not replayed"));
            }
        };
        let text = response
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n");
        if response.get("isError").and_then(Value::as_bool) == Some(true) {
            bail!("{text}");
        }
        if let Some(structured) = response.get("structuredContent") {
            return Ok(structured.clone());
        }
        serde_json::from_str(&text).context("Fangida returned no structured JSON result")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn frames_are_bounded_and_do_not_consume_the_next_reply() {
        let mut reader = BufReader::new(&b"{\"id\":1}\n{\"id\":2}\n"[..]);
        assert_eq!(read_frame(&mut reader).await.unwrap(), b"{\"id\":1}\n");
        assert_eq!(read_frame(&mut reader).await.unwrap(), b"{\"id\":2}\n");
        let bytes = vec![b'x'; MAX_FRAME_BYTES + 1];
        assert!(read_frame(&mut BufReader::new(bytes.as_slice()))
            .await
            .unwrap_err()
            .to_string()
            .contains("4 MiB"));
    }
}
