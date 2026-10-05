//! Native Fangida tools. The analyzer remains an independent lazy-loaded process.
mod client;
pub use client::BridgeConfig;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use client::Session;
use kkagent_tools::{Tool, ToolAccesses, ToolContext, ToolOutput, ToolRegistry};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use tokio::sync::Mutex;

const MAX_SESSIONS: usize = 16;
const MAX_OUTPUT_BYTES: usize = 256 * 1024;
pub const TOOL_NAMES: &[&str] = &[
    "FangidaAnalyze",
    "FangidaRead",
    "FangidaDatabase",
    "FangidaSave",
    "FangidaAnnotate",
];
pub const SYSTEM_PROMPT: &str = "\n\n# Native Fangida binary analysis\nUse FangidaAnalyze to open native binaries with full executable-region disassembly, function recovery, CFG and xrefs. For APK/DEX/JAR/class pass full_analysis=false; these use the separate APK analyzer. FangidaRead returns bounded pages of functions, disassembly, CFG blocks/edges/frontier, xrefs, optional pseudocode/API evidence and a compact coverage summary. Follow next_offset; disassembly supports source, CFG supports source/address_space to disambiguate archive members; open members separately for other queries. Full byte coverage does not prove complete function recovery or indirect xrefs. Pseudocode requires an available decompiler; do not invent it. Handles are local to the current session and survive turns; close unused handles or reset to release the backend. FangidaDatabase opens saved .fdb analyses without reanalysis or the original binary. FangidaSave persists an existing analysis. FangidaAnnotate writes database names/comments under the normal write permission policy; reload a saved snapshot to observe new annotations. The database contains analysis only, never original binary bytes. Prefer these native tools for static evidence instead of scripting shell/MCP setup.\n";

#[derive(Default)]
pub struct Backend {
    config: Option<BridgeConfig>,
    sessions: Mutex<HashMap<String, Arc<Mutex<Session>>>>,
}

impl Backend {
    pub fn new(config: BridgeConfig) -> Self {
        Self {
            config: Some(config),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    async fn session(&self, id: &str) -> Result<Arc<Mutex<Session>>> {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get(id) {
            return Ok(session.clone());
        }
        // Discard idle entries left after explicit reset before enforcing the bound.
        sessions.retain(|_, session| {
            session.try_lock().map_or(true, |session| {
                !session.files.is_empty() || !session.databases.is_empty()
            })
        });
        if sessions.len() >= MAX_SESSIONS {
            bail!("Fangida is limited to 16 active sessions; close/reset an unused session");
        }
        let session = Arc::new(Mutex::new(Session::default()));
        sessions.insert(id.to_string(), session.clone());
        Ok(session)
    }

    pub async fn close_session(&self, id: &str) {
        let session = { self.sessions.lock().await.remove(id) };
        if let Some(session) = session {
            session.lock().await.reset();
        }
    }

    async fn execute(&self, kind: Kind, input: Value, ctx: &ToolContext) -> Result<Value> {
        let session = self.session(&ctx.session_id).await?;
        let mut session = session.lock().await;
        if matches!(kind, Kind::Read)
            && input.get("action").and_then(Value::as_str) == Some("reset")
        {
            session.reset();
            return Ok(json!({"reset":true,"handles_expired":true}));
        }
        let config = match &self.config {
            Some(config) => config.clone(),
            None => BridgeConfig::discover(&ctx.working_dir)?,
        };
        match kind {
            Kind::Analyze => {
                let path = checked_path(&input, ctx)?;
                let mut arguments = fields(
                    &input,
                    &["max_bytes", "full_analysis", "use_ghidra", "deep_analysis"],
                );
                arguments.insert("path".into(), json!(path));
                arguments.entry("full_analysis").or_insert(json!(true));
                arguments.entry("use_ghidra").or_insert(json!(false));
                let result = session
                    .call(&config, ctx, "open_file", Value::Object(arguments))
                    .await?;
                let handle = text(&result, "handle")?;
                session.files.insert(handle.to_owned(), path);
                Ok(result)
            }
            Kind::Read => {
                let handle = text(&input, "handle")?;
                check_handle(&session.files, handle, ctx)?;
                let action = text(&input, "action")?;
                if input.get("source").is_some() && !matches!(action, "disasm" | "cfg") {
                    bail!("source filtering is supported for disasm/cfg; open a separate member for other queries");
                }
                if input.get("address_space").is_some() && action != "cfg" {
                    bail!("address_space filtering is supported for cfg");
                }
                let remote = match action {
                    "summary" => "analysis_summary",
                    "functions" => "list_functions",
                    "disasm" => "get_disasm",
                    "cfg" => "get_cfg",
                    "xrefs" => "xref_query",
                    "pseudocode" => "get_pseudoc",
                    "api_calls" => "list_api_calls",
                    "close" => "close_file",
                    _ => bail!("Unknown read action"),
                };
                let mut arguments = fields(&input, &["handle"]);
                let extra: &[&str] = match action {
                    "functions" | "api_calls" => &["offset", "limit"],
                    "disasm" => &["address", "source", "offset", "limit"],
                    "cfg" => &[
                        "address",
                        "source",
                        "address_space",
                        "collection",
                        "offset",
                        "limit",
                    ],
                    "xrefs" => &["address", "direction", "offset", "limit"],
                    "pseudocode" => &["address"],
                    _ => &[],
                };
                arguments.extend(fields(&input, extra));
                if matches!(action, "cfg" | "xrefs" | "pseudocode") {
                    text_or_address(&input)?;
                }
                if action == "functions" {
                    arguments.insert("include_details".into(), json!(false));
                }
                let result = session
                    .call(&config, ctx, remote, Value::Object(arguments))
                    .await?;
                if action == "close" {
                    session.files.remove(handle);
                }
                Ok(result)
            }
            Kind::Database => {
                let action = text(&input, "action")?;
                if action == "open" {
                    let path = checked_path(&input, ctx)?;
                    let result = session
                        .call(
                            &config,
                            ctx,
                            "open_database",
                            json!({"path":path,"read_only":true}),
                        )
                        .await?;
                    session
                        .databases
                        .insert(text(&result, "database")?.to_owned(), path);
                    return Ok(result);
                }
                let database = text(&input, "database")?;
                let path = check_handle(&session.databases, database, ctx)?.to_path_buf();
                let remote = match action {
                    "history" => "database_history",
                    "page" => "database_page",
                    "load" => "open_database_snapshot",
                    "annotations" => "database_annotations",
                    "close" => "close_database",
                    _ => bail!("Unknown database action"),
                };
                let mut arguments = fields(&input, &["database"]);
                let extra: &[&str] = match action {
                    "history" => &["offset", "limit"],
                    "page" => &["snapshot_id", "collection", "offset", "limit"],
                    "load" => &["snapshot_id"],
                    "annotations" => &["snapshot_id", "offset", "limit"],
                    _ => &[],
                };
                arguments.extend(fields(&input, extra));
                if matches!(action, "page" | "annotations") {
                    positive_snapshot(&input)?;
                }
                if action == "page" {
                    text(&input, "collection")?;
                }
                if action == "page"
                    && input.get("collection").and_then(Value::as_str) == Some("functions")
                {
                    arguments.insert("include_details".into(), json!(false));
                }
                let result = session
                    .call(&config, ctx, remote, Value::Object(arguments))
                    .await?;
                if action == "load" {
                    session
                        .files
                        .insert(text(&result, "handle")?.to_owned(), path);
                }
                if action == "close" {
                    session.databases.remove(database);
                }
                Ok(result)
            }
            Kind::Save => {
                let handle = text(&input, "handle")?;
                check_handle(&session.files, handle, ctx)?;
                let path = checked_path(&input, ctx)?;
                let opened = session
                    .call(&config, ctx, "create_database", json!({"path":path}))
                    .await?;
                let database = text(&opened, "database")?.to_owned();
                let result = session
                    .call(
                        &config,
                        ctx,
                        "save_to_database",
                        json!({"database":database,"handle":handle}),
                    )
                    .await;
                let closed = session
                    .close_temporary_database(&config, ctx, &database)
                    .await;
                let mut result = result?;
                closed?;
                result["database_path"] = json!(path);
                Ok(result)
            }
            Kind::Annotate => {
                let path = checked_path(&input, ctx)?;
                positive_snapshot(&input)?;
                text_or_address(&input)?;
                let action = text(&input, "action")?;
                let value = input
                    .get("value")
                    .and_then(Value::as_str)
                    .context("value must be a string")?;
                let remote = match action {
                    "rename" => "database_rename_symbol",
                    "comment" => "database_set_comment",
                    _ => bail!("Unknown annotation action"),
                };
                let opened = session
                    .call(
                        &config,
                        ctx,
                        "open_database",
                        json!({"path":path,"read_only":false}),
                    )
                    .await?;
                let database = text(&opened, "database")?.to_owned();
                let mut arguments = fields(&input, &["snapshot_id", "address"]);
                arguments.insert("database".into(), json!(database));
                arguments.insert(
                    if action == "rename" { "name" } else { "text" }.into(),
                    json!(value),
                );
                let result = session
                    .call(&config, ctx, remote, Value::Object(arguments))
                    .await;
                let closed = session
                    .close_temporary_database(&config, ctx, &database)
                    .await;
                let mut result = result?;
                closed?;
                result["database_path"] = json!(path);
                result["snapshot_id"] = input["snapshot_id"].clone();
                result["reload_required"] = json!(true);
                Ok(result)
            }
        }
    }
}

static DEFAULT_BACKEND: LazyLock<Arc<Backend>> = LazyLock::new(|| Arc::new(Backend::default()));
pub fn register_tools(registry: &mut ToolRegistry) {
    register_tools_with_backend(registry, DEFAULT_BACKEND.clone());
}
pub fn register_tools_with_backend(registry: &mut ToolRegistry, backend: Arc<Backend>) {
    for kind in [
        Kind::Analyze,
        Kind::Read,
        Kind::Database,
        Kind::Save,
        Kind::Annotate,
    ] {
        registry.register(Arc::new(FangidaTool {
            kind,
            backend: backend.clone(),
        }));
    }
}
pub async fn close_session(id: &str) {
    DEFAULT_BACKEND.close_session(id).await;
}

/// Release a delegated session even if its future is aborted mid-tool call.
pub struct SessionLease(String);
impl SessionLease {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}
impl Drop for SessionLease {
    fn drop(&mut self) {
        let id = self.0.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                close_session(&id).await;
            });
        }
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Analyze,
    Read,
    Database,
    Save,
    Annotate,
}
struct FangidaTool {
    kind: Kind,
    backend: Arc<Backend>,
}

#[async_trait]
impl Tool for FangidaTool {
    fn name(&self) -> &str {
        TOOL_NAMES[self.kind as usize]
    }
    fn description(&self) -> &str {
        match self.kind {
            Kind::Analyze => "Analyze a local binary with Fangida, returning a session handle. Native full_analysis defaults to true; APK/DEX/JAR/class need false. Ghidra defaults to false. No binary is executed.",
            Kind::Read => "Read bounded pages of Fangida summary, functions, disassembly, CFG, xrefs, optional pseudocode or API calls. CFG/pseudocode/xrefs require address. Follow next_offset. close releases a handle; reset releases all this session's backend resources.",
            Kind::Database => "Read existing .fdb databases without reanalysis or original binary. open needs path; other actions need database handle. page/annotations need snapshot_id; page also needs collection. load returns an analysis handle.",
            Kind::Save => "Save an existing Fangida analysis handle to a .fdb path. Requires write permission. Stores analysis, names and comments; never embeds binary bytes or reanalyzes.",
            Kind::Annotate => "Persist rename/comment on a saved .fdb snapshot under write permission. Needs path, snapshot_id, address, action and value. Does not rewrite the binary. Reload a snapshot to see changed annotations.",
        }
    }
    fn read_only(&self) -> bool {
        !matches!(self.kind, Kind::Save | Kind::Annotate)
    }
    fn accesses(&self, input: &Value, working_dir: &Path) -> ToolAccesses {
        if let Some(path) = input.get("path").and_then(Value::as_str) {
            let path = if Path::new(path).is_absolute() {
                PathBuf::from(path)
            } else {
                working_dir.join(path)
            };
            if self.read_only() {
                kkagent_tools::tool_accesses::read_file(path.to_string_lossy())
            } else {
                kkagent_tools::tool_accesses::read_write_file(path.to_string_lossy())
            }
        } else {
            kkagent_tools::tool_accesses::all()
        }
    }
    fn parameters_schema(&self) -> Value {
        schema(self.kind)
    }
    async fn execute(&self, input: Value, ctx: &ToolContext) -> Result<ToolOutput> {
        if let Err(error) = kkagent_tools::args_validator::validate_against_schema(
            &self.parameters_schema(),
            &input,
        ) {
            return Ok(ToolOutput::error(error.message));
        }
        match self.backend.execute(self.kind, input, ctx).await {
            Ok(value) => {
                let content = serde_json::to_string(&value)?;
                if content.len() > MAX_OUTPUT_BYTES {
                    return Ok(ToolOutput::error("Fangida page exceeds 256 KiB; retry with a smaller limit. No analysis records were removed."));
                }
                let mut output = ToolOutput::success(content);
                output.data = Some(value);
                Ok(output)
            }
            Err(error) => Ok(ToolOutput::error(format!("{error:#}"))),
        }
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .with_context(|| format!("Missing non-empty {key}"))
}
fn fields(input: &Value, keys: &[&str]) -> Map<String, Value> {
    keys.iter()
        .filter_map(|key| {
            input
                .get(*key)
                .map(|value| ((*key).to_owned(), value.clone()))
        })
        .collect()
}
fn positive_snapshot(input: &Value) -> Result<()> {
    if input
        .get("snapshot_id")
        .and_then(Value::as_u64)
        .is_none_or(|id| id == 0)
    {
        bail!("snapshot_id must be a positive integer");
    }
    Ok(())
}
fn text_or_address(input: &Value) -> Result<()> {
    if !input.get("address").is_some_and(|address| {
        address.as_u64().is_some() || address.as_str().is_some_and(|text| !text.is_empty())
    }) {
        bail!("address is required");
    }
    Ok(())
}
fn guard_path(path: &Path, ctx: &ToolContext) -> Result<()> {
    ctx.check_path_guard(path).map_err(anyhow::Error::msg)?;
    if ctx.sensitive_check_enabled() && kkagent_tools::path_policy::is_sensitive_path(path) {
        bail!("Fangida cannot access a sensitive path under the active path policy");
    }
    Ok(())
}
fn checked_path(input: &Value, ctx: &ToolContext) -> Result<PathBuf> {
    let raw = Path::new(text(input, "path")?);
    let path = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        ctx.working_dir.join(raw)
    };
    guard_path(&path, ctx)?;
    let path = kkagent_tools::path_policy::resolve_access_path(&path)?;
    guard_path(&path, ctx)?;
    Ok(path)
}
fn check_handle<'a>(
    handles: &'a HashMap<String, PathBuf>,
    handle: &str,
    ctx: &ToolContext,
) -> Result<&'a Path> {
    let path = handles
        .get(handle)
        .context("Unknown Fangida handle in this session; open the file/database first")?;
    guard_path(path, ctx)?;
    Ok(path)
}

fn schema(kind: Kind) -> Value {
    let mut properties = Map::new();
    let string = json!({"type":"string","minLength":1});
    let required: &[&str] = match kind {
        Kind::Analyze => {
            properties.insert("path".into(), string.clone());
            properties.insert(
                "full_analysis".into(),
                json!({"type":"boolean","default":true}),
            );
            properties.insert(
                "use_ghidra".into(),
                json!({"type":"boolean","default":false}),
            );
            properties.insert("deep_analysis".into(), json!({"type":"boolean"}));
            properties.insert(
                "max_bytes".into(),
                json!({"type":"integer","minimum":1,"maximum":67108864}),
            );
            &["path"]
        }
        Kind::Read => {
            properties.insert("action".into(), json!({"type":"string","enum":["summary","functions","disasm","cfg","xrefs","pseudocode","api_calls","close","reset"]}));
            properties.insert("handle".into(), string.clone());
            properties.insert("source".into(), json!({"type":"string"}));
            properties.insert("address_space".into(), string.clone());
            properties.insert(
                "collection".into(),
                json!({"type":"string","enum":["blocks","edges","frontier"]}),
            );
            properties.insert(
                "direction".into(),
                json!({"type":"string","enum":["to","from","both"]}),
            );
            &["action"]
        }
        Kind::Database => {
            properties.insert("action".into(), json!({"type":"string","enum":["open","history","page","load","annotations","close"]}));
            properties.insert("path".into(), string.clone());
            properties.insert("database".into(), string.clone());
            properties.insert("collection".into(), json!({"type":"string","enum":["functions","strings","imports","exports","xrefs","warnings","disassembly"]}));
            properties.insert("snapshot_id".into(), json!({"type":"integer","minimum":1}));
            &["action"]
        }
        Kind::Save => {
            properties.insert("path".into(), string.clone());
            properties.insert("handle".into(), string.clone());
            &["path", "handle"]
        }
        Kind::Annotate => {
            properties.insert("path".into(), string.clone());
            properties.insert(
                "action".into(),
                json!({"type":"string","enum":["rename","comment"]}),
            );
            properties.insert("snapshot_id".into(), json!({"type":"integer","minimum":1}));
            properties.insert("value".into(), json!({"type":"string"}));
            &["path", "action", "snapshot_id", "address", "value"]
        }
    };
    if matches!(kind, Kind::Read | Kind::Annotate) {
        properties.insert("address".into(), json!({"oneOf":[{"type":"integer","minimum":0},{"type":"string","pattern":"^(0[xX][0-9a-fA-F]+|[0-9]+)$"}]}));
    }
    if matches!(kind, Kind::Read | Kind::Database) {
        properties.insert(
            "offset".into(),
            json!({"type":"integer","minimum":0,"default":0}),
        );
        properties.insert(
            "limit".into(),
            json!({"type":"integer","minimum":1,"maximum":200,"default":100}),
        );
    }
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}
