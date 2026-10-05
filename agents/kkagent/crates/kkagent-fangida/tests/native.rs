use kkagent_fangida::{register_tools_with_backend, Backend, BridgeConfig, TOOL_NAMES};
use kkagent_tools::{ToolContext, ToolRegistry};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let token = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "fangida native 中文 {} {token}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn context(path: &Path, id: &str) -> ToolContext {
    ToolContext {
        working_dir: path.to_path_buf(),
        session_id: id.into(),
        turn_id: format!("{id}:1"),
        plan_file_path: None,
        image: Default::default(),
        tool_call_id: None,
        interrupted: None,
        tools_config: Default::default(),
        model_alias: None,
    }
}
fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap()
        .to_path_buf()
}
fn config(repository: PathBuf) -> BridgeConfig {
    BridgeConfig {
        python: std::env::var_os("FANGIDA_PYTHON").unwrap_or_else(|| {
            if cfg!(windows) {
                "python".into()
            } else {
                "python3".into()
            }
        }),
        repository: Some(repository),
        timeout: Duration::from_secs(30),
    }
}
fn registry(backend: Arc<Backend>) -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_tools_with_backend(&mut registry, backend);
    registry
}
async fn call(registry: &ToolRegistry, name: &str, input: Value, ctx: &ToolContext) -> Value {
    let output = registry
        .get(name)
        .unwrap()
        .execute(input, ctx)
        .await
        .unwrap();
    assert!(!output.is_error, "{}: {}", name, output.content);
    output.data.unwrap()
}
fn put(data: &mut [u8], offset: usize, bytes: &[u8]) {
    data[offset..offset + bytes.len()].copy_from_slice(bytes);
}
fn sample() -> Vec<u8> {
    // Exact ELF64 .text: call helper; ret; padding; helper: push rbp; ret.
    let mut data = vec![0; 0x240];
    put(&mut data, 0, b"\x7fELF\x02\x01\x01\x00");
    for (offset, value) in [
        (0x10, 2u16),
        (0x12, 62),
        (0x34, 64),
        (0x36, 56),
        (0x38, 1),
        (0x3a, 64),
        (0x3c, 3),
        (0x3e, 2),
    ] {
        put(&mut data, offset, &value.to_le_bytes());
    }
    put(&mut data, 0x14, &1u32.to_le_bytes());
    for (offset, value) in [
        (0x18, 0x401000u64),
        (0x20, 0x40),
        (0x28, 0x180),
        (0x48, 0x100),
        (0x50, 0x401000),
        (0x58, 0x401000),
        (0x60, 10),
        (0x68, 10),
        (0x70, 0x1000),
        (0x1c8, 6),
        (0x1d0, 0x401000),
        (0x1d8, 0x100),
        (0x1e0, 10),
        (0x1f0, 1),
        (0x218, 0x120),
        (0x220, 17),
        (0x230, 1),
    ] {
        put(&mut data, offset, &value.to_le_bytes());
    }
    for (offset, value) in [
        (0x40, 1u32),
        (0x44, 5),
        (0x1c0, 1),
        (0x1c4, 1),
        (0x200, 7),
        (0x204, 3),
    ] {
        put(&mut data, offset, &value.to_le_bytes());
    }
    put(
        &mut data,
        0x100,
        &[0xe8, 3, 0, 0, 0, 0xc3, 0x90, 0x90, 0x55, 0xc3],
    );
    put(&mut data, 0x120, b"\0.text\0.shstrtab\0");
    data
}

#[test]
fn native_registration_preserves_read_and_write_policy() {
    let tools = registry(Arc::new(Backend::default()));
    for name in TOOL_NAMES {
        assert!(tools.get(name).is_some());
    }
    for name in ["FangidaAnalyze", "FangidaRead", "FangidaDatabase"] {
        assert!(tools.get(name).unwrap().read_only());
    }
    for name in ["FangidaSave", "FangidaAnnotate"] {
        assert!(!tools.get(name).unwrap().read_only());
        assert!(!tools.get(name).unwrap().default_approve());
    }
}

#[test]
fn native_tools_follow_delegated_profile_permissions() {
    for profile in ["explore", "general", "coder"] {
        let mut tools = registry(Arc::new(Backend::default()));
        kkagent_tools::retain_profile_tools(&mut tools, profile);
        for name in ["FangidaAnalyze", "FangidaRead", "FangidaDatabase"] {
            assert!(tools.get(name).is_some(), "{profile} lost {name}");
        }
        for name in ["FangidaSave", "FangidaAnnotate"] {
            assert_eq!(tools.get(name).is_some(), profile != "explore");
        }
    }
}

fn slow_backend(scratch: &Scratch, timeout: Duration) -> BridgeConfig {
    let package = scratch.0.join("fangida");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::write(package.join("__init__.py"), "").unwrap();
    std::fs::write(package.join("mcp_server.py"), r#"
import json, sys, time
for line in sys.stdin:
    request = json.loads(line)
    if 'id' not in request:
        continue
    if request['method'] == 'initialize':
        result = {'protocolVersion': '2025-11-25'}
    else:
        name = request['params']['name']
        if name == 'open_file':
            payload = {'handle': 'f001'}
        elif name == 'create_database':
            payload = {'database': 'db1'}
        elif name == 'save_to_database':
            with open('writes.log', 'a', encoding='utf-8') as audit:
                audit.write(json.dumps(request) + '\n')
            time.sleep(5)
            payload = {'snapshot_id': 1}
        elif name == 'analysis_summary':
            time.sleep(5)
            payload = {}
        else:
            payload = {}
        result = {'content': [{'type': 'text', 'text': json.dumps(payload)}], 'structuredContent': payload}
    print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}), flush=True)
"#).unwrap();
    let mut config = config(scratch.0.clone());
    config.timeout = timeout;
    config
}

#[tokio::test]
#[ignore = "requires Python to simulate a slow local transport"]
async fn timed_out_writes_are_not_replayed_and_expire_handles() {
    let scratch = Scratch::new();
    let ctx = context(&scratch.0, "timeout");
    let backend = Arc::new(Backend::new(slow_backend(&scratch, Duration::from_secs(1))));
    let tools = registry(backend.clone());
    let opened = call(&tools, "FangidaAnalyze", json!({"path":"sample.elf"}), &ctx).await;
    let saved = tools
        .get("FangidaSave")
        .unwrap()
        .execute(
            json!({"handle":opened["handle"],"path":"analysis.fdb"}),
            &ctx,
        )
        .await
        .unwrap();
    assert!(saved.is_error && saved.content.contains("timed out"));
    let expired = tools
        .get("FangidaRead")
        .unwrap()
        .execute(json!({"action":"summary","handle":opened["handle"]}), &ctx)
        .await
        .unwrap();
    assert!(expired.is_error && expired.content.contains("Unknown Fangida handle"));
    call(&tools, "FangidaAnalyze", json!({"path":"sample.elf"}), &ctx).await;
    assert_eq!(
        std::fs::read_to_string(scratch.0.join("writes.log"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    backend.close_session(&ctx.session_id).await;
}

#[tokio::test]
#[ignore = "requires Python to simulate a slow local transport"]
async fn cancellation_during_a_request_expires_the_session_handles() {
    let scratch = Scratch::new();
    let mut ctx = context(&scratch.0, "cancel-in-flight");
    let flag = Arc::new(AtomicBool::new(false));
    ctx.interrupted = Some(flag.clone());
    let backend = Arc::new(Backend::new(slow_backend(&scratch, Duration::from_secs(3))));
    let tools = registry(backend.clone());
    let opened = call(&tools, "FangidaAnalyze", json!({"path":"sample.elf"}), &ctx).await;
    let cancel = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        flag.store(true, Ordering::Relaxed);
    });
    let cancelled = tools
        .get("FangidaRead")
        .unwrap()
        .execute(json!({"action":"summary","handle":opened["handle"]}), &ctx)
        .await
        .unwrap();
    cancel.await.unwrap();
    assert!(cancelled.is_error && cancelled.content.contains("cancelled"));
    ctx.interrupted = None;
    let expired = tools
        .get("FangidaRead")
        .unwrap()
        .execute(json!({"action":"summary","handle":opened["handle"]}), &ctx)
        .await
        .unwrap();
    assert!(expired.is_error && expired.content.contains("Unknown Fangida handle"));
    backend.close_session(&ctx.session_id).await;
}

#[tokio::test]
async fn invalid_arguments_and_path_policy_do_not_start_backend() {
    let scratch = Scratch::new();
    let mut ctx = context(&scratch.0, "policy");
    ctx.tools_config.path_guard_mode = "strict".into();
    let tools = registry(Arc::new(Backend::new(BridgeConfig {
        python: "missing-python-never-started".into(),
        repository: None,
        timeout: Duration::from_millis(5),
    })));
    let invalid = tools
        .get("FangidaAnalyze")
        .unwrap()
        .execute(json!({"path":"a","full_analysis":"yes"}), &ctx)
        .await
        .unwrap();
    assert!(invalid.is_error && invalid.content.contains("Invalid tool arguments"));
    let denied = tools
        .get("FangidaAnalyze")
        .unwrap()
        .execute(
            json!({"path":std::env::temp_dir().join("outside-file")}),
            &ctx,
        )
        .await
        .unwrap();
    assert!(denied.is_error && denied.content.contains("outside the workspace"));
    let foreign = tools
        .get("FangidaRead")
        .unwrap()
        .execute(json!({"action":"summary","handle":"foreign"}), &ctx)
        .await
        .unwrap();
    assert!(foreign.is_error && foreign.content.contains("Unknown Fangida handle"));
}

#[tokio::test]
#[ignore = "requires Python with the local Fangida package and a native decoder"]
async fn native_analysis_database_and_annotations_work_without_model_or_mcp_config() {
    let scratch = Scratch::new();
    let ctx = context(&scratch.0, "native-roundtrip");
    let backend = Arc::new(Backend::new(config(repository())));
    let tools = registry(backend.clone());
    let source = scratch.0.join("binary sample.elf");
    let original = sample();
    std::fs::write(&source, &original).unwrap();
    let database = scratch.0.join("saved analysis.fdb");
    let opened = call(&tools, "FangidaAnalyze", json!({"path":source}), &ctx).await;
    let handle = opened["handle"].as_str().unwrap();
    let summary = call(
        &tools,
        "FangidaRead",
        json!({"action":"summary","handle":handle}),
        &ctx,
    )
    .await;
    assert_eq!(summary["stats"]["full_instructions"], 6);
    let functions = call(
        &tools,
        "FangidaRead",
        json!({"action":"functions","handle":handle,"limit":1}),
        &ctx,
    )
    .await;
    assert!(functions["items"][0].get("blocks").is_none());
    assert!(functions["next_offset"].is_number());
    let disasm = call(
        &tools,
        "FangidaRead",
        json!({"action":"disasm","handle":handle,"limit":2}),
        &ctx,
    )
    .await;
    assert_eq!(disasm["items"].as_array().unwrap().len(), 2);
    let cfg = call(
        &tools,
        "FangidaRead",
        json!({"action":"cfg","handle":handle,"address":"0x401000"}),
        &ctx,
    )
    .await;
    assert!(cfg["counts"]["blocks"].as_u64().unwrap() > 0);
    let xrefs = call(
        &tools,
        "FangidaRead",
        json!({"action":"xrefs","handle":handle,"address":"0x401008","direction":"to"}),
        &ctx,
    )
    .await;
    assert_eq!(xrefs["items"][0]["kind"], "call");
    // Fresh registries for another turn retain the same per-session backend.
    let next_turn = registry(backend.clone());
    call(
        &next_turn,
        "FangidaRead",
        json!({"action":"summary","handle":handle}),
        &ctx,
    )
    .await;
    let other_ctx = context(&scratch.0, "another-session");
    let foreign = next_turn
        .get("FangidaRead")
        .unwrap()
        .execute(json!({"action":"summary","handle":handle}), &other_ctx)
        .await
        .unwrap();
    assert!(foreign.is_error);
    let saved = call(
        &tools,
        "FangidaSave",
        json!({"path":database,"handle":handle}),
        &ctx,
    )
    .await;
    let id = saved["snapshot_id"].as_u64().unwrap();
    call(&tools, "FangidaAnnotate", json!({"path":database,"snapshot_id":id,"address":"0x401000","action":"rename","value":"native_entry"}), &ctx).await;
    call(&tools, "FangidaAnnotate", json!({"path":database,"snapshot_id":id,"address":"0x401000","action":"comment","value":"原生集成验证"}), &ctx).await;
    assert_eq!(std::fs::read(&source).unwrap(), original);
    std::fs::remove_file(&source).unwrap();
    let db = call(
        &tools,
        "FangidaDatabase",
        json!({"action":"open","path":database}),
        &ctx,
    )
    .await;
    let db_handle = db["database"].as_str().unwrap();
    let page = call(&tools, "FangidaDatabase", json!({"action":"page","database":db_handle,"snapshot_id":id,"collection":"functions","limit":1}), &ctx).await;
    assert!(page["items"][0].get("blocks").is_none());
    let restored = call(
        &tools,
        "FangidaDatabase",
        json!({"action":"load","database":db_handle,"snapshot_id":id}),
        &ctx,
    )
    .await;
    let restored_handle = restored["handle"].as_str().unwrap();
    let restored_cfg = call(
        &tools,
        "FangidaRead",
        json!({"action":"cfg","handle":restored_handle,"address":"0x401000"}),
        &ctx,
    )
    .await;
    assert_eq!(restored_cfg["function"]["name"], "native_entry");
    let annotations = call(
        &tools,
        "FangidaDatabase",
        json!({"action":"annotations","database":db_handle,"snapshot_id":id}),
        &ctx,
    )
    .await;
    assert!(annotations["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["value"] == "原生集成验证"));
    let cancelled = Arc::new(AtomicBool::new(true));
    let mut stopped_ctx = ctx.clone();
    stopped_ctx.interrupted = Some(cancelled.clone());
    let interrupted = tools
        .get("FangidaRead")
        .unwrap()
        .execute(json!({"action":"summary","handle":handle}), &stopped_ctx)
        .await
        .unwrap();
    assert!(interrupted.is_error && interrupted.content.contains("cancelled before dispatch"));
    cancelled.store(false, Ordering::Relaxed);
    call(&tools, "FangidaRead", json!({"action":"reset"}), &ctx).await;
    let expired = tools
        .get("FangidaRead")
        .unwrap()
        .execute(json!({"action":"summary","handle":handle}), &ctx)
        .await
        .unwrap();
    assert!(expired.is_error && expired.content.contains("Unknown Fangida handle"));
    backend.close_session(&ctx.session_id).await;
    backend.close_session(&other_ctx.session_id).await;
}
