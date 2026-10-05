//! Exercise native tools against a real binary without calling a model.
use anyhow::{bail, Context, Result};
use kkagent_tools::{ToolContext, ToolRegistry};
use serde_json::{json, Value};
use std::time::Instant;

async fn call(tools: &ToolRegistry, name: &str, input: Value, ctx: &ToolContext) -> Result<Value> {
    let output = tools
        .get(name)
        .context("Missing native tool")?
        .execute(input, ctx)
        .await?;
    if output.is_error {
        bail!("{}", output.content);
    }
    output.data.context("Missing structured result")
}

#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .context("Usage: inspect /path/to/native-binary")?;
    let path = std::path::PathBuf::from(path).canonicalize()?;
    let ctx = ToolContext {
        working_dir: std::env::current_dir()?,
        session_id: format!("native-inspect-{}", std::process::id()),
        turn_id: "inspect:1".into(),
        plan_file_path: None,
        image: Default::default(),
        tool_call_id: None,
        interrupted: None,
        tools_config: Default::default(),
        model_alias: None,
    };
    let mut tools = ToolRegistry::new();
    kkagent_fangida::register_tools(&mut tools);
    let started = Instant::now();
    let result = async {
        let opened = call(&tools, "FangidaAnalyze", json!({"path":path}), &ctx).await?;
        let summary = call(
            &tools,
            "FangidaRead",
            json!({"action":"summary","handle":opened["handle"]}),
            &ctx,
        )
        .await?;
        let functions = call(
            &tools,
            "FangidaRead",
            json!({"action":"functions","handle":opened["handle"],"limit":2}),
            &ctx,
        )
        .await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "elapsed_seconds":started.elapsed().as_secs_f64(),
                "summary":summary,
                "functions":functions
            }))?
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    kkagent_fangida::close_session(&ctx.session_id).await;
    result
}
