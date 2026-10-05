use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::task::AbortHandle;

use kkagent_config::AppConfig;
use kkagent_protocol::{
    subagent::{allowed_subagents_for, stamp_child_depth, SubagentConfig, SubagentManager},
    AgentEvent, PermissionMode,
};
use kkagent_tools::{
    register_core_tools, register_subagent_tools, retain_profile_tools, ToolRegistry,
};

use crate::agent_loop::AgentLoop;
use crate::permission::PermissionChain;
use crate::session::Session;

/// Parent context used to mirror child agent events into the parent TUI.
#[derive(Clone)]
pub struct SubagentMirrorContext {
    pub parent_session_id: String,
    pub parent_tool_call_id: String,
    pub parent_event_tx: mpsc::Sender<AgentEvent>,
}

/// Run a focused subagent to completion and return its final assistant text.
pub async fn run_subagent(
    app_config: Arc<AppConfig>,
    sub_cfg: SubagentConfig,
    permission_mode: PermissionMode,
) -> anyhow::Result<String> {
    let web = Arc::new(kkagent_tools::WebServicesConfig::from_app(
        app_config.as_ref(),
    ));
    run_subagent_mirrored(app_config, web, sub_cfg, permission_mode, None, None).await
}

pub async fn run_subagent_mirrored(
    app_config: Arc<AppConfig>,
    web: Arc<kkagent_tools::WebServicesConfig>,
    sub_cfg: SubagentConfig,
    permission_mode: PermissionMode,
    mirror: Option<SubagentMirrorContext>,
    inherit_interrupt: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> anyhow::Result<String> {
    run_subagent_mirrored_boxed(
        app_config,
        web,
        sub_cfg,
        permission_mode,
        mirror,
        inherit_interrupt,
    )
    .await
}

fn run_subagent_mirrored_boxed(
    app_config: Arc<AppConfig>,
    web: Arc<kkagent_tools::WebServicesConfig>,
    sub_cfg: SubagentConfig,
    permission_mode: PermissionMode,
    mirror: Option<SubagentMirrorContext>,
    inherit_interrupt: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> futures::future::BoxFuture<'static, anyhow::Result<String>> {
    Box::pin(async move {
        let profile = sub_cfg
            .profile
            .as_deref()
            .unwrap_or("general")
            .to_lowercase();

        let model = app_config.resolve_subagent_model(
            &profile,
            sub_cfg.model.as_deref(),
            sub_cfg.parent_model.as_deref(),
        );

        let mut session = Session::for_subagent(
            format!("sub-{}", sub_cfg.agent_id),
            PathBuf::from(&sub_cfg.working_dir),
            permission_mode,
            model.clone(),
        );
        // Interrupt propagation (#5): share the parent's interrupt flag so an
        // Esc at any ancestor stops this subagent (and, via the same
        // mechanism on its own children, the whole subtree) immediately.
        if let Some(parent_flag) = inherit_interrupt {
            session.inherit_interrupted(parent_flag);
        }
        let _fangida_lease = kkagent_fangida::SessionLease::new(session.id.clone());
        session.image_config = app_config.image.clone();
        session.attach_workspace_concurrency_guard();
        session.inject_workspace_instructions().await;
        session
            .system_prompt
            .push_str(&profile_system_addon(&profile));
        session
            .system_prompt
            .push_str(kkagent_fangida::SYSTEM_PROMPT);
        session.add_user_message(sub_cfg.prompt.clone());

        let permission_rules = app_config
            .permission
            .as_ref()
            .map(|p| p.rules.clone())
            .unwrap_or_default();
        let permission = PermissionChain::new(PermissionMode::Auto, permission_rules);

        let (event_tx, mut event_rx) = mpsc::channel(256);

        let mut tools = ToolRegistry::new();
        register_core_tools(&mut tools);
        kkagent_fangida::register_tools(&mut tools);
        let nested_manager = Arc::new(SubagentManager::new(
            app_config.subagent.effective_max_concurrent(),
        ));
        let launch_manager = nested_manager.clone();
        let launch_config = app_config.clone();
        let launch_event_tx = event_tx.clone();
        let launch_web = web.clone();
        let max_depth = app_config.subagent.effective_max_depth();
        let parent_depth = sub_cfg.depth;
        let nested_launch: kkagent_tools::builtin::task::SubagentLaunchFn =
            Arc::new(move |mut config, interrupt| {
                let manager = launch_manager.clone();
                let app_config = launch_config.clone();
                let web = launch_web.clone();
                let agent_id = config.agent_id.clone();
                // Depth budget, layer 2 (launch guard): stamp the child's
                // nesting depth; when the budget is exhausted, fail loudly so
                // the parent's TaskOutput surfaces the reason instead of
                // waiting on an agent that will never run.
                if let Err(reason) = stamp_child_depth(&mut config, parent_depth, max_depth) {
                    tracing::warn!("Rejected nested subagent {agent_id}: {reason}");
                    let manager = manager.clone();
                    tokio::spawn(async move {
                        manager.fail(&agent_id, reason).await;
                    });
                    return;
                }
                let abort_manager = manager.clone();
                let abort_agent_id = agent_id.clone();
                let nested_mirror = match (
                    config.parent_session_id.clone(),
                    config.parent_tool_call_id.clone(),
                ) {
                    (Some(parent_session_id), Some(parent_tool_call_id)) => {
                        Some(SubagentMirrorContext {
                            parent_session_id,
                            parent_tool_call_id,
                            parent_event_tx: launch_event_tx.clone(),
                        })
                    }
                    _ => None,
                };
                let join = tokio::spawn(async move {
                    match run_subagent_mirrored_boxed(
                        app_config,
                        web,
                        config,
                        PermissionMode::Auto,
                        nested_mirror,
                        Some(interrupt),
                    )
                    .await
                    {
                        Ok(result) => manager.complete(&agent_id, result).await,
                        Err(error) => manager.fail(&agent_id, error.to_string()).await,
                    }
                });
                let abort = join.abort_handle();
                tokio::spawn(async move {
                    abort_manager.set_abort_handle(&abort_agent_id, abort).await;
                });
            });
        let allowed_subagents = sub_cfg
            .subagents
            .clone()
            .or_else(|| allowed_subagents_for(&profile));
        register_subagent_tools(
            &mut tools,
            nested_manager,
            nested_launch,
            allowed_subagents,
            app_config.tools.clone(),
            Vec::new(),
        );
        // Web access for subagents: registered from the same config snapshot
        // as the parent turn (plugin overrides applied) and then kept only
        // where the profile allowlist lists "Web" (explore/general/coder do).
        if let Some(web_tool) = kkagent_tools::builtin::WebTool::try_new(web.clone()) {
            tools.register(Arc::new(web_tool));
        }
        retain_profile_tools(&mut tools, &profile);
        // Depth budget, layer 1 (schema pruning): a subagent already at the
        // depth cap cannot launch children within budget — remove the
        // delegation tools entirely so its schema never offers them.
        prune_delegation_tools_at_depth(&mut tools, sub_cfg.depth, max_depth);

        if let Some(m) = &mirror {
            let _ = m
                .parent_event_tx
                .send(AgentEvent::SubagentSpawned {
                    session_id: m.parent_session_id.clone(),
                    subagent_id: sub_cfg.agent_id.clone(),
                    subagent_name: profile.clone(),
                    parent_tool_call_id: m.parent_tool_call_id.clone(),
                    description: Some(sub_cfg.description.clone()),
                    model: Some(model.clone()),
                    run_in_background: sub_cfg.run_in_background,
                    prompt: Some(sub_cfg.prompt.clone()),
                })
                .await;
            let _ = m
                .parent_event_tx
                .send(AgentEvent::SubagentStarted {
                    session_id: m.parent_session_id.clone(),
                    subagent_id: sub_cfg.agent_id.clone(),
                })
                .await;
        }

        let mirror_for_drain = mirror.clone();
        let child_id = sub_cfg.agent_id.clone();
        // Store the JoinHandle so we can await it before sending SubagentCompleted,
        // preventing a race where the completion event arrives before the last
        // content event has been drained.
        let drain_handle: tokio::task::JoinHandle<()> = tokio::spawn(async move {
            while let Some(ev) = event_rx.recv().await {
                if let Some(m) = &mirror_for_drain {
                    // Forward ALL events — both content events (MessageDelta, etc.)
                    // and lifecycle events (SubagentSpawned, etc.) from grandchild
                    // agents. The previous 7-type filter silently dropped all
                    // grandchild lifecycle events, making 3-level nesting invisible.
                    let _ = m
                        .parent_event_tx
                        .send(AgentEvent::SubagentChildEvent {
                            session_id: m.parent_session_id.clone(),
                            subagent_id: child_id.clone(),
                            parent_tool_call_id: m.parent_tool_call_id.clone(),
                            event: Box::new(ev),
                        })
                        .await;
                }
            }
        });

        let abort_registry = Arc::new(Mutex::new(HashMap::<String, AbortHandle>::new()));
        let max_rounds = profile_max_rounds(&profile);
        let mut agent = AgentLoop::with_max_rounds(
            app_config,
            Arc::new(tools),
            Arc::new(Mutex::new(permission)),
            event_tx,
            abort_registry,
            max_rounds,
        );
        // Subagent oversized outputs spill into the parent session's bucket so
        // they are swept together when the parent session is deleted.
        if let Some(parent_session_id) = sub_cfg.parent_session_id.clone() {
            let store = crate::agent_loop::ToolResultStore::for_subagent(
                kkagent_config::default_config_dir(),
                parent_session_id,
            );
            agent = agent.with_tool_result_store(Arc::new(store));
        }

        let run_result = agent.run_turn(&mut session).await;
        // Ephemeral subagent scratch dir (SessionCreateSource::Subagent) —
        // remove it on every exit path so temp storage never accumulates.
        let _ = std::fs::remove_dir_all(session.session_dir());

        // --- Fix #2: drain all pending events before signalling completion.
        //
        // The drain task pumps child events to the parent's event channel.
        // If we send `SubagentCompleted` immediately after `run_turn` returns,
        // the drain task may still have buffered events in `event_rx`, causing
        // content events to arrive *after* the completion event (TUI sees the
        // child finish before its last messages).
        //
        // Dropping `agent` releases its `event_tx` clone, which closes the
        // mpsc channel, causing the drain loop's `event_rx.recv()` to return
        // `None` and exit. We then join the drain handle to guarantee all
        // events have been forwarded before sending `SubagentCompleted`.
        drop(agent);
        let _ = drain_handle.await;

        // --- Fix #5: attach token usage to the completion event.
        let snap = session.usage.snapshot();
        let usage = kkagent_protocol::TokenUsage::from_buckets(
            snap.input_tokens,
            snap.output_tokens,
            snap.cache_creation_input_tokens,
            snap.cache_read_input_tokens,
            snap.input_includes_cache,
        );

        let outcome = match run_result {
            Ok(()) => {
                let result = extract_final_assistant_text(&session);
                persist_subagent_output(&sub_cfg, &result).await;
                if let Some(m) = &mirror {
                    let summary: String = result.chars().take(400).collect();
                    let _ = m
                        .parent_event_tx
                        .send(AgentEvent::SubagentCompleted {
                            session_id: m.parent_session_id.clone(),
                            subagent_id: sub_cfg.agent_id.clone(),
                            result_summary: summary,
                            usage: Some(usage),
                            model: Some(model.clone()),
                        })
                        .await;
                }
                Ok(result)
            }
            Err(e) => {
                if let Some(m) = &mirror {
                    let _ = m
                        .parent_event_tx
                        .send(AgentEvent::SubagentFailed {
                            session_id: m.parent_session_id.clone(),
                            subagent_id: sub_cfg.agent_id.clone(),
                            error: e.to_string(),
                        })
                        .await;
                }
                Err(e)
            }
        };

        // Worktree lifecycle (issues/subagent_issues.md #2): now that the run
        // has fully finished and its output/events were emitted, dispose of
        // the disposable git worktree, if this run had one. Resumed agents
        // get a fresh worktree (created from HEAD) on relaunch.
        kkagent_tools::git_worktree::cleanup_worktree(std::path::Path::new(&sub_cfg.working_dir))
            .await;

        outcome
    })
}

/// Compact-report contract shared by every subagent profile. Long raw dumps
/// fed back into the parent's context are the main driver of hallucination
/// blow-up: reports must carry conclusions plus tight evidence references,
/// never bulk output.
const SUBAGENT_REPORT_CONTRACT: &str = "\n\n# Report contract (mandatory)\n\
Your final message is the ONLY thing the parent agent receives. It must be a compact report:\n\
1. Start with the answer/result (flag, address, offset, verdict — whatever was asked for).\n\
2. Evidence as references only: file:line, address, function name, or a <=32-byte hex snippet.\n\
   Never paste large raw dumps, full listings, or long logs into the report.\n\
3. Keep the whole report under ~60 lines. Anything longer belongs in a file you write to the\n\
   working directory; report the path and a one-line summary instead.\n\
4. State clearly what is verified fact (tool output seen) vs. hypothesis. Never fabricate\n\
   addresses, offsets, or API behavior you did not observe.";

/// Per-profile agent-loop round budget. CTF solving profiles (re/pwn/crypto/
/// web/forensics) get a wider budget: reversing a target legitimately takes
/// many analyze → act → observe cycles.
fn profile_max_rounds(profile: &str) -> u32 {
    match profile.trim().to_ascii_lowercase().as_str() {
        "explore" => 16,
        "coder" => 32,
        "re" | "reverse" | "pwn" | "crypto" | "web" | "forensics" | "misc" => 48,
        _ => 24,
    }
}

fn profile_system_addon(profile: &str) -> String {
    let role = match profile.trim().to_ascii_lowercase().as_str() {
        "explore" => {
            "\
# Subagent profile: explore\n\
Read-only recon. Map the target: entry points, protections, interesting strings/imports,\n\
key functions with addresses. Prefer Glob/Grep/Read and read-only Bash (file/strings/objdump).\n\
Do not modify files or the target. Deliver a structured map (paths + addresses + what/why)."
        }
        "coder" => {
            "\
# Subagent profile: coder\n\
Implementation agent. Make focused changes with Edit/Write and verify them by running the\n\
result. Keep changes scoped; delegate through the Agent profiles exposed to you."
        }
        "re" | "reverse" => {
            "\
# Subagent profile: re (reverse engineering)\n\
Statically reverse the assigned target (ELF/Mach-O/PE/APK/bytecode). Disassemble and\n\
decompile, name functions, recover the algorithm or protocol, and extract every constant\n\
the parent needs (addresses, offsets, keys, tables). Verify claims by re-reading the\n\
disassembly — never guess an offset. radare2/Frida/angr/Unicorn references are embedded in\n\
the `radare2`, `frida` and `symexec` skills; load them with the Skill tool before writing\n\
such scripts."
        }
        "pwn" => {
            "\
# Subagent profile: pwn (binary exploitation)\n\
Exploitation agent. Establish mitigations, find the bug, build and locally verify the\n\
exploit, then produce the exact payload/script the parent can run against the remote.\n\
Never claim a leak/gadget/offset without a command output or decompilation proving it.\n\
glibc/heap reasoning must state the version it assumes."
        }
        "crypto" => {
            "\
# Subagent profile: crypto\n\
Cryptanalysis agent. Identify the scheme from math/constants, recover keys or break the\n\
construction, and verify the break reproduces the given ciphertext. Show the decisive\n\
computation result, not the whole worksheet. Batch arithmetic through code, not mental math."
        }
        "web" => {
            "\
# Subagent profile: web\n\
Web exploitation agent. Enumerate the attack surface, reproduce the bug with a concrete\n\
HTTP request, and hand the parent a curl/script that reproduces it. Read source for logic\n\
bugs before reaching for generic payloads; state the exact endpoint and parameter."
        }
        "forensics" | "misc" => {
            "\
# Subagent profile: forensics/misc\n\
Evidence-processing agent (files, memory images, network captures, stego, encoding).\n\
Identify formats, carve/decode step by step, and report each transformation with the\n\
command that produced it. Correlate artifacts into one conclusion."
        }
        _ => {
            "\
# Subagent mode\n\
Focused execution unit. Complete the assigned task end-to-end with tools, then finish\n\
with the compact report required by the report contract. Do not ask questions — decide,\n\
act, verify, report."
        }
    };
    format!("{role}{SUBAGENT_REPORT_CONTRACT}")
}

async fn persist_subagent_output(cfg: &SubagentConfig, result: &str) {
    let dir = PathBuf::from(&cfg.working_dir)
        .join(".kkagent")
        .join("tasks");
    let _ = tokio::fs::create_dir_all(&dir).await;
    let path = dir.join(format!("{}.md", cfg.agent_id));
    let body = format!(
        "# Task {}\n\n**description:** {}\n**profile:** {}\n\n---\n\n{}\n",
        cfg.agent_id,
        cfg.description,
        cfg.profile.as_deref().unwrap_or("general"),
        result
    );
    let _ = tokio::fs::write(path, body).await;
}

pub(crate) fn extract_final_assistant_text(session: &Session) -> String {
    for msg in session.messages.iter().rev() {
        if msg.role != "assistant" {
            continue;
        }
        let mut text = String::new();
        for block in &msg.content {
            if let kkagent_llm::ChatContent::Text { text: t } = block {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(t);
            }
        }
        if !text.trim().is_empty() {
            return text;
        }
    }
    "(subagent finished with no text output)".into()
}

/// Remove delegation tools when a subagent at `depth` has no remaining
/// nesting budget under `max_depth` (any child it launches would exceed
/// the cap). This is the schema-level layer of the depth budget; the
/// launch-closure stamp is the runtime backstop.
fn prune_delegation_tools_at_depth(tools: &mut ToolRegistry, depth: u32, max_depth: u32) {
    if depth >= max_depth {
        tools.remove("Agent");
        tools.remove("AgentSwarm");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kkagent_tools::{Tool, ToolContext, ToolOutput, ToolRegistry};
    use serde_json::Value;

    #[test]
    fn every_profile_carries_the_report_contract() {
        for profile in [
            "general",
            "explore",
            "coder",
            "re",
            "pwn",
            "crypto",
            "web",
            "forensics",
        ] {
            let addon = profile_system_addon(profile);
            assert!(
                addon.contains("# Report contract"),
                "{profile} missing contract"
            );
            assert!(
                !addon.contains("You are a"),
                "{profile} keeps persona phrasing"
            );
        }
        // CTF roles get role-specific operating instructions.
        assert!(profile_system_addon("pwn").contains("mitigations"));
        assert!(profile_system_addon("re").contains("radare2"));
        assert!(profile_system_addon("re").contains("frida"));
        assert!(profile_system_addon("explore").contains("Read-only recon"));
    }

    #[test]
    fn ctf_profiles_get_wider_round_budget() {
        assert_eq!(profile_max_rounds("explore"), 16);
        assert_eq!(profile_max_rounds("coder"), 32);
        assert_eq!(profile_max_rounds("general"), 24);
        for ctf in ["re", "reverse", "Pwn", "crypto", "web", "forensics", "misc"] {
            assert_eq!(profile_max_rounds(ctf), 48, "{ctf} should get 48 rounds");
        }
    }

    struct StubTool(&'static str);

    #[async_trait::async_trait]
    impl Tool for StubTool {
        fn name(&self) -> &str {
            self.0
        }

        fn description(&self) -> &str {
            "stub"
        }

        fn parameters_schema(&self) -> Value {
            serde_json::json!({"type": "object", "properties": {}})
        }

        async fn execute(&self, _input: Value, _ctx: &ToolContext) -> anyhow::Result<ToolOutput> {
            Ok(ToolOutput::success("stub"))
        }
    }

    fn registry_with_delegation_tools() -> ToolRegistry {
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(StubTool("Agent")));
        registry.register(Arc::new(StubTool("AgentSwarm")));
        registry.register(Arc::new(StubTool("Read")));
        registry
    }

    fn names(registry: &ToolRegistry) -> Vec<String> {
        let mut names: Vec<String> = registry
            .list()
            .iter()
            .map(|t| t.name().to_string())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn delegation_tools_survive_while_budget_remains() {
        let mut registry = registry_with_delegation_tools();
        // depth 1 with max_depth 2: may still launch depth-2 children.
        prune_delegation_tools_at_depth(&mut registry, 1, 2);
        assert_eq!(names(&registry), vec!["Agent", "AgentSwarm", "Read"]);
    }

    #[test]
    fn delegation_tools_pruned_at_the_depth_cap() {
        let mut registry = registry_with_delegation_tools();
        // depth 2 with max_depth 2: any child would be depth 3 > cap.
        prune_delegation_tools_at_depth(&mut registry, 2, 2);
        assert_eq!(names(&registry), vec!["Read"]);
    }

    #[test]
    fn max_depth_one_makes_every_subagent_a_leaf() {
        let mut registry = registry_with_delegation_tools();
        prune_delegation_tools_at_depth(&mut registry, 1, 1);
        assert_eq!(names(&registry), vec!["Read"]);
    }
}
