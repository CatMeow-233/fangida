//! Session agent profile catalog seed.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProfileSummary {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default)]
    pub tools: Vec<String>,
}

#[derive(Default)]
pub struct SessionAgentProfileCatalog {
    profiles: RwLock<HashMap<String, AgentProfileSummary>>,
}

impl SessionAgentProfileCatalog {
    pub fn new() -> Self {
        let svc = Self::default();
        svc.upsert(AgentProfileSummary {
            name: "coder".into(),
            description: Some("General coding agent".into()),
            model: None,
            tools: vec![],
        });
        svc.upsert(AgentProfileSummary {
            name: "explorer".into(),
            description: Some("Read-only codebase explorer".into()),
            model: None,
            tools: vec!["Read".into(), "Grep".into(), "Glob".into()],
        });
        for (name, description) in [
            (
                "re",
                "Reverse engineering agent (static analysis, algorithm recovery)",
            ),
            (
                "pwn",
                "Binary exploitation agent (mitigations, bugs, verified exploits)",
            ),
            (
                "crypto",
                "Cryptanalysis agent (scheme ID, key recovery, verified breaks)",
            ),
            (
                "web",
                "Web exploitation agent (surface enum, reproduced requests)",
            ),
            (
                "forensics",
                "Forensics agent (formats, carving, decoding, correlation)",
            ),
            ("misc", "Miscellaneous challenge agent"),
        ] {
            svc.upsert(AgentProfileSummary {
                name: name.into(),
                description: Some(description.into()),
                model: None,
                tools: vec![],
            });
        }
        svc
    }

    pub fn upsert(&self, profile: AgentProfileSummary) {
        self.profiles
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(profile.name.clone(), profile);
    }

    pub fn get(&self, name: &str) -> Option<AgentProfileSummary> {
        self.profiles
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .cloned()
    }

    pub fn list(&self) -> Vec<AgentProfileSummary> {
        self.profiles
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }
}
