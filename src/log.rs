//! Append-only JSONL decision log.

use anyhow::Result;
use serde_json::{Value, json};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use crate::report::{Report, Verdict};

pub fn append(path: &Path, entry: &Value) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{}", serde_json::to_string(entry)?)?;
    Ok(())
}

pub fn report_entry(action: &str, r: &Report) -> Value {
    json!({
        "ts": crate::now(),
        "action": action,
        "cwd": r.discovery.cwd,
        "git_root": r.discovery.git_root,
        "agent": r.agents.first().map(|a| &a.name),
        "verdict": if r.verdict == Verdict::Go { "go" } else { "blocked" },
        "reasons": r.reasons,
        "warnings": r.warnings,
        "files": r.files.iter().map(|f| json!({
            "path": f.path,
            "sha256": f.sha256,
            "state": f.state.as_str(),
            "provenance": f.provenance,
        })).collect::<Vec<_>>(),
    })
}
