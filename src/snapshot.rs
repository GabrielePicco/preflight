//! Before/after hashes of agent configs, MCP configs and shell startup files, so a run that
//! quietly persisted something (new MCP server, edited rc file, new hook) gets reported.

use crate::Ctx;
use crate::discovery::discover;
use crate::trust::{sha256_bytes, sha256_file};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Watched files relative to $HOME.
pub const WATCHED_HOME_FILES: &[&str] = &[
    ".claude.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/CLAUDE.md",
    ".codex/config.toml",
    ".codex/AGENTS.md",
    ".gemini/settings.json",
    ".gemini/GEMINI.md",
    ".cursor/mcp.json",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".config/fish/config.fish",
    ".gitconfig",
    ".npmrc",
    ".ssh/authorized_keys",
    ".ssh/config",
];

/// display path -> sha256
pub type Snapshot = BTreeMap<String, String>;

#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    Added(String),
    Removed(String),
    Modified(String),
}

pub fn take(ctx: &Ctx, cwd: &Path) -> Snapshot {
    let mut paths: Vec<PathBuf> = discover(cwd, ctx.home.as_deref()).files.into_iter().map(|f| f.path).collect();
    if let Some(h) = &ctx.home {
        paths.extend(WATCHED_HOME_FILES.iter().map(|r| h.join(r)));
    }
    let mut snap = Snapshot::new();
    for p in paths {
        let is_claude_json = p.file_name().is_some_and(|n| n == ".claude.json");
        let hash = if is_claude_json { claude_json_digest(&p) } else { sha256_file(&p).ok() };
        if let Some(h) = hash {
            let label = if is_claude_json { format!("{} (MCP servers / trust)", ctx.tilde(&p)) } else { ctx.tilde(&p) };
            snap.insert(label, h);
        }
    }
    snap
}

/// ~/.claude.json is rewritten constantly (usage stats), so only hash the parts that matter.
fn claude_json_digest(p: &Path) -> Option<String> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).ok()?).ok()?;
    let mut projects = serde_json::Map::new();
    if let Some(obj) = v.get("projects").and_then(|x| x.as_object()) {
        for (k, proj) in obj {
            projects.insert(
                k.clone(),
                json!({
                    "mcpServers": proj.get("mcpServers"),
                    "allowedTools": proj.get("allowedTools"),
                    "hasTrustDialogAccepted": proj.get("hasTrustDialogAccepted"),
                }),
            );
        }
    }
    let relevant = json!({ "mcpServers": v.get("mcpServers"), "projects": projects });
    Some(sha256_bytes(relevant.to_string().as_bytes()))
}

pub fn diff(before: &Snapshot, after: &Snapshot) -> Vec<Change> {
    let mut out = Vec::new();
    for (k, h) in after {
        match before.get(k) {
            None => out.push(Change::Added(k.clone())),
            Some(b) if b != h => out.push(Change::Modified(k.clone())),
            _ => {}
        }
    }
    out.extend(before.keys().filter(|k| !after.contains_key(*k)).map(|k| Change::Removed(k.clone())));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detects_added_modified_removed() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().canonicalize().unwrap();
        let ctx = Ctx { home: Some(home.clone()), trust_file: "/x".into(), log_file: "/y".into(), temp_roots: vec![] };
        fs::write(home.join(".bashrc"), "a").unwrap();
        fs::write(home.join(".zshrc"), "z").unwrap();
        let before = take(&ctx, &home);
        fs::write(home.join(".bashrc"), "a\nalias ls='curl x'").unwrap();
        fs::remove_file(home.join(".zshrc")).unwrap();
        fs::write(home.join("AGENTS.md"), "new").unwrap();
        let after = take(&ctx, &home);
        let mut d = diff(&before, &after);
        d.sort_by_key(|c| format!("{c:?}"));
        assert_eq!(
            d,
            vec![
                Change::Added("~/AGENTS.md".into()),
                Change::Modified("~/.bashrc".into()),
                Change::Removed("~/.zshrc".into())
            ]
        );
    }

    #[test]
    fn claude_json_noise_is_ignored() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().canonicalize().unwrap();
        let ctx = Ctx { home: Some(home.clone()), trust_file: "/x".into(), log_file: "/y".into(), temp_roots: vec![] };
        fs::write(home.join(".claude.json"), r#"{"numStartups":1,"mcpServers":{}}"#).unwrap();
        let a = take(&ctx, &home);
        fs::write(home.join(".claude.json"), r#"{"numStartups":2,"mcpServers":{}}"#).unwrap();
        assert!(diff(&a, &take(&ctx, &home)).is_empty());
        fs::write(home.join(".claude.json"), r#"{"numStartups":2,"mcpServers":{"x":{"command":"evil"}}}"#).unwrap();
        assert_eq!(diff(&a, &take(&ctx, &home)).len(), 1);
    }
}
