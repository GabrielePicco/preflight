//! Read the agent setup around you: installed agents and versions, MCP servers,
//! permission / sandbox settings, and secret-looking files in reach. All best-effort:
//! unknown or unparsable configs are skipped, never fatal.

use crate::Ctx;
use crate::discovery::Discovery;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const KNOWN_AGENTS: &[&str] = &["claude", "codex", "gemini"];

#[derive(Debug, Clone)]
pub struct AgentInfo {
    pub name: String,
    pub path: Option<PathBuf>,
    pub version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct McpServer {
    pub name: String,
    pub target: String,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct Setting {
    pub agent: String,
    pub key: String,
    pub value: String,
    pub risky: bool,
    pub source: String,
}

// ---------- agents ----------

pub fn which(name: &str) -> Option<PathBuf> {
    if name.contains('/') || name.contains('\\') {
        let p = PathBuf::from(name);
        return p.is_file().then_some(p);
    }
    let exts: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ".bat", ""]
    } else {
        &[""]
    };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .flat_map(|dir| exts.iter().map(move |e| dir.join(format!("{name}{e}"))))
        .find(|p| p.is_file())
}

/// Run `<agent> --version` with a short timeout; first line of stdout.
pub fn version(path: &Path) -> Option<String> {
    let mut child = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < Duration::from_secs(4) => {
                std::thread::sleep(Duration::from_millis(25))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let out = child.wait_with_output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s.lines().find(|l| !l.trim().is_empty())?.trim();
    Some(line.chars().filter(|c| !c.is_control()).take(40).collect())
}

pub fn probe_agents(names: &[String], with_version: bool) -> Vec<AgentInfo> {
    let handles: Vec<_> = names
        .iter()
        .cloned()
        .map(|name| {
            std::thread::spawn(move || {
                let path = which(&name);
                let version = if with_version {
                    path.as_deref().and_then(version)
                } else {
                    None
                };
                AgentInfo {
                    name,
                    path,
                    version,
                }
            })
        })
        .collect();
    handles.into_iter().filter_map(|h| h.join().ok()).collect()
}

// ---------- config readers ----------

fn read_json(p: &Path) -> Option<Value> {
    serde_json::from_str(&fs::read_to_string(p).ok()?).ok()
}

fn read_toml(p: &Path) -> Option<toml::Table> {
    fs::read_to_string(p).ok()?.parse::<toml::Table>().ok()
}

fn canon(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}

/// Config files of one kind: the user-level one in $HOME plus project-level ones discovered.
fn config_files(ctx: &Ctx, disc: &Discovery, home_rel: &[&str], patterns: &[&str]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for f in disc.files.iter().filter(|f| patterns.contains(&f.pattern)) {
        out.push(f.path.clone());
    }
    if let Some(h) = &ctx.home {
        out.extend(home_rel.iter().map(|r| h.join(r)).filter(|p| p.is_file()));
    }
    let mut seen = HashSet::new();
    out.retain(|p| seen.insert(canon(p)));
    out
}

// ---------- MCP servers ----------

pub fn mcp_servers(ctx: &Ctx, disc: &Discovery) -> Vec<McpServer> {
    let mut out = Vec::new();
    let json_files = config_files(
        ctx,
        disc,
        &[".gemini/settings.json", ".cursor/mcp.json"],
        &[
            ".mcp.json",
            ".cursor/mcp.json",
            ".gemini/settings.json",
            ".vscode/mcp.json",
        ],
    );
    for p in json_files {
        if let Some(v) = read_json(&p) {
            let key = if p.ends_with(".vscode/mcp.json") {
                "servers"
            } else {
                "mcpServers"
            };
            json_servers(v.get(key), &ctx.tilde(&p), &mut out);
        }
    }
    for p in config_files(ctx, disc, &[".codex/config.toml"], &[".codex/config.toml"]) {
        if let Some(t) = read_toml(&p)
            && let Some(servers) = t.get("mcp_servers").and_then(|v| v.as_table())
        {
            for (name, cfg) in servers {
                let target = match cfg.get("command").and_then(|c| c.as_str()) {
                    Some(cmd) => {
                        let args: Vec<&str> = cfg
                            .get("args")
                            .and_then(|a| a.as_array())
                            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                            .unwrap_or_default();
                        redact_command(cmd, &args)
                    }
                    None => cfg
                        .get("url")
                        .and_then(|u| u.as_str())
                        .map(redact_url)
                        .unwrap_or_else(|| "?".into()),
                };
                out.push(McpServer {
                    name: name.clone(),
                    target,
                    source: ctx.tilde(&p),
                });
            }
        }
    }
    if let Some(h) = &ctx.home
        && let Some(v) = read_json(&h.join(".claude.json"))
    {
        json_servers(v.get("mcpServers"), "~/.claude.json", &mut out);
        if let Some(projects) = v.get("projects").and_then(|p| p.as_object()) {
            for dir in &disc.scanned {
                if let Some(p) = projects.get(&dir.to_string_lossy().into_owned()) {
                    json_servers(
                        p.get("mcpServers"),
                        &format!("~/.claude.json [{}]", ctx.tilde(dir)),
                        &mut out,
                    );
                }
            }
        }
    }
    out
}

fn json_servers(servers: Option<&Value>, source: &str, out: &mut Vec<McpServer>) {
    let Some(obj) = servers.and_then(|s| s.as_object()) else {
        return;
    };
    for (name, cfg) in obj {
        let target = if let Some(cmd) = cfg.get("command").and_then(|c| c.as_str()) {
            let args: Vec<&str> = cfg
                .get("args")
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                .unwrap_or_default();
            redact_command(cmd, &args)
        } else if let Some(url) = ["url", "httpUrl", "serverUrl"]
            .iter()
            .find_map(|k| cfg.get(*k).and_then(|u| u.as_str()))
        {
            redact_url(url)
        } else {
            "?".into()
        };
        out.push(McpServer {
            name: name.clone(),
            target,
            source: source.to_string(),
        });
    }
}

fn secret_word(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    ["key", "token", "secret", "pass", "auth", "bearer", "cookie"]
        .iter()
        .any(|k| l.contains(k))
}

fn looks_secret(a: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "sk-",
        "ghp_",
        "gho_",
        "github_pat_",
        "xox",
        "AKIA",
        "glpat-",
        "hf_",
        "Bearer ",
    ];
    PREFIXES.iter().any(|p| a.starts_with(p))
        || (a.len() >= 32
            && a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
}

/// Render a server command line with anything secret-looking replaced, so the panel is
/// safe to screenshot. Environment variables are never printed.
pub fn redact_command(cmd: &str, args: &[&str]) -> String {
    let mut parts = vec![cmd.to_string()];
    let mut prev_flag_secret = false;
    for a in args {
        let shown = if prev_flag_secret || looks_secret(a) {
            "•••".to_string()
        } else if let Some((k, _)) = a.split_once('=')
            && secret_word(k)
        {
            format!("{k}=•••")
        } else if a.contains("://") {
            redact_url(a)
        } else {
            a.to_string()
        };
        prev_flag_secret = a.starts_with('-') && !a.contains('=') && secret_word(a);
        parts.push(shown);
    }
    parts.join(" ")
}

pub fn redact_url(url: &str) -> String {
    match url.split_once('?') {
        Some((base, q)) if secret_word(q) => format!("{base}?•••"),
        _ => url.to_string(),
    }
}

// ---------- permissions / sandbox ----------

pub fn settings(ctx: &Ctx, disc: &Discovery) -> Vec<Setting> {
    let mut out = Vec::new();
    claude_settings(ctx, disc, &mut out);
    codex_settings(ctx, disc, &mut out);
    gemini_settings(ctx, disc, &mut out);
    out
}

fn push(out: &mut Vec<Setting>, agent: &str, key: &str, value: String, risky: bool, source: &str) {
    out.push(Setting {
        agent: agent.into(),
        key: key.into(),
        value,
        risky,
        source: source.into(),
    });
}

fn claude_settings(ctx: &Ctx, disc: &Discovery, out: &mut Vec<Setting>) {
    let files = config_files(
        ctx,
        disc,
        &[".claude/settings.json", ".claude/settings.local.json"],
        &[".claude/settings.json", ".claude/settings.local.json"],
    );
    for p in files {
        let Some(v) = read_json(&p) else { continue };
        let src = ctx.tilde(&p);
        if let Some(mode) = v
            .pointer("/permissions/defaultMode")
            .and_then(|m| m.as_str())
        {
            push(
                out,
                "claude",
                "defaultMode",
                mode.into(),
                mode == "bypassPermissions",
                &src,
            );
        }
        if let Some(allow) = v.pointer("/permissions/allow").and_then(|a| a.as_array())
            && !allow.is_empty()
        {
            let rules: Vec<&str> = allow.iter().filter_map(|r| r.as_str()).collect();
            let broad = rules
                .iter()
                .any(|r| matches!(*r, "Bash" | "Bash(*)" | "Bash(**)" | "*"));
            let mut shown = rules.iter().take(3).copied().collect::<Vec<_>>().join(", ");
            if rules.len() > 3 {
                shown.push_str(", …");
            }
            push(
                out,
                "claude",
                "allow",
                format!("{} rules: {shown}", rules.len()),
                broad,
                &src,
            );
        }
        if let Some(hooks) = v.get("hooks").and_then(|h| h.as_object())
            && !hooks.is_empty()
        {
            let events = hooks.keys().cloned().collect::<Vec<_>>().join(", ");
            push(
                out,
                "claude",
                "hooks",
                format!("{events} (run shell commands)"),
                true,
                &src,
            );
        }
        if v.get("enableAllProjectMcpServers")
            .and_then(|b| b.as_bool())
            == Some(true)
        {
            push(
                out,
                "claude",
                "enableAllProjectMcpServers",
                "true".into(),
                true,
                &src,
            );
        }
    }
    if let Some(h) = &ctx.home
        && let Some(v) = read_json(&h.join(".claude.json"))
    {
        let projects = v.get("projects").and_then(|p| p.as_object());
        let accepted = disc.scanned.iter().find(|d| {
            projects
                .and_then(|p| p.get(&d.to_string_lossy().into_owned()))
                .and_then(|p| p.get("hasTrustDialogAccepted"))
                .and_then(|b| b.as_bool())
                == Some(true)
        });
        let value = match accepted {
            Some(d) => format!("accepted for {}", ctx.tilde(d)),
            None => "not accepted here yet".into(),
        };
        push(
            out,
            "claude",
            "folder trust",
            value,
            false,
            "~/.claude.json",
        );
    }
}

fn codex_settings(ctx: &Ctx, disc: &Discovery, out: &mut Vec<Setting>) {
    for p in config_files(ctx, disc, &[".codex/config.toml"], &[".codex/config.toml"]) {
        let Some(t) = read_toml(&p) else { continue };
        let src = ctx.tilde(&p);
        for (key, risky_value) in [
            ("approval_policy", "never"),
            ("sandbox_mode", "danger-full-access"),
            ("default_permissions", ":danger-full-access"),
        ] {
            if let Some(v) = t.get(key).and_then(|v| v.as_str()) {
                push(out, "codex", key, v.into(), v == risky_value, &src);
            }
        }
        if let Some(projects) = t.get("projects").and_then(|p| p.as_table()) {
            for dir in &disc.scanned {
                if let Some(level) = projects
                    .get(&dir.to_string_lossy().into_owned())
                    .and_then(|p| p.get("trust_level"))
                    .and_then(|l| l.as_str())
                {
                    push(
                        out,
                        "codex",
                        "trust_level",
                        format!("{level} for {}", ctx.tilde(dir)),
                        false,
                        &src,
                    );
                }
            }
        }
    }
}

fn gemini_settings(ctx: &Ctx, disc: &Discovery, out: &mut Vec<Setting>) {
    for p in config_files(
        ctx,
        disc,
        &[".gemini/settings.json"],
        &[".gemini/settings.json"],
    ) {
        let Some(v) = read_json(&p) else { continue };
        let mut leaves = Vec::new();
        flatten("", &v, &mut leaves);
        for (key, val) in leaves {
            let last = key.rsplit('.').next().unwrap_or(&key);
            let interesting = matches!(
                last,
                "autoAccept" | "approvalMode" | "defaultApprovalMode" | "yolo" | "sandbox"
            ) || key.contains("folderTrust");
            if interesting {
                let risky = ((last == "autoAccept" || last == "yolo") && val == "true")
                    || val.contains("yolo");
                push(out, "gemini", &key, val, risky, &ctx.tilde(&p));
            }
        }
    }
}

fn flatten(prefix: &str, v: &Value, out: &mut Vec<(String, String)>) {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                if k != "mcpServers" {
                    flatten(&key, child, out);
                }
            }
        }
        Value::String(s) => out.push((prefix.into(), s.clone())),
        Value::Bool(_) | Value::Number(_) => out.push((prefix.into(), v.to_string())),
        _ => {}
    }
}

/// Risky flags on the agent command line itself.
pub fn flag_settings(agent: &str, args: &[String]) -> Vec<Setting> {
    const RISKY: &[&str] = &[
        "--dangerously-skip-permissions",
        "--dangerously-bypass-approvals-and-sandbox",
        "--yolo",
        "--full-auto",
        "--allow-dangerously-skip-permissions",
    ];
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        let next = args.get(i + 1).map(String::as_str).unwrap_or("");
        let risky = RISKY.contains(&a.as_str())
            || (agent == "gemini" && a == "-y")
            || (matches!(
                a.as_str(),
                "--permission-mode" | "--sandbox" | "--approval-mode" | "-s"
            ) && matches!(next, "bypassPermissions" | "danger-full-access" | "yolo"));
        if risky {
            let value = if a.starts_with("--") && RISKY.contains(&a.as_str()) || a == "-y" {
                "set".into()
            } else {
                next.to_string()
            };
            push(&mut out, agent, a, value, true, "command line");
        }
    }
    out
}

// ---------- secrets in reach ----------

/// Names (never contents) of secret-looking files directly in `dir`.
pub fn sensitive_files(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return vec![];
    };
    let mut out: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| is_sensitive(n))
        .collect();
    out.sort();
    out
}

pub fn is_sensitive(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    if l.starts_with(".env") {
        return !["example", "sample", "template", "dist"]
            .iter()
            .any(|s| l.contains(s));
    }
    [".pem", ".key", ".p12", ".pfx", ".keystore", ".jks", ".kdbx"]
        .iter()
        .any(|e| l.ends_with(e))
        || ["id_rsa", "id_ed25519", "id_ecdsa"]
            .iter()
            .any(|p| l.starts_with(p))
        || matches!(
            l.as_str(),
            ".npmrc"
                | ".pypirc"
                | ".netrc"
                | "credentials"
                | "credentials.json"
                | ".aws"
                | ".ssh"
                | "wallet.json"
        )
        || (l.ends_with(".json") && (l.contains("keypair") || l.starts_with("service-account")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secrets_in_commands() {
        let s = redact_command(
            "npx",
            &[
                "-y",
                "@modelcontextprotocol/server-github",
                "--api-key",
                "abc",
                "TOKEN=xyz",
                "sk-live123",
            ],
        );
        assert_eq!(
            s,
            "npx -y @modelcontextprotocol/server-github --api-key ••• TOKEN=••• •••"
        );
        assert_eq!(
            redact_url("https://mcp.example/sse?api_key=123"),
            "https://mcp.example/sse?•••"
        );
    }

    #[test]
    fn sensitive_names() {
        for n in [
            ".env",
            ".env.local",
            "id_ed25519",
            "server.pem",
            "my-keypair.json",
            ".npmrc",
        ] {
            assert!(is_sensitive(n), "{n}");
        }
        for n in [".env.example", "README.md", "package.json", "keys.rs"] {
            assert!(!is_sensitive(n), "{n}");
        }
    }

    #[test]
    fn risky_cli_flags() {
        let args: Vec<String> = ["--dangerously-skip-permissions", "-p", "hi"]
            .map(String::from)
            .to_vec();
        assert_eq!(flag_settings("claude", &args).len(), 1);
        let args: Vec<String> = ["--sandbox", "danger-full-access"]
            .map(String::from)
            .to_vec();
        assert_eq!(flag_settings("codex", &args)[0].value, "danger-full-access");
        assert!(flag_settings("codex", &["exec".into()]).is_empty());
    }
}
