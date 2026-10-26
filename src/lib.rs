//! preflight: a pre-flight guard for coding agents.
//!
//! Before an agent (Codex, Claude Code, Gemini CLI, ...) starts, preflight walks from the
//! working directory up to `$HOME`, finds every file an agent would read as instructions
//! or config, and refuses to launch if any of them is new or changed since you trusted it.

pub mod discovery;
pub mod heuristics;
pub mod log;
pub mod panel;
pub mod provenance;
pub mod report;
pub mod setup;
pub mod snapshot;
pub mod trust;

use std::path::{Path, PathBuf};

/// Everything that depends on the environment, so tests can point it at a temp dir.
#[derive(Debug, Clone)]
pub struct Ctx {
    pub home: Option<PathBuf>,
    pub trust_file: PathBuf,
    pub log_file: PathBuf,
    /// Directories treated as "temporary" for provenance flags.
    pub temp_roots: Vec<PathBuf>,
}

impl Ctx {
    pub fn from_env() -> Ctx {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .map(|h| h.canonicalize().unwrap_or(h));
        let base = home.clone().unwrap_or_else(|| PathBuf::from("."));
        let config = env_path("XDG_CONFIG_HOME").unwrap_or_else(|| base.join(".config"));
        let state = env_path("XDG_STATE_HOME").unwrap_or_else(|| base.join(".local/state"));
        let trust_file =
            env_path("PREFLIGHT_TRUST_FILE").unwrap_or_else(|| config.join("preflight/trusted.json"));
        let log_file =
            env_path("PREFLIGHT_LOG_FILE").unwrap_or_else(|| state.join("preflight/log.jsonl"));
        let raw: Vec<PathBuf> = match std::env::var_os("PREFLIGHT_TEMP_ROOTS") {
            Some(s) => std::env::split_paths(&s).filter(|p| !p.as_os_str().is_empty()).collect(),
            None => {
                let mut v = vec![std::env::temp_dir()];
                v.extend(["/tmp", "/var/tmp", "/private/tmp", "/dev/shm"].map(PathBuf::from));
                v
            }
        };
        let mut temp_roots: Vec<PathBuf> = Vec::new();
        for p in raw {
            let p = p.canonicalize().unwrap_or(p);
            if !temp_roots.contains(&p) {
                temp_roots.push(p);
            }
        }
        Ctx { home, trust_file, log_file, temp_roots }
    }

    /// Show a path with `$HOME` replaced by `~`.
    pub fn tilde(&self, p: &Path) -> String {
        if let Some(h) = &self.home
            && let Ok(rest) = p.strip_prefix(h)
        {
            return if rest.as_os_str().is_empty() {
                "~".into()
            } else {
                format!("~/{}", rest.display())
            };
        }
        p.display().to_string()
    }
}

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key).filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
