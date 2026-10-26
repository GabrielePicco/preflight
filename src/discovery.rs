//! Find every file an agent may read as instructions or config, from cwd up to $HOME.

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Single files agents read as instructions or config, relative to each scanned directory.
/// Extend this list as new agents and conventions appear.
pub const INSTRUCTION_FILES: &[&str] = &[
    "AGENTS.md",
    "AGENTS.override.md",
    "CLAUDE.md",
    "CLAUDE.local.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    ".github/copilot-instructions.md",
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/CLAUDE.md",
    ".codex/config.toml",
    ".codex/AGENTS.md",
    ".gemini/settings.json",
    ".gemini/GEMINI.md",
];

/// Directories where every file is an instruction (rules, commands, subagents, skills).
pub const INSTRUCTION_DIRS: &[&str] = &[
    ".cursor/rules",
    ".claude/commands",
    ".claude/agents",
    ".claude/skills",
    ".codex/prompts",
    ".gemini/commands",
    ".github/instructions",
];

/// Cap per instruction directory so a huge tree can't stall a launch.
const MAX_DIR_FILES: usize = 64;

#[derive(Debug, Clone)]
pub struct Found {
    pub path: PathBuf,
    /// Which entry of `INSTRUCTION_FILES` / `INSTRUCTION_DIRS` matched.
    pub pattern: &'static str,
}

#[derive(Debug, Clone)]
pub struct Discovery {
    pub cwd: PathBuf,
    pub git_root: Option<PathBuf>,
    /// Directories scanned, innermost first.
    pub scanned: Vec<PathBuf>,
    pub files: Vec<Found>,
}

/// Walk from `cwd` upward, stopping after `home` (or at the filesystem root when cwd is
/// outside home). The walk deliberately continues past the git root: a repo cloned into
/// ~/Downloads still picks up a planted ~/Downloads/AGENTS.md.
pub fn discover(cwd: &Path, home: Option<&Path>) -> Discovery {
    let cwd = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    let home = home.map(|h| h.canonicalize().unwrap_or_else(|_| h.to_path_buf()));
    let mut scanned = Vec::new();
    let mut files: Vec<Found> = Vec::new();
    let mut git_root = None;
    let mut dir = Some(cwd.as_path());
    while let Some(d) = dir {
        scanned.push(d.to_path_buf());
        if git_root.is_none() && d.join(".git").exists() {
            git_root = Some(d.to_path_buf());
        }
        scan_dir(d, &mut files);
        if home.as_deref() == Some(d) {
            break;
        }
        dir = d.parent();
    }
    let mut seen = std::collections::HashSet::new();
    files.retain(|f| seen.insert(f.path.canonicalize().unwrap_or_else(|_| f.path.clone())));
    Discovery {
        cwd,
        git_root,
        scanned,
        files,
    }
}

fn scan_dir(d: &Path, out: &mut Vec<Found>) {
    for pattern in INSTRUCTION_FILES {
        let p = d.join(pattern);
        if p.is_file() {
            out.push(Found { path: p, pattern });
        }
    }
    for pattern in INSTRUCTION_DIRS {
        let root = d.join(pattern);
        if !root.is_dir() {
            continue;
        }
        WalkDir::new(&root)
            .max_depth(4)
            .sort_by_file_name()
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .take(MAX_DIR_FILES)
            .for_each(|e| {
                out.push(Found {
                    path: e.into_path(),
                    pattern,
                })
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn walks_up_to_home_and_notes_git_root() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        let repo = home.join("Downloads/repo");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::create_dir_all(repo.join("src")).unwrap();
        fs::write(home.join("Downloads/AGENTS.md"), "planted").unwrap();
        fs::write(repo.join("CLAUDE.md"), "repo").unwrap();
        fs::write(t.path().join("AGENTS.md"), "above home, ignored").unwrap();
        fs::create_dir_all(repo.join(".cursor/rules")).unwrap();
        fs::write(repo.join(".cursor/rules/style.mdc"), "rule").unwrap();

        let d = discover(&repo.join("src"), Some(&home));
        let names: Vec<String> = d
            .files
            .iter()
            .map(|f| {
                f.path
                    .strip_prefix(home.canonicalize().unwrap())
                    .unwrap()
                    .display()
                    .to_string()
            })
            .collect();
        assert_eq!(
            names,
            vec![
                "Downloads/repo/CLAUDE.md",
                "Downloads/repo/.cursor/rules/style.mdc",
                "Downloads/AGENTS.md"
            ]
        );
        assert_eq!(d.git_root.unwrap(), repo.canonicalize().unwrap());
        assert_eq!(d.scanned.last().unwrap(), &home.canonicalize().unwrap());
    }

    #[test]
    fn nothing_found_in_clean_tree() {
        let t = tempfile::tempdir().unwrap();
        let d = discover(t.path(), Some(t.path()));
        assert!(d.files.is_empty());
        assert_eq!(d.scanned.len(), 1);
    }
}
