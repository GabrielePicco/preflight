//! Where did a file come from? Flags files in ~/Downloads or temp dirs, and files carrying
//! "downloaded from the internet" marks (macOS quarantine / WhereFroms, Linux
//! user.xdg.origin.url, Windows Zone.Identifier).

use crate::Ctx;
use std::path::Path;

/// Human-readable provenance flags. Any flag means "this file probably came from outside".
pub fn flags(path: &Path, ctx: &Ctx) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(home) = &ctx.home
        && path.starts_with(home.join("Downloads"))
    {
        out.push("in ~/Downloads".to_string());
    }
    if let Some(t) = ctx.temp_roots.iter().find(|t| path.starts_with(t)) {
        out.push(format!("in temp dir {}", t.display()));
    }
    out.extend(mark_flags(path));
    out
}

#[cfg(unix)]
fn mark_flags(path: &Path) -> Vec<String> {
    const ATTRS: &[(&str, &str)] = &[
        ("com.apple.quarantine", "quarantine xattr"),
        ("com.apple.metadata:kMDItemWhereFroms", "WhereFroms xattr"),
        ("user.xdg.origin.url", "xdg.origin.url xattr"),
    ];
    let mut out = Vec::new();
    for (name, label) in ATTRS {
        if let Ok(Some(value)) = xattr::get(path, name) {
            let detail = describe(name, &value);
            out.push(if detail.is_empty() { label.to_string() } else { format!("{label}: {detail}") });
        }
    }
    out
}

#[cfg(windows)]
fn mark_flags(path: &Path) -> Vec<String> {
    // NTFS alternate data stream written by browsers / mail clients ("Mark of the Web").
    let ads = format!("{}:Zone.Identifier", path.display());
    match std::fs::read_to_string(ads) {
        Ok(s) => {
            let zone = s.lines().find_map(|l| l.strip_prefix("ZoneId=")).unwrap_or("?").trim().to_string();
            let url = s.lines().find_map(|l| l.strip_prefix("HostUrl=")).unwrap_or("").trim().to_string();
            vec![format!("Zone.Identifier (zone {zone}) {url}").trim().to_string()]
        }
        Err(_) => vec![],
    }
}

#[cfg(not(any(unix, windows)))]
fn mark_flags(_: &Path) -> Vec<String> {
    vec![]
}

/// Best-effort short description of an xattr value (quarantine agent or first URL).
#[allow(dead_code)]
fn describe(name: &str, value: &[u8]) -> String {
    let text: String = value
        .iter()
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { ' ' })
        .collect();
    let detail = if name == "com.apple.quarantine" {
        text.split(';').nth(2).unwrap_or("").to_string()
    } else {
        text.split_whitespace().find(|w| w.contains("://")).unwrap_or(text.trim()).to_string()
    };
    detail.chars().take(60).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ctx(home: &Path, temp: Vec<PathBuf>) -> Ctx {
        Ctx { home: Some(home.into()), trust_file: "/x".into(), log_file: "/y".into(), temp_roots: temp }
    }

    #[test]
    fn downloads_and_temp_flags() {
        let c = ctx(Path::new("/home/u"), vec![PathBuf::from("/tmp")]);
        assert_eq!(flags(Path::new("/home/u/Downloads/x/AGENTS.md"), &c), vec!["in ~/Downloads"]);
        assert_eq!(flags(Path::new("/tmp/x/AGENTS.md"), &c), vec!["in temp dir /tmp"]);
        assert!(flags(Path::new("/home/u/code/AGENTS.md"), &c).is_empty());
    }

    #[test]
    fn describes_quarantine_and_wherefroms() {
        assert_eq!(describe("com.apple.quarantine", b"0083;65a1b2c3;Chrome;ABC-123"), "Chrome");
        assert_eq!(
            describe("com.apple.metadata:kMDItemWhereFroms", b"bplist00\xa2\x01\x02_\x10https://evil.example/a.zip"),
            "https://evil.example/a.zip"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_origin_xattr_if_supported() {
        let t = tempfile::tempdir_in(".").unwrap();
        let f = t.path().join("AGENTS.md");
        std::fs::write(&f, "x").unwrap();
        if xattr::set(&f, "user.xdg.origin.url", b"https://example.com/repo.zip").is_err() {
            eprintln!("filesystem has no user xattrs; skipping");
            return;
        }
        let c = ctx(Path::new("/nonexistent"), vec![]);
        assert_eq!(flags(&f, &c), vec!["xdg.origin.url xattr: https://example.com/repo.zip"]);
    }
}
