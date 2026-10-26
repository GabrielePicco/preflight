//! The setup panel: one compact, colored screen of everything an agent is about to inherit.

use crate::Ctx;
use crate::heuristics::{Hit, Severity};
use crate::report::{FileReport, Report, Verdict};
use crate::snapshot::Change;
use crate::trust::TrustState;
use owo_colors::{OwoColorize, Style};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

const RULE_WIDTH: usize = 92;
const LINE_WIDTH: usize = 100;

pub struct Painter {
    pub color: bool,
}

impl Painter {
    pub fn paint(&self, s: &str, st: Style) -> String {
        if self.color { s.style(st).to_string() } else { s.to_string() }
    }
    fn dim(&self, s: &str) -> String {
        self.paint(s, Style::new().dimmed())
    }
    fn bold(&self, s: &str) -> String {
        self.paint(s, Style::new().bold())
    }
}

fn pad(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n >= w { s.to_string() } else { format!("{s}{}", " ".repeat(w - n)) }
}

/// Keep the tail of long paths: "…/very/long/AGENTS.md".
fn shorten(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n <= w { s.to_string() } else { format!("…{}", s.chars().skip(n - w + 1).collect::<String>()) }
}

fn clip(s: &str, w: usize) -> String {
    if s.chars().count() <= w { s.to_string() } else { format!("{}…", s.chars().take(w - 1).collect::<String>()) }
}

pub fn render(ctx: &Ctx, r: &Report, color: bool, show_contents: bool) -> String {
    let p = Painter { color };
    let mut o = String::new();
    let rule = p.dim(&"─".repeat(RULE_WIDTH));
    let section = |o: &mut String, title: &str, n: Option<usize>| {
        let count = n.map(|n| format!(" ({n})")).unwrap_or_default();
        let _ = writeln!(o, "\n {}{}", p.paint(title, Style::new().bold().cyan()), p.dim(&count));
    };

    let _ = writeln!(
        o,
        " {} {}",
        p.paint("▲ preflight", Style::new().bold().cyan()),
        p.dim(&format!("v{} · what your agent is about to inherit", env!("CARGO_PKG_VERSION")))
    );
    let _ = writeln!(o, "{rule}");
    let d = &r.discovery;
    let kv = |o: &mut String, k: &str, v: String| {
        let _ = writeln!(o, "  {} {v}", p.dim(&pad(k, 9)));
    };
    kv(&mut o, "cwd", ctx.tilde(&d.cwd));
    kv(&mut o, "git root", d.git_root.as_ref().map(|g| ctx.tilde(g)).unwrap_or_else(|| p.dim("none")));
    let first = d.scanned.first().map(|s| ctx.tilde(s)).unwrap_or_default();
    let last = d.scanned.last().map(|s| ctx.tilde(s)).unwrap_or_default();
    kv(&mut o, "scanned", format!("{} dirs, {first} → {last}", d.scanned.len()));
    let agents: Vec<String> = r
        .agents
        .iter()
        .map(|a| match (&a.path, &a.version) {
            (Some(_), Some(v)) => format!("{} {}", p.paint(&a.name, Style::new().bold().green()), p.dim(v)),
            (Some(_), None) => p.paint(&a.name, Style::new().bold().green()),
            (None, _) => p.dim(&format!("{} not found", a.name)),
        })
        .collect();
    if !agents.is_empty() {
        kv(&mut o, "agent", agents.join(&p.dim("  ·  ")));
    }

    // Instruction files
    section(&mut o, "INSTRUCTION FILES", Some(r.files.len()));
    if r.files.is_empty() {
        let _ = writeln!(o, "  {}", p.dim("none found between cwd and the top of the walk"));
    }
    let path_w = r.files.iter().map(|f| ctx.tilde(&f.path).chars().count()).max().unwrap_or(0).min(48);
    for f in &r.files {
        let (icon, badge, st) = match f.state {
            TrustState::Trusted => ("✓", "TRUSTED", Style::new().green()),
            TrustState::New => ("✗", "NEW", Style::new().red().bold()),
            TrustState::Changed => ("✗", "CHANGED", Style::new().yellow().bold()),
        };
        let mut tags = Vec::new();
        if !f.provenance.is_empty() {
            tags.push(p.paint("⬇ downloaded", Style::new().magenta().bold()));
        }
        let flags = {
            let mut rules: Vec<&str> = f.hits.iter().filter(|h| h.severity >= Severity::Medium).map(|h| h.rule).collect();
            rules.sort_unstable();
            rules.dedup();
            rules.len()
        };
        if flags > 0 {
            tags.push(p.paint(&format!("⚑ {flags} flag{}", if flags == 1 { "" } else { "s" }), Style::new().yellow()));
        }
        let path = pad(&shorten(&ctx.tilde(&f.path), 48), path_w);
        let path = if f.untrusted() { p.bold(&path) } else { path };
        let _ = writeln!(o, "  {} {} {path}  {}", p.paint(icon, st), p.paint(&pad(badge, 8), st), tags.join("  "));
    }

    // MCP servers
    section(&mut o, "MCP SERVERS", Some(r.mcp.len()));
    if r.mcp.is_empty() {
        let _ = writeln!(o, "  {}", p.dim("none configured"));
    }
    let name_w = r.mcp.iter().map(|m| m.name.chars().count()).max().unwrap_or(0).min(16);
    for m in &r.mcp {
        let _ = writeln!(
            o,
            "  {} {}  {}  {}",
            p.paint("•", Style::new().blue()),
            p.paint(&pad(&clip(&m.name, 16), name_w), Style::new().bold()),
            clip(&m.target, 60),
            p.dim(&m.source)
        );
    }

    // Permissions
    section(&mut o, "PERMISSIONS & SANDBOX", None);
    if r.settings.is_empty() {
        let _ = writeln!(o, "  {}", p.dim("no permission overrides found"));
    }
    for s in &r.settings {
        let icon = if s.risky { p.paint("!", Style::new().red().bold()) } else { p.dim("·") };
        let value = if s.risky { p.paint(&clip(&s.value, 40), Style::new().red()) } else { clip(&s.value, 40) };
        let _ = writeln!(o, "  {icon} {} {} = {value}  {}", p.dim(&pad(&s.agent, 6)), s.key, p.dim(&s.source));
    }

    // Secrets
    section(&mut o, "SECRETS IN REACH", Some(r.sensitive.len()));
    if r.sensitive.is_empty() {
        let _ = writeln!(o, "  {}", p.dim("no secret-looking files in cwd"));
    } else {
        let names: Vec<String> = r.sensitive.iter().map(|n| p.paint(n, Style::new().yellow())).collect();
        let _ = writeln!(o, "  {} {}", p.paint("!", Style::new().yellow().bold()), names.join("  "));
    }

    // Contents of untrusted files
    if show_contents {
        for f in r.files.iter().filter(|f| f.untrusted() && f.readable) {
            excerpt(ctx, f, &p, &mut o);
        }
    }

    // Verdict
    let _ = writeln!(o, "\n{rule}");
    match r.verdict {
        Verdict::Go => {
            let what = if r.files.is_empty() {
                "no instruction files in reach".to_string()
            } else {
                format!("all {} instruction files match their trusted hashes", r.files.len())
            };
            let _ = writeln!(o, "  {}  {what}", p.paint(" GO ", Style::new().black().on_green().bold()));
        }
        Verdict::Blocked => {
            let n = r.reasons.len();
            let _ = writeln!(
                o,
                "  {}  {n} untrusted instruction file{}",
                p.paint(" BLOCKED ", Style::new().white().on_red().bold()),
                if n == 1 { "" } else { "s" }
            );
            for reason in &r.reasons {
                let _ = writeln!(o, "     {} {}", p.paint("•", Style::new().red()), clip(reason, LINE_WIDTH - 7));
            }
        }
    }
    for w in &r.warnings {
        let _ = writeln!(o, "     {} {}", p.paint("⚠", Style::new().yellow()), clip(w, LINE_WIDTH - 7));
    }
    if r.verdict == Verdict::Blocked {
        let _ = writeln!(o, "     {} {}", p.dim("review the file(s) above, then run:"), p.bold("preflight trust"));
    }
    o
}

fn excerpt(ctx: &Ctx, f: &FileReport, p: &Painter, o: &mut String) {
    let lines: Vec<&str> = f.text.lines().collect();
    let _ = writeln!(
        o,
        "\n {} {}  {}",
        p.paint("▸", Style::new().red().bold()),
        p.bold(&ctx.tilde(&f.path)),
        p.dim(&format!("{} · {} line{} · sha256 {}…", f.state.as_str(), lines.len(), if lines.len() == 1 { "" } else { "s" }, &f.sha256[..12]))
    );
    let hit_lines: BTreeSet<usize> = f.hits.iter().map(|h| h.line).collect();
    let show: BTreeSet<usize> = if lines.len() <= 14 {
        (1..=lines.len()).collect()
    } else {
        (1..=4).chain(hit_lines.iter().copied().take(10)).collect()
    };
    let mut last = 0;
    for &n in &show {
        if last > 0 && n > last + 1 {
            let _ = writeln!(o, "  {}", p.dim("     ┆"));
        }
        let hits: Vec<&Hit> = f.hits.iter().filter(|h| h.line == n).collect();
        let sev = hits.iter().map(|h| h.severity).max();
        let num = format!("{n:>5} │");
        let num = match sev {
            Some(Severity::High) => p.paint(&num, Style::new().red().bold()),
            Some(Severity::Medium) => p.paint(&num, Style::new().yellow()),
            _ => p.dim(&num),
        };
        let _ = writeln!(o, "  {num} {}", render_line(lines[n - 1], &hits, p));
        last = n;
    }
    if lines.len() > last {
        let _ = writeln!(o, "  {}", p.dim(&format!("      … {} more lines", lines.len() - last)));
    }
    let mut by_rule: BTreeMap<(std::cmp::Reverse<Severity>, &str), BTreeSet<usize>> = BTreeMap::new();
    for h in &f.hits {
        by_rule.entry((std::cmp::Reverse(h.severity), h.label)).or_default().insert(h.line);
    }
    for ((sev, label), ls) in by_rule {
        let (tag, st) = match sev.0 {
            Severity::High => ("high", Style::new().red().bold()),
            Severity::Medium => ("med ", Style::new().yellow()),
            Severity::Low => ("low ", Style::new().cyan()),
        };
        let ls: Vec<String> = ls.iter().map(|l| format!("L{l}")).collect();
        let _ = writeln!(o, "     {} {} {}", p.paint(&format!("⚑ {tag}"), st), label, p.dim(&ls.join(" ")));
    }
}

/// Make every character visible: control and invisible Unicode chars become ⟨U+XXXX⟩, so a
/// file can't hide text or inject terminal escapes into the panel.
fn visible(ch: char) -> String {
    let invisible = matches!(ch as u32, 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0xFEFF);
    if ch == '\t' {
        "  ".into()
    } else if ch.is_control() || invisible {
        format!("⟨U+{:04X}⟩", ch as u32)
    } else {
        ch.to_string()
    }
}

fn render_line(line: &str, hits: &[&Hit], p: &Painter) -> String {
    let mut out = String::new();
    let mut buf = String::new();
    let mut cur: Option<Severity> = None;
    let mut width = 0;
    let flush = |out: &mut String, buf: &mut String, sev: Option<Severity>| {
        if buf.is_empty() {
            return;
        }
        let st = match sev {
            Some(Severity::High) => Style::new().red().bold().underline(),
            Some(Severity::Medium) => Style::new().yellow().bold(),
            Some(Severity::Low) => Style::new().cyan().underline(),
            None => Style::new(),
        };
        out.push_str(&p.paint(buf, st));
        buf.clear();
    };
    let masks = secret_ranges(line);
    for (i, ch) in line.char_indices() {
        if width >= LINE_WIDTH - 10 {
            flush(&mut out, &mut buf, cur);
            out.push_str(&p.dim("…"));
            return out;
        }
        let sev = hits.iter().filter(|h| i >= h.start && i < h.end).map(|h| h.severity).max();
        if sev != cur {
            flush(&mut out, &mut buf, cur);
            cur = sev;
        }
        let v = if masks.iter().any(|r| r.contains(&i)) { "•".to_string() } else { visible(ch) };
        width += v.chars().count();
        buf.push_str(&v);
    }
    flush(&mut out, &mut buf, cur);
    out
}

/// Byte ranges of token-looking values (after their prefix) to mask in excerpts, so the
/// panel stays safe to screenshot.
fn secret_ranges(line: &str) -> Vec<std::ops::Range<usize>> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"(ghp_|gho_|ghs_|github_pat_|sk-|sk_live_|xox[abprs]-|AKIA|glpat-|hf_)([A-Za-z0-9_\-]{4,})").unwrap()
    });
    re.captures_iter(line).filter_map(|c| c.get(2)).map(|m| m.range()).collect()
}

pub fn render_changes(ctx: &Ctx, changes: &[Change], color: bool) -> String {
    let _ = ctx;
    let p = Painter { color };
    let mut o = String::new();
    if changes.is_empty() {
        let _ = writeln!(o, " {} {}", p.paint("▲ preflight", Style::new().bold().cyan()), p.dim("agent exited · no config, MCP or shell rc changes"));
        return o;
    }
    let _ = writeln!(
        o,
        " {} {}",
        p.paint("▲ preflight", Style::new().bold().cyan()),
        p.paint(&format!("agent exited · {} watched file(s) changed during the run", changes.len()), Style::new().yellow().bold())
    );
    for c in changes {
        let (tag, path, st) = match c {
            Change::Added(x) => ("added   ", x, Style::new().green()),
            Change::Modified(x) => ("modified", x, Style::new().yellow()),
            Change::Removed(x) => ("removed ", x, Style::new().red()),
        };
        let _ = writeln!(o, "   {} {path}", p.paint(tag, st));
    }
    let _ = writeln!(o, "   {}", p.dim("review these; changed instruction files will need `preflight trust` again"));
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_invisible_and_control_chars() {
        let p = Painter { color: false };
        assert_eq!(render_line("a\u{1b}[2Jb\u{200B}c", &[], &p), "a⟨U+001B⟩[2Jb⟨U+200B⟩c");
        assert_eq!(render_line("token ghp_abcdef", &[], &p), "token ghp_••••••");
    }

    #[test]
    fn shortens_long_paths_from_the_left() {
        assert_eq!(shorten("abcdefghij", 5), "…ghij");
        assert_eq!(shorten("abc", 5), "abc");
    }
}
