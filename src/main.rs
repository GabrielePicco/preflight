use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use preflight::report::{self, Options, Verdict};
use preflight::setup::KNOWN_AGENTS;
use preflight::trust::{TrustStore, sha256_file};
use preflight::{Ctx, log, panel, snapshot};
use serde_json::json;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

/// Exit code when a launch or status check is blocked.
const EXIT_BLOCKED: u8 = 3;

#[derive(Parser)]
#[command(
    name = "preflight",
    version,
    about = "Pre-flight guard for coding agents: blocks launch when untrusted instruction files are in reach."
)]
struct Cli {
    /// When to use colors
    #[arg(long, global = true, value_enum, default_value_t = ColorMode::Auto)]
    color: ColorMode,
    /// Run as if started in this directory
    #[arg(short = 'C', long, global = true)]
    dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show the setup panel and verdict (exit 0 GO / 3 BLOCKED); probes agent versions unless disabled
    Status {
        /// Agent(s) to show; default: claude, codex, gemini
        #[arg(long)]
        agent: Vec<String>,
        /// Don't run `<agent> --version`
        #[arg(long)]
        no_version: bool,
        /// Don't print the contents of untrusted files
        #[arg(long)]
        no_contents: bool,
    },
    /// Check, then launch the agent if GO: `preflight run -- codex ...`
    Run {
        /// Launch even if blocked (still logged)
        #[arg(long)]
        force: bool,
        /// Only print the full panel when blocked
        #[arg(short, long)]
        quiet: bool,
        /// Don't run `<agent> --version`
        #[arg(long)]
        no_version: bool,
        /// The agent command and its arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Approve the current content of instruction files (all untrusted ones in reach, or the given paths)
    Trust {
        /// Files to approve after review; omit to approve all untrusted files in reach
        paths: Vec<PathBuf>,
    },
    /// Print shell aliases that route codex / claude / gemini through preflight
    InitShell {
        /// bash, zsh or fish (default: from $SHELL, else bash)
        #[arg(long)]
        shell: Option<String>,
    },
}

fn use_color(mode: ColorMode, stream_is_tty: bool) -> bool {
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => stream_is_tty && std::env::var_os("NO_COLOR").is_none(),
    }
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("preflight: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn real_main() -> Result<ExitCode> {
    let cli = Cli::parse();
    let ctx = Ctx::from_env();
    let cwd = match &cli.dir {
        Some(d) => d
            .canonicalize()
            .with_context(|| format!("no such directory {}", d.display()))?,
        None => std::env::current_dir()?,
    };
    match cli.cmd {
        Cmd::Status {
            agent,
            no_version,
            no_contents,
        } => {
            let store = TrustStore::load(&ctx.trust_file)?;
            let agents = if agent.is_empty() {
                KNOWN_AGENTS.iter().map(|s| s.to_string()).collect()
            } else {
                agent
            };
            let opts = Options {
                agents,
                probe_versions: !no_version,
                agent_args: vec![],
            };
            let r = report::build(&ctx, &cwd, &store, &opts);
            let color = use_color(cli.color, std::io::stdout().is_terminal());
            print!("{}", panel::render(&ctx, &r, color, !no_contents));
            log::append(&ctx.log_file, &log::report_entry("status", &r))?;
            Ok(if r.verdict == Verdict::Go {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(EXIT_BLOCKED)
            })
        }
        Cmd::Run {
            force,
            quiet,
            no_version,
            command,
        } => run(&ctx, &cwd, cli.color, force, quiet, no_version, &command),
        Cmd::Trust { paths } => trust(&ctx, &cwd, &paths),
        Cmd::InitShell { shell } => {
            let shell = shell.unwrap_or_else(|| {
                std::env::var("SHELL")
                    .ok()
                    .and_then(|s| s.rsplit('/').next().map(str::to_string))
                    .filter(|s| ["bash", "zsh", "fish"].contains(&s.as_str()))
                    .unwrap_or_else(|| "bash".into())
            });
            print!("{}", init_shell(&shell)?);
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn run(
    ctx: &Ctx,
    cwd: &std::path::Path,
    mode: ColorMode,
    force: bool,
    quiet: bool,
    no_version: bool,
    command: &[String],
) -> Result<ExitCode> {
    let program = &command[0];
    let agent = std::path::Path::new(program)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.clone());
    let store = TrustStore::load(&ctx.trust_file)?;
    let opts = Options {
        agents: vec![agent.clone()],
        probe_versions: !no_version,
        agent_args: command[1..].to_vec(),
    };
    let r = report::build(ctx, cwd, &store, &opts);
    let color = use_color(mode, std::io::stderr().is_terminal());
    let blocked = r.verdict == Verdict::Blocked;
    if quiet && !blocked {
        eprintln!(
            "preflight: GO · {} instruction file(s) trusted · launching {agent}",
            r.files.len()
        );
    } else {
        eprint!("{}", panel::render(ctx, &r, color, true));
    }
    let mut entry = log::report_entry("run", &r);
    entry["command"] = json!(command);
    entry["forced"] = json!(blocked && force);
    log::append(&ctx.log_file, &entry)?;
    if blocked && !force {
        eprintln!("     not launching. Use --force to launch anyway (logged).");
        return Ok(ExitCode::from(EXIT_BLOCKED));
    }

    let before = snapshot::take(ctx, cwd);
    // Let Ctrl-C reach the agent without killing us, so the after-run diff still prints.
    let _ = ctrlc::set_handler(|| {});
    let status = Command::new(program)
        .args(&command[1..])
        .current_dir(cwd)
        .status()
        .with_context(|| format!("launching {program}"))?;
    let after = snapshot::take(ctx, cwd);
    let changes = snapshot::diff(&before, &after);
    eprint!("{}", panel::render_changes(ctx, &changes, color));
    log::append(
        &ctx.log_file,
        &json!({
            "ts": preflight::now(),
            "action": "exit",
            "cwd": cwd,
            "command": command,
            "exit_code": status.code(),
            "changes": changes.iter().map(|c| format!("{c:?}")).collect::<Vec<_>>(),
            "snapshot_after": after,
        }),
    )?;
    Ok(ExitCode::from(
        status.code().unwrap_or(1).clamp(0, 255) as u8
    ))
}

fn trust(ctx: &Ctx, cwd: &std::path::Path, paths: &[PathBuf]) -> Result<ExitCode> {
    let mut store = TrustStore::load(&ctx.trust_file)?;
    let targets: Vec<PathBuf> = if paths.is_empty() {
        let opts = Options {
            agents: vec![],
            probe_versions: false,
            agent_args: vec![],
        };
        report::build(ctx, cwd, &store, &opts)
            .files
            .into_iter()
            .filter(|f| f.untrusted() && f.readable)
            .map(|f| f.path)
            .collect()
    } else {
        paths
            .iter()
            .map(|p| {
                cwd.join(p)
                    .canonicalize()
                    .with_context(|| format!("no such file {}", p.display()))
            })
            .collect::<Result<_>>()?
    };
    if targets.is_empty() {
        println!("preflight: nothing to trust, every instruction file in reach is already trusted");
        return Ok(ExitCode::SUCCESS);
    }
    let mut logged = Vec::new();
    for path in &targets {
        if !path.is_file() {
            bail!("{} is not a file", path.display());
        }
        let sha = sha256_file(path)?;
        store.trust(path, &sha);
        println!("trusted  {}  sha256 {}…", ctx.tilde(path), &sha[..16]);
        logged.push(json!({ "path": path, "sha256": sha }));
    }
    store.save(&ctx.trust_file)?;
    log::append(
        &ctx.log_file,
        &json!({ "ts": preflight::now(), "action": "trust", "cwd": cwd, "files": logged }),
    )?;
    Ok(ExitCode::SUCCESS)
}

fn init_shell(shell: &str) -> Result<String> {
    let mut out = String::new();
    match shell {
        "bash" | "zsh" | "sh" => {
            out.push_str(&format!(
                "# add to your ~/.{shell}rc:  eval \"$(preflight init-shell --shell {shell})\"\n"
            ));
            for a in KNOWN_AGENTS {
                out.push_str(&format!("alias {a}='preflight run -- {a}'\n"));
            }
        }
        "fish" => {
            out.push_str("# add to ~/.config/fish/config.fish:  preflight init-shell --shell fish | source\n");
            for a in KNOWN_AGENTS {
                out.push_str(&format!("alias {a} 'preflight run -- {a}'\n"));
            }
        }
        other => bail!("unsupported shell {other} (use bash, zsh or fish)"),
    }
    Ok(out)
}
