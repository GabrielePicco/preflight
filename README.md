# preflight

![preflight status: BLOCKED](demo/status-blocked.png)

**A pre-flight check for coding agents.** Before `codex`, `claude` or `gemini` starts, `preflight`
shows supported instruction files, MCP servers, permission settings and secret-looking filenames
in reach, and **refuses to launch** if any instruction file is new or has changed since you last
approved it.

## What it is / isn’t

preflight is a local review step and file-hash gate for launches you route through it.
The Cargo package is `agent-preflight`; the executable is `preflight`.

It is not a sandbox, malware scanner, or complete security boundary. **Heuristics are
not a security boundary:** they can miss attacks and flag harmless text. A trusted
file can still be malicious. Keep each agent’s built-in folder trust, sandbox, and
approval controls enabled.

## Why

In October 2026 researchers reported a real-world case where a malicious `AGENTS.md` sitting in a
developer's **Downloads folder** tried to get an AI coding agent to install a rogue npm package.
Agents read instruction files from the working directory *and its parents*, so one planted file can
steer every session that starts underneath it.

- The Hacker News: [post](https://x.com/TheHackersNews/status/2114600105752015027) ·
  [article](https://thehackernews.com/2026/10/malicious-file-in-downloads-folder.html)
- BleepingComputer: [post](https://x.com/BleepinComputer/status/2114383958028750884) ·
  [article](https://www.bleepingcomputer.com/news/security/ai-coding-agents-hijacked-using-agentsmd-file-in-downloads-folder/)

Credit for the research and reporting goes to them. preflight is a small, independent,
detection-and-prevention tool written in response. It is not affiliated with OpenAI, Anthropic or Google.

## Install

```sh
cargo install agent-preflight --locked
preflight --help
```

Or install from GitHub (requires access while the repository is private):

```sh
cargo install --git https://github.com/GabrielePicco/preflight --branch prep-share --locked agent-preflight
# Or from a checkout:
cargo install --path . --locked
preflight --help
```

Homebrew installation is coming. The GitHub repository remains private until an
explicit visibility decision; `prep-share` is the unmerged preparation branch.

Optional: route your agents through preflight automatically.

```sh
eval "$(preflight init-shell)"            # bash / zsh  (add to ~/.bashrc or ~/.zshrc)
preflight init-shell --shell fish | source
```

This defines `codex`, `claude` and `gemini` aliases that call `preflight run -- <agent> ...`.

## Usage

```sh
preflight status                 # the setup panel + GO / BLOCKED verdict (exit 0 / 3)
preflight trust                  # approve every untrusted file currently in reach
preflight trust AGENTS.md        # ...or just specific files
preflight run -- codex "fix the failing test"
preflight run --force -- claude  # launch despite BLOCKED (logged)
preflight -C ~/some/dir status   # check another directory
```

Flags: `--color auto|always|never`, `status --no-contents`, `status --no-version`,
`status --agent codex` (repeatable).

### The setup panel

`preflight status` answers "what is my agent about to inherit?" in one screen:

| Section | What it shows |
|---|---|
| header | cwd, git root, how far up the scan went, which agents are on `PATH` and their `--version` |
| INSTRUCTION FILES | every file found, `✓ TRUSTED` / `✗ NEW` / `✗ CHANGED`, `⬇ downloaded` provenance, `⚑` heuristic flags |
| MCP SERVERS | servers from `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`, `~/.codex/config.toml`, `~/.claude.json`; command lines with secret-looking values redacted, env vars never printed |
| PERMISSIONS & SANDBOX | Claude `permissions.defaultMode` / `allow` / hooks / folder trust, Codex `approval_policy` / `sandbox_mode` / project `trust_level`, Gemini auto-accept / YOLO / sandbox, and risky CLI flags passed to `run` |
| SECRETS IN REACH | `.env*`, `*.pem`, `id_rsa`, `credentials.json`, ... by **name only**; contents are never read |
| excerpts | full text of every untrusted file with suspicious spans highlighted; invisible and control characters shown as `⟨U+200B⟩` |
| verdict | `GO` or `BLOCKED`, the reasons, and warnings |

After trusting:

![preflight status: GO](demo/status-go.png)

### What it checks

1. **Discovery.** From the current directory up to `$HOME` (or `/`), it looks for `AGENTS.md`,
   `AGENTS.override.md`, `CLAUDE.md`, `CLAUDE.local.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`,
   `.clinerules`, `.github/copilot-instructions.md`, the MCP and settings files above, and the
   `.claude/{commands,agents,skills}`, `.codex/prompts`, `.cursor/rules`, `.gemini/commands` and
   `.github/instructions` directories. The walk deliberately **does not stop at the git root**: a repo
   cloned into `~/Downloads` still sees a planted `~/Downloads/AGENTS.md`.
2. **Trust list (the launch gate).** `~/.config/preflight/trusted.json` maps each absolute path to
   the SHA-256 of the content you approved. A new or changed file is a hard BLOCK, and its contents are
   printed so you can read them before running `preflight trust`.
3. **Provenance.** Files under `~/Downloads` or a temp directory, files carrying the macOS
   `com.apple.quarantine` / `kMDItemWhereFroms` xattrs, the freedesktop `user.xdg.origin.url` xattr, or
   a Windows `Zone.Identifier` stream get a `⬇ downloaded` tag. These add to the block reason and stay as
   a warning after you trust the file.
4. **Heuristics (advisory only).** These highlight pipe-to-shell, prompt-injection phrasing, references
   to secrets, package installs, long encoded blobs, persistence and exec patterns, hidden HTML comments,
   zero-width and bidi characters, and URLs. **They are not the boundary.** A clean scan never makes an
   untrusted file GO, and a flagged file you have trusted stays GO.
5. **Config diff around a run.** `preflight run` snapshots agent configs (`~/.claude*`, `~/.codex`,
   `~/.gemini`, `~/.cursor/mcp.json`), shell rc files, `~/.gitconfig`, `~/.npmrc`, `~/.ssh/config` and
   `authorized_keys`, plus every discovered file. After the agent exits it prints what was added,
   modified or removed. For `~/.claude.json`, only the security-relevant keys are compared, because
   the file changes on every session.
6. **Log.** Every status, trust, block, forced launch and exit is appended as JSON lines to
   `~/.local/state/preflight/log.jsonl`.

Paths can be overridden with `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `PREFLIGHT_TRUST_FILE`,
`PREFLIGHT_LOG_FILE`, and `PREFLIGHT_TEMP_ROOTS` (a path list; empty means none). Set `NO_COLOR` to
turn colors off.

## What the agents already do (and what preflight adds)

The agents do have folder trust. preflight is meant to complement it, not replace it. As of October 2026,
from public docs, advisories and issues:

- **Claude Code** asks "Do you trust the files in this folder?" the first time an interactive session
  starts in a folder. The trust is keyed on the folder (git root or start dir) and stored in
  `~/.claude.json`. Project `.claude/settings.json` permissions apply only after trust. The dialog is an
  interactive-session feature: non-interactive `claude -p` / SDK runs don't show it. See the
  [security docs](https://code.claude.com/docs/en/security) and advisory
  [GHSA-ph6w-f82w-28w6](https://github.com/anthropics/claude-code/security/advisories/GHSA-ph6w-f82w-28w6).
- **Codex** records `trust_level = "trusted" | "untrusted"` per project in `~/.codex/config.toml`.
  Untrusted projects don't load project-level `.codex` config, hooks or rules. The 0.150.0 release
  notes say untrusted projects no longer contribute `AGENTS.md`, but
  [openai/codex#41499](https://github.com/openai/codex/issues/41499) reports it still being included
  in 0.150.1. **We have not reproduced either behavior.** Check your version.

What preflight adds on top:

| | built-in folder trust | preflight |
|---|---|---|
| Unit of trust | a folder, once | **each file's exact content (SHA-256)**: any edit re-blocks |
| Parent directories | depends on agent/version | always walks up to `$HOME`, past the git root |
| Provenance | none | `~/Downloads`, temp dirs, quarantine / WhereFroms / origin xattrs, Zone.Identifier |
| Config changes during a session | not reported | before/after diff of agent configs, rc files, ssh, git, npm |
| One view of the setup | spread across several files | one panel: files, MCP servers, permissions, sandbox, secrets |
| Non-interactive runs | dialog not shown | same check, exit 3 if blocked |
| Cross-agent | per agent | Codex, Claude Code, Gemini CLI (plus Cursor/Copilot/Windsurf/Cline files) |

## Limitations (please read)

- **It only protects launches that go through it.** Running the agent binary directly, from an IDE
  extension, or from a script bypasses preflight. `init-shell` aliases cover interactive shells only.
- **It is a pre-launch check, not a sandbox.** It doesn't see files the agent opens later, web pages,
  issue text, tool output, or MCP server responses, which are all common prompt-injection vectors. Keep
  the agent's own sandbox and approval prompts on.
- **Trusting is a human decision.** If you trust a malicious file, preflight will GO. Heuristics are
  pattern matches, and they will produce both false positives and false negatives.
- **TOCTOU.** A file could change between the check and the moment the agent reads it.
- **Coverage is a list.** New agents, file names or config schemas need updates. The settings and MCP
  parsing follows each agent's documented format on a best-effort basis and may miss keys.
- **Provenance is best-effort.** `~/Downloads` and temp checks are path-based. The xattr check was tested
  on Linux (`user.xdg.origin.url`) and on macOS with a file saved from Chrome over HTTPS
  (quarantine and binary-plist WhereFroms). Windows Zone.Identifier remains unverified.
  `git clone` doesn't set these marks at all.
- **The secrets list is by name.** It doesn't scan file contents, so it's a reminder, not a DLP tool.
- **Real setup coverage is limited.** On macOS, `status` was checked in a real project with
  `~/.claude.json`, `~/.claude/settings.json`, and `~/.codex/config.toml`: Codex MCP entries and
  project trust, and Claude permission rules, hooks, and folder trust were read successfully.
  Version probes were exercised, but actual agent sessions and their trust enforcement were
  not tested. No real `~/.gemini/settings.json` was present; Gemini uses synthetic fixtures.
  Unknown config keys, profiles, and precedence remain best-effort.
- **Output is private by default.** Redaction is heuristic: paths, project names, URLs, and
  unrecognized secrets can appear. Never share real-setup screenshots or logs; use the demo sandbox.

## Demo

[Download the 22-second terminal recording](demo/demo.cast) and play it locally with
`asciinema play demo/demo.cast`. It is recorded from `demo/demo.sh` with only fake
configs and the stub agent; no recording is uploaded to an external service.

```sh
cargo build --release
./demo/demo.sh             # status BLOCKED -> run refused -> trust -> GO -> run -> edit -> CHANGED
./demo/screenshots.sh      # regenerates demo/*.png (needs python3 and Chrome/Chromium)
python3 demo/record.py     # regenerates demo/demo.cast (no additional recording tool needed)
```

The demo builds a fake `$HOME` under `demo/sandbox/` with a "downloaded" repo whose `AGENTS.md`
hides a comment telling the agent to run `echo PWNED > /tmp/preflight-canary`. That is a harmless
canary. preflight only displays it, and the script checks at the end that the canary file was never
created. The `codex` used in the demo is a stub shell script that just prints a line.

## Development

```sh
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Exit codes: `0` GO, `3` BLOCKED, `2` error. `run` returns the agent's own exit code.

## Release preparation

CI builds, tests, and lints on Ubuntu and macOS. Windows has a build-only job whose
failure is allowed. The tag-triggered workflow packages macOS arm64, macOS x86_64,
and Linux x86_64 (glibc) binaries with SHA-256 checksums as workflow artifacts.
It does not create GitHub Releases or publish packages. Binaries are not signed or
notarized. Tags, releases, and public visibility require separate approval.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
