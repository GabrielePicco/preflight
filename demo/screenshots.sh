#!/usr/bin/env bash
# Regenerates demo/status-blocked.png and demo/status-go.png (needs python3 + google-chrome/chromium).
set -euo pipefail
cd "$(dirname "$0")"
DEMO="$PWD"
BIN="$DEMO/../target/release/preflight"
SETUP_ONLY=1 ./demo.sh
export HOME="$DEMO/sandbox/home" XDG_CONFIG_HOME="$DEMO/sandbox/home/.config" XDG_STATE_HOME="$DEMO/sandbox/home/.local/state"
export PREFLIGHT_TEMP_ROOTS="" PATH="$DEMO/sandbox/bin:$PATH"
CHROME="$(command -v google-chrome || command -v chromium || command -v chromium-browser)"
cd "$HOME/Downloads/cool-repo"

shot() { # name, height, command...
  local name=$1 h=$2; shift 2
  { printf '\033[1;36m~/Downloads/cool-repo $\033[0m %s\n' "preflight ${*:4}"; "$@" || true; } \
    | python3 "$DEMO/ansi2html.py" > "$DEMO/sandbox/$name.html"
  "$CHROME" --headless=new --no-sandbox --disable-gpu --hide-scrollbars --force-device-scale-factor=2 \
    --window-size=1000,"$h" --screenshot="$DEMO/$name.png" "file://$DEMO/sandbox/$name.html" 2>/dev/null
}
shot status-blocked 1120 "$BIN" --color always status --agent codex
"$BIN" trust >/dev/null
shot status-go 700 "$BIN" --color always status --agent codex
echo "wrote $DEMO/status-blocked.png $DEMO/status-go.png"
