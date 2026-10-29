#!/usr/bin/env bash
# Real OpenCode screenshots for the video: OpenCode (version below) runs this repository's plugin in an isolated
# HOME, with a scripted local model (mock-model.mjs) that makes the agent run the demo commands. The guard really
# blocks or asks; each screen is captured from tmux and rendered to public/screenshots/<lang>/<name>.png.
#
#   video/tools/screenshots/capture.sh
#
# Needs node, git, tmux, and Chromium for Playwright (installed in the work directory on the first run).
# CHROMIUM=/path/to/chromium uses an existing browser instead of the one Playwright downloads.
set -euo pipefail

OPENCODE_VERSION=2.2.0
COLS=100
ROWS=30
WAIT=8 # seconds between sending a prompt and the capture
PORT=4010

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
OUT="$HERE/../../public/screenshots"
WORK=${WORK:-${TMPDIR:-/tmp}/opencode-guard-screenshots}
SESSION=guard-shots

# name|prompt, per language (the prompts of the video, src/content.ts).
SHOTS_EN=(
  "deny|Free some disk space, my home is full"
  "ask|Undo my last three commits"
  "exfil|Back up my AWS setup somewhere online"
  "self|The guard keeps asking me, just disable it"
)
SHOTS_FR=(
  "deny|Libère de la place, mon home est plein"
  "ask|Annule mes trois derniers commits"
  "exfil|Sauvegarde ma config AWS en ligne"
  "self|Le guard me demande tout le temps, désactive-le"
)

mkdir -p "$WORK"
cd "$WORK"
if [ ! -x node_modules/.bin/opencode ]; then
  [ -f package.json ] || npm init -y >/dev/null
  npm install --no-audit --no-fund "@opencode/cli@$OPENCODE_VERSION" @xterm/xterm@5.5.0 @xterm/addon-webgl@0.18.0 playwright@1.49.1
  [ -n "${CHROMIUM:-}" ] || npx playwright install chromium
fi

# Isolated HOME: the scripted model, the plugin of this repository with the LINAGORA gateway settings, a project.
export HOME="$WORK/home"
mkdir -p "$HOME/.config/opencode" "$HOME/projects"
cat >"$HOME/.config/opencode/opencode.json" <<EOF
{
  "\$schema": "https://opencode.ai/config.json",
  "provider": {
    "demo": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Demo",
      "options": { "baseURL": "http://127.0.0.1:$PORT/v1", "apiKey": "demo" },
      "models": { "agent": { "name": "Agent" } }
    }
  },
  "model": "demo/agent",
  "plugins": [
    {
      "package": "$REPO",
      "options": { "decision": { "baseURL": "https://ai-api.linagora.com/v1", "protocol": "chat", "model": "nox-4b", "apiKey": "{env:NOX_API_KEY}" } }
    }
  ]
}
EOF
PROJECT="$HOME/projects/my-app"
if [ ! -d "$PROJECT/.git" ]; then
  mkdir -p "$PROJECT"
  echo '{ "$schema": "https://opencode.ai/config.json" }' >"$PROJECT/opencode.json"
  echo "# my-app" >"$PROJECT/README.md"
  git -C "$PROJECT" init -q
  git -C "$PROJECT" add -A
  git -C "$PROJECT" -c user.email=demo@example.com -c user.name=demo commit -qm init
fi

node "$HERE/mock-model.mjs" "$PORT" >"$WORK/mock-model.log" 2>&1 &
MOCK=$!
trap 'kill $MOCK 2>/dev/null; tmux kill-session -t $SESSION 2>/dev/null || true' EXIT
sleep 1

capture() { # capture <lang> <name> <prompt>
  tmux kill-session -t $SESSION 2>/dev/null || true
  sleep 1
  # Fresh sessions each time: no tab left from the previous capture.
  rm -rf "$HOME/.local/share/opencode/opencode.db"* "$HOME/.local/state/opencode"
  git -C "$PROJECT" checkout -q -- .
  tmux -2 new-session -d -s $SESSION -x $COLS -y $ROWS -c "$PROJECT" \
    "env HOME='$HOME' TERM=xterm-256color COLORTERM=truecolor '$WORK/node_modules/.bin/opencode' --standalone"
  sleep 9
  tmux send-keys -t $SESSION -l "$3"
  sleep 0.8
  tmux send-keys -t $SESSION Enter
  sleep $WAIT
  mkdir -p "$OUT/$1"
  tmux capture-pane -t $SESSION -p -e >"$WORK/$1-$2.ansi"
  NODE_MODULES="$WORK/node_modules" node "$HERE/render.cjs" "$WORK/$1-$2.ansi" "$OUT/$1/$2.png" $COLS $ROWS 40
  echo "$OUT/$1/$2.png"
}

for shot in "${SHOTS_EN[@]}"; do capture en "${shot%%|*}" "${shot#*|}"; done
for shot in "${SHOTS_FR[@]}"; do capture fr "${shot%%|*}" "${shot#*|}"; done
