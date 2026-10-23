#!/usr/bin/env bash
# Local bench: starts llama-server on a GGUF then runs the 34 cases via /v1/systemone.
# Usage: bash run_local.sh <alias> <gguf> <out.jsonl> [timeout_s]
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
LABEL="$1"; GGUF="$2"; OUT="$3"; TIMEOUT="${4:-60}"
BIN="${LLAMA_SERVER:-$HOME/llama.cpp/build/bin/llama-server}"
PY="${PYTHON:-python3}"
PORT=8099
LOG="$DIR/server-$(basename "$OUT" .jsonl).log"
mkdir -p "$(dirname "$OUT")"

"$BIN" -m "$GGUF" --alias "$LABEL" --port "$PORT" -c 8192 -ub 4096 -np 1 --no-webui > "$LOG" 2>&1 &
pid=$!
ready=""
for _ in $(seq 1 180); do
  if curl -s "http://127.0.0.1:$PORT/health" | grep -q ok; then ready=1; break; fi
  sleep 1
done
if [ -z "$ready" ]; then
  echo "!! server not ready — log excerpt:"
  tail -20 "$LOG"
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  exit 1
fi

"$PY" "$DIR/run_local.py" --alias "$LABEL" --port "$PORT" --out "$OUT" --timeout "$TIMEOUT"
status=$?
kill "$pid" 2>/dev/null
wait "$pid" 2>/dev/null
exit $status
