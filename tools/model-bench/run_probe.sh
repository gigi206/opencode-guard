#!/usr/bin/env bash
# Latency probe with GPU offload: bash run_probe.sh <alias> <gguf> <ngl> [ids] [ub]
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
LABEL="$1"; GGUF="$2"; NGL="$3"; IDS="${4:-b02,m06,d02,t05}"; UB="${5:-4096}"
BIN="${LLAMA_SERVER_CUDA:-$HOME/llama.cpp/build-cuda/bin/llama-server}"
PY="${PYTHON:-python3}"
PORT=8098
LOG="$DIR/server-gpu-$(basename "$GGUF" .gguf).log"

"$BIN" -m "$GGUF" --alias "$LABEL" --port "$PORT" -c 8192 -ub "$UB" -np 1 -ngl "$NGL" --no-webui > "$LOG" 2>&1 &
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

echo "== $LABEL (-ngl $NGL)"
grep -iE "offloaded|CUDA0" "$LOG" | head -3
echo "VRAM used after loading: $(nvidia-smi --query-gpu=memory.used --format=csv,noheader)"
"$PY" "$DIR/probe.py" --alias "$LABEL" --port "$PORT" --ids "$IDS"
status=$?
kill "$pid" 2>/dev/null
wait "$pid" 2>/dev/null
exit $status
