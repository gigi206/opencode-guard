#!/usr/bin/env bash
# Full bench (34 cases) on the CUDA server: bash run_local_gpu.sh <alias> <gguf> <ngl> <out.jsonl> [ub]
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
LABEL="$1"; GGUF="$2"; NGL="$3"; OUT="$4"; UB="${5:-4096}"
BIN="${LLAMA_SERVER_CUDA:-$HOME/llama.cpp/build-cuda/bin/llama-server}"
PY="${PYTHON:-python3}"
PORT=8099
LOG="$DIR/server-gpu-$(basename "$OUT" .jsonl).log"
mkdir -p "$(dirname "$OUT")"

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

echo "VRAM after loading: $(nvidia-smi --query-gpu=memory.used --format=csv,noheader)"
"$PY" "$DIR/run_local.py" --alias "$LABEL" --port "$PORT" --out "$OUT"
status=$?
kill "$pid" 2>/dev/null
wait "$pid" 2>/dev/null
exit $status
