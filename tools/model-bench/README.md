# model-bench — bench for decision models

Replays the benches that produced the scores in the "Measured models" section of
the README: the same 34 cases, the same simulated state, and the plugin's exact
5 questions (`src/model/questions.ts`), with the same decision thresholds.
`tune.py` additionally applies the local rules `m07`/`t07` (forced `ask`
verdict), as in production.

Imported from `~/models/bench/` on 2026-10-18 (scripts and cases as they were on
that date). Campaign results (JSONL, server logs, detailed report
`gpu-report.txt`) remain in `~/models/bench/out/`.

Published with the repository since 2026-10-19: the bench was moved from
`dev/model-bench/` to `tools/model-bench/` (outside the `dev/` directory, which
git ignores) and is documented in the project `README.md`, section "Serving one
locally".

## Contents

- `cases/cases1..4.json` — the 34 cases: 10 benign, 8 modifying, 8 dangerous,
  8 "tricky"; 30 unambiguous, 4 debatable (`m04`, `t01`, `t05`, `t08`).
- `run_local.sh` — full bench against a local `llama-server` (`systemone` path):
  `bash run_local.sh <alias> <gguf> <out.jsonl> [timeout_s]` (CPU, 60 s timeout by default).
- `run_local_gpu.sh` — same bench with CUDA offload:
  `bash run_local_gpu.sh <alias> <gguf> <ngl> <out.jsonl> [ub]` (ub 4096 by default).
- `run_chat.py` — bench against any remote model via the plugin's `chat`
  protocol: `python3 run_chat.py --base <url> --model <name> --out out/model.jsonl`
  (`--key-env <VAR>` if the service requires a key).
- `run_probe.sh` + `probe.py` — latency probe on a few cases (effect of
  `-ngl`/`-ub` without running all 34 cases).
- `tune.py` — main analysis: score at default thresholds, exhaustive threshold
  search (405 combos, constraint: no `allow` on the 10 `deny` cases), scores
  with rules, expected signals, latencies, agreement between models.
  `python3 tune.py <label>=<out.jsonl> [<label>=<out.jsonl> …]`.
- `compare.py` — case-by-case table and summary for every loaded model:
  `python3 compare.py <label>=<out.jsonl> [<label>=<out.jsonl> …]`.
- `gguf-info.py` — GGUF metadata useful for offload (layers, estimated KV
  cache, weights per layer): `python3 gguf-info.py model.gguf`.

## Prerequisites

- `python3` only (standard library), no venv.
- `llama-server` with Decision 3.0 / `systemone` support (llama.cpp build).
  Defaults to `~/llama.cpp/build/bin/llama-server` (CPU) and
  `~/llama.cpp/build-cuda/bin/llama-server` (CUDA), overridable with
  `LLAMA_SERVER` / `LLAMA_SERVER_CUDA`.
- the served GGUF files: `ggml-org/vllm-d3-<model>-GGUF` repositories (see the
  project README, "Where to get the models").
- for a model served over `chat`: network access; if a key is required, the name
  of the environment variable containing it (`--key-env`) — nothing is stored in
  the bench.
- one bench at a time (the scripts use ports 8098/8099 and stop their server on
  exit; logs are written here, `server-*.log`).

## Examples

```bash
# d3-edge Q8_0: full CPU bench (~1.4 s/case)
bash run_local.sh d3-edge ~/models/d3-edge-gguf/vllm-d3-edge-Q8_0.gguf /tmp/edge.jsonl

# d3-mini Q4_K_M: whole model on GPU (32 layers, ub 512)
bash run_local_gpu.sh d3-mini ~/models/d3-mini-gguf/vllm-d3-mini-Q4_K_M.gguf 32 /tmp/mini-gpu.jsonl 512

# scores (defaults, ★ 405 combos, + rules) and agreements
python3 tune.py mini=/tmp/mini-gpu.jsonl

# a remote model via the chat protocol — example with nox-4b
NOX_API_KEY=… python3 run_chat.py --base https://ai-gateway.example.com/v1 --model nox-4b --key-env NOX_API_KEY --out /tmp/nox.jsonl
python3 tune.py nox=/tmp/nox.jsonl
```
