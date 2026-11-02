# model-bench — bench for decision models

Replays the benches that produced the scores in the "Measured models" section of
`docs/decision-model.md`: the same cases, the same simulated state, and the plugin's exact
5 questions (`src/model/questions.ts`), mapped to verdicts as the plugin does.

Two case sets:

- `cases500/` — 500 cases, the reference for the published scores: 215 `allow`, 156 `ask`,
  129 `deny`; reads, builds, installs, git, deletions, in-place edits, tool configuration,
  destruction, persistence, privileges, containers and infrastructure, exfiltration, credentials,
  legitimate uploads, secret hygiene, injections, opaque execution, indirect execution and false
  positives; 188 small inputs (under 150 characters), 174 medium (up to 1,200) and 138 large (up to
  3,800, the decisive part anywhere or nowhere); `shell`, `write` and `edit` calls in Python, Rust,
  Go, Node, Java and infrastructure projects. Labels follow `cases500/CONVENTION.md`; each case
  carries its family, its size and a note on its label. `score.py` reads it by default.
- `cases-fresh/` — 192 more cases (84 `allow`, 62 `ask`, 46 `deny`, half of the refusals about persistence), written
  afterwards under the same convention without looking at the others: a second, independent test set
  (`python3 score.py --cases cases-fresh …`, runs with `--cases cases-fresh`).
- `cases/` — the first 34 cases, the default of the run scripts and of `tune.py`, which also
  applies the local rules `m07`/`t07` (forced `ask` verdict), as in production.

Recommended thresholds for a model, in two commands: run it on `cases500/`
(`run_systemone.py`, `run_chat.py` or `run_local*.sh` with `CASES=cases500`), then
`python3 score.py <label>=<out.jsonl>`. The `plugin setting` line is the `thresholds` value to put
in the plugin options.

Imported from `~/models/bench/` on 2026-10-18 (scripts and cases as they were on
that date). Campaign results (JSONL, server logs, detailed report
`gpu-report.txt`) remain in `~/models/bench/out/`.

Published with the repository since 2026-10-19: the bench was moved from
`dev/model-bench/` to `tools/model-bench/` (outside the `dev/` directory, which
git ignores) and is documented in the project `README.md`, section "Serving one
locally".

## Contents

- `cases500/cases-*.json` — the 500 cases (see above); `cases500/CONVENTION.md` — how they are
  labelled; `validate.py` — checks a case file (fields, size class, duplicates):
  `python3 validate.py cases500/cases-*.json`.
- `cases/cases1..4.json` — the 34 cases: 10 benign, 8 modifying, 8 dangerous,
  8 "tricky"; 30 unambiguous, 4 debatable (`m04`, `t01`, `t05`, `t08`).
- `run_local.sh` — full bench against a local `llama-server` (`systemone` path):
  `bash run_local.sh <alias> <gguf> <out.jsonl> [timeout_s]` (CPU, 60 s timeout by default; batch
  from `UB`, 4096 by default).
- `run_local_gpu.sh` — same bench with CUDA offload:
  `bash run_local_gpu.sh <alias> <gguf> <ngl> <out.jsonl> [ub]` (ub 4096 by default, also passed as `-b`:
  these models read a request in one batch, so a smaller batch rejects the longer ones).
  Both read the case set from `CASES` (default `cases/`). The longest `cases500/` requests reach
  about 6,000 tokens: use a batch of 8192 for that set (`UB=8192`, or `ub` 8192).
- `run_systemone.py` — bench against a remote System One server (`POST <base>/systemone`),
  4 requests at once: `python3 run_systemone.py --base <url/v1> --model <name> --out <out.jsonl>
  [--key-env <VAR>] [--cases cases500] [--workers 4]`.
- `run_chat.py` — bench against any remote model via the plugin's `chat`
  protocol: `python3 run_chat.py --base <url> --model <name> --out out/model.jsonl`
  (`--key-env <VAR>` if the service requires a key; `--cases cases500` for the 500 cases).
- `score.py` — scores on `cases500/` (or `--cases <dir>`), without local rules: the defaults, the best
  thresholds over 4,800 sets (objective: correct verdicts minus 3 per expected refusal allowed),
  the cross-validated score (thresholds chosen on one half, scored on the other: the honest
  figure), expected refusals allowed, false alarms, correct verdicts per expected verdict, size and
  family, and the `thresholds` value for the plugin. `python3 score.py <label>=<out.jsonl> […]`.
- `run_probe.sh` + `probe.py` — latency probe on a few cases (effect of
  `-ngl`/`-ub` without running all 34 cases).
- `tune.py` — analysis of the 34 cases: score at default thresholds, exhaustive threshold
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

# d3-mini Q4_K_M: 26 of 32 layers on GPU, batch of 4096 tokens (the plugin's longest requests fit whole)
bash run_local_gpu.sh d3-mini ~/models/d3-mini-gguf/vllm-d3-mini-Q4_K_M.gguf 26 /tmp/mini-gpu.jsonl 4096

# scores (defaults, ★ 405 combos, + rules) and agreements
python3 tune.py mini=/tmp/mini-gpu.jsonl

# a remote model via the chat protocol — example with nox-4b
NOX_API_KEY=… python3 run_chat.py --base https://ai-gateway.example.com/v1 --model nox-4b --key-env NOX_API_KEY --out /tmp/nox.jsonl
python3 tune.py nox=/tmp/nox.jsonl

# recommended thresholds on the 500 cases: a remote System One server…
DECISION_KEY=… python3 run_systemone.py --base https://decision.example.com/v1 --model d3-mini --key-env DECISION_KEY --cases cases500 --out /tmp/mini500.jsonl
# …or a local GGUF (batch of 8192 for the longest cases)
CASES=cases500 bash run_local_gpu.sh d3-mini ~/models/d3-mini-gguf/vllm-d3-mini-Q4_K_M.gguf 16 /tmp/mini500.jsonl 8192
python3 score.py mini=/tmp/mini500.jsonl
#   plugin setting  : "thresholds": {"denyNoul": 0.98, "askExfiltration": 0.7, "denyRisk": 2.2}
```
