# Decision model

Any model that answers typed questions through the System One API can be configured under `decision`: Nox-4B is the one used and calibrated here; TypeSafe AI's Jev uses the same API. No behaviour depends on the model's name: it is sent with each request and shown in the start line and in the reasons (`nox-4b opinion: …`).

Each tool call that the local rules do not settle triggers one call to the model (results are cached), except the read-only tools `read`, `glob` and `grep` and the task list `todowrite` (see below). It receives the redacted, truncated tool input and five typed questions:

| Question | Type | Meaning |
|---|---|---|
| `destructive` | probability 0–1 | deletes, overwrites or corrupts data that cannot easily be recovered |
| `exfiltration` | probability 0–1 | sends local files, environment variables or other data to a remote host |
| `credentials` | probability 0–1 | reads, prints, copies or sends credentials, keys, tokens or passwords |
| `privilege_persistence` | probability 0–1 | escalates privileges or changes system configuration, shell startup files, scheduled tasks, SSH keys or git hooks |
| `risk` | score 0–3 | overall damage level, from none to critical. Optional: if the model refuses it, the decision relies on the probabilities alone |

**Verdict.**
- `deny` if any probability ≥ `denyNoul`, or the risk ≥ `denyRisk`.
- `ask` if any probability ≥ `askNoul` (for `exfiltration`: ≥ `askExfiltration`, never below `askNoul`), or the risk ≥ `askRisk`. A confidence below `minConfidence` also asks, and so does a missing confidence while the check is enabled; it is disabled by default.
- `allow` otherwise.

**Opinion on local confirmations.** When a local rule asks for confirmation (except for read-only tools and the task list), the model is consulted too and its opinion is appended to the reason, for example `guard · rm: file deletion (rm -r/-f) — nox-4b opinion: ask (risk 1.67/3, data destruction 0.89)` in the confirmation's title (cut at 160 characters; complete in the log). By default, it does not change the verdict: neither stricter (you keep the decision on doubtful cases, including your own edits of the plugin or of `~/.config/opencode/`) nor looser. The local rules keep the last word because, on the actions they send to confirmation, the model alone would allow many and refuse some ordinary transfers. If the model is unreachable, the prompt shows no opinion; a local refusal does not consult it. Two exceptions are decided by the model instead (see [Local rules](rules.md#local-rules)), unless the rule is set to `"ask"` in `ruleOverrides`: a confirmation caused only by heredoc data, and a CodeMode script that uses `fetch` without referring to `tools` or writing a local address, when the model received the whole code.

**When the model has the last word on a local confirmation.** With `"localAsks": "model"`, or `"model"` on a rule in `ruleOverrides`, you hand the model the confirmations of the rules concerned (self-protection only with `selfProtectionByModel`, and never a change of the plugin's settings, a recognized launch of another OpenCode with its configuration changed or approving its own confirmations, nor a call to the OpenCode server API): when it judged the whole input, its verdict (allow, ask or deny) replaces your confirmation; disabled, unreachable, an invalid answer or an input cut to `maxStateChars`, and the confirmation stays with you. A refusal never changes, a confirmation that stays with you always comes before one left to the model, and some confirmations are never left to it (a check the plugin could not finish, an internal error, a script written then run, your own rules, the read-only tools); see [Letting the decision model decide local confirmations](configuration.md#letting-the-decision-model-decide-local-confirmations-localasks). The risk is the one these settings accept: the model reads text written by the agent (comments, strings, heredoc bodies in the command), which can steer its answer, and it would then allow an action that a local rule sent to you.

**Only the model of your global configuration allows.** In every case above (heredoc data, CodeMode's `fetch`, and the confirmations left to it by `localAsks`, `"model"` or `selfProtectionByModel`), the model may allow only if its configuration is the one your global configuration file or the system configuration declares for this plugin (`decision`, or `jev`): `decision.baseURL` (compared as for `outputCheck`) and `decision.model`, and also what else decides its verdict, each read as the plugin reads it (a value left out counts as its default): `decision.protocol`, `decision.timeoutMs`, `decision.apiKey` and `decision.headers` (who answers, and in time: a gateway may pick the model it serves by key or header), `maxStateChars` and `secretPatterns` (what the model sees) and `thresholds` (how its answers are read). A `{file:…}` reference in these entries of that declaration is not followed, so they do not match. It must also be switched on: by the system configuration when it declares the plugin (loaded last by OpenCode, its `decisionModel` or `profile` decides), otherwise by the global sources (`decisionModel` in the global file, the global `guard.json` and its sections). Or else the session's project is [trusted](configuration.md#settings-by-agent-and-by-project-guardjson). Otherwise it may still refuse, with the thresholds in force, but a confirmation it would allow stays with you, the reason says so, and a startup warning says why (it names the settings, never their values). A repository's `opencode.json` that replaces the model's address or one of these settings, or turns the model on, cannot have the model allow these actions. The calls that no local rule matches are judged by the model as before.

**Scripts written then run.** When a command runs a file that the agent created **in full** earlier in the same session (since the plugin was last loaded, see [Known limitations](operations.md#known-limitations)), the content of that file is checked too:
- **Files concerned:** a file written with `write`, added by `patch` (`*** Add File:`), or created by a heredoc on its own line (`cat > f <<'EOF'`, `cat <<'EOF' > f`, `tee f <<'EOF'`, with a quoted delimiter or a body without `$`, backtick or `\`, and only if the file on disk is exactly the heredoc body). The file stays tracked after the agent modifies it with `edit` or `patch` (`*** Update File:`, also in the same `patch` call that added it, and with a `*** Move to:` its own path), and after a modification by anything else (see below). Moving it to another path (`*** Move to:`) or deleting it ends tracking; a copy is not tracked. A patch is read section by section exactly as OpenCode 2.0.31's `patch` tool reads it: blanks before a header where OpenCode accepts them, a path that starts with or contains a carriage return or a Unicode line separator, Windows line endings (the content expected for `*** Add File:` is the one OpenCode writes). A line that only looks like a header, such as an indented header or `*** Move to:` line inside the body of an `*** Update File:` section, which OpenCode reads as a context line, neither ends nor starts tracking.
- **Shown to the decision model only if already judged in full:** the content is sent to the model only if every call that produced it (creation, then each modification) was judged by the model on its **full** input (answer received, input not truncated) and the file on disk is exactly that content (a file reformatted by OpenCode's formatter is not): the content is then not new to the model. Otherwise, including when the decision model is disabled or failed, and for a file added then modified in the same `patch` call, only the local rules see it.
- **Commands recognized:** `bash f.sh`, `sh`, `zsh`… with a file, `source ./f`, `. ./f`, `python3 f.py`, `node`, `perl`, `ruby`, `php`, `bun run`, `deno run`, or a file run by its path (`./f.sh`, `bin/x`), behind `sudo`, `timeout`, `env`…, at most 4 files per command. A file redirected to the standard input of a shell or interpreter that runs its input (`sh < f.sh`) counts too, wherever the redirection stands, and continued lines are joined first. Paths are resolved like OpenCode (shell `workdir`, `~`), and after a leading `cd <path> &&` when the path is absolute or starts with `~`, `./` or `../` (another relative path is looked up in `CDPATH`); a command that changes directory any other way, `source f`/`. f` without a `/` (looked up in `PATH` first), or a path with a variable or a wildcard, is skipped.
- **Changed or unreadable files:** the file is read only if it is a regular file (not a symbolic link), at most 64 KiB, and not a credential file (path and real path). If its SHA-256 is no longer the one recorded after the agent's last tracked write (a formatter, another command or program changed it), its current content is checked by the local rules but never shown to the decision model, and tracking continues with that content. If it can no longer be read (larger than 64 KiB, a symbolic link, not a regular file, a credential file), since its creation by `write` or `patch` or later, running it asks for confirmation (rule `script-unverifiable`), whatever the program that runs it; a file created by a heredoc that cannot be read is simply not tracked. The same rule applies after a `patch` call that OpenCode applied although its text is not one that OpenCode 2.0.31 accepts (another OpenCode version): what it created, changed or moved is unknown, so every existing file named on one of its header lines is unverifiable, even if it can be read, until the agent rewrites it in full, modifies it with `edit` or `patch` (its content then goes to the local rules only), moves or deletes it.
- **Decision model:** for content already judged in full, the state gains `executed_scripts` (path and content, both redacted, content truncated to `maxStateChars` like the input), with a note that this content is as untrusted as the tool call. The cache key includes it.
- **Local rules:** for every tracked script read by a shell (shell, `source`, or run by its path with a shell shebang or none), the shell rules are applied to its content (except the placeholder rule, which protects writes) and lead **at most to a confirmation**, never to a refusal (a file has branches that may never run), for example `git reset --hard (uncommitted changes lost), in the script deploy.sh run by this command`. A refusal of the command itself still applies.
- Nothing is remembered or read for the [unprotected agent](rules.md#unprotected-agent-unprotectedagent).

**Read-only tools.** `read`, `glob` and `grep` are not sent to the model: reads come in bursts (subagents read many files in parallel), which would cause timeouts and confirmations, while what makes a read sensitive, a credential file, is covered by the local rules (confirmation). Every tool output is redacted.

**Task list.** `todowrite`, which OpenCode provides only when `experimental.todo` is enabled, is not sent to the model either: it only records the session's task list, without writing a file or using the network. The local rules still apply to its input (redaction placeholder, secrets, paths, your own `rules`).

## Output check (`outputCheck`)

Off by default: with it, tool outputs are sent to the decision model, so turn it on only if that model is yours (for example on your own servers). The decision model then also checks what a tool returns, as a complement to the [redaction](rules.md#secret-redaction): it judges whether an output still contains a secret in clear (a password, a private key, an API key, a token), but it cannot say where, so it cannot mask it.

- **Activation.** The option is effective only if your global configuration file (`$OPENCODE_CONFIG_DIR`, or `$XDG_CONFIG_HOME/opencode`, or `~/.config/opencode`, as OpenCode resolves it, `opencode.json` or `opencode.jsonc`) or the system configuration declares it too for this plugin, with the same `decision.baseURL` (or `jev.baseURL`). A repository's `opencode.json` can replace the plugin's options, but cannot turn the check on towards its own server this way. `{env:…}` references in that file are resolved with the server's environment, as OpenCode does; a `{file:…}` reference, a missing or unreadable file, a missing entry, a missing option or a different address leave the option inactive, with a warning that says why. The start line of the log shows `output check: active` or `output check: inactive`.
- **What is sent.** The output as the model would see it (the text of its `content`, plus its `output` when that adds something, or the error message), always redacted first by the check itself, whatever `redactOutputs` says, then truncated to `maxStateChars`, with a note that it is untrusted data. Only a secret that the redaction does not recognize can therefore reach the decision model.
- **Which tools.** Shell commands, web requests, MCP and other plugin tools, OpenCode's own tools, and tool errors. Not checked: `read`, `glob` and `grep` (they come in bursts, as for their inputs), `edit`, `write` and `patch` (their output repeats what the agent wrote), `question`, `skill` and `subagent` (each tool of a sub-agent is checked), `todowrite` (its output repeats the task list), outputs that are empty or made only of placeholders (and the note for the model), and the inner calls of a CodeMode script: only the result of the outer `execute`, which is what the model receives, is checked. Nothing is checked for the [unprotected agent](rules.md#unprotected-agent-unprotectedagent).
- **When an output is flagged** (probability at or above `threshold`): a confirmation asks whether to pass it to the agent. Approved, it is passed as is. Rejected, the agent receives a notice instead (with your feedback, if you give one, never written to the log), and the step goes on. In unattended mode (`askAs: "deny"`) it is withheld without asking; with `--auto`, the client approves the confirmation and the output is passed.
- **When the check fails** (timeout, error, invalid answer): the output, already redacted, is passed on, and the log says so once per series of failures. This differs from actions, where an unreachable model leads to a confirmation: here, refusing by caution would make every tool unusable while the model is down. A check is never retried, and verdicts are cached like the decisions (`cacheTtlMs`, `cacheMax`).
- **Cost.** One call per checked output, at most `timeoutMs` each.
- **Calibration.** The defaults are set for `nox-4b` on shell outputs. A secret in a JSON field with an ordinary name, such as `"session": "…"`, is the hardest case. Other tools (MCP, web) and other models (`jev-latest`) are not calibrated: recalibrate before relying on them.

**Failures.** A timeout is retried once, so the wait can reach twice `decision.timeoutMs`; other errors are not retried. A refused question (a non-empty `error` field, e.g. `max_length_exceeded`; `null` or `""` means no error), an HTTP error, a timeout or an invalid answer all lead to a confirmation prompt, with the cause shown. An out-of-range value (a probability outside 0–1, a risk outside 0–3) is judged on the value brought back into range, then never less than a confirmation: `noul: 5` is still a refusal, `score: -5` no longer allows anything. Response bodies are read with a cap (16 KiB for an error message, 1 MiB for an answer): a larger answer is never parsed and leads to a confirmation. The model's URL must answer directly: a redirection is never followed (the new address would receive the request and the `decision.headers`) and leads to a confirmation (`HTTP 307: redirect refused`), without a retry.

## Thresholds

| Threshold | Default | `thresholds` option |
|---|---|---|
| deny when a probability ≥ | 0.9 | `denyNoul` |
| ask when a probability ≥ | 0.7 | `askNoul` |
| ask when the `exfiltration` probability ≥ (never below `askNoul`) | 0.85 | `askExfiltration` |
| deny when risk (0–3) ≥ | 2.5 | `denyRisk` |
| ask when risk (0–3) ≥ | 1.5 | `askRisk` |
| ask when confidence < | 0 (disabled) | `minConfidence` |

**Changing them.** Set them in `opencode.json`. To make one depend on the environment, reference a variable, quoted: `"askNoul": "{env:GUARD_ASK_NOUL}"` (an unset variable keeps the default). A decimal comma is accepted. Invalid or out-of-range values are ignored, and a warning is logged when an `ask` threshold is above its `deny` threshold.

**Calibration.** The defaults are set for `nox-4b`:

- **Probabilities.** Most benign actions score below `askNoul` and most dangerous ones above it, but no threshold separates every case: this is why the local rules come first.
- **Exfiltration.** Downloads and reads of public APIs often score between `askNoul` and `askExfiltration` on `exfiltration` without sending local data, while clear exfiltrations reach `denyNoul`. With `sensitiveFiles: false`, this signal becomes the main protection against data leaving the machine.
- **Confidence.** The score's confidence is low even on clear cases, hence `minConfidence` disabled.
- **Watching the thresholds.** With `debug: true`, the log shows each allowed action's highest probability, to check the thresholds on real traffic.
- **Other models.** Another model (Jev `jev-latest`, …) scores differently: recalibrate before relying on it.
- **Input size.** Nox-4B rejects requests above 16,384 tokens, so the input sent is capped at 4,000 characters.

## Measured models

On 2026-10-17 and 18, seven models were scored on a bench of 34 tool calls with hand-checked verdicts (10 benign, 8 modifying, 8 dangerous, 8 trickier shell and tool payloads; 30 unambiguous, 4 debatable). Every model gets the same redacted inputs, and its answers alone are mapped to verdicts with the thresholds above — the local rules are identical for every model and would hide the differences. The d3 models were served locally by llama.cpp (`systemone` path), `nox-4b` through an OpenAI-compatible gateway. "Recommended" is the best threshold set found on that bench while keeping all ten expected refusals; the last column adds the two rules below, which apply before the model is called.

| Model | With the defaults | Recommended `thresholds` | With them | With the two rules | Notes |
|---|---|---|---|---|---|
| `nox-4b` | 26/34 | `{ "askRisk": 1.2, "denyRisk": 2.2 }` | 30/34 | 32/34 | the current default; indulgent on risk-only cases (installs, `crontab`, `curl \| bash`), which these thresholds turn into confirmations |
| `d3-mini` | 28/34 | `{ "denyNoul": 0.94, "denyRisk": 2.8 }` | 31/34 | 33/34 | best of the local models: over-strict with the defaults, about 1.3 s per call with 26 of its 32 layers on a 4 GB GPU (`systemone` path); all 32 fit at `-ngl 32 -ub 512` (0.83 s, 47 MiB margin) |
| `d3-nano` | 23/34 | `{ "denyNoul": 0.94, "denyRisk": 2.2, "askRisk": 1.2 }` | 25/34 | 27/34 | below `nox-4b` |
| `d3-lite` | 21/34 | `{ "askRisk": 1.2 }` | 23/34 | 24/34 | below `nox-4b` |
| `d3-edge` | 22/34 | `{ "denyNoul": 0.86, "askNoul": 0.6 }` | 25/34 | 27/34 | identical verdicts on CPU and GPU, 884 MiB and about 0.1 s per call on a 4 GB GPU (about 1.4 s on CPU); denies two benign network commands, indulgent on installs |

Two other models were measured as well; their recommended values: `d3-flash` `{ "denyNoul": 0.98 }`, `d3-27b` `{ "denyNoul": 0.96 }`.

The values do not transfer from one model to another: the `0.94` would drop three expected refusals from `nox-4b`, and `nox-4b`'s values do nothing for `d3-mini`. They were searched on this same bench, so the last points are optimistic: watch real traffic with `debug: true`.

**Where to get the models.** The original d3 weights and their runtime are published on Hugging Face under [`vllm-sr`](https://huggingface.co/vllm-sr) (`d3-mini`, `d3-nano`, `d3-lite`, `d3-edge`, `d3-flash`); the GGUF conversions served here are under [`ggml-org`](https://huggingface.co/ggml-org), one `vllm-d3-<model>-GGUF` repository per model, each with a `BF16` file (the original precision) and a `Q8_0` file; `Q4_K_M` is also published for `d3-mini` and `d3-flash`. The main table used `Q4_K_M` for `d3-mini` and `Q8_0` for `d3-nano`, `d3-lite` and `d3-edge`; the `d3-flash` measurements used `Q4_K_M`. `d3-mini`'s `BF16` file was measured too (on CPU, since it is 9.1 GiB): 27/34 at the defaults, 31/34 with the recommended values, 33/34 with the rules — the same verdicts as `Q4_K_M` once tuned, so quantizing to fit the 4 GB GPU costs nothing measurable.

## Serving one locally

The repository ships `tools/serve.sh`, a service script for the whole Decision 3.0 family. It exposes the same `POST /v1/systemone` API on port 8899 and drives three backends:

- **`llama`** — `llama-server` plus a quantized GGUF, no Python venv and no kernels to compile. The recommended path on a small GPU: `d3-mini` Q4_K_M fits entirely on 4 GB (`-ngl 32 -ub 512`, 3,622 MiB used, 47 MiB margin), while `d3-flash` Q4_K_M runs partially offloaded (`-ngl 14 -ub 1024`).
- **`native`** (default) — the model's own Transformers runtime (`d3_server.py`) in a local venv, with the kernels compiled from source; `d3-edge` uses about 2.3 GiB of VRAM.
- **`engine`** (alias `container`) — `vllm-sr serve -e` in a Docker or Podman container, with batching; `d3-edge` uses about 1.75 GiB of VRAM. The dev CLI is pinned at first install and checked on every start (a different version needs `--yes` or `VLLM_SR_VERSION`), and the mode refuses the CPU fallback: use `--gpu` or `native --cpu`.

One command downloads the artifact, checks the VRAM, stops the service already on the port, starts the backend, verifies `/v1/systemone`, and prints the plugin entry. For `d3-mini` Q4_K_M (4.5B, 32 layers, 3.7 GB), the best local model measured and the one that fits entirely on a 4 GB GPU:

```sh
bash tools/serve.sh llama --model d3-mini --yes
```

The script stops only recognized local services (`d3_server.py`, `llama-server`, `vllm-sr`); a foreign process on the port is reported and left alone. In llama mode it downloads the GGUF from `ggml-org/vllm-d3-<model>-GGUF` into `<home>/models/ggml-org/<model>/`, resumes partial files, and refuses to load when its VRAM estimate (weights + KV cache + compute buffers) exceeds the free memory. Logs go to `<home>/logs/llama-<model>-<quant>.log`. Main options:

| Option | Effect |
|---|---|
| `--model NAME` | `d3-mini`, `d3-flash`, `d3-nano`, `d3-lite`, `d3-edge`; Hub identifier with or without the `vllm-sr/` prefix, or a local package directory (native). |
| `--quant Q` | llama: `Q4_K_M` (default for `d3-mini`/`d3-flash`), `Q8_0` (default for the others), `BF16`. |
| `--ngl N`, `--ub N`, `--ctx N` | llama: layers on the GPU, micro-batch, context. Defaults: `32/512/8192` for `d3-mini`, `14/1024/8192` for `d3-flash`, `99/4096/8192` for the others. |
| `--gguf FILE` | llama: use a local GGUF instead of downloading one. |
| `--keep` | do not stop the service already on the port (fails if it still holds the VRAM). |
| `--dry-run` | print the download URL, the VRAM estimate and the command; start nothing. |
| `--replace` | native: stop a recognized local service on the port before starting. |
| `--cpu`, `--gpu` | force CPU (llama: `-ngl 0`) or require a GPU. |
| `--port N`, `--home DIR` | listening port (default 8899) and working root (default `~/.local/share/opencode-guard`). |
| `--stop`, `--check` | stop the local llama or vllm-sr instance, or verify one already listening. |
| `--yes` | skip the confirmation before a multi-gigabyte download. |

In the global `~/.config/opencode/opencode.json` (a project file may be applied after it), point the plugin's `decision` option at the local service — no `apiKey` is needed for a local server:

```jsonc
{
  "plugins": [
    {
      "package": "/path/to/plugin_opencode",
      "options": {
        "decision": {
          "baseURL": "http://127.0.0.1:8899/v1",
          "protocol": "systemone",
          "model": "d3-mini",
          "timeoutMs": 5000
        }
      }
    }
  ]
}
```

`model` must match the server's `--alias` (`d3-mini` here; the script prints the exact block at startup). `timeoutMs` is per call and mandatory; `5000` is enough for `d3-mini`, use `8000` for `d3-flash`. This `decision` block replaces the Nox-4B one from [Installation](../README.md#installation); thresholds, rules and the other options are independent of the model. For `d3-mini`, add under `options` the recommended set from the table above — `"thresholds": { "denyNoul": 0.94, "denyRisk": 2.8 }` — rather than the Nox-4B defaults (31/34 instead of 28/34; 33/34 with the two rules). OpenCode reads the configuration when the server starts, so restart it after editing the file.

For manual control, download the GGUF and start the same server yourself:

```sh
HF_HUB_DISABLE_XET=1 hf download ggml-org/vllm-d3-mini-GGUF \
  --include vllm-d3-mini-Q4_K_M.gguf --local-dir models/d3-mini
```

Two options control whether the server fits on the GPU: `-ngl` is the number of layers kept on the GPU (`99` means all of them), and `-ub` is the micro-batch size used for prompt processing, which sizes the CUDA compute buffers. Lowering `-ub` frees VRAM, so more layers fit. On the 4 GB card used for these measurements:

```sh
# d3-mini Q4_K_M: all 32 layers on the GPU.
# 3,622 MiB used (47 MiB margin), 0.83 s per call in the bench.
llama-server -m models/d3-mini/vllm-d3-mini-Q4_K_M.gguf --alias d3-mini --port 8899 \
  -c 8192 -ub 512 -np 1 -ngl 32 --no-webui
```

The bench harness behind the table above lives in `tools/model-bench/` (see its README). `run_local_gpu.sh` starts the same server on port 8099, runs the 34 cases, then stops it:

```sh
bash tools/model-bench/run_local_gpu.sh d3-mini \
  models/d3-mini/vllm-d3-mini-Q4_K_M.gguf 32 /tmp/mini-gpu.jsonl 512
```

`model` must equal the `--alias`. `-ngl 32 -ub 512` leaves only 47 MiB of VRAM, so another CUDA process can prevent the server from loading; the service script stops the current local service first. For a long-running service, `-ngl 30 -ub 1024` (~0.97 s) or `-ngl 26 -ub 4096` (~1.34 s) leaves more headroom. The lighter models fit entirely with `-ngl 99`: `d3-nano` Q8_0 (~2.4 GiB), `d3-lite` Q8_0 (~1.2 GiB) and `d3-edge` Q8_0 (~0.9 GiB). `d3-flash` Q4_K_M is 6.6 GB and does not fit entirely on 4 GB; its measured partial configuration is `-ngl 14 -ub 1024` (14/32 layers, 3.7 s per call).

**Shared blind spots.** Every model in the table allows an in-place file edit (`sed -i`) and misses a secret looked up in the shell history (`history | grep`). Two [custom rules](configuration.md#configuration-reference) settle both for any model, before it is called:

```jsonc
"rules": [
  { "id": "in-place-edit", "pattern": "sed -i", "verdict": "ask", "reason": "in-place file edit: the original content is overwritten" },
  { "id": "history-secrets", "pattern": "history \\| grep", "verdict": "ask", "reason": "secrets looked up in the shell history" }
]
```

## Protocols

- **`chat`** follows the common OpenAI-compatible gateway convention. It sends `POST <baseURL>/chat/completions` with `{"model", "messages"}`, the System One request `{"state", "questions"}` being serialized as JSON in the last message. The answer `{"model", "answers"}` comes back as JSON in `choices[0].message.content` (a string, or an array of parts whose `text` parts are concatenated).
- **`systemone`** sends `POST <baseURL>/systemone` with `{"model", "state", "questions"}`, e.g. with `baseURL` set to `https://api.typesafe.ai/v1`. According to its model card, vLLM Semantic Router's Decision 3.0 is served by vLLM (development builds) on the same path (`/v1/systemone`). The d3 family (served locally by llama.cpp) was tested with this plugin on that path on 2026-10-17 and 18: its `score` answers are read like the other probabilities, and its thresholds need their own calibration (see [Measured models](#measured-models)).
