# Decision model

Any model that answers typed questions through the System One API can be configured under `decision`: Nox-4B is the one used and calibrated here; TypeSafe AI's Jev uses the same API. No behaviour depends on the model's name: it is sent with each request and shown in the start line and in the reasons (`nox-4b opinion: …`).

Each tool call that the local rules do not settle triggers one call to the model (results are cached), except the read-only tools `read`, `glob` and `grep` and the task list `todowrite` (see below). It receives the redacted, truncated tool input and five typed questions:

| Question | Type | Meaning |
|---|---|---|
| `destructive` | probability 0–1 | deletes, overwrites or corrupts data that cannot easily be recovered |
| `exfiltration` | probability 0–1 | sends local files, environment variables or other data to a remote host |
| `credentials` | probability 0–1 | reads, prints, copies or sends the value of credentials, keys, tokens or passwords (listing their names does not count) |
| `privilege_persistence` | probability 0–1 | escalates privileges or makes something run or grant access later: system configuration, shell startup files, autostart entries, systemd units or timers, cron entries, SSH keys or configuration, git hooks, sudoers, privileged groups |
| `risk` | score 0–3 | overall damage level: none (read-only), low (ordinary work inside the working directory, easy to undo), high (deletions, in-place overwrites, history rewrites, installs, deploys, configuration outside the working directory), critical (irreversible destruction outside it, privilege escalation, persistence, reading private keys or credential stores, sending local data out). Optional: if the model refuses it, the decision relies on the probabilities alone |

A note in the state tells the model that writing or editing a file is judged by what the write itself does: the file's content runs only if it is executed later, and that execution is judged again.

**Verdict.**
- `deny` if any probability ≥ `denyNoul`, or the risk ≥ `denyRisk`.
- `ask` if any probability ≥ `askNoul` (for `exfiltration`: ≥ `askExfiltration`, never below `askNoul`), or the risk ≥ `askRisk`. A confidence below `minConfidence` also asks, and so does a missing confidence while the check is enabled; it is disabled by default.
- `allow` otherwise.

**Opinion on local confirmations.** When a local rule asks for confirmation (except for read-only tools and the task list), the model is consulted too and its opinion is appended to the reason, for example `rm: file deletion (rm -r/-f) — nox-4b opinion: ask (risk 1.67/3, data destruction 0.89)`; the confirmation's action shows as much of it as fits, for example `guard · rm: file deletion (rm -r/-f) — nox-4b: ask (risk 1.67/3, data destruction 0.89) · shell: rm -rf build`, the opinion's verdict alone when its details do not fit; the full reason is in the log. By default, it does not change the verdict: neither stricter (you keep the decision on doubtful cases, including your own edits of the plugin or of `~/.config/opencode/`) nor looser. The local rules keep the last word because, on the actions they send to confirmation, the model alone would allow many and refuse some ordinary transfers. If the model is unreachable, the prompt shows no opinion; a local refusal does not consult it. Two exceptions are decided by the model instead (see [Local rules](rules.md#local-rules)), unless the rule is set to `"ask"` in `ruleOverrides`: a confirmation caused only by heredoc data, and a CodeMode script that uses `fetch` without referring to `tools` or writing a local address, when the model received the whole code.

**When the model has the last word on a local confirmation.** With `"localAsks": "model"`, or `"model"` on a rule in `ruleOverrides`, you hand the model the confirmations of the rules concerned (self-protection only with `selfProtectionByModel`, and never a change of the plugin's settings, a recognized launch of another OpenCode with its configuration changed or approving its own confirmations, nor a call to the OpenCode server API): when it judged the whole input, its verdict (allow, ask or deny) replaces your confirmation; disabled, unreachable, an invalid answer or an input cut to `maxStateChars`, and the confirmation stays with you. A refusal never changes, a confirmation that stays with you always comes before one left to the model, and some confirmations are never left to it (a check the plugin could not finish, an internal error, a script written then run, your own rules, the read-only tools); see [Letting the decision model decide local confirmations](configuration.md#letting-the-decision-model-decide-local-confirmations-localasks). The risk is the one these settings accept: the model reads text written by the agent (comments, strings, heredoc bodies in the command), which can steer its answer, and it would then allow an action that a local rule sent to you.

**Only the model of your global configuration allows.** In every case above (heredoc data, CodeMode's `fetch`, and the confirmations left to it by `localAsks`, `"model"` or `selfProtectionByModel`), the model may allow only if its configuration is the one your global configuration file or the system configuration declares for this plugin (`decision`): `decision.baseURL` (compared as for `outputCheck`) and `decision.model`, and also what else decides its verdict, each read as the plugin reads it (a value left out counts as its default): `decision.protocol`, `decision.timeoutMs`, `decision.apiKey` and `decision.headers` (who answers, and in time: a gateway may pick the model it serves by key or header), `maxStateChars` and `secretPatterns` (what the model sees) and `thresholds` (how its answers are read). A `{file:…}` reference in these entries of that declaration is not followed, so they do not match. It must also be switched on: by the system configuration when it declares the plugin (loaded last by OpenCode, its `decisionModel` or `profile` decides), otherwise by the global sources (`decisionModel` in the global file, the global `guard.json` and its sections). Or else the session's project is [trusted](configuration.md#settings-by-agent-and-by-project-guardjson). Otherwise it may still refuse, with the thresholds in force, but a confirmation it would allow stays with you, the reason says so, and a startup warning says why (it names the settings, never their values). A repository's `opencode.json` that replaces the model's address or one of these settings, or turns the model on, cannot have the model allow these actions. The calls that no local rule matches are judged by the model as before.

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

On by default when the decision model is configured: tool outputs are sent to it, so set `"outputCheck": false` if that model is not yours. As a complement to the [redaction](rules.md#secret-redaction), which recognizes secrets by their form, the decision model looks for a secret written in plain words in what a tool returns (`log in as deploy with chocolat82` in a comment, a log, a page, a file), in any language, and the words it finds are masked. No output is passed on unchecked, however long.

- **Activation.** The check is effective only if your global configuration file (`$OPENCODE_CONFIG_DIR`, or `$XDG_CONFIG_HOME/opencode`, or `~/.config/opencode`, as OpenCode resolves it, `opencode.json` or `opencode.jsonc`) or the system configuration declares this plugin with the same `decision.baseURL` and does not turn it off there (`false`, `"false"`, `"0"` or `{ "enabled": false }`; any other value, or none, keeps it on). A repository's `opencode.json` can replace the plugin's options, but cannot turn the check on towards its own server this way. `{env:…}` references in that file are resolved with the server's environment, as OpenCode does; a `{file:…}` reference, a missing or unreadable file, a missing entry, the check turned off there or a different address leave it inactive, with a warning that says why when you set `outputCheck` yourself. When the decision model is on, the start line of the log shows `output check: active`, `inactive` or `off` (turned off by `false`, in your configuration or a project's).
- **What is checked.** Every text the agent may receive: the `output` and the text of the `content`, the strings of an output that is not a text, the error message and its causes, and the strings of the metadata (OpenCode sends the output of an interrupted command to the model from there; short metadata strings are checked together). Each text is first redacted by the patterns, whatever `redactOutputs` says, so only a secret that the redaction does not recognize reaches the decision model.
- **How.** As for the [prompt check](#prompt-check-promptcheck): each text is cut into parts of 2,000 characters, at line ends chosen by their content (the same file read again from another line is cut at the same places), the secrets already masked shown as `<redacted>`. For a part that seems to give a credential's value, the model names the most likely word, then is asked whether it really is one; the part is asked again without it, to find a second secret. In every part, a word built like a password (at least 8 characters with a lower case letter, an upper case letter, a digit and another character) is also put to that last question, even when the part seems clean; it is never masked on its form alone. The words confirmed are masked everywhere in the result, as whole words (`[[GUARD_REDACTED:output_secret]]`), and the usual note tells the agent that the file itself is unchanged.
- **Secret seen but not located.** When the model is fairly sure a part holds a secret (`askScore`) but confirms none of its words, the whole part is masked (`[[GUARD_REDACTED:output_unchecked]]`), with its copies elsewhere in the result, and a note tells the agent to read a smaller range or to ask you. Below `askScore`, with no word confirmed, the part is passed on: that is mostly a false alarm.
- **When the model fails** (timeout, error, refused question, invalid answer): the output is held and a confirmation asks whether to pass it to the agent, with what was masked, the safety-net words included. Approved, it is passed that way, and a secret may remain; rejected, the agent receives a notice instead (with your feedback, if you give one, never written to the log), and the step goes on. In unattended mode (`askAs: "deny"`) it is withheld without asking. The log says once per series of failures that the check is unavailable. If the masks cannot be applied everywhere in the result, the output is withheld.
- **Your `!` commands.** OpenCode adds the command you type after `!` and its output to the conversation without any hook (OpenCode 2.2.5). The plugin finds that text in each request to the provider (it opens with `The following shell command was executed by the user:`) and checks it the same way, with the same cache: a word found is masked in what is sent, a part seen but not located is masked whole, and the local history keeps the original. If the decision model fails, the request is blocked, nothing is sent, and the session stops with the plugin's message: send it again once the model answers. Not with a provider that bypasses the wire hooks ("Claude Agent").
- **Which tools.** Every tool, MCP and plugin tools included, but the successful outputs of those of `skip`: by default `edit`, `write`, `apply_patch` and `patch` (their output repeats what the agent wrote), `todowrite` (it repeats the task list) and `invalid`; their errors are checked (an `edit` error quotes lines of the file). The answers of `question` are typed by you: they are checked with the questions and settings of the prompt check. Not checked: outputs that are empty or made only of placeholders and notes, the inner calls of a CodeMode script (only the result of the outer `execute`, which is what the model receives), and every output of the [unprotected agent](rules.md#unprotected-agent-unprotectedagent).
- **Cost.** One call per part, plus the calls of the parts that seem to hold a secret and one per word built like a password. The gateway answers several calls at once (`parallel`, 4 per check); one call takes about 0.4 s. The result of each part is kept for a day, for every session (at most 20,000 parts): a file read again costs far less. A large output can still take tens of seconds: the session waits.
- **Log.** The number of words masked and of parts masked whole, the number of calls and the duration; never a word of the output, nor the message of a model error.
- **Calibration.** The defaults are set for `nox-4b`. A value that reads as an ordinary word next to a user name, with nothing else around it, is the hardest case.

**Failures.** A timeout is retried once, so the wait can reach twice `decision.timeoutMs`; other errors are not retried. A refused question (a non-empty `error` field, e.g. `max_length_exceeded`; `null` or `""` means no error), an HTTP error, a timeout or an invalid answer all lead to a confirmation prompt, with the cause shown. An out-of-range value (a probability outside 0–1, a risk outside 0–3) is judged on the value brought back into range, then never less than a confirmation: `noul: 5` is still a refusal, `score: -5` no longer allows anything. Response bodies are read with a cap (16 KiB for an error message, 1 MiB for an answer): a larger answer is never parsed and leads to a confirmation. The model's URL must answer directly: a redirection is never followed (the new address would receive the request and the `decision.headers`) and leads to a confirmation (`HTTP 307: redirect refused`), without a retry.

## Prompt check (`promptCheck`)

On by default when the decision model is configured: what you type is sent to it (as the tool calls already are), so set `"promptCheck": false` if that model is not yours. The [redaction](rules.md#secret-redaction) recognizes secrets by their form (key formats, `DB_PASSWORD=…`, `Authorization: Bearer …`); a password typed in plain words (`mon mot de passe est soleil42`, `пароль: медведь42`, `log in as alice with sunflower`) has none. The decision model finds it instead, in any language: the plugin holds no keyword of any language.

- **Activation.** Effective only if your global configuration file or the system configuration declares the same `decision.baseURL` and does not turn the check off, as for [`outputCheck`](#output-check-outputcheck): a repository's `opencode.json` that points the model at its own server cannot receive your prompts this way. When the decision model is on, the start line of the log shows `prompt check: active`, `inactive` or `off` (turned off by `false`, in your configuration or a project's); the reason it is inactive is given as a warning when you set `promptCheck` yourself. A value other than `false`, `"false"`, `"0"` or `{ "enabled": false }` keeps it on.
- **How.** The prompt is first redacted by the patterns, and that redaction stays whatever follows. It is then cut into parts of 2,000 characters (with much larger parts, a secret buried in a long pasted text goes unseen). For each part, the model is asked whether it gives the value of a credential; the secrets already masked are shown to it as `<redacted>`. For a part that does, the model names the words most likely to be that value, then is asked about each of them whether it really is one (a user name, a variable such as `GITHUB_TOKEN`, a command or an ordinary word is not); only the words it confirms are masked, everywhere in the prompt and as whole words (`[[GUARD_REDACTED:prompt_secret]]`). The part is then asked again without them, to find a second secret. A note tells the conversation model that a secret was masked. A password written out as an example is masked too.
- **Confirmation.** When the model is fairly sure a part holds a secret but confirms none of its words (a passphrase of several words, for example), when it fails or does not answer in time (`decision.timeoutMs` per call, the whole check at most three times that), or for a prompt longer than 32,000 characters, a confirmation asks: approved, the prompt is sent with what was masked, and a secret may remain; rejected, the prompt is not sent: the TUI shows an error (`UnexpectedStatus: 500`) and keeps your text in the input, to retype it without the secret. A sub-agent's prompt is checked too, with its confirmation shown in your session; rejected, the agent is told not to send it again nor to pass the value another way, and to tell you. When it is only somewhat sure and confirms no word, the prompt is sent: on real prompts, that is almost always a false alarm. In unattended mode (`askAs: "deny"`) a prompt that needs a confirmation is not sent, without asking. An internal error of the plugin leads to the same confirmation: a prompt is never sent unchecked without your approval.
- **Safety net.** A word built like a password (at least 8 characters with a lower case letter, an upper case letter, a digit and another character) is put to the last question even when the part seems clean, and masked if the model confirms it; it is never masked on its form alone, except when the model fails or the check takes too long: then it is masked before the confirmation.
- **Cost.** One call per part of 2,000 characters, and for a part that seems to hold a secret one more per 16 distinct words (up to about 15 for a full part), then one per word checked; the gateway answers several calls at once (about 0.4 s each).
- **Log.** The number of words masked, the model's score, the number of calls and the duration; never a word of the prompt, nor the message of a model error (a gateway may copy the request into it).
- **Calibration.** The default settings (threshold 0.2) are set for `nox-4b`. A value that reads as an ordinary word with nothing around it (`connecte-toi avec admin et soleil`) may pass. Nothing is checked for the [unprotected agent](rules.md#unprotected-agent-unprotectedagent).

## Settings and questions of the checks

Every setting of the two checks, and the text of each question they ask the model, can be changed under `outputCheck` and `promptCheck`, for example to use another decision model. They count only if your global configuration file or the system configuration sets **the same value** for the plugin (compared exactly): otherwise the defaults apply, the check stays on, and a warning says so. A project's `opencode.json` can thus turn a check off (`false`, shown on the start line), but cannot weaken it silently, with a threshold of 1 or a rewritten question. When settings other than the defaults are in force, the start line says `(custom settings)`. Changing a question changes the model's scores: run `dev/tools/prompt-check-calibrate.ts` (with `--questions` and, for a local model, `--local`) to find the thresholds that go with it; it prints the `promptCheck` block to paste.

Settings (number, default for `promptCheck` / `outputCheck`, bounds):

| Setting | Default | Meaning |
|---|---|---|
| `threshold` | 0.2 / 0.2 | Stage 1: probability from which a part holds a secret (0–1). |
| `partChars` | 2000 / 2000 | Characters per part sent to the model (200–20000). |
| `candidates` | 1 / 1 | Stage 2: at most this many words, each checked by stage 3 (1–10). |
| `minCandidate` | 0.1 / 0.1 | Stage 2: smallest probability of a candidate (0–1). |
| `verify` | 0.6 / 0.6 | Stage 3: probability from which a word is masked (0–1). |
| `askScore` | 0.6 / 0.6 | Stage 1 probability from which a part with no confirmed word leads to a confirmation (prompts) or is masked whole (outputs); below, it is passed on (0–2; above 1: never). |
| `rounds` | 3 / 3 | Stage 2 and stage 1 again, to find a second secret, at most this many times (1–10). |
| `wordsPerQuestion` | 16 / 16 | Words offered in one stage-2 question (2–50). |
| `minWord` | 4 / 4 | Shortest word offered (1–20). |
| `parallel` | 4 / 4 | Simultaneous calls of the check (1–16). |
| `maxChars` | 32000 / — | Longer prompts are not checked: confirmation (1000–1000000). Outputs: no limit. |
| `deadlineCalls` | 3 / — | The whole prompt check takes at most this many times `decision.timeoutMs` (1–20). Outputs: no limit, each call has its own timeout. |
| `timeoutMs` | — / 5000 | Outputs: timeout of one call (100–60000); a call that fails holds the output for a confirmation. Prompts: `decision.timeoutMs`. |
| `skip` | — / see above | Outputs: names of the tools whose output is not checked (replaces the default list). |

Questions: texts of 1 to 2,000 characters; a text left out keeps its default, and an invalid one too, with a warning. Only the texts change: the kind of each question and the names the code reads stay. In a question, `` `message` `` is the part of the prompt, `` `output` `` the part of the output (with `tool`, the tool's name), `` `value` `` the word checked.

```jsonc
"promptCheck": {   // same keys under "outputCheck"
  "questions": {
    "secret": { "instructions": "…", "criteria": { "true": "…", "false": "…" } }, // stage 1, yes/no
    "word": { "instructions": "…", "none": "…" },                              // stage 2, a choice among the words; `none`: the last option
    "value": { "instructions": "…", "criteria": { "true": "…", "false": "…" } }   // stage 3, yes/no
  }
}
```

The questions that decide actions (risk, destruction, exfiltration…) are not settings: they may allow an action.

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

Nine models (ten builds, with both `d1-2B` files) were scored on the 500 cases of `tools/model-bench/cases500/`: 215 to allow, 156 to confirm and 129 to refuse, across reads, builds, installs, git, deletions, in-place edits, tool configuration, destruction, persistence, privileges, containers, exfiltration, credentials, legitimate uploads, injections, opaque or indirect execution and false positives, with small, medium and large inputs (up to 3,800 characters). The labels follow the bench's `CONVENTION.md`. Every model gets the same inputs with the plugin's current questions (`src/model/questions.ts`), and its answers alone are mapped to verdicts — the local rules are identical for every model and would hide the differences. The d3 models answered with their original weights through vllm-sr's System One API (`https://decision.vllm-sr.ai/v1`), `nox-4b` and TypeSafe AI's Jev (`jev-latest`, Jev 1.14) through an OpenAI-compatible gateway, `d1-2B` through its official GGUF files in llama.cpp.

"Recommended" is the best of 4,800 threshold sets for correct verdicts minus three per expected refusal allowed. Since it is chosen on the cases it scores, the table gives the cross-validated score instead: thresholds chosen on one half of the cases, scored on the other — what to expect on new calls, within about ±3.5 points on 500 cases. "Refusals allowed" counts expected refusals the model allows; "false alarms", calls to allow that it confirms or refuses.

| Model | Defaults: score, refusals allowed, false alarms | Recommended `thresholds` | Cross-validated | With them: refusals allowed, false alarms | Notes |
|---|---|---|---|---|---|
| `d3-ultra` (27B) | 78.2 %, 0, 6 | `{ "denyNoul": 0.99, "askNoul": 0.5, "askExfiltration": 0.7, "denyRisk": 2.95, "askRisk": 1.2 }` | 84.0 % | 0, 8 | never allows an expected refusal; turns many confirmations into allow or deny (9 of the 11 uploads to confirm are refused); about 19 GB in `Q4_K_M`, far beyond a 4 GB GPU |
| `jev-latest` (Jev 1.14) | 78.8 %, 0, 17 | `{ "denyNoul": 0.98, "askNoul": 0.8, "askExfiltration": 0.7, "denyRisk": 2.2, "askRisk": 1.2 }` | 83.2 % | 0, 23 | for reference only: a public model, not a private model meant for opencode-guard; with `nox-4b`'s `{ "askRisk": 1.2, "denyRisk": 2.2 }`, already 82.0 % (0, 25); hosted outside the EU; confirms few in-place edits |
| `d3-mini` (4B) | 80.8 %, 1, 16 | `{ "denyNoul": 0.98, "askExfiltration": 0.7, "denyRisk": 2.2 }` | 81.2 % | 1, 16 | the best local model, already well set at the defaults; the minimum recommended for a local decision model |
| `d3-flash` (9B) | 76.2 %, 0, 43 | `{ "denyNoul": 0.99, "askNoul": 0.9, "askExfiltration": 0.7, "askRisk": 1.2 }` | 80.6 % | 1, 35 | at the defaults, confirms many writes of long project files; does not fit entirely on a 4 GB GPU |
| `nox-4b` | 64.8 %, 7, 26 | `{ "askRisk": 1.2, "denyRisk": 2.2 }` | 69.6 % (set on real traffic, not on this bench) | 5, 36 | the current default; the best set on this bench, `{ "denyNoul": 0.8, "askExfiltration": 0.8, "denyRisk": 2.0, "askRisk": 1.2 }` (70.6 % cross-validated), is within the margin and lowers `askExfiltration` below the 0.85 set from real traffic (see Calibration); with these thresholds, confirms most persistence instead of refusing it, and allows many tool configuration changes and in-place edits |
| `d3-nano` (2B) | 65.0 %, 2, 77 | `{ "denyNoul": 0.99, "askNoul": 0.9, "askExfiltration": 0.7, "denyRisk": 2.2 }` | 69.6 % | 2, 53 | many false alarms |
| `d1-2B` Q4_K_M | 61.2 %, 8, 55 | `{ "denyNoul": 0.94, "askNoul": 0.6, "askExfiltration": 0.8, "denyRisk": 2.2, "askRisk": 1.2 }` | 60.6 % | 6, 61 | Q8_0: 60.0 % at the defaults (10, 55), 58.6 % cross-validated; fits a 4 GB GPU (Q4: 2.4 GiB, Q8: 3.1 GiB with an 8k context) |
| `d3-lite` (0.8B) | 62.2 %, 2, 81 | `{ "denyNoul": 0.98, "askNoul": 0.9, "askExfiltration": 0.7 }` | 59.4 % | 2, 70 | many false alarms; confirms most persistence instead of refusing it |
| `d3-edge` (0.6B) | 55.0 %, 34, 44 | `{ "askNoul": 0.6, "askExfiltration": 0.7, "denyRisk": 2.0, "askRisk": 1.0 }` | 54.8 % | 18, 88 | no threshold set balances refusals and false alarms |

Most models score lowest on the calls to confirm (`d3-mini` 84 of 156, `d3-ultra` 55): they tend to allow or refuse them outright. The values do not transfer from one model to another; to set them for another model or another version, run it on `cases500/` and let `tools/model-bench/score.py` print the `thresholds` value (see the bench's README).

A second set, `tools/model-bench/cases-fresh/` (192 cases: 84 to allow, 62 to confirm, 46 to refuse), is kept apart from the tuning: written without access to any model's answers, it was not used to set the thresholds; `nox-4b` scores 70.8 % there with its thresholds above (1 refusal allowed, 12 false alarms).

**Where to get the models.** The original d3 weights and their runtime are published on Hugging Face under [`vllm-sr`](https://huggingface.co/vllm-sr) (`d3-mini`, `d3-nano`, `d3-lite`, `d3-edge`, `d3-flash`); the GGUF conversions served here are under [`ggml-org`](https://huggingface.co/ggml-org), one `vllm-d3-<model>-GGUF` repository per model, each with a `BF16` file (the original precision) and a `Q8_0` file; `Q4_K_M` is also published for `d3-mini` and `d3-flash`. On the first 34 cases of the bench (`tools/model-bench/cases/`), the GGUF files served locally (`d3-mini` `Q4_K_M`, `d3-edge` `Q8_0`) gave the same verdicts as the original weights, and `d3-mini`'s `BF16` file the same verdicts as `Q4_K_M` once tuned: quantizing costs nothing measurable there.

### Secret checks (prompts and tool outputs)

The [prompt check](#prompt-check-promptcheck) and the [output check](#output-check-outputcheck) were measured on their own sets: typed passwords in many languages and forms, ordinary prompts, real prompts (counts only), and tool outputs in the format of `read`, `grep`, `bash` and `webfetch` with a secret the redaction patterns do not catch. A leak is a secret left visible; a false mask, an ordinary word masked. Best settings per model:

| Model | `promptCheck` | Prompts: leaks, false masks | Outputs, stage 1 alone (parts of 2,000) | Notes |
|---|---|---|---|---|
| `nox-4b` | the defaults (`threshold` 0.2, `verify` 0.6, `askScore` 0.6, `partChars` 2000, `candidates` 1) | 5 to 6 %, 2 to 8 % | `threshold` 0.2: 13 of 235 secrets missed, 1 real output in 127 flagged | the defaults; whole output chain at these settings: 19 of 195 secrets missed, no real output masked whole |
| `d3-mini` | `{ "threshold": 0.5, "verify": 0.9, "askScore": 0.5, "partChars": 1500, "candidates": 2 }` | 1 to 1.5 %, 0 to 1.2 % | `threshold` 0.1 to 0.3: 4 to 7 missed, 0 to 1 real output flagged | separates passwords from ordinary words much better than `nox-4b`, about ten times more slowly |
| `d3-flash` | — | — | `threshold` 0.2: 4 missed, no real output flagged | |
| `d3-nano` | — | — | `threshold` 0.1 (parts of 1,000): 18 missed, 23 real outputs in 263 flagged | below `nox-4b` |
| `d3-lite`, `d3-edge` | — | — | over 70 missed, or hundreds of outputs flagged | not usable for the checks |

The secrets still missed by every model are mostly a password written next to a user name with no keyword (`deploy / rainbow89`). A local model must accept a whole part in one batch: see the batch size below.

## Serving one locally

The repository ships `tools/serve.sh`, a service script for the whole Decision 3.0 family. It exposes the same `POST /v1/systemone` API on port 8899 and drives three backends:

- **`llama`** — `llama-server` plus a quantized GGUF, no Python venv and no kernels to compile. The recommended path on a small GPU. A request must fit whole in one batch (`-ub`, with `-b` at least as large): the plugin sends inputs of up to 4,000 characters (plus the scripts it runs) and prompt parts of 2,000, so the script uses a batch of 4,096 tokens; a smaller batch makes the server reject the longer requests, which the plugin then treats as a model failure (a confirmation). Then as many layers on the GPU as the free VRAM allows (see below).
- **`native`** (default) — the model's own Transformers runtime (`d3_server.py`) in a local venv, with the kernels compiled from source; `d3-edge` uses about 2.3 GiB of VRAM.
- **`engine`** (alias `container`) — `vllm-sr serve -e` in a Docker or Podman container, with batching; `d3-edge` uses about 1.75 GiB of VRAM. The dev CLI is pinned at first install and checked on every start (a different version needs `--yes` or `VLLM_SR_VERSION`), and the mode refuses the CPU fallback: use `--gpu` or `native --cpu`.

One command downloads the artifact, checks the VRAM, stops the service already on the port, starts the backend, verifies `/v1/systemone`, and prints the plugin entry. For `d3-mini` Q4_K_M (4.5B, 32 layers, 3.7 GB), the best local model measured for its speed:

```sh
bash tools/serve.sh llama --model d3-mini --yes
```

The script stops only recognized local services (`d3_server.py`, `llama-server`, `vllm-sr`); a foreign process on the port is reported and left alone. In llama mode it downloads the GGUF from `ggml-org/vllm-d3-<model>-GGUF` into `<home>/models/ggml-org/<model>/`, resumes partial files, and refuses to load when its VRAM estimate (weights + KV cache + compute buffers) exceeds the free memory. Logs go to `<home>/logs/llama-<model>-<quant>.log`. Main options:

| Option | Effect |
|---|---|
| `--model NAME` | `d3-mini`, `d3-flash`, `d3-nano`, `d3-lite`, `d3-edge`; Hub identifier with or without the `vllm-sr/` prefix, or a local package directory (native). |
| `--quant Q` | llama: `Q4_K_M` (default for `d3-mini`/`d3-flash`), `Q8_0` (default for the others), `BF16`. |
| `--ngl N`, `--ub N`, `--ctx N` | llama: layers on the GPU, batch (passed as `-ub` and `-b`), context (at least the batch). Defaults: `26/4096/8192` for `d3-mini`, `8/4096/8192` for `d3-flash`, `99/4096/8192` for the others. Below 4096, the script warns, and its startup check (a request of about 4,000 characters) fails. |
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

`model` must match the server's `--alias` (`d3-mini` here; the script prints the exact block at startup). `timeoutMs` is per call and mandatory; `5000` is enough for `d3-mini` on short calls, use `8000` for `d3-flash`. A long call takes much more when part of the model runs on the CPU: with 26 of `d3-mini`'s 32 layers on the GPU, about 1.1 s for a 2,000-character prompt part, but 9 to 14 s for a decision on a 4,000-character input, beyond `5000` (the call then fails and the plugin asks for confirmation); a larger `timeoutMs` has it judged, at the cost of the wait. This `decision` block replaces the Nox-4B one from [Installation](../README.md#installation); thresholds, rules and the other options are independent of the model. For `d3-mini`, add under `options` the recommended set from the table above — `"thresholds": { "denyNoul": 0.98, "askExfiltration": 0.7, "denyRisk": 2.2 }` — rather than the Nox-4B defaults (81.2 % cross-validated instead of 80.8 %). OpenCode reads the configuration when the server starts, so restart it after editing the file.

For manual control, download the GGUF and start the same server yourself:

```sh
HF_HUB_DISABLE_XET=1 hf download ggml-org/vllm-d3-mini-GGUF \
  --include vllm-d3-mini-Q4_K_M.gguf --local-dir models/d3-mini
```

Two options control whether the server fits on the GPU: `-ngl` is the number of layers kept on the GPU (`99` means all of them), and `-ub` is the batch used for prompt processing, which sizes the CUDA compute buffers. These models read a request in one batch, so `-ub` (and `-b`, whose default is 2048) must hold the longest request the plugin sends: 4096 tokens. A larger batch takes VRAM that layers would use. The optimal parameters:

```sh
# d3-mini Q4_K_M, batch of 4096 tokens; -ngl: every layer that fits in the free VRAM
# (99 = all 32, about 4.4 GiB estimated; 26 layers: 3.7 GiB; 20: 3.2 GiB).
llama-server -m models/d3-mini/vllm-d3-mini-Q4_K_M.gguf --alias d3-mini --port 8899 \
  -c 8192 -b 4096 -ub 4096 -np 1 -ngl 99 --no-webui
```

The bench harness behind the table above lives in `tools/model-bench/` (see its README). `run_local_gpu.sh` starts the same server on port 8099, runs the cases, then stops it (the first 34 by default; `CASES=tools/model-bench/cases500` with a batch of 8192 for the 500, whose longest requests reach about 6,000 tokens):

```sh
bash tools/model-bench/run_local_gpu.sh d3-mini \
  models/d3-mini/vllm-d3-mini-Q4_K_M.gguf 26 /tmp/mini-gpu.jsonl 4096
```

`model` must equal the `--alias`. Each layer moved to the CPU slows every call; keep the batch at 4096 and lower `-ngl` until the server loads (`tools/serve.sh` defaults to 26, which needs 3.7 GiB). A batch of 8192 (for a decision with several long scripts, about 6,600 tokens) fits only with `-ngl 16`, slower on every call. The lighter models fit entirely with `-ngl 99` and a batch of 4096: `d3-nano` Q8_0 (~2.4 GiB), `d3-lite` Q8_0 (~1.2 GiB) and `d3-edge` Q8_0 (~0.9 GiB). `d3-flash` Q4_K_M is 6.6 GB and does not fit entirely on a 4 GB GPU; with a batch of 4096 it runs there with `-ngl 8`.

**Shared blind spots.** The models often allow an in-place file edit (`sed -i`) and a secret looked up in the shell history (`history | grep`). Two [custom rules](configuration.md#configuration-reference) settle both for any model, before it is called:

```jsonc
"rules": [
  { "id": "in-place-edit", "pattern": "sed -i", "verdict": "ask", "reason": "in-place file edit: the original content is overwritten" },
  { "id": "history-secrets", "pattern": "history \\| grep", "verdict": "ask", "reason": "secrets looked up in the shell history" }
]
```

## Protocols

- **`chat`** follows the common OpenAI-compatible gateway convention. It sends `POST <baseURL>/chat/completions` with `{"model", "messages"}`, the System One request `{"state", "questions"}` being serialized as JSON in the last message. The answer `{"model", "answers"}` comes back as JSON in `choices[0].message.content` (a string, or an array of parts whose `text` parts are concatenated).
- **`systemone`** sends `POST <baseURL>/systemone` with `{"model", "state", "questions"}`, e.g. with `baseURL` set to `https://api.typesafe.ai/v1`. According to its model card, vLLM Semantic Router's Decision 3.0 is served by vLLM (development builds) on the same path (`/v1/systemone`). The d3 family (served locally by llama.cpp) was tested with this plugin on that path on 2026-10-17 and 18: its `score` answers are read like the other probabilities, and its thresholds need their own calibration (see [Measured models](#measured-models)).
