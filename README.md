# opencode-guard

OpenCode agents can run shell commands, edit files and send data over the network. A single bad command is enough to erase uncommitted work, rewrite your shell configuration, or leak an API key.

**opencode-guard** is an **OpenCode V2** plugin (tested with `opencode v2.2.5`) that sits in front of those actions. It blocks or asks for confirmation before dangerous tool calls, and redacts secrets before they reach the model provider or the session history.

> **This is not a sandbox.** It is a heuristic guardrail and can be bypassed (obfuscation, writing a script and running it later…). Use a container for real isolation.

## What it does

- **Local rules first.** Destructive commands, credential files, data leaving the machine and protected writes are settled instantly, without network access.
- **A decision model for the rest.** Anything the local rules leave open is judged by a model that answers typed questions with probabilities through the System One API, such as **Nox-4B** or TypeSafe AI's **Jev**. The model and its address are set in `opencode.json`; nothing is hard-coded.
- **Secret redaction.** API keys, tokens, passwords and private keys are masked before they reach the LLM provider or the stored history (with OpenCode's "Claude Agent" provider, only at the source: see [Known limitations](docs/operations.md#known-limitations)).
- **Self-protection.** The agent cannot silently disable the guard: writing to the plugin directory, OpenCode's configuration, `.opencode/` or `opencode.json(c)` requires confirmation.

Every tool call goes through `tool.execute.before`: local rules first, then the decision model if they do not settle it.

```text
tool call
  │
  ├─ local rules ── deny ──▶ call rejected
  │                └ ask  ──▶ confirmation prompt
  ▼
decision model ── deny / ask / allow
  │ unreachable, timeout, HTTP error, invalid answer
  └▶ confirmation prompt
```

A local `deny` is final, and the decision model can only make a decision **stricter**, unless you leave some local confirmations to it (`localAsks`, `"model"` in `ruleOverrides`); only the model your global configuration declares, with the same thresholds and other settings, can allow them. Read-only tools (`read`, `glob`, `grep`) and the task list are not sent to the model. See [How it works](docs/architecture.md) for the full hook list and principles.

## Rules at a glance

| Area | What the guard does | Verdict |
|---|---|---|
| Destructive commands | `rm -rf /`, `mkfs`, `dd of=/dev/sda`, fork bombs, writes to a device | `deny` |
| Destructive git and system changes | `git reset --hard`, force-push, `sudo`, shutdown, package installs, `kubectl delete` | `ask` |
| Credential files | reading `.env`, `~/.ssh/`, `~/.aws/`, cloud keys, other agents' credential stores | `ask` |
| Files the plugin cannot read | `read` or a raw print (`cat`, `base64`…) of a PDF or an Office document: a yes lets it through unchecked; the same for images once `opaque-image` is turned on | `ask` |
| Secrets leaving the machine | a credential file or a detected secret in a network command, web request, MCP call or CodeMode code | `deny` |
| Protected locations | recognized writes to the plugin directory, `opencode.json(c)`, `.opencode/`, shell startup files, `/etc`, git hooks | `ask` |
| Redaction placeholder | writing a placeholder back into a file would destroy the real secret | `deny` |
| Secrets in prompts and results | API keys, tokens, passwords in code or configuration (`DB_PASSWORD=…`), private keys, base64 and hex dumps; with the decision model, passwords written in plain words in the prompt and in tool outputs | redacted |

A yes to a document or an image checks nothing: the plugin sees only its name, and for `read` its first bytes, so a file renamed and printed by `cat` does not ask, a file attached to the prompt is not a tool call, and a scanned page holds no text to mask (see [Known limitations](docs/operations.md#known-limitations)).

The exact patterns, exceptions and false positives are listed in [Rules and redaction](docs/rules.md).

## Installation

**Platforms:** Linux and macOS, tested in the CI on Node and Bun. On Windows, only a dedicated subset of tests runs in the CI, and the rules are written for POSIX shells: most PowerShell commands are left to the decision model, and pass without it. See [the limits](docs/operations.md).

OpenCode V2 loads a local plugin from a **directory** containing `index.ts` at its root. Add the plugin to `opencode.json` — the global file is `~/.config/opencode/opencode.json`, the project file is `<project>/opencode.json`:

```jsonc
{
  "plugins": [
    {
      "package": "/path/to/plugin_opencode",
      "options": {
        "decision": {
          "baseURL": "https://ai-gateway.example.com/v1",
          "model": "nox-4b",
          "apiKey": "{env:NOX_API_KEY}"
        },
        "askAs": "{env:GUARD_ASK_AS}"
      }
    }
  ]
}
```

### From Git

OpenCode can also install the plugin from a Git specifier. Pin the full commit, so that nothing changes until you decide it:

```jsonc
{
  "plugins": [
    {
      "package": "github:gigi206/opencode-guard#<full commit sha>",
      "options": { /* same options */ }
    }
  ],
  // Keeps a project from blocking the plugin with a `plugin.use` deny: the resource is the specifier, word for word.
  "policies": [{ "action": "plugin.use", "resource": "github:gigi206/opencode-guard#<full commit sha>", "effect": "allow" }]
}
```

The plugin recognizes its entry only by the exact specifier it was installed from, and treats the whole OpenCode cache entry of that specifier as its own directory. Do not use `opencode plugin add`, which writes the entry without its options. To change version, edit the commit in both places and restart the server. With a specifier that follows a branch (`github:gigi206/opencode-guard#main`), `guard update --check` runs `opencode plugin check` and `guard update` runs `opencode plugin update`, on that specifier, then says whether the installed commit changed ([Operations](docs/operations.md#updating-the-plugin)); neither acts on a pinned commit.

Node refuses TypeScript under `node_modules`, so the `guard` command needs its own launcher. Once OpenCode has installed the plugin, run:

```sh
curl -fsSL https://raw.githubusercontent.com/gigi206/opencode-guard/<full commit sha>/tools/install-cli.sh | sh
```

It installs `guard` in `~/.local/bin` (or `GUARD_BIN_DIR`), replacing an existing link. The command finds the configured specifier and runs the installed generation with the Bun inside OpenCode, so it needs no change when you change version.

Put the API key in the environment of the **OpenCode server**, under the name referenced by `{env:…}`. With the background service:

```sh
read -rs K && opencode service set env NOX_API_KEY "$K"; unset K
opencode service restart
```

Everything is configured in `opencode.json`: the plugin never reads environment variables itself. Values that depend on the environment use `{env:VAR}` (or `{file:path}`), quoted. A missing key disables the decision model and logs a warning. No build step and no runtime dependency is needed.

Check that the plugin is loaded:

```sh
opencode plugin list    # should show: guard  local  /path/to/plugin_opencode/index.ts
tail -f ~/.local/share/opencode/log/guard.log
```

Recommended: keep a global policy so a project cannot block the plugin by policy:

```jsonc
"policies": [
  { "action": "plugin.use", "resource": "/path/to/plugin_opencode", "effect": "allow" }
]
```

A project can still remove the plugin; if it replaces its options, the plugin keeps what you set and the project can only harden it, `logFile`, `debug` and the cache settings apart. See [Protecting the plugin from project configuration](docs/configuration.md#protecting-the-plugin-from-project-configuration) for the full protection.

## Useful parameters

All options live under `options` in the plugin entry.

| Option | Default | Description |
|---|---|---|
| `decision.baseURL` | required | Versioned base URL, without the final path (e.g. `https://ai-gateway.example.com/v1`). Missing or invalid: only the local rules apply. |
| `decision.model` | required | Model name, e.g. `nox-4b` or `jev-latest`. |
| `decision.apiKey` | — | Key sent as `Authorization: Bearer …`, normally `{env:NOX_API_KEY}`. |
| `decision.protocol` | `"chat"` | `"chat"` for an OpenAI-compatible gateway, `"systemone"` for a direct System One API. |
| `decision.timeoutMs` | `5000` | Timeout per call (100–60000 ms). A timeout is retried once. |
| `askAs` | `"ask"` | `"deny"` turns every confirmation into a refusal (unattended mode). |
| `thresholds` | see docs | `denyNoul`, `askNoul`, `askExfiltration`, `denyRisk`, `askRisk`, `minConfidence`. |
| `rules` | `[]` | Extra local rules: `{ "id", "pattern", "flags"?, "verdict": "deny" \| "ask", "reason", "tools"? }`; also read at the top level of the global `guard.json` (`guard rules add`). |
| `outputCheck` | on | Also ask the decision model for a secret written in plain words in tool outputs, and mask it. |
| `promptCheck` | on | Also ask the decision model for a secret typed in plain words in the prompt, in any language, and mask it. |
| `dangerousCommands`, `sensitiveFiles`, `decisionModel`, `scripts`, `redactOutputs`, `redactPrompt`, `redactWire` | `true` | Turn a feature on or off; `false` must also be in your global configuration, or in a `projects` section of it. |
| `ruleOverrides` | `{}` | One built-in rule by its identifier: `"off"`, `"ask"`, `"deny"` or `"model"` (its confirmations decided by the decision model); `"off"`, `"ask"` and `"model"` must also be in your global configuration (plugin options or global `guard.json`), unless the project is trusted. |
| `exceptions`, `rememberConfirmations` | `{}`, `0` | Credential files you no longer confirm (`{ "secret-file-read": ["<absolute path>"] }`, `guard rules off secret-file-read --path <file>`), and minutes during which a confirmed set of files is not asked again in the session (off by default, `guard set rememberConfirmations <minutes>`); only for a file named by an absolute path (never `~/`) in a command that only reads, never for a script written in the session or a call made by CodeMode code (recognized while its code runs, not across a reload of the plugin: see Configuration); never a refusal, must also be in your global configuration unless the project is trusted. |
| `localAsks` | `"ask"` | `"model"`: the confirmations of the built-in rules without a setting are decided by the decision model (self-protection only with `selfProtectionByModel: true`); must also be in your global configuration (plugin options or global `guard.json`), unless the project is trusted. |
| `profile` | `"standard"` | `"credentials-only"` turns `dangerousCommands`, `decisionModel` and `scripts` off by default; must also be in your global configuration (plugin options or global `guard.json`), unless the project is trusted. |
| `debug` | `false` | Also log allowed actions and redaction counts; confirmations, refusals and local confirmations decided by the model are always logged. |
| `logFile` | `~/.local/share/opencode/log/guard.log` | Plugin log file; `false` means stderr only. |

Full reference, defaults, environment substitutions and edge cases: [Configuration](docs/configuration.md). Model choices, thresholds and local serving: [Decision model](docs/decision-model.md).

The [`guard` command](docs/configuration.md#the-guard-command) (`bin/guard`) lists the built-in rules and your own (`guard rules --explain <rule>` explains one in words), the redaction formats with their regular expressions (`guard redaction`), shows the settings in force and where they come from, lists the latest confirmations and refusals, gives the verdict the plugin would give to a command without running it (`guard test`), reports the plugin's state from its log (`guard status`), and writes settings to the global `guard.json` (`guard rules off|ask|deny|model|reset <rule>`, `--agent`, `--project`, `guard rules off|reset secret-file-read --path <file>`, `guard rules add|remove`, `guard set|unset`, `guard redaction off|on <format>`, `guard trust`), applied without a restart; `guard completion bash|zsh` prints a completion script, `guard help` lists the commands, in color in a terminal.

## Logs

The start line states the model, the confirmation mode and whether the system configuration enforces the plugin. Every confirmation and refusal is logged with its source (`local`, `model`, `cache`…), its rule, its full reason and the duration of the model call, for example `shell → ask (local, rule git-reset-hard): …`; with `debug: true`, allowed actions too. A confirmation prompt shows the rule, the reason, the decision model's opinion and the tool call's summary (`guard · <rule>: <reason> — <opinion> · <tool call>`), as much of them as fits in 120 characters; the full reason is in the log.

```sh
tail -f ~/.local/share/opencode/log/guard.log
```

More in [Logs and verification](docs/operations.md#logs-and-verification).

## Documentation

- [How it works](docs/architecture.md) — hooks, decision flow, self-protection
- [Rules and redaction](docs/rules.md) — local rules, secret redaction, confirmations, unattended mode, unprotected agent
- [Configuration](docs/configuration.md) — full reference, project-config protection, feature toggles, disabling
- [Decision model](docs/decision-model.md) — protocols, thresholds, measured models, serving one locally
- [Operations](docs/operations.md) — logs, trying it out, known limitations, development

## License

MIT, see [LICENSE](LICENSE). Part of the secret patterns is adapted from OpenCode (MIT, Copyright (c) 2025 opencode); the coding agents' credential paths and backup suffixes are adapted from cc-safety-net (MIT, Copyright (c) 2026 J Liew).
