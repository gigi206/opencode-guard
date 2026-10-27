# opencode-guard

OpenCode agents can run shell commands, edit files and send data over the network. A single bad command is enough to erase uncommitted work, rewrite your shell configuration, or leak an API key.

**opencode-guard** is an **OpenCode V2** plugin (tested with `opencode v2.2.0`) that sits in front of those actions. It blocks or asks for confirmation before dangerous tool calls, and redacts secrets before they reach the model provider or the session history.

> **This is not a sandbox.** It is a heuristic guardrail and can be bypassed (obfuscation, writing a script and running it later…). Use a container for real isolation.

## What it does

- **Local rules first.** Destructive commands, credential files, data leaving the machine and protected writes are settled instantly, without network access.
- **A decision model for the rest.** Anything the local rules leave open is judged by a model that answers typed questions with probabilities through the System One API, such as **Nox-4B** or TypeSafe AI's **Jev**. The model and its address are set in `opencode.json`; nothing is hard-coded.
- **Secret redaction.** API keys, tokens, passwords and private keys are masked before they reach the LLM provider or the stored history.
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

A local `deny` is final, and the decision model can only make a decision **stricter**. Read-only tools (`read`, `glob`, `grep`) and the task list are not sent to the model. See [How it works](docs/architecture.md) for the full hook list and principles.

## Rules at a glance

| Area | What the guard does | Verdict |
|---|---|---|
| Destructive commands | `rm -rf /`, `mkfs`, `dd of=/dev/sda`, fork bombs, writes to a device | `deny` |
| Destructive git and system changes | `git reset --hard`, force-push, `sudo`, shutdown, package installs, `kubectl delete` | `ask` |
| Credential files | reading `.env`, `~/.ssh/`, `~/.aws/`, cloud keys, other agents' credential stores | `ask` |
| Secrets leaving the machine | a credential file or a detected secret in a network command, web request, MCP call or CodeMode code | `deny` |
| Protected locations | writes to the plugin directory, `opencode.json(c)`, `.opencode/`, shell startup files, `/etc`, git hooks | `ask` |
| Redaction placeholder | writing a placeholder back into a file would destroy the real secret | `deny` |
| Secrets in prompts and results | API keys, tokens, passwords, private keys, base64 and hex dumps | redacted |

The exact patterns, exceptions and false positives are listed in [Rules and redaction](docs/rules.md).

## Installation

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
  { "action": "integration.use", "resource": "plugin:/path/to/plugin_opencode", "effect": "allow" }
]
```

A project can still remove the plugin or replace its options. See [Protecting the plugin from project configuration](docs/configuration.md#protecting-the-plugin-from-project-configuration) for the full protection.

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
| `rules` | `[]` | Extra local rules: `{ "id", "pattern", "flags"?, "verdict": "deny" \| "ask", "reason", "tools"? }`. |
| `outputCheck` | off | Also ask the decision model whether an output still holds a secret in clear. |
| `dangerousCommands`, `sensitiveFiles`, `decisionModel`, `scripts`, `redactOutputs`, `redactPrompt`, `redactWire` | `true` | Turn a feature on or off. |
| `debug` | `false` | Log every decision and every redaction count. |
| `logFile` | `~/.local/share/opencode/log/guard.log` | Plugin log file; `false` means stderr only. |

Full reference, defaults, environment substitutions and edge cases: [Configuration](docs/configuration.md). Model choices, thresholds and local serving: [Decision model](docs/decision-model.md).

## Logs

The start line states the model, the confirmation mode and whether the system configuration enforces the plugin. With `debug: true`, each line shows the verdict, its source (`local`, `model`, `cache`…) and the duration of the model call.

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
