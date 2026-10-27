# Configuration

## Configuration reference

All options live under `options` in the plugin entry.

| Option | Default | Description |
|---|---|---|
| `decision.baseURL` | — (required) | Versioned base URL, without the final path (e.g. `https://ai-gateway.example.com/v1`). Missing, empty or invalid: the decision model is disabled and only the local rules apply. Plain `http://` to a host that is not local (anything but `localhost`, `*.localhost`, `127.x.x.x` and `[::1]`) triggers a warning, since the key and the redacted tool calls would travel unencrypted; the model stays enabled. |
| `decision.protocol` | `"chat"` | `"chat"` for an OpenAI-compatible gateway, `"systemone"` for a direct System One API (see [Protocols](decision-model.md#protocols)). |
| `decision.model` | — (required) | Model name, e.g. `"nox-4b"`, or `"jev-latest"` for TypeSafe AI's Jev (experimental data level, hosted outside the EU). Missing or empty: the decision model is disabled. |
| `decision.apiKey` | — | Key sent as `Authorization: Bearer …`, normally a variable reference such as `"{env:NOX_API_KEY}"`. Absent or `null`: no authentication. Empty (referenced variable not set): the decision model is disabled. Never written to the log, and redacted like any known secret; a key shorter than 8 characters cannot be redacted verbatim, and a warning says so (also for short authentication headers in `decision.headers`). |
| `decision.timeoutMs` | `5000` | Timeout per call, from 100 to 60000. OpenCode applies no timeout to hooks, so this one is mandatory. A call that times out is retried once, so the wait can reach twice this value. |
| `decision.headers` | `{}` | Extra HTTP headers. Values are trimmed; a value containing a line break, or an invalid header name, is ignored with a warning. Every value of 8 characters or more is treated as a secret and redacted verbatim everywhere (outputs, requests, log), whatever the header's name, so a non-secret header (a title, an API version) is redacted too, and a file that contains its value can then no longer be rewritten (placeholder rule). |
| `jev` | — | Former name of `decision`, still accepted with the same settings; warnings then name it `jev.…`. If both are set, `decision` is used, even when invalid, and `jev` is ignored with a warning. |
| `askAs` | `"ask"` | `"deny"` (in any case) turns every confirmation request into a refusal (unattended mode, see [Confirmations and run modes](rules.md#confirmations-and-run-modes)). Typically `"{env:GUARD_ASK_AS}"`; empty means `"ask"`. |
| `thresholds` | see [Thresholds](decision-model.md#thresholds) | Decision thresholds. |
| `redactPrompt` | `true` | Redact secrets typed in the prompt. The redacted text is what gets stored. |
| `dangerousCommands`, `sensitiveFiles`, `decisionModel`, `scripts`, `redactOutputs`, `redactWire` | `true` | Turn a feature on or off; see [Turning features off](#turning-features-off). |
| `debug` | `false` | Log every decision and every redaction count. |
| `logFile` | `$XDG_DATA_HOME/opencode/log/guard.log` | Plugin log file, falling back to `~/.local/share/opencode/log/guard.log`. `false` means stderr only. A leading `~` is expanded; a relative path triggers a warning. If the file cannot be created or written, the plugin switches once to the default log file and writes a warning there (the error code, never the system message), since the OpenCode service's stderr cannot be read. The log is never written through a symbolic link: a log file that is one, at startup or later, is treated the same way. A log file that is a credential file or a protected location (OpenCode's configuration, the plugin directory, startup files, `~/.ssh/`, git hooks, `/etc`) is refused at startup with a warning, and the default log file is used; the default path itself is always accepted. |
| `maxStateChars` | `4000` | Maximum size of the redacted input sent to the decision model, from 200 to 100000. Above 8000, a warning: the model is less accurate with a long state, and a state over its limit leads to a confirmation. |
| `cacheTtlMs` | `600000` | How long a verdict is cached (10 min), at most 3600000 (1 h). A verdict is reused only for the same tool, input, agent and directory, i.e. everything the model receives. Errors are never cached. Eviction is first-in, first-out. |
| `cacheMax` | `500` | Maximum number of cached verdicts, at most 10000. |
| `unprotectedAgent` | none | ID of an agent for which the plugin does nothing (no rules, no decision model, no redaction), selected with Shift+Tab; see [Unprotected agent](rules.md#unprotected-agent-unprotectedagent). Built-in agents (`build`, `plan`…) are refused. |
| `rules` | `[]` | Extra local rules, as an array: `{ "id", "pattern", "flags"?, "verdict": "deny" \| "ask", "reason", "tools"? }`. `tools` defaults to `["shell"]`; a single name such as `"*"` is also accepted. `"*"` matches every tool and is tested against the serialized input. OpenCode v1 tool names are mapped with a warning (`bash` → `shell`, `task` → `subagent`, `apply_patch` → `patch`), so a copied rule still applies; `todowrite` (present in v2 only when `experimental.todo` is enabled) and patterns that mention the renamed arguments `filePath` (now `path`) or `subagent_type` (now `agent`) are reported. The id `placeholder` is reserved for the built-in redaction placeholder rule: a rule given that id gets `custom-<index>` instead (its position in `rules`, counted from 0), with a warning. |
| `secretPatterns` | `[]` | Extra secret patterns, as an array: `{ "type", "pattern" }` (regular expression source), or the pattern source alone (type `custom`). The type names the placeholder (`]` replaced by `_`, at most 200 characters). |
| `allowlist` | `[]` | Strings that are never redacted, compared exactly after trimming their surrounding spaces. A non-string entry is ignored with a warning (index and type only). |
| `outputCheck` | off | `true`, or `{ "enabled", "threshold", "timeoutMs" }` (`enabled` defaults to `true` and turns the check off when `false`; defaults 0.45 and 1100 ms, `timeoutMs` from 100 to 60000): the decision model also checks tool outputs for a secret in clear; effective only if your global configuration file declares it too, with the same `decision.baseURL`. See [Output check](decision-model.md#output-check-outputcheck). |

Full example:

```jsonc
{
  "plugins": [
    {
      "package": "/path/to/plugin_opencode",
      "options": {
        "decision": {
          "baseURL": "https://ai-gateway.example.com/v1",
          "protocol": "chat",
          "model": "nox-4b",
          "apiKey": "{env:NOX_API_KEY}",
          "timeoutMs": 5000,
          "headers": {}
        },
        "thresholds": { "denyNoul": 0.9, "askNoul": 0.7, "denyRisk": 2.5, "askRisk": 1.5, "minConfidence": 0 },
        "askAs": "{env:GUARD_ASK_AS}",
        "redactPrompt": true,
        "debug": false,
        "logFile": "/path/to/guard.log",
        "rules": [
          { "id": "no-prod", "pattern": "--env=prod", "verdict": "deny", "reason": "production deployments are forbidden", "tools": ["shell"] }
        ],
        "secretPatterns": [{ "type": "internal", "pattern": "INT-[A-Z0-9]{24}" }],
        "allowlist": []
      }
    }
  ]
}
```

Numbers and booleans may also be given as strings (`"0.7"`, `"0,7"`; `"true"`/`"false"` in any case, `"1"`/`"0"`), as produced by `{env:…}`; an empty string means "not set". Invalid values fall back to their defaults, and unknown (e.g. misspelled) options are ignored; both are reported as warnings in the plugin log (never with the key's value, nor the content of an object). The model settings go under `decision`; `decisionModel` is only the on/off switch, and a warning says so if it receives an object.

## Protecting the plugin from project configuration

OpenCode applies a project's `opencode.json` (and `.opencode/opencode.json`) **after** the global one. A repository you open can therefore, without any action from the agent:

- remove the plugin: `"plugins": ["-guard"]` (by plugin id) or `"plugins": ["-*"]`. An entry with the path, `"-/path/to/plugin_opencode"`, has no effect;
- weaken it, by declaring the same `package` with its own `options` (for example without `decision`), which replace yours;
- block it with a policy: `"policies": [{ "action": "integration.use", "resource": "plugin:*", "effect": "deny" }]`.

The environment variables `OPENCODE_CONFIG` and `OPENCODE_CONFIG_CONTENT` can do the same for a process started with them; the agent cannot set them for a nested OpenCode without confirmation (see [Local rules](rules.md#local-rules)).

To check what applies in a given project, run `opencode plugin list` in its directory: `guard` must be listed.

**Minimum: a global policy.** Global policies outrank project ones. In the global `opencode.json`:

```jsonc
"policies": [
  { "action": "integration.use", "resource": "plugin:/path/to/plugin_opencode", "effect": "allow" }
]
```

This stops a project from blocking the plugin with a policy (with a project policy denying `plugin:*`, `opencode plugin list` still shows `guard`). It needs no restart and no duplicated setting, but removal (`"-guard"`) and replaced options remain possible.

**Full protection** needs a configuration layer loaded after the projects. Two ways, each with a cost:

- **System configuration** (requires root): `/etc/opencode/opencode.json` on Linux (`/Library/Application Support/opencode` on macOS, `%ProgramData%\opencode` on Windows) is loaded last and is not affected by `OPENCODE_CONFIG_DIR`. Declare the plugin there with its full options, plus the policy above. The file is owned by root: the agent cannot change it without `sudo`, which requires confirmation. The start line of the plugin log then ends with `system config: enforced`.
- **`OPENCODE_CONFIG_CONTENT` in the server environment** (stays in your home): `{"plugins": [<the full plugin entry>]}`, set with `opencode service set env` for the background service. The options are then duplicated, the variable's win, every change needs the variable regenerated and the service restarted (which interrupts sessions), and a `--standalone` process gets the protection only if the variable is also in its environment.

In either layer, also set `"experimental": { "location_idle_timeout": "60 minutes" }` (OpenCode's default; any other duration, or `false` to never unload): OpenCode reads this delay from the last configuration that sets it, so without it a project can shorten it and make the plugin forget sooner the scripts it saw written (see [Scripts written then run](operations.md#known-limitations) in the known limitations).

In both cases, **keep the entry in the global file too**, with the same options. OpenCode keeps the first plugin with a given id, in loading order. Without a global entry, a project could declare the same directory under another spelling (`/path/to/plugin_opencode/`, a symbolic link) with weaker options: loaded first, that variant would run and the later entry would be dropped as a duplicate. With the global entry loaded first, the later entry applies its options to it and the project variant is the one dropped. (For the system file, this follows from OpenCode's loading order; not verified.)

**Not covered by any of these:** a repository that ships its own plugin (`.opencode/plugins/`, or `plugins` pointing to a directory of the repository) runs code as soon as OpenCode opens it, which no plugin can prevent. Only open repositories you trust.

## Turning features off

Each feature has a boolean option, `true` by default (same style as `redactPrompt`). Set it to `false` in the plugin options:

| Option | What `false` turns off |
|---|---|
| `dangerousCommands` | Built-in local rules for dangerous actions: deletions (`rm`, `find -delete`, home directory moves), destructive git commands, devices and disk formatting, `sudo` and permission changes, `kill`, shutdown, `crontab`, installs and publishing, containers and infrastructure, downloaded scripts that are run, `eval`, dynamic execution through launchers (`xargs`, GNU `parallel`), interpreters and `awk`, shell startup files and `git` settings that name a program to run, running a file created by the agent that can no longer be checked, uploads and remote copies, network access by inline interpreter code, writes to startup files, `~/.ssh/`, git hooks and `/etc` (also as a path argument of an MCP or plugin tool), and CodeMode network access. Also in the shell sub-commands checked at permission time. |
| `sensitiveFiles` | Built-in local rules for credential files and outgoing secrets (including the reading of file headers to recognize private keys): reading a credential file (also as a path argument of an MCP or plugin tool), a credential file or a secret in a network command or in a command whose inline interpreter code makes network requests, an environment dump sent over the network, a secret in a web request, a search, MCP arguments or CodeMode code. |
| `decisionModel` | Calls to the decision model; the `decision` settings are kept. Same as removing `decision.baseURL`. |
| `scripts` | Checks of [scripts written then run](decision-model.md#decision-model). |
| `redactOutputs` | Redaction of tool results and errors at the source: secrets are then stored in the history and shown in the interface. |
| `redactPrompt` | Redaction of the typed prompt. |
| `redactWire` | The safety net on model requests (HTTP bodies, WebSocket frames). |

Turning the local rules off does not mean "allow everything": with the decision model enabled, every action it does not stop runs, but it is still judged. The model alone would allow many of the actions the local rules send to confirmation (see [Decision model](decision-model.md#decision-model)). With both rule options and the decision model off, only the protections below remain.

**Always on, whatever the options:** the placeholder rule (writing a placeholder would destroy the real secret); self-protection: confirmation for writes to OpenCode's configuration (global, system, project `opencode.json`/`opencode.jsonc` and `.opencode/`) and to the plugin directory, and for an MCP or plugin tool whose path arguments designate them, and for commands that start another OpenCode, change its service, print its password, environment or credentials, write a copy of its memory, request a pairing code, add or remove a plugin or an MCP server, or call its server API other than a known read, or use an OpenCode subcommand unknown to the plugin, and for a command whose program is known only when it runs (a command substitution joined to other characters in the command word, unless the word starts with it and a `/` follows it) or could not be determined (a command word longer than 1,024 characters that contains a quote, a backquote, `$` or a backslash, a command too complex to read, or an internal error of the analysis) (rules `self-protection`, `nested-opencode`, `opencode-service`, `opencode-server-api`), so that the agent cannot turn the other protections off without asking; your own `rules`; redaction of everything sent to the decision model and of the log; `askAs`.

Each option set to `false` is listed in the log at startup (`INFO active (…; disabled: …)`) with a warning. Like the other options, these can be set by a project's `opencode.json`, for example `"redactOutputs": false` for a repository full of fake test secrets; a repository you clone can therefore turn a protection off, as it can already remove the plugin (see [Protecting the plugin from project configuration](#protecting-the-plugin-from-project-configuration)).

## Disabling

Remove the plugin entry from the `plugins` array in `opencode.json` (and from `/etc/opencode/opencode.json` or `OPENCODE_CONFIG_CONTENT` if you [use them](#protecting-the-plugin-from-project-configuration)), or restore the backup made before activation. To keep the local rules and redaction but disable the decision model, set `"decisionModel": false`, remove `decision.baseURL` or unset the key variable. To turn off only part of the plugin, see [Turning features off](#turning-features-off).
