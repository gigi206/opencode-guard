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
| `ruleOverrides` | `{}` | One built-in rule set by its identifier: `{ "<rule>": "off" \| "allow" \| "ask" \| "deny" \| "model" }` (`"allow"` is the same as `"off"`); see [Setting one rule](#setting-one-rule-ruleoverrides). `"off"`, `"allow"`, `"ask"` and `"model"` apply only if your global configuration declares them too. |
| `localAsks` | `"ask"` | `"model"` (in any case): the confirmations of the built-in rules without a setting are decided by the decision model; see [Letting the decision model decide local confirmations](#letting-the-decision-model-decide-local-confirmations-localasks). Applies only if your global configuration declares it too. |
| `selfProtectionByModel` | `false` | `true`: `localAsks: "model"` and `"model"` in `ruleOverrides` also reach the confirmations of the always-active rules (self-protection), except those about a change of the plugin's settings, a recognized launch of another OpenCode with its configuration or plugins changed or approving its own confirmations, and the OpenCode server API. Applies only if your global configuration declares it too. |
| `profile` | `"standard"` | `"credentials-only"` sets the default of `dangerousCommands`, `decisionModel` and `scripts` to `false`; see [Profile](#profile-profile). Applies only if your global configuration declares it too. |
| `agents` | `{}` | Settings for one agent: `{ "<agent>": { <policy settings> } }`; see [Settings by agent and by project](#settings-by-agent-and-by-project-guardjson). |
| `projects`, `trustedProjects` | none | Settings for a project directory, and the projects whose own settings may relax; read only from the global configuration file, the system configuration and the global `guard.json`. See [Settings by agent and by project](#settings-by-agent-and-by-project-guardjson). |
| `debug` | `false` | Also log allowed actions and redaction counts. Confirmations and refusals of tool calls, and the answers to them, are always logged, and so are the local confirmations decided by the decision model. |
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

**Always on, whatever the options:** the placeholder rule (writing a placeholder would destroy the real secret); self-protection: confirmation for writes to OpenCode's configuration (global, system, project `opencode.json`/`opencode.jsonc` and `.opencode/`, and any `opencode.json`, `opencode.jsonc` or `guard.json` wherever it is), to OpenCode's service file and to the plugin directory, and for an MCP or plugin tool whose path arguments designate them, and for commands that start another OpenCode, change its service, print its password, environment or credentials, write a copy of its memory, request a pairing code, add or remove a plugin or an MCP server, or call its server API other than a known read, or use an OpenCode subcommand unknown to the plugin, and for a command whose program is known only when it runs (a command substitution joined to other characters in the command word, unless the word starts with it and a `/` follows it) or could not be determined (a command word longer than 1,024 characters that contains a quote, a backquote, `$` or a backslash, a command too complex to read, or an internal error of the analysis) (rules `self-protection`, `nested-opencode`, `opencode-service`, `opencode-server-api`), so that the agent cannot turn the other protections off without asking; your own `rules`; redaction of everything sent to the decision model and of the log; `askAs`.

To change a single rule rather than a whole group, see [Setting one rule](#setting-one-rule-ruleoverrides); to keep only the credential protections, see [Profile](#profile-profile).

Each option set to `false` is listed in the log at startup (`INFO active (…; disabled: …)`) with a warning. Like the other options, these can be set by a project's `opencode.json`, for example `"redactOutputs": false` for a repository full of fake test secrets; a repository you clone can therefore turn a protection off, as it can already remove the plugin (see [Protecting the plugin from project configuration](#protecting-the-plugin-from-project-configuration)).

## Setting one rule (`ruleOverrides`)

`ruleOverrides` maps the identifier of a built-in rule, as listed in [Rule identifiers](rules.md#rule-identifiers), to a setting (in any case):

| Setting | Effect |
|---|---|
| `"off"` or `"allow"` | The rule no longer asks or refuses: the call is judged as if it did not exist, by the other rules, then by the decision model if it is on. The two values are the same setting; the start line of the log shows `off`. |
| `"ask"` | A refusal by this rule becomes a confirmation, and every confirmation by this rule stays with you: the decision model never decides it in your place, also where it would otherwise decide (heredoc data, CodeMode code). |
| `"deny"` | A confirmation by this rule becomes a refusal, also where the decision model would otherwise decide (heredoc data, CodeMode code) and in a script written then run, where the shell rules otherwise only ask. Its refusals are unchanged. |
| `"model"` | A confirmation by this rule is decided by the decision model, as described in [Letting the decision model decide local confirmations](#letting-the-decision-model-decide-local-confirmations-localasks). Its refusals are unchanged. |

```jsonc
"ruleOverrides": { "git-reset-hard": "off", "secret-file-network": "ask", "privilege": "deny", "eval": "model" }
```

- A setting on a rule wins over its group switch: `"ask"`, `"deny"` or `"model"` turns the rule on even with `dangerousCommands: false` or `sensitiveFiles: false`, and `"off"` (or `"allow"`) turns it off in an active group. It also wins over `localAsks`: a rule set to `"ask"` keeps asking you when `localAsks` is `"model"`.
- The always-active rules (`placeholder`, `self-protection`, `nested-opencode`, `opencode-service`, `opencode-server-api`, `guard-cli`) accept only `"deny"`, and `"model"` when `selfProtectionByModel` is retained (never for `guard-cli` or `opencode-server-api`, nor for `placeholder`, which only refuses): `"off"`, `"allow"` and `"ask"` are ignored with a warning, and so is `"model"` without `selfProtectionByModel`. `internal-error` and the identifiers of your own `rules` cannot be set (a user rule that reuses a built-in identifier makes it unsettable). An unknown identifier or an invalid value is ignored with a warning.
- Each setting applies to every finding of its rule before the findings of a call are combined: a rule set to `"off"`, `"allow"` or `"ask"` never takes the place of another rule's refusal or confirmation, whether in the command, its other readings, the scripts it runs or the shell sub-commands OpenCode checks at permission time. A rule turned off can leave a weaker rule in place: with `"rm-critical": "off"`, `rm -rf ~` still asks under `rm`.
- The retained settings are listed in the start line of the log (`rule overrides: git-reset-hard off, …`).

## Letting the decision model decide local confirmations (`localAsks`)

By default, a confirmation asked by a local rule stays with you: the decision model only adds its opinion to the reason. With `"localAsks": "model"`, the confirmations of every built-in rule without a setting are decided by the decision model instead; `"model"` in `ruleOverrides` does the same for one rule. The setting of a rule wins: with `"localAsks": "model"`, a rule set to `"ask"` still asks you, and one set to `"deny"` refuses.

- **The model decides only when it judged the whole input.** It then allows, asks you or refuses, like for an action that no local rule matches, and the reason says so (`privilege escalation, left to the decision model by localAsks, decided by nox-4b: risk 0.10/3, …`). If the model is disabled or unreachable, if its answer is invalid, or if the input was cut to `maxStateChars`, the confirmation stays with you.
- **Refusals never change**: a refusal by a local rule stays a refusal, and `"model"` on a rule only reaches its confirmations.
- **Only the model of your global configuration allows**: the decision model allows a confirmation only if its address, model name and the other settings its verdict depends on (`decision.protocol`, `timeoutMs`, `apiKey`, `headers`, `maxStateChars`, `secretPatterns`, `thresholds`) are those your global configuration file or the system configuration declares for this plugin, and the system configuration when it declares the plugin, or else the global sources, switch it on, or in a trusted project; otherwise it may refuse, but the confirmation stays with you, with a startup warning (see [Decision model](decision-model.md)). The same holds for the two built-in exceptions, heredoc data and CodeMode's `fetch`.
- **A confirmation you must give always comes first.** When a call has several findings, a refusal wins, then a confirmation that stays with you, then one the model decides: one rule left to the model never hides another rule's confirmation, nor one found in another reading of the command, in a script it runs, or in the shell sub-commands OpenCode checks at permission time.
- **Never left to the model**, whatever the setting: an internal error (`internal-error`); a confirmation born from a check the plugin could not finish (a limit on what it reads, a command word whose program is known only when the command runs or cannot be determined, an OpenCode command line it cannot read, a command too complex to read, a write target relative to the launch directory or known only when the command runs); a refusal found only inside heredoc data or code given to an interpreter, which becomes a confirmation; a script written then run by the command; your own `rules`; and the read-only tools and the task list (`read`, `glob`, `grep`, `todowrite`), for which the model is never consulted. The rules about dynamic execution (`eval`, `xargs-dynamic-exec`, `parallel-dynamic-exec`, `dynamic-shell-source`, `git-config-alias`…) are ordinary rules: their confirmations are left to the model like the others.
- **Self-protection** (the always-active rules) stays with you unless `"selfProtectionByModel": true` is set as well; the `placeholder` rule only refuses and is not affected (`"model"` on it is ignored with a warning). What changes the plugin's settings is never left to the decision model, even then: running the [`guard` command](#the-guard-command) (`guard-cli`), writing a `guard.json`, an `opencode.json` or an `opencode.jsonc` (recognized by their names wherever they are, also under a directory known only once the shell expands it), an OpenCode configuration directory itself, its `plugin` or `plugins` directory (code OpenCode loads), the plugin directory or OpenCode's service file (`service.json`, `service-<channel>.json` and their backup copies under the service directories, which hold the service's environment and settings), with a tool or a shell command, a link to them included, and a write to an OpenCode location whose links could not all be followed (it may lead to them), `opencode plugin add`/`remove` or `opencode mcp add`, and `opencode service set`/`unset`. Nor, by your decision, a launch of another OpenCode that the plugin recognizes (`opencode run`, `serve`, `web`, `acp` or `attach`, or with `--auto`; `opencode` alone, without a subcommand, is recognized only with `--auto`, see [Local rules](rules.md#local-rules)) with an option that approves its own confirmations (`--auto`, `--yolo`, `--dangerously-skip-permissions`) or with a variable that changes its configuration or plugins (`OPENCODE_CONFIG`, `OPENCODE_CONFIG_CONTENT`, `OPENCODE_CONFIG_DIR`, `OPENCODE_CLI_CONFIG_CONTENT`, `OPENCODE_CONFIG_PROJECT_DISABLE`, `OPENCODE_DISABLE_PROJECT_CONFIG`, or `XDG_CONFIG_HOME`, `XDG_CACHE_HOME` and `HOME`, from which its global configuration and its npm plugins are found), and a call to the OpenCode server API (rule `opencode-server-api`: the routes and `opencode api` calls described in [The server API](rules.md#unprotected-agent-unprotectedagent), `opencode auth export` and `opencode debug heap-dump`, which call it; not a known read, nor a call to another local service). The rest of self-protection (agents, commands, skills… in a configuration directory, another OpenCode launched without these options and variables, OpenCode's other service subcommands) can be left to it.
- **Shell sub-commands**: once the model has allowed a command on its whole input, the confirmations that a setting leaves to the model are not asked again for the sub-commands OpenCode checks at permission time; any other confirmation, a refusal, or another call still applies.
- **Unattended mode** (`askAs: "deny"`): a confirmation the model leaves to you, or that stays with you, is refused as before.
- **Log**: a local confirmation decided by the model is logged at the info level with its rule and the model's verdict (`shell → allow (model, rule privilege): …`). The start line shows `local asks: model` and `self-protection by model` when retained; if the decision model is disabled, a startup warning says these settings do nothing and the confirmations stay with you.

**Risk.** The decision model reads the command, including its comments, strings and heredoc bodies, written by the agent: text placed there can steer its answer. A confirmation left to the model therefore protects less than one you give yourself. Keep `"model"` for rules whose confirmations you find repetitive and low in risk, and leave self-protection and credential files with you.

## Profile (`profile`)

`"standard"` (default) or `"credentials-only"`. The latter sets the default of `dangerousCommands`, `decisionModel` and `scripts` to `false`: the credential file and outgoing secret rules, redaction, self-protection and your own `rules` remain. An option given explicitly wins (`"profile": "credentials-only", "dangerousCommands": true` keeps the rules for dangerous actions). An invalid value gives a warning and `"standard"`. The start line of the log then shows `profile: credentials-only`.

## Relaxations come from the global configuration

A project's `opencode.json` can replace the plugin's options (see [Protecting the plugin from project configuration](#protecting-the-plugin-from-project-configuration)). A rule set to `"off"`, `"allow"`, `"ask"` or `"model"`, `"localAsks": "model"`, `"selfProtectionByModel": true` and the `credentials-only` profile are therefore applied only if your global configuration file (`$OPENCODE_CONFIG_DIR`, or `$XDG_CONFIG_HOME/opencode`, or `~/.config/opencode`, as OpenCode resolves it, `opencode.json` or `opencode.jsonc`) or the system configuration declares this plugin with the same value for that entry (`"allow"` and `"off"` count as the same value). Otherwise each one is ignored with a warning that names the entry and says why (file missing or unreadable, not valid JSON, plugin not declared, value not set there). If these files cannot be checked at all, every relaxation is ignored, never applied. `{env:…}` references in them are resolved with the server's environment, as OpenCode does; a `{file:…}` reference is not followed, so its value does not match. They are read once, at startup. In a [trusted project](#settings-by-agent-and-by-project-guardjson), these relaxations are kept without that check. The decision model follows the same rule: it allows a confirmation only with the address, model and other settings your global or system configuration declares (see [Letting the decision model decide local confirmations](#letting-the-decision-model-decide-local-confirmations-localasks)).

`"deny"` is accepted from any configuration, and the existing switches (`dangerousCommands`, `sensitiveFiles`, `decisionModel`, `scripts`…) can still be set by a project. `credentials-only` only sets switches that a project can already set on its own: for the profile, this check keeps the rule the same for every relaxation rather than closing a gap.

## Settings by agent and by project (`guard.json`)

The **policy settings** (`profile`, `ruleOverrides`, `localAsks`, `selfProtectionByModel`, `dangerousCommands`, `sensitiveFiles`, `scripts`, `decisionModel`) can also be set for one agent, for one project, and in dedicated files. The other options (decision model, `askAs`, log, `rules`, redaction switches, `outputCheck`…) stay in the plugin options only; anywhere else they are ignored with a warning.

**Files.** `guard.json` in OpenCode's global configuration directory (the same one as above), and `guard.json` in a project's `.opencode` directory. Project files are looked up like OpenCode's own `.opencode` directories: in the session directory and every parent directory up to `/`, the closest one winning (so a `~/.opencode/guard.json` applies to every project under your home directory). OpenCode itself neither loads nor reports these files. A file is plain JSON, an object with the policy settings, `agents`, and in the global file only `projects` and `trustedProjects`. It is read at startup and read again when it changes: the files are checked at most every 2 seconds, on the next tool call, never read on every call. A file that is not valid JSON, is not an object, is larger than 64 KiB, is a symbolic link or cannot be read is ignored as a whole, with a warning that never quotes its content; an unknown key is ignored with a warning. Writing into OpenCode's configuration directories, `.opencode` included, already asks for your confirmation (self-protection).

**Two layers.** The **global layer** is, from lowest to highest: the plugin options of your global configuration file, the global `guard.json`, then the `projects` sections that match the session directory. The **project layer** is what the effective plugin options change from your global file (a project's `opencode.json` can replace them), then the project `guard.json` files. The project layer is laid over the global one setting by setting: what makes the plugin stricter always applies; what makes it less strict applies only in a **trusted project**, and is otherwise ignored with a warning. For the effective plugin options, the rule of [Relaxations come from the global configuration](#relaxations-come-from-the-global-configuration) still holds (a value the global or system configuration also sets is kept), and their switches set at the top level are accepted as before.

**What relaxes.** A setting relaxes when it makes some finding less severe than the value it replaces: refusal, then confirmation, then a confirmation left to the decision model, then nothing (`"off"`/`"allow"`). The plugin checks this on every built-in rule with the same functions it uses on each call, as if each rule could both refuse and ask: `"ask"` therefore counts as a relaxation for any rule (it would lower a refusal), even for a rule that only asks, where it in fact only hardens (and is set aside, with a warning, outside the global sources and trusted projects); likewise `"model"` for any rule while the decision model is on. `"localAsks": "model"`, `"selfProtectionByModel": true`, the `credentials-only` profile and a switch set to `false` relax; so does `"decisionModel": true` when confirmations are left to the model.

**Trusted projects.** `"trustedProjects": ["/home/me/work", "/home/me/src/app"]`, or `"*"` for every project, in the global configuration file, the system configuration or the global `guard.json` (anywhere else it is ignored with a warning: a project cannot trust itself). A project is trusted when its real directory is a listed one (real path) or below it: trusting a parent directory trusts every repository cloned under it later, including one you have not read. Each project `guard.json` file is judged by its own directory (the one holding its `.opencode`): a file above the trusted directory (in a parent directory, the home directory, `/tmp`…) only hardens. A listed directory that does not exist is ignored with a warning. A change of the global `guard.json` counts at the next check, without a restart.

**Projects.** `"projects": { "/home/me/work": { <policy settings>, "agents": { … } } }` in the same global sources: the section applies to that directory and below, in the global layer (it may relax), after the global `guard.json`; when several match, the closest directory comes last.

**Agents.** `"agents": { "<agent>": { <policy settings> } }` in any source, also inside a `projects` section. For a call, the resolved layers come first, then the section of the **main agent** of the session, then the section of the **subagent** making the call, if it has one: `ruleOverrides` merge rule by rule, the other settings key by key. A subagent without a section uses the main agent's settings; a subagent's section may harden or relax them. A section from a project source follows the project layer: it relaxes only in a trusted project.

- The main agent is the session's agent when you sent your last prompt, provided its mode is `primary`; for a subagent's session, it is the main agent of the root session. It is recorded by the plugin at each prompt, while the settings in force have an agent section (otherwise no session is read): a section added while OpenCode runs counts from your next prompt. An agent switch made by the model during a turn does not count until your next prompt: only what the new agent's section makes stricter applies.
- When the main agent is unknown (plugin reloaded since your last prompt, no prompt since the first agent section was added, session that cannot be read, agent whose mode is not `primary`), only what makes the calling agent's section stricter applies: never less strict than the layers.
- **Risk.** The model chooses which subagent it launches. A subagent whose section relaxes a rule lets the model obtain that relaxation by launching it; keep relaxing sections for subagents whose purpose needs them.

```jsonc
// ~/.config/opencode/guard.json
{
  "ruleOverrides": { "git-reset-hard": "ask" },
  "agents": { "reviewer": { "dangerousCommands": false } },
  "projects": { "/home/me/sandbox": { "ruleOverrides": { "rm": "off" } } },
  "trustedProjects": ["/home/me/work/app"]
}
```

**Log.** The start line `settings by agent and by project (guard.json: …; agent sections: …; project sections: …; this project: trusted|not trusted)` lists the files read, the agents with a section, the matching project sections and the trust of the session directory; `guard.json re-read (…)` is logged at the info level each time the files change, followed by their warnings. Without any `guard.json` file and without `agents`, `projects` or `trustedProjects`, nothing changes and nothing is logged.

## The `guard` command

`bin/guard`, in the plugin directory, lists the rules and reads or writes these settings from a terminal. It runs with the Node.js found on the `PATH`, which reads the plugin's TypeScript files directly (no build step, no dependency): that Node.js must run TypeScript files without any option (a version that strips types by default; an older one refuses the launcher). A link makes it available everywhere, for example `~/.local/bin/guard` pointing to it.

**The terminal's environment.** Every command reads the terminal's environment, not the OpenCode server's: the global configuration directory (`OPENCODE_CONFIG_DIR`, `XDG_CONFIG_HOME`, `HOME`), the `{env:…}` references of the configuration files, and for `last` the log file (`XDG_DATA_HOME`, `HOME`, `logFile`). When the server runs with another environment (a background service), the command may read other files than the plugin does.

**What it prints.** Every line goes through the plugin's redaction: its built-in formats, the `secretPatterns` and the decision model's key and headers of the global and system configurations, and the terminal's secret environment variables. It also replaces control characters (C0, line breaks included, C1 and bidirectional controls) with a space, as the plugin's log does: a repository's `guard.json` quoted in a line cannot change the display. In a terminal, `guard rules`, `guard show` and `guard last` print blocks, each under a banner of its own color and a separator line: the built-in rules grouped by the option that turns them off, your rules each with its pattern on the next line, the sources read, the project's trust, the settings in force (in green when they keep a protection, in yellow when they relax one, a rule's setting in the colors of `guard rules`) and those set aside, the latest asks and denials by day with their reason below them. Columns are aligned and texts wrapped to the terminal's width (at least 60 columns), a confirmation's model opinion on a dimmed line of its own; headings, verdicts and states are colored unless `NO_COLOR` is set or `TERM` is `dumb`. Redirected to a file or another program, they print one line per item, as before. Each field is redacted before it is wrapped, and colors are added only to a line that the redaction leaves unchanged.

| Command | What it does |
|---|---|
| `guard rules [--builtins\|--custom]` | lists the built-in rules in the plugin's order (identifier, group, own verdict, what they check), then your own `rules` as the plugin reads them (identifier, verdict, tools, reason, pattern) from the system configuration when it declares the plugin, otherwise from the global one, with the rules it sets aside and why; a project's `opencode.json` can replace that list, which the command does not see. `--builtins` or `--custom` keeps one of the two |
| `guard allow <rule>`, `guard off <rule>`, `guard ask <rule>`, `guard deny <rule>`, `guard model <rule>` | sets the rule in `ruleOverrides` of the global `guard.json` (`allow` is written as is and read as `"off"`) |
| `guard reset <rule>` | removes that setting (an object left empty is removed), and says if another source still sets the rule there |
| `guard trust [<dir>\|--all]`, `guard untrust [<dir>\|--all]` | adds or removes the directory's real path in `trustedProjects` of the global `guard.json` (`--all`: `"*"`) |
| `guard show [--agent <name>]` | the policy settings in force for the current directory (and that main agent), each with the file and section it comes from, the project's trust, and the settings set aside with the reason |
| `guard last [<count>]` | the latest confirmations and refusals of the plugin's log (same file, `logFile` included), with their time, rule and reason as logged; 20 by default, at most 200 |
| `guard help` | the commands |

**Scopes.** A setting goes to the top level of the global `guard.json`; `--agent <name>` writes it in `agents["<name>"]`, `--project [<dir>]` in `projects["<real path>"]` of the same global file, and both together in `projects[…].agents[…]`. Without a directory, the project is the first directory, going up from the current one, that holds a `.git` entry (directory or file), otherwise the current directory; no program is run to find it. `trust` and `untrust` without a directory take the same project. A `projects` section lives in your global file: it takes effect without trusting the project and leaves the repository untouched.

**What it writes.** Only the global `guard.json`, in OpenCode's global configuration directory resolved from the terminal's environment as OpenCode does (`OPENCODE_CONFIG_DIR`, then `$XDG_CONFIG_HOME/opencode`, then `~/.config/opencode`); when the OpenCode server runs with another environment (a background service), check the path printed after each change. Never an `opencode.json`, never a project's `guard.json`. The file is replaced atomically (an exclusive temporary file in the same directory, then renamed), created with mode 600, its mode kept otherwise, and its unknown keys kept. If the file changed between the command's read and its write (another `guard` command, an editor), nothing is written: run the command again. Nothing is written, with the reason, for a file the plugin would ignore (symbolic link, not a regular file, unreadable, not valid JSON, not an object, larger than 64 KiB, or a result larger than that), a section that is not an object, a directory that does not exist (except for `reset` and `untrust`), and a value the plugin would not apply in that scope, with the plugin's own warning: unknown identifier, `internal-error`, one of your `rules`, `"off"`, `"allow"` or `"ask"` on an always-active rule, `"model"` on one unless `selfProtectionByModel` is retained in the same scope (never for `guard-cli` or `placeholder`). `trust` warns for `/`, your home directory and `--all`: every project below becomes trusted, and its settings may relax yours.

**Without a restart.** The plugin checks its `guard.json` files at most every 2 seconds, on the next tool call: a setting applies from the following calls; an agent section counts from your next prompt, when the main agent is recorded.

**What `show` sees.** It computes the settings only from the files it reads itself: the global and system configuration, the global `guard.json` and the project ones. It does not see the plugin options OpenCode merges from a project's `opencode.json` (or `OPENCODE_CONFIG_CONTENT`), and says so: where they are set, the plugin may run with other settings, which its log shows at startup. A setting of the system configuration shows `system configuration` as its origin. It never prints another option of the configuration (decision model address, headers, keys…).

**No confirmation in the terminal.** The command asks nothing: what stops the agent is the plugin's own confirmation. Any shell command that runs it is a confirmation under the always-active rule `guard-cli`, whatever the subcommand (`rules`, `show` and `last` included): by its name `guard` as the program run (another program named `guard` asks too), or by the path of its launcher (a file `…/bin/guard` in any directory, so a link to it too) or of a module of the plugin's `src/cli/` directory, run directly or through an interpreter, or only named. It is never left to the decision model, whatever `localAsks`, `"model"` or `selfProtectionByModel`; `"guard-cli": "deny"` refuses it outright.

## Disabling

Remove the plugin entry from the `plugins` array in `opencode.json` (and from `/etc/opencode/opencode.json` or `OPENCODE_CONFIG_CONTENT` if you [use them](#protecting-the-plugin-from-project-configuration)), or restore the backup made before activation. To keep the local rules and redaction but disable the decision model, set `"decisionModel": false`, remove `decision.baseURL` or unset the key variable. To turn off only part of the plugin, see [Turning features off](#turning-features-off).
