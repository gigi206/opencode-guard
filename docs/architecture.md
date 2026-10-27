# How it works

| OpenCode hook | Role |
|---|---|
| `tool.execute.before` | Runs on every tool call, including MCP tools and CodeMode inner calls, before OpenCode's own permission check. Applies the local rules to the full input, then the decision model (not for the read-only tools `read`, `glob` and `grep`, nor for the task list `todowrite`). `deny` fails the call and the model receives the reason, with an instruction not to evade the check (obfuscation, rewording, a script file) but to explain the block to the user; the redaction-placeholder refusal has no such instruction, since it asks for a different edit. `ask` raises a native confirmation through `ctx.permission.assert` (or becomes a refusal in [unattended mode](rules.md#unattended-mode-askas-deny)); for a local confirmation, the decision model's opinion is shown in it. |
| `permission.evaluate` | Forces the `guard` permission to `ask` and shows the reason. Also re-checks each shell sub-command extracted by OpenCode's tree-sitter parser, and can only make the decision stricter; a command you already confirmed is not asked again (for up to one hour after the confirmation), but a refusal found in its sub-commands still applies; a CodeMode script's confirmation does not cover the shell commands that the script runs. In unattended mode, turns every remaining confirmation, OpenCode's own included, into a refusal. |
| `tool.execute.after` | Redacts tool results and tool errors, so the stored history and the UI stay clean. Remembers the files the agent has just created in full, for [scripts written then run](decision-model.md#decision-model). With the optional [output check](decision-model.md#output-check-outputcheck), asks the decision model whether an output still holds a secret in clear. |
| `session.prompt` | Redacts secrets typed in the prompt. |
| `session.http.request`, `session.experimental.ws.send` | Final safety net: redacts the JSON actually sent to the provider, over HTTP and over WebSocket (the default transport for OpenAI, xAI and Azure). If the redaction itself fails (internal error), the request is blocked: nothing is sent, and the session stops with the plugin's message. |

Each part can be turned off with an option (local rule groups, decision model, scripts, redaction of tool results, of the prompt and on the wire): see [Turning features off](configuration.md#turning-features-off).

Decision flow for each tool call:

```
local rules ──deny──▶ call rejected (reason sent to the model)
     │ ask ─────────▶ confirmation prompt (the decision model's opinion is shown, it never changes the verdict)
     │ nothing (read, glob, grep, todowrite: allowed here, not sent to the model)
     ▼
decision model ──deny / ask / allow──▶ same outcomes
     │ unreachable, timeout (after one retry), HTTP error or redirection, invalid answer
     ▼
confirmation prompt
```

Principles:
- a local `deny` is final, and a local `ask` is never relaxed by the decision model, except in the two cases described under [Opinion on local confirmations](decision-model.md#decision-model) (a confirmation caused only by heredoc data, and a CodeMode script that uses `fetch` without referring to `tools` or writing a local address, when the model received the whole code);
- the decision model can only make a decision **stricter**, never override an OpenCode permission rule;
- **no secret that the redaction recognizes is ever sent to the decision model**: its input (and, with the optional [output check](decision-model.md#output-check-outputcheck), the outputs it checks) is redacted, then truncated;
- hooks that redact never throw. An exception there would fail the session, and fail it again on every retry. The one deliberate exception is the final safety net on the wire: a request that it cannot redact (internal error) is blocked rather than sent unredacted;
- an internal error never relaxes a decision: what the checks already found stands (a refusal found for one part of a command, by another check of the same tool call or for another shell sub-command still applies), and the part that could not be checked asks for confirmation.

**Self-protection.** Writing to or deleting from the plugin directory (which OpenCode hot-reloads), `~/.config/opencode/` (and OpenCode's global configuration directory wherever the server's environment puts it: `OPENCODE_CONFIG_DIR`, `XDG_CONFIG_HOME`), any `.opencode/` directory or any `opencode.json(c)` requires confirmation, also through a symbolic link or the path arguments of an MCP or plugin tool, and so do `opencode service set|unset|stop|restart` and `opencode uninstall` (they can change the environment that the settings reference through `{env:…}`, e.g. the key or `GUARD_ASK_AS`), `opencode plugin add|remove` and `opencode mcp add` (they rewrite OpenCode's configuration), and the subcommands that hand out access to the server: printing the service password, environment or settings (`opencode service get`), pairing (`opencode pair`), exporting the credentials (`opencode auth export`), writing a copy of the server's memory to a file (`opencode debug heap-dump`) and any `opencode api` call other than a known read (see “The server API” under [Unprotected agent](rules.md#unprotected-agent-unprotectedagent)). The agent therefore cannot silently disable the guard. This also applies when you use OpenCode to work on the plugin itself, and it stays active when the [feature options](configuration.md#turning-features-off) turn the local rules off.
