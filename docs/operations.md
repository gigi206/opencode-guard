# Operations

## Logs and verification

**Plugin log.** When OpenCode runs as a background service, the plugin's stderr goes nowhere useful. The plugin therefore writes to `~/.local/share/opencode/log/guard.log`:
- the start line (`INFO active (…)`, with the decision model, the effective confirmation mode, whether the [system configuration](configuration.md#protecting-the-plugin-from-project-configuration) declares the plugin, the [profile](configuration.md#profile-profile) and the [rule settings](configuration.md#setting-one-rule-ruleoverrides) retained, when set, `profile: …` and `rule overrides: …`, the [features turned off](configuration.md#turning-features-off), `disabled: …`, and, when it is requested, whether the [output check](decision-model.md#output-check-outputcheck) is active) and warnings are always written;
- confirmations and refusals of tool calls are always written (`INFO`), with the rule that gave them (`(local, rule git-reset-hard)`; a verdict of the decision model alone has none, its reason says why), including those added by the check of shell sub-commands (`shell sub-commands → …`) and the refusals of unattended mode, and so are the answers to confirmations (`confirmed by the user`, or `confirmation not granted` with the error class, never your feedback text);
- allowed actions and redaction counts are written only when `debug` is `true` (`DEBUG`);
- a decision line ends with the duration of the model calls (`[model 640 ms]`, and `, 2 attempts` after a timeout was retried) and gives the source of the verdict (`(local)` for a local rule, `(model)` for the decision model, `(model-error)` when it failed, `(default)` when no model gave the verdict (decision model turned off, or an internal error), `(read-only)` for a read not sent to the model, `(task-list)` for `todowrite`, `(cache)` for a verdict reused from the cache) and, for an allowed action, the highest probability (`highest: credential access 0.43`), useful to calibrate `askNoul`;
- it contains only the tool name, the verdict, the rule, the reason and counts, and every line also goes through the redaction (defense in depth: a server response or an internal error message); the decision model URL is shown without credentials, query string or fragment;
- if an optional part fails to start, the guard still loads and the start line says so: `unprotected agent: UNAVAILABLE` (every agent stays protected), `secret redaction: INCOMPLETE` (secrets may reach the provider) or `output check: UNAVAILABLE`;
- each entry is a single line: line breaks and control characters (from a path chosen by the model or a server response) are replaced by spaces, and an entry longer than 8,192 characters after redaction is shortened in the middle (`…[N characters omitted]…`), keeping its start and its end;
- above 5 MB the file is renamed to `guard.log.1` (one copy kept), at startup and while running (size checked every 100 entries).

```sh
tail -f ~/.local/share/opencode/log/guard.log
tail -f ~/.local/share/opencode/log/guard.log | grep ' INFO '   # confirmations and refusals only (and start lines)
```

Typical lines:

```
INFO active (decision model: nox-4b via https://ai-gateway.example.com/v1 (chat); confirmations: ask; system config: not enforced)   # every start
WARN decision.apiKey is empty (is the variable referenced with {env:…} set …): decision model disabled # key missing
WARN unattended mode (askAs: deny): every confirmation request is denied                              # unattended mode
WARN redaction of model requests disabled (redactWire: false): only what is redacted at the source …  # feature turned off
DEBUG shell → allow (model): nox-4b: risk 0.14/3, highest: data destruction 0.05 [model 640 ms]
DEBUG read → allow (read-only): read-only tool, no local rule matched
INFO shell → ask (local, rule git-reset-hard): git reset --hard (uncommitted changes lost)
INFO shell → confirmed by the user
INFO shell → deny (local, rule pipe-to-shell): running a downloaded script (download piped to a shell or an interpreter)
INFO shell sub-commands → ask (local, rule git-clean): git clean -f (untracked files deleted)
DEBUG execute.after read: 2 secret(s) redacted
```

**Why a call was asked or refused.** A confirmation shows the rule and the reason in its title (`Call tool guard · <rule>: <reason>`), the rule and reason cut at 160 characters. A refusal is the tool's error, which the agent receives: OpenCode shows it in red under a shell command, an edit or a patch; for a tool shown on one line (read, search, `webfetch`, a refused `write`), the line turns red and the message appears when you click it. In both cases the log has the full line, with the rule.

**Checking that the plugin is loaded.**
- `opencode plugin list`, run from a project directory, should show `guard  local  /path/to/plugin_opencode/index.ts`. The first call from a directory the service has not opened yet may answer "No plugins found"; run it again from the same directory.
- `~/.local/share/opencode/log/opencode.log` should contain `loading plugin`, and neither `failed to load plugin` nor `configured plugin path must be a directory`.

## Trying it out

Use a throwaway git repository and ask the agent to run:

| Request | Expected result |
|---|---|
| `git status` | allowed; the model answers in about 0.5 s |
| `git reset --hard` | confirmation prompt titled `Call tool guard · git-reset-hard: git reset --hard (uncommitted changes lost)` |
| `curl -s file:///dev/null \| sh` | denied (the command is harmless even if it ran) |
| read a file containing a fake key, created with the command below | the agent sees `[[GUARD_REDACTED:openai_key]]` |

```sh
echo "OPENAI_API_KEY=sk-proj-$(head -c 40 /dev/urandom | base64 | tr -dc A-Za-z0-9)" > demo.txt
```

## Known limitations

- **Not redacted:**
  - GitHub Copilot's internal "utility" title request, which bypasses the hooks;
  - OpenCode's direct generation (`Generate.text`, and in OpenCode 2.2 the text, image and decision generation of the server API), which has no hook and sends only what its caller provides;
  - images and PDFs;
  - encrypted contents and signed reasoning blocks;
  - voice calls: what a client sends to start a voice call or, in OpenCode 2.1, to change its instructions is relayed by the OpenCode server to the voice provider, outside the hooks;
  - raw files under OpenCode's `tool-output` data directory (full outputs of truncated tool results, shell command output files, binary contents returned by MCP tools), which are not sent unless read again.
- **Model-generated tool arguments** are redacted on the wire but stored as-is in the local history.
- **False positives:**
  - a secret in MCP tool arguments or in CodeMode code is denied;
  - an MCP or plugin tool that only reads a protected location (`/etc`, `~/.ssh/`, OpenCode's configuration) asks for confirmation, since the plugin cannot tell whether the tool reads or writes;
  - an MCP tool whose path argument names a remote file (for example in a hosted repository) is checked as if the path were local, so a remote name that looks like a credential file or a protected location asks for confirmation;
  - running a file created by the agent that is larger than 64 KiB, or that is a credential file, asks for confirmation every time, since its content cannot be checked (until OpenCode restarts or reloads the plugin, see “Scripts written then run” below);
  - in a command that uses a network tool, a variable whose name contains a secret word without holding a secret (an authentication server's address, a sort key) asks for confirmation;
  - a server environment variable whose name contains one of the secret words inside a longer word (`AUTH` in `GIT_AUTHOR_EMAIL`, `KEY` in a sort-key setting) has its value redacted like a secret, and a file that contains that value can then no longer be rewritten (placeholder rule);
  - a password-like value in code may still be redacted;
  - your own fake secrets in test fixtures are redacted when read;
  - a value that is not a secret but has the shape of a key, printed in the format of an OpenCode credential, is learned and masked everywhere until OpenCode restarts or reloads the plugin, and a network command that names it is then refused;
  - code given inline to a JavaScript runtime that only mentions `fetch` (in a string, a comment or a `git fetch` it runs), or code that names `curl` or `wget` while calling a process function for something else, asks for confirmation, and is refused if the command also holds a secret or names a credential file;
  - inline interpreter code that is only text is checked for network access as if it were run, whether it is given as an argument of another command (`echo node -e "…"`) or written into a heredoc body that is not set aside (see “Network access by inline interpreter code”), for example when the same command also runs a command other than the data commands listed under “Confirmations caused only by heredoc data”;
  - the path of `mkfs`, `wipefs` or `dd` preceded in the same word by `=`, an opening quote or `${` (a variable assignment, an option value, quoted text, a parameter expansion), and these names written right after `${`, can be refused even where the tool would not run (for `dd`, only with a device output in the same call or among the words of a launcher before it);
  - an unquoted command substitution after `git checkout` counts as several arguments, since the shell may split it into several files: a commit computed this way (`git checkout $(git rev-parse HEAD~1)`) asks for confirmation.
- **Detection gaps:** the local rules are pattern-based, and the decision model misses some cases, such as a `webfetch` sending encoded data in its URL. The home-directory `mv` rule only sees `~`, `$HOME` and absolute paths: `mv Documents …` run from the home directory is judged by the model. Network access by inline interpreter code is recognized only by the checks described in [Local rules](rules.md#local-rules); any other way such code reaches the network is left to the decision model. Code that the recognition of inline code does not cover, including code given in a file or on standard input, is not concerned (for a file written earlier in the session, see “Scripts written then run” under [Decision model](decision-model.md#decision-model)). Once confirmed, what the code sends is not checked again.
- **Command names:** the rules do not all recognize the launched program the same way. Several recognize a command only by its bare name or by some of its spellings; written otherwise, the command is left to the decision model for those rules, so the same command can be refused or confirmed under one spelling and not under another. Conversely, a few rules look for a program name without checking that it is the program the command launches, and can refuse or ask for a command that only mentions it. The command word is read as the shell reads it (quotes, escapes, bash's `$'…'` quoting) for each command of the command line (not after a reserved word of the shell such as `then` or `do`), of a subshell or group and of a heredoc read by a shell; not inside a command substitution, nor behind a program that runs its other arguments as a command (`env`, `nohup`, `exec`, `xargs`, privilege or time-limit wrappers), nor behind a shell launcher written with its path, and bash's control-character escape is not decoded. When a command also passes text to a shell, heredoc text that no shell reads can disturb the reading of the command words that follow it, and the confirmation for a command word or a command that cannot be read does not apply inside a heredoc body that the shell does not expand, even one read by a shell. In the option of a shell launcher that passes the command string, only a string that starts with bash's `$'…'` quoting is decoded; written in several pieces, or with a command substitution joined to it, the string is not normalized.
- **Launchers:** a command run by another program that takes it in its arguments is examined as a command of its own only by the rules that say so, and only behind the launchers they know; for the other rules, the decision model judges it.
- **Protected write targets:** only the write targets listed under “Protected write locations” count. An output file named by another program's own option or operand, and a target written with quotes inside it, are not recognized as writes; the decision model judges them.
- **Persistent git settings:** an alias or a setting that names a program for `git` to run is recognized when given in the command or the environment, not once written to a git configuration file, and git configuration files are not protected locations (git hooks are).
- **Infrastructure commands:** the container and infrastructure rules look for the subcommand right after the tool's name (scaling to zero replicas excepted): with the tool's global options before it, the subcommand is not recognized.
- **Credential files named indirectly:** a credential file is recognized by its path as written. Reached through a symbolic link, through a value known only when the command runs or relative to a change of directory, it is not recognized; written in a form that designates it only once normalized, it may not be recognized. The decision model then judges the command.
- **Devices through the file tools:** OpenCode's `write`, `edit` and `patch` tools have no device rule; such a write is left to OpenCode's permissions and the decision model.
- **CodeMode network access:** once you confirm a script that uses `fetch`, or once the decision model allows a script that does not refer to `tools`, what it sends is not checked again: the addresses and the data are computed when the script runs, and OpenCode's CodeMode `fetch` goes through no plugin hook. Such a script can reach any HTTP service that the machine reaches, local services included (among them OpenCode's own local server, which still requires its password), follows redirections, and is not limited in its number of requests; it can also send out what the interpreter offers without any tool, such as the catalogue of tools (names and descriptions) and the machine's clock and time zone. A local or private address is only recognized when it is written as is in the code.
- **Long inputs:** the decision model receives at most `maxStateChars` characters of the redacted input; beyond that, it judges only the beginning. The local rules see the whole input, except inline interpreter code and quoted text in an `awk` program longer than 64 KiB, which they do not examine: such a command asks for confirmation.
- **Output check:** the decision model judges only the first `maxStateChars` characters of an output, cannot locate a secret (it can only flag the whole output), and reads text written by others (a fetched page, a file of a cloned repository) that may be written to make it answer that there is no secret. It adds to the redaction, it never replaces it.
- **OpenCode secrets in outputs:** a credential value or a pairing code printed alone the first time it appears is not recognized, nor is a credential value that does not have the shape of a token (described above), nor a value that is split, partly printed or encoded otherwise than as described under “Other encodings”; a service password shorter than 8 characters is not masked; the environment of the service is masked only for the variables named like a secret, and the metadata of a credential are not masked. The confirmation that these subcommands require remains the main protection.
- **OpenCode subcommands behind another confirmation:** when the same command also matches a confirmation rule checked before them (privilege escalation, an upload, a remote connection), the confirmation shows that rule's reason; the subcommand's reason, with its note on what the output masks, is not shown.
- **Variable assignments inside a launcher's command string:** in the string of `sh -c '…'` or `bash -c "…"`, an assignment value that contains the string's own quote character is not delimited as the inner shell delimits it, so the program after it may not be recognized as run.
- **`git checkout` with a single argument:** without `--`, `git checkout <name>` switches to a branch or restores a file of that name, depending on what exists in the repository; the local rules leave it to the decision model. A path that starts with `-` is not counted as a file to restore, even after `--`.
- **Other encodings:** only base64 (gzip included) and `xxd`/`hexdump -C` dumps are decoded. `xxd -p` (plain hex), `od`, other compressions inside base64, `rev`, rot13, text split character by character, base64 blocks under 24 characters, without any digit, `+` or `/` (about 0.2% of 30-character blocks), larger than 2 MB, or an output that is exactly a binary `data:` URL still pass. A secret written by you in the prompt without a keyword (`log in with admin / Xy…`) is not detected either.
- **Download then run in two steps:** `curl -o x.sh …; sh x.sh` is not a pipe; the second command is judged by the decision model.
- **Scripts written then run:** the content is checked only for files created in full by the agent in the session (see [Scripts written then run](decision-model.md#decision-model)); the decision model sees it only if it already judged it in full. Not concerned: a copy of the file, a file run after another `cd`, through a variable, by a program that is not recognized (`make`, `npm run`…), or `rm x` inside `sh -c "…"` (judged by the model). For such files the command is judged on its own text. The tracking lives in memory: it starts again from zero when OpenCode restarts or reloads the plugin, which it does once a project has had no session activity for a while (60 minutes by default, OpenCode's `experimental.location_idle_timeout` setting, which a project's configuration can lower; see [Full protection](configuration.md#protecting-the-plugin-from-project-configuration)); a file written before is then judged like a file the agent did not create. The tracking keeps up to 200 files per session and 1,000 sessions; beyond, the oldest file is forgotten and judged the same way. The decision model state then holds up to the input plus one `maxStateChars` per script (at most 4).
- **Private keys recognized by their content:** only a path written in the command or the tool input counts (a program that opens a key by itself is not seen), within the per-check limits (beyond them, a confirmation is asked), with the header in the first 4 KiB. The headers are read in a synchronous hook without a timeout: a path on a network or automounted filesystem that does not respond blocks the call.
- **Protected writes through links:** links are resolved when the call is checked, in a synchronous hook without a timeout (a path on a filesystem that does not respond blocks the call). Not recognized: a link created or changed by the same command or after the check, a hard link, a bind mount, a write through an open file descriptor, and a link whose name is the protected location (a `.opencode` that points elsewhere: only its name is protected, not the directory behind it; the plugin directory and OpenCode's global configuration directory are protected under both forms). The decision model still judges these writes.
- **Devices named indirectly:** a redirection to a target whose value is only known when the command runs (`> "$OUT"`, common in scripts) is left to the decision model. Symbolic links are not resolved for the targets of `dd` and `shred`, for a destination given as `--target-directory=…`, nor for a target found only in code or data for another program, and the read-write redirection (`<>`) is recognized only with the device written as is. Link resolution has the limits described for protected writes: at most 512 path components looked up per check and 40 links per path (beyond them, a confirmation), the state of the disk when the call is checked, and no write through an open file descriptor (`/proc/self/fd/…`, `/dev/fd/…`) or through a link created by the same command. A link that leads to `/proc/self/cwd` or `/proc/thread-self/cwd` is recognized as such only when at least two directories stand for it, counting the command's directories and the OpenCode server's directory.
- **Relative paths given to an MCP server:** the plugin resolves them from the session directory. A local MCP server started in its own configured directory (`cwd` in its configuration) resolves them from that directory instead, so a relative path that reaches a protected location only from there is not recognized.
- **Relative writes after a change of directory:** a chain of relative `cd` is not followed (each literal target is resolved from the directory where the command starts), and a directory given through a variable is not resolved; the session directory and the `workdir` still apply.
- **Pattern bounds:** not recognized: a secret name with more than 128 characters after its last secret word, a URL scheme longer than 64 characters. A JWT whose header contains `-eyJ` is redacted from that point on (the header holds no secret), and not at all if fewer than 10 characters separate that point from the next `.`. A PEM block whose body contains another `-----BEGIN` is judged block by block; a truncated block is still redacted by the "header followed by base64 lines" pattern (lines of 16 characters or more).
- **Options and keys:** not redacted: options with a single dash (`openssl -pass`, `-passin`, `mysql -p…`, `sshpass -p`) and quoted passphrases after a lowercase key (`password: "two words"`). Redacted although not secret: a value that names a variable, after a key that contains a secret word (`…_PASSPHRASE_ENV_NAME = "…"`).
- **Delegated to the decision model:** `npx`, `bunx`, `yarn dlx`, `uv run` and similar commands run arbitrary packages; a local rule would be too noisy (`npx tsc`…), so they are judged by the model.
- **Environment secrets** are read once, when the plugin starts: after rotating a secret, restart OpenCode.
- **Project configuration and project plugins:** a repository's `opencode.json` can remove the plugin (`"-guard"`, `"-*"`) or replace its options (including the [feature options](configuration.md#turning-features-off)), unless a configuration layer loaded after the projects declares it; a global policy only prevents blocking it by policy (see [Protecting the plugin from project configuration](configuration.md#protecting-the-plugin-from-project-configuration)). In every case, a repository that ships its own plugin runs code when OpenCode opens it.
- **Wire safety net:** only JSON bodies (plain, gzip, zstd, br or deflate) and JSON WebSocket frames are redacted; model requests are JSON. A body or a frame that is not, or that cannot be decoded, is sent unchanged (reported once in the log). A request whose redaction fails is blocked, and blocks the session until the content that causes it is gone. Not verified: if a provider signs the request body (AWS SigV4 on Bedrock) before the hook, a redaction on the wire would invalidate the signature and the request would fail, without leaking the secret.

## Development

```sh
npm test            # node --test (Node ≥ 22.18, native TypeScript stripping)
npm run test:bun    # same tests with the Bun embedded in opencode (BUN_BE_BUN=1 opencode test)
npm install         # dev dependencies only (types and compiler); nothing is needed at runtime
npm run typecheck   # tsc --noEmit
```

Source layout:

```
index.ts                     entry point resolved by the OpenCode loader
src/index.ts                 plugin definition and wiring
src/config.ts                options parsing and defaults, guard.json settings, layers by agent and by project
src/decide.ts                local rules → decision model → verdict, cache
src/scripts.ts               files created in full by the agent (fingerprints, protected reads)
src/patch.ts                 patch headers read like OpenCode's patch tool (broad reading for checks, exact for tracking)
src/output-check.ts          output check: activation only if the global configuration declares it
src/guard-file.ts            guard.json files: locations and bounded reads
src/scopes.ts                settings in force for a call (guard.json re-read, main agent, agent and project sections)
src/credential-content.ts    private keys recognized by their content (bounded header reads)
src/real-path.ts             real paths of write targets (symbolic links resolved like the kernel)
src/hooks/gate.ts            tool.execute.before, permission.evaluate
src/hooks/redaction.ts       tool.execute.before (running CodeMode scripts), tool.execute.after, session.prompt, http.request, ws.send
src/hooks/output-check.ts    tool.execute.before, tool.execute.after: optional check of tool outputs by the decision model
src/hooks/unprotected.ts     unprotected agent: sessions and prompts where the plugin does nothing
src/hooks/agents.ts          session.prompt: main agent of each session, for the agent sections
src/cli/                     the guard command (rules, settings, trust, show, last)
src/model/client.ts          decision model client (System One API: chat and systemone protocols)
src/model/questions.ts       question set and verdict mapping
src/rules/                   shell rules, per-tool rules, network checks shared by both (code-network.ts), sensitive paths, feature of each rule
src/secrets/                 secret patterns, redaction, tool error redaction, OpenCode's own secrets (service files, credential formats)
src/types.ts                 structural subset of the plugin context, logger
test/                        node:test suites (runnable with Node and Bun)
bin/guard                    launcher of the guard command (Node.js)
tools/serve.sh       local Decision 3.0 service (native, engine/container, llama)
tools/model-bench/           bench harness behind the "Measured models" table
```

**Notes.**
- **Hot reload.** OpenCode watches the plugin files and reloads the plugin on every change, including in running sessions. Edit a copy and deploy the files in one go, or stop the service while editing. When you use OpenCode itself to edit the plugin, the self-protection asks for confirmation on every write.
- **Imports.** Only `import type` is used from `@opencode/plugin`: Node refuses to strip types from `.ts` files under `node_modules`, and OpenCode provides the package at runtime anyway.
- **Credits.** The secret patterns are adapted from OpenCode's `packages/http-recorder/src/redaction/secrets.ts` (MIT, © 2025 opencode). The list of other coding agents' credential files and the backup suffixes are adapted from [cc-safety-net](https://github.com/kenryu42/cc-safety-net) 2.6.12 (`src/core/rules/secret.ts`, MIT, © 2026 J Liew), and some test cases come from its `tests/fixtures/gate/harvested-verdicts.jsonl`, with this plugin's own expected verdicts.
