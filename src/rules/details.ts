// Detailed, human-readable explanation of each built-in rule for `guard rules --explain`: what it looks at, in words,
// and the reason a finding usually carries. Never the rule's pattern or an internal expression: the shell rules are
// functions, not one regular expression, and the explanations stay at the level of docs/rules.md.

import { DENY_ONLY_RULES, TARGETED_RULES, USER_ONLY_RULES } from "./features.ts"

export interface RuleDetail {
  /** What the rule looks at, in words (no pattern or internal expression). */
  readonly how: string
  /** Reason a finding usually carries, in words; the exact text may add the target, the path, the data examined or an instruction. */
  readonly reason?: string
  /**
   * Short form of `reason` for the confirmation prompt's action (OpenCode shows that action twice), used only when the
   * finding's reason is exactly `reason` and the whole of it does not fit (`guardAction`, hooks/gate.ts).
   */
  readonly prompt?: string
}

const detail = (how: string, reason?: string, prompt?: string): RuleDetail => ({
  how,
  ...(reason === undefined ? {} : { reason }),
  ...(prompt === undefined ? {} : { prompt }),
})

export const RULE_DETAILS: ReadonlyMap<string, RuleDetail> = new Map<string, RuleDetail>([
  [
    "placeholder",
    detail(
      "The redaction placeholder is the marker the plugin puts in place of a secret. Writing it into a command or into content to write would replace the real secret with the marker, so the rule refuses it. It also recognizes the marker encoded in base64, up to two levels.",
      "the redaction placeholder is present: writing it would destroy the real secret",
    ),
  ],
  [
    "self-protection",
    detail(
      "Protects the files that decide how the plugin and OpenCode run: OpenCode's configuration (global, system and project, including .opencode/ and opencode.json(c)), the plugin directory and OpenCode's service file. It asks before a write or delete that reaches them, including through a symbolic link or the path arguments of an MCP or plugin tool, and before adding or removing a plugin or an MCP server through opencode. A shell command that has one of these locations as a literal word and does more than read asks too, even in a form of write the plugin does not recognize: the cost is a confirmation for a command that names the location without writing there (git add opencode.json).",
      "write to OpenCode's configuration or to the guard plugin (self-protection)",
      "writes OpenCode's configuration or the plugin",
    ),
  ],
  [
    "nested-opencode",
    detail(
      "Recognizes a command that starts another OpenCode agent or server, or that changes its configuration or the environment it reads. It also asks when the program a command runs cannot be determined (a command word built at run time, too long or too complex to read), because the plugin cannot rule out another OpenCode.",
      "launches another OpenCode agent or server, or changes its configuration: it may run without the guard or approve its confirmations (--auto)",
      "another OpenCode or a configuration change",
    ),
  ],
  [
    "opencode-service",
    detail(
      "Recognizes commands that change the OpenCode service (its environment, restart or uninstall) and commands that print its password, environment or settings, or request a pairing code. These values give access to the server and can disable the guard.",
      "change to the OpenCode service (environment, restart) or uninstall: can disable the guard",
      "changes the OpenCode service",
    ),
  ],
  [
    "opencode-server-api",
    detail(
      "Recognizes a call to the OpenCode server API that can switch a session's agent, send a prompt or a command, replace a voice call's instructions or answer a permission request, as well as exporting the OpenCode credentials and writing a copy of the server's memory, and an artifact written with OpenCode's artifact tools whose page code calls one of these routes. These actions can bypass the guard.",
      "call to the OpenCode server API that switches the agent, sends a prompt or a command, replaces the instructions of a voice call, or answers a permission request: it can bypass the guard",
      "an OpenCode server API call",
    ),
  ],
  [
    "guard-cli",
    detail(
      "Recognizes the guard command line, run directly, through an interpreter or only named, and another program named guard. The command changes the plugin's settings: its own verdict is a confirmation, and it is never left to the decision model.",
      "the guard command line, which changes the plugin's settings, run or named by the command (self-protection; another program named guard asks too)",
      "changes the plugin's settings",
    ),
  ],
  [
    "secret-file-read",
    detail(
      "Recognizes a read of a credential file: a known credential path or name, a backup copy of one, the system's password files (/etc/shadow, /etc/gshadow, /etc/shadow-, /etc/gshadow-), a private key recognized by its content, or OpenCode's own credential stores. The check covers shell commands, the read/glob/grep tools and path arguments of MCP or plugin tools; what is read is never kept, logged or sent.",
      "access to a credential file",
    ),
  ],
  [
    "secret-file-network",
    detail(
      "A credential file and a network tool in the same command, or a credential file in inline interpreter code that makes network requests. It refuses because the file could leave the machine; the network tool must be the command actually run, not a mere mention.",
      "credential file and network tool in the same command (exfiltration)",
      "credential file and network tool",
    ),
  ],
  [
    "secret-network",
    detail(
      "A detected secret in a command that runs a network tool, in a web request or search, in MCP arguments or in CodeMode code. The secret can be a known provider format, a value from the environment or configuration, or a credential value; the rule refuses before the data leaves the machine.",
      "secret found in the request (exfiltration)",
    ),
  ],
  [
    "secret-network-word",
    detail(
      "A detected secret in a command that mentions a network tool without running it, for example a search or a text that names the tool. It asks instead of refusing, because the secret may not be sent.",
      "secret in a command that mentions a network tool",
    ),
  ],
  [
    "secret-variable-network",
    detail(
      "A variable whose name looks like a secret (a token, key or password name) used in a command that runs a network tool. The value is not known in advance, so the rule asks.",
      "variable holding a secret used in a network command",
    ),
  ],
  [
    "env-dump-network",
    detail(
      "An environment dump (printenv, env, export, a bare set, declare -x or /proc/<pid>/environ) sent through a network tool in the same command. It refuses because the environment can hold credentials.",
      "environment variables sent over the network (exfiltration)",
    ),
  ],
  [
    "env-dump-network-word",
    detail(
      "An environment dump in a command that mentions a network tool without running it; it asks instead of refusing.",
      "environment variables in a command that mentions a network tool",
      "environment variables next to a network tool",
    ),
  ],
  [
    "rm",
    detail(
      "A shell command that runs rm with a recursive or force option. A plain rm on a file is handled by file-delete; the command is read segment by segment, as the shell reads it.",
      "file deletion (rm -r/-f)",
    ),
  ],
  [
    "rm-critical",
    detail(
      "A recursive rm whose target is the root, the home directory or a system directory, or an rm that disables the root protection. The target is normalized (repeated slashes, dot and dot-dot components); a relative target is not resolved against the working directory for this refusal, so it does not make the command critical, and a recursive or forced deletion of it still asks under rm.",
      "recursive deletion of a system directory or HOME",
    ),
  ],
  [
    "file-delete",
    detail(
      "A shell command that runs rm, unlink or shred on a file; an rm with a recursive or force option belongs to rm. The word in quoted text or as an argument of another program is not concerned.",
      "file deletion or destruction (rm, unlink or shred)",
    ),
  ],
  ["find-delete", detail("A find command that deletes files, directly or by running a deletion command.", "deletion via find")],
  [
    "home-move",
    detail(
      "A move of the home directory, one of its top-level entries or a system directory. The rule recognizes mv and its destination options; relative paths are not resolved against the working directory for this confirmation.",
      "moving a home or system directory",
    ),
  ],
  [
    "permissions-critical",
    detail(
      "A recursive permission change on the root, the home directory or a system directory. It refuses because the change can make the system or the user's files unusable.",
      "recursive permission change on / , HOME or a system directory",
      "recursive permission change on / or HOME",
    ),
  ],
  [
    "recursive-permissions",
    detail(
      "A recursive or 777 permission change on another target. It asks because the change can expose or break files.",
      "recursive or 777 permission change",
    ),
  ],
  [
    "git-branch-delete",
    detail(
      "A forced branch deletion: the branch's commits can become unreachable. Git's global options before the subcommand are recognized.",
      "forced branch deletion",
    ),
  ],
  ["git-clean", detail("A git clean that forces the deletion of untracked files. The rule reads git's options before the subcommand and the force option in its forms.", "git clean -f (untracked files deleted)")],
  [
    "git-discard",
    detail(
      "An operation that discards all changes: checking out the whole tree, dropping or clearing the stash, or rewriting history. The rule asks because uncommitted work can be lost.",
      "discarding git changes",
    ),
  ],
  [
    "git-discard-file",
    detail(
      "A git restore or git checkout of named files, including paths read from a file and the interactive mode; it asks because their uncommitted changes are lost. Restoring only the index is not concerned.",
      "git restore or checkout of named files (their uncommitted changes are lost)",
      "git restore or checkout of files",
    ),
  ],
  [
    "git-push-force",
    detail("A forced git push, including an abbreviated force option or a refspec that forces the update; it rewrites remote history. Git's global options before the subcommand are recognized.", "forced git push (rewrites remote history)"),
  ],
  [
    "git-push-delete",
    detail("A git push that deletes or replaces remote refs, including pruning and mirroring.", "git push deleting or replacing remote refs"),
  ],
  ["git-reset-hard", detail("git reset in hard mode, which discards uncommitted changes. Git's global options before the subcommand are recognized.", "git reset --hard (uncommitted changes lost)")],
  ["git-checkout-force", detail("A forced git checkout or git switch, which discards local changes.", "forced git checkout or switch (uncommitted changes lost)", "forced git checkout or switch")],
  ["git-worktree-force", detail("A git worktree removal that forces past uncommitted changes.", "forced worktree removal (uncommitted changes lost)", "forced worktree removal")],
  [
    "git-reflog",
    detail(
      "Deleting reflog entries; commits that were only reachable through the reflog can no longer be recovered.",
      "deleting reflog entries (commits lost since then can no longer be recovered)",
      "deletes reflog entries",
    ),
  ],
  [
    "git-config-alias",
    detail(
      "A git alias or configuration given in the command or the environment, including include files and configuration variables. The command it runs is not checked, so the rule asks.",
      "git alias or configuration given in the command or the environment (the command it runs is not checked)",
      "a git alias or configuration",
    ),
  ],
  [
    "dd-device",
    detail(
      "dd writing to a device. The rule recognizes the output operand, a device written directly or reached through a link, and a target whose value is only known at run time.",
      "raw write to a device",
    ),
  ],
  ["mkfs", detail("Disk formatting (mkfs, wipefs), including calls by path, behind sudo or xargs, or inside a shell; it refuses because the device's data is destroyed.", "disk formatting")],
  ["shred-device", detail("shred on a device; it refuses because the device's data is overwritten.", "device wipe")],
  ["write-device", detail("tee or a copy program (cp, mv, install, rsync) writing to a device; the destination is checked as written and through symbolic links.", "raw write to a device")],
  ["redirect-device", detail("A shell redirection to a device; the target is checked as written and through symbolic links.", "raw write to a device")],
  ["fork-bomb", detail("A shell function that calls itself twice in a pipeline, whatever its name; it refuses because it can exhaust the process table.", "fork bomb")],
  [
    "kill",
    detail(
      "A forced process kill or the USR1 signal. USR1 makes an OpenCode server write a copy of its memory, which can contain credentials.",
      "forced process kill, or signal USR1 sent to a process (an OpenCode server then writes a copy of its memory to a file)",
    ),
  ],
  ["power", detail("Shutdown, reboot or stopping system services; it asks because the machine or a service becomes unavailable.", "shutdown / reboot / system services")],
  ["privilege", detail("Privilege escalation (sudo, doas, su, pkexec); it asks because the command runs with more rights.", "privilege escalation")],
  ["crontab", detail("A change to scheduled tasks; it asks because the change can run later, outside the current session.", "scheduled task change")],
  ["install", detail("Global or system-wide software installation; it asks because it changes the system and may run install scripts.", "software installation")],
  ["publish", detail("Package publishing; it asks because the package leaves the machine and cannot be unpublished easily.", "package publishing")],
  ["containers", detail("Removal or pruning of containers, images, volumes or networks; it asks because data or images can be lost.", "removal of containers, images or volumes")],
  [
    "infra",
    detail(
      "Infrastructure changes such as deleting or draining cluster resources, scaling a service to zero, uninstalling a release, or destroying or applying infrastructure; it asks because remote resources can be destroyed or changed.",
      "infrastructure change",
    ),
  ],
  [
    "pipe-to-shell",
    detail(
      "A download piped into a shell or an interpreter that runs its input, including through other stages. It refuses because the downloaded code runs without being reviewed.",
      "running a downloaded script (download piped to a shell or an interpreter)",
      "runs a downloaded script",
    ),
  ],
  ["eval", detail("eval; it asks because the text it evaluates is not checked as a command.", "dynamic execution (eval)")],
  ["base64-exec", detail("Running decoded content (for example, base64 output piped to a shell); it asks because the decoded command is not visible in the original text.", "running decoded content")],
  ["xargs-dynamic-exec", detail("Dynamic execution through xargs; the input can supply the command that runs, so the rule asks.", "dynamic execution via xargs (input can supply the executed command)", "dynamic execution through xargs")],
  ["parallel-dynamic-exec", detail("Dynamic execution through GNU parallel; the input can supply the command that runs, so the rule asks.", "dynamic execution via parallel (input can supply the executed command)", "dynamic execution through parallel")],
  [
    "dynamic-shell-source",
    detail("A shell or interpreter running a file or command text designated by a variable; the target is only known at run time, so the rule asks.", "shell or interpreter launched on a variable-designated file or command text", "runs a file or text named by a variable"),
  ],
  [
    "shell-startup-file",
    detail("A shell startup file chosen by an environment variable or a command-line option; the file runs when the shell starts, so the rule asks. It also asks for a variable set for the launched program, in front of it, behind env and the other launchers, or with export, declare or typeset: those of the dynamic loader (LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH, DYLD_INSERT_LIBRARIES), those of a runtime (NODE_OPTIONS, NODE_PATH, PERL5OPT, PERL5LIB, RUBYOPT, RUBYLIB, PYTHONSTARTUP, PYTHONPATH, PYTHONHOME), and EDITOR, VISUAL, PAGER and BROWSER, unless the value, given whole with =, is one of cat, true, :, less, more, vi, vim or nano. An empty value given with = loads nothing and does not ask. The reason then says that the variable makes the program load or run other code.", "shell startup file designated by environment or command-line option", "a startup file chosen at run time"),
  ],
  ["awk-dynamic-exec", detail("An awk program that runs non-literal text as a command; the command is only known at run time, so the rule asks.", "awk program executing non-literal text as a command")],
  ["git-exec-config", detail("A git setting that names a program to run (for example, a pager, an SSH command or a hook); the program is not checked, so the rule asks.", "git configuration designates a program to run")],
  [
    "interpreter-dangerous-code",
    detail(
      "Inline interpreter code that launches a dangerous command, or a tracked script run by a non-shell interpreter that does; the rule recognizes the code passed to the interpreter, or the content of that script when the decision model does not see it whole, and asks when the code can run a command the local rules would otherwise check.",
      "interpreter code launching a dangerous command",
    ),
  ],
  [
    "interpreter-network",
    detail(
      "Inline interpreter code that makes network requests; the rule recognizes the code passed to a non-shell interpreter and asks because data can leave the machine.",
      "inline interpreter code making network requests",
    ),
  ],
  ["upload", detail("An HTTP upload; it asks because data leaves the machine.", "data upload over HTTP")],
  ["gh-upload", detail("A GitHub CLI upload or API call; it asks because data leaves the machine or the call changes a remote repository.", "GitHub CLI upload or API call")],
  ["remote", detail("A connection or transfer to a remote host (ssh, scp, nc…); it asks because the command reaches another machine.", "connection or transfer to a remote host")],
  [
    "protected-write",
    detail(
      "A write target in a protected location: shell startup files, /etc, ~/.ssh, git hooks, fish and nushell configuration, OpenCode's configuration, .opencode/, opencode.json(c), guard.json, OpenCode's service file or the plugin directory. The target is checked as written, lexically and through symbolic links; a target that cannot be fully checked asks. A copy into a directory counts the file it creates there, and a literal path that inline interpreter code or an awk program writes counts as a target.",
      "write to a protected location (startup file, ~/.ssh, git hook, /etc)",
      "writes to a protected location",
    ),
  ],
  [
    "codemode-fetch",
    detail(
      "CodeMode code that refers to fetch. When the code also refers to tools or writes a local or private address, the rule asks; otherwise the decision model may decide, if it received the whole code.",
      "CodeMode code making network requests (fetch)",
    ),
  ],
  [
    "script-unverifiable",
    detail(
      "A script written by the agent whose content can no longer be checked (for example, it was modified outside the plugin); the rule asks before the script runs.",
      "the script was created by the agent but can no longer be checked",
    ),
  ],
])

/** How a built-in rule can be set, in words (`ruleOverrides` values and the group switch). */
export function ruleSettings(id: string, group: "always" | "sensitiveFiles" | "dangerousCommands"): string {
  if (group === "always") {
    if (DENY_ONLY_RULES.has(id))
      return `Always active and refuse-only: ruleOverrides.${id} accepts only "deny"; "off", "ask" and "model" are ignored, and localAsks does not reach it. The rule cannot be turned off, and no setting can make it ask.`
    if (USER_ONLY_RULES.has(id))
      return `Always active: ruleOverrides.${id} accepts only "deny"; "off", "ask" and "model" are ignored, and localAsks does not reach it. The group cannot be turned off.`
    const common = `Always active: ruleOverrides.${id} accepts "deny" (and "model" only with selfProtectionByModel); "off" and "ask" are ignored, and localAsks: "model" reaches it only with selfProtectionByModel.`
    if (id === "self-protection")
      return `${common} A write to the plugin's settings (a guard.json, an opencode.json or opencode.jsonc, an OpenCode configuration directory or its plugin directory, the service file), and a write whose links could not all be followed, are never left to the decision model. The group cannot be turned off.`
    if (id === "nested-opencode")
      return `${common} A recognized launch of another OpenCode with its configuration or plugins changed, or approving its own confirmations, is never left to the decision model. The group cannot be turned off.`
    if (id === "opencode-service")
      return `${common} A change to the service's environment or settings is never left to the decision model; stopping, restarting or uninstalling it can be. The group cannot be turned off.`
    return `${common} The group cannot be turned off.`
  }
  const switchName = group === "sensitiveFiles" ? "sensitiveFiles" : "dangerousCommands"
  const common = `Part of the ${group} group: "${switchName}": false turns it off. ruleOverrides.${id} accepts "off", "ask", "deny" or "model"; "model" leaves its confirmations to the decision model, and so does localAsks: "model" when the rule has no setting. A value that relaxes the rule must also be declared in the global configuration, unless the project is trusted.`
  // Its findings name their files: the only rule an exception or the memory of confirmations reaches.
  if (!TARGETED_RULES.has(id)) return common
  return `${common} It also accepts exceptions, absolute paths of files whose asks it no longer makes when the command only reads them (exceptions.${id}, or guard rules off ${id} --path <file>), and rememberConfirmations, minutes (1 to 60) during which a set of files the user confirmed in a session is not asked again; neither ever lifts a denial, and both are off by default.`
}
