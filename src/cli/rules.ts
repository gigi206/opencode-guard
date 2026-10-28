// `guard rules`: the built-in rules in the registry order (`rules/features.ts`), with their group, their own verdict
// (before any setting) and what they check: the same text as the table of docs/rules.md (a test compares them).
import { RULE_FEATURES } from "../rules/features.ts"

/** Rule → its own verdict and what it checks. */
export const RULE_SUMMARIES: ReadonlyMap<string, { readonly verdict: "deny" | "ask"; readonly description: string }> = new Map(
  (
    [
      ["placeholder", "deny", "the redaction placeholder in a command or in content to write (writing it would destroy the real secret)"],
      ["self-protection", "ask", "writing to OpenCode's configuration or to the plugin directory; adding or removing a plugin or an MCP server through opencode"],
      ["nested-opencode", "ask", "starting another OpenCode agent or server or changing its configuration; a command whose program the plugin cannot determine"],
      ["opencode-service", "ask", "changing the OpenCode service, or printing its password, environment or settings"],
      ["opencode-server-api", "ask", "a call to the OpenCode server API that can bypass the guard; exporting the OpenCode credentials; a copy of the server's memory"],
      ["guard-cli", "ask", "running or naming the guard command line, which changes the plugin's settings (another program named guard too)"],
      ["secret-file-read", "ask", "reading a credential file"],
      ["secret-file-network", "deny", "a credential file and a network tool in the same command, or in inline code that makes network requests"],
      ["secret-network", "deny", "a secret in a network command, a web request, a search, MCP arguments or CodeMode code"],
      ["secret-network-word", "ask", "a secret next to the name of a network tool that is not run"],
      ["secret-variable-network", "ask", "a variable named like a secret in a network command"],
      ["env-dump-network", "deny", "an environment dump sent over the network"],
      ["env-dump-network-word", "ask", "an environment dump next to the name of a network tool that is not run"],
      ["rm", "ask", "rm -r or rm -f"],
      ["rm-critical", "deny", "recursive deletion of /, the home directory or a system directory"],
      ["file-delete", "ask", "rm, unlink or shred run on a file"],
      ["find-delete", "ask", "deletion through find"],
      ["home-move", "ask", "moving the home directory, one of its top-level entries or a system directory"],
      ["permissions-critical", "deny", "recursive permission change on /, the home directory or a system directory"],
      ["recursive-permissions", "ask", "recursive or 777 permission change"],
      ["git-branch-delete", "ask", "forced branch deletion"],
      ["git-clean", "ask", "git clean -f"],
      ["git-discard", "ask", "discarding all changes (git checkout ., stash drop or clear, history rewriting)"],
      ["git-discard-file", "ask", "git restore or git checkout of named files"],
      ["git-push-force", "ask", "forced git push"],
      ["git-push-delete", "ask", "git push that deletes or replaces remote refs"],
      ["git-reset-hard", "ask", "git reset --hard"],
      ["git-checkout-force", "ask", "forced git checkout or git switch"],
      ["git-worktree-force", "ask", "git worktree remove --force"],
      ["git-reflog", "ask", "deleting reflog entries"],
      ["git-config-alias", "ask", "a git alias or configuration given in the command or the environment"],
      ["dd-device", "deny", "dd writing to a device"],
      ["mkfs", "deny", "disk formatting (mkfs, wipefs)"],
      ["shred-device", "deny", "shred on a device"],
      ["write-device", "deny", "tee or a copy writing to a device"],
      ["redirect-device", "deny", "a redirection to a device"],
      ["fork-bomb", "deny", "fork bomb"],
      ["kill", "ask", "forced process kill, or the USR1 signal"],
      ["power", "ask", "shutdown, reboot, stopping system services"],
      ["privilege", "ask", "sudo, doas, su, pkexec"],
      ["crontab", "ask", "changing scheduled tasks"],
      ["install", "ask", "global or system-wide software installation"],
      ["publish", "ask", "package publishing"],
      ["containers", "ask", "removing containers, images or volumes"],
      ["infra", "ask", "infrastructure changes (kubectl delete, terraform destroy…)"],
      ["pipe-to-shell", "deny", "a download run by a shell or an interpreter"],
      ["eval", "ask", "eval"],
      ["base64-exec", "ask", "running decoded content (base64 -d | sh)"],
      ["xargs-dynamic-exec", "ask", "dynamic execution through xargs"],
      ["parallel-dynamic-exec", "ask", "dynamic execution through GNU parallel"],
      ["dynamic-shell-source", "ask", "a shell or interpreter running a file or text named by a variable"],
      ["shell-startup-file", "ask", "a shell startup file chosen by an environment variable or an option"],
      ["awk-dynamic-exec", "ask", "an awk program running non-literal text"],
      ["git-exec-config", "ask", "a git setting that names a program to run"],
      ["interpreter-dangerous-code", "ask", "inline interpreter code that launches a dangerous command"],
      ["interpreter-network", "ask", "inline interpreter code that makes network requests"],
      ["upload", "ask", "HTTP upload"],
      ["gh-upload", "ask", "GitHub CLI upload or API call"],
      ["remote", "ask", "connection or transfer to a remote host (ssh, scp, nc…)"],
      ["protected-write", "ask", "writing to a protected location (startup files, /etc, ~/.ssh, git hooks…)"],
      ["codemode-fetch", "ask", "CodeMode code that makes network requests"],
      ["script-unverifiable", "ask", "a script written by the agent that can no longer be checked"],
    ] as const
  ).map(([rule, verdict, description]) => [rule, { verdict, description }]),
)

/** One line per rule, columns aligned. */
export function ruleLines(): string[] {
  const rows = [...RULE_FEATURES].map(([rule, group]) => [rule, group, RULE_SUMMARIES.get(rule)?.verdict ?? "-", RULE_SUMMARIES.get(rule)?.description ?? ""])
  const width = (column: number) => Math.max(...rows.map((row) => row[column]!.length))
  const [rule, group, verdict] = [width(0), width(1), width(2)]
  return rows.map((row) => `${row[0]!.padEnd(rule)}  ${row[1]!.padEnd(group)}  ${row[2]!.padEnd(verdict)}  ${row[3]}`)
}
