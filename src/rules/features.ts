// Feature of each built-in rule, for the `dangerousCommands` and `sensitiveFiles` switches (plugin options).
// Single registry: a test verifies that every finding produced by the built-in rules carries a name present here.

export type RuleFeature = "dangerousCommands" | "sensitiveFiles" | "always"

/** Local rule switches; absent = all active. */
export interface ActiveRules {
  readonly dangerousCommands: boolean
  readonly sensitiveFiles: boolean
}

export const RULE_FEATURES: ReadonlyMap<string, RuleFeature> = new Map<string, RuleFeature>([
  // Always active: integrity of real secrets (placeholder) and self-protection (OpenCode configuration, plugin
  // directory, nested OpenCode, service and its API); without them, the agent could disable the other protections.
  ["placeholder", "always"],
  ["self-protection", "always"],
  ["nested-opencode", "always"],
  ["opencode-service", "always"],
  ["opencode-server-api", "always"],
  // Credential files and secrets leaving the machine.
  ["secret-file-read", "sensitiveFiles"],
  ["secret-file-network", "sensitiveFiles"],
  ["secret-network", "sensitiveFiles"],
  ["secret-network-word", "sensitiveFiles"],
  ["secret-variable-network", "sensitiveFiles"],
  ["env-dump-network", "sensitiveFiles"],
  ["env-dump-network-word", "sensitiveFiles"],
  // Dangerous actions: destruction, system, execution of downloads, network, persistence writes.
  ...[
    "rm",
    "rm-critical",
    "file-delete",
    "find-delete",
    "home-move",
    "permissions-critical",
    "recursive-permissions",
    "git-branch-delete",
    "git-clean",
    "git-discard",
    "git-discard-file",
    "git-push-force",
    "git-push-delete",
    "git-reset-hard",
    "git-checkout-force",
    "git-worktree-force",
    "git-reflog",
    "git-config-alias",
    "dd-device",
    "mkfs",
    "shred-device",
    "write-device",
    "redirect-device",
    "fork-bomb",
    "kill",
    "power",
    "privilege",
    "crontab",
    "install",
    "publish",
    "containers",
    "infra",
    "pipe-to-shell",
    "eval",
    "base64-exec",
    "xargs-dynamic-exec",
    "parallel-dynamic-exec",
    "dynamic-shell-source",
    "shell-startup-file",
    "awk-dynamic-exec",
    "git-exec-config",
    "interpreter-dangerous-code",
    "interpreter-network",
    "upload",
    "gh-upload",
    "remote",
    "protected-write",
    "codemode-fetch",
    "script-unverifiable",
  ].map((rule) => [rule, "dangerousCommands"] as [string, RuleFeature]),
])

/** Is the rule active? User rules (`rules`, absent from the registry) are always active. */
export function ruleEnabled(rule: string, active?: ActiveRules): boolean {
  if (!active) return true
  const feature = RULE_FEATURES.get(rule)
  return feature === undefined || feature === "always" || active[feature]
}
