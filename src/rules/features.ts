// Feature of each built-in rule, for the `dangerousCommands` and `sensitiveFiles` switches (plugin options), and the
// rule policy (switches, `ruleOverrides`, `localAsks`), applied to each finding before any combination.
// Single registry: a test verifies that every finding produced by the built-in rules carries a name present here.
import type { Finding } from "./types.ts"

export type RuleFeature = "dangerousCommands" | "sensitiveFiles" | "always"

/** Setting of one built-in rule (`ruleOverrides` option; `allow` is read as `off`). */
export type RuleOverride = "off" | "ask" | "deny" | "model"

/** Local rule switches and retained `ruleOverrides` (rule policy); absent = all active, no override. */
export interface ActiveRules {
  readonly dangerousCommands: boolean
  readonly sensitiveFiles: boolean
  /** Registry identifiers only, never a user rule's (`config.ts`): a setting on a rule wins over its group switch. */
  readonly overrides?: ReadonlyMap<string, RuleOverride>
  /** Same policy with the rules set to `ask` turned off, built with it (`shellFinding`). */
  readonly withoutLowered?: ActiveRules
  /** `localAsks: "model"` retained: the asks of the rules without a setting are left to the decision model. */
  readonly localAsksByModel?: boolean
  /** `selfProtectionByModel` retained: `"model"` and `localAsks` also reach the always-active rules' asks. */
  readonly selfProtectionByModel?: boolean
}

/** `modelDecides` of an ask left to the decision model by a setting (quoted in the reason). */
export const BY_RULE_SETTING = "left to the decision model by ruleOverrides"
export const BY_LOCAL_ASKS = "left to the decision model by localAsks"

export const RULE_FEATURES: ReadonlyMap<string, RuleFeature> = new Map<string, RuleFeature>([
  // Always active: integrity of real secrets (placeholder) and self-protection (OpenCode configuration, plugin
  // directory, nested OpenCode, service and its API, the plugin's command line); without them, the agent could disable
  // the other protections.
  ["placeholder", "always"],
  ["self-protection", "always"],
  ["nested-opencode", "always"],
  ["opencode-service", "always"],
  ["opencode-server-api", "always"],
  ["guard-cli", "always"],
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

/**
 * Always-active rules never left to the decision model, `selfProtectionByModel` included (user's decision), with what
 * they are about (quoted in the warning on `"model"`): a change of the plugin's settings, a call to the OpenCode server
 * API. The other changes of the plugin's settings are marked where they are found (writes, nested OpenCode).
 */
export const USER_ONLY_RULES: ReadonlyMap<string, string> = new Map([
  ["guard-cli", "a change of the plugin's settings"],
  ["opencode-server-api", "a call to the OpenCode server API, which can bypass the guard"],
])

/** Always-active rules that only deny: `model` has no ask to leave to the decision model there (ignored with a warning). */
export const DENY_ONLY_RULES: ReadonlySet<string> = new Set(["placeholder"])

/** Settings with the rules set to `ask` turned off. */
const loweredOff = (overrides: ReadonlyMap<string, RuleOverride>) =>
  new Map([...overrides].map(([rule, value]) => [rule, value === "ask" ? "off" : value] as const))

/** Settings that leave asks to the decision model, kept only when set (same object shape as before without them). */
const byModel = (active: ActiveRules) => ({
  ...(active.localAsksByModel ? { localAsksByModel: true } : {}),
  ...(active.selfProtectionByModel ? { selfProtectionByModel: true } : {}),
})

/** Policy built once from the configuration: the switches alone without a setting (same object shape as before). */
export function rulePolicy(switches: ActiveRules, overrides: ReadonlyMap<string, RuleOverride>): ActiveRules {
  const { dangerousCommands, sensitiveFiles } = switches
  if (overrides.size === 0) return { dangerousCommands, sensitiveFiles, ...byModel(switches) }
  const policy = { dangerousCommands, sensitiveFiles, overrides, ...byModel(switches) }
  return [...overrides.values()].includes("ask") ? { ...policy, withoutLowered: { ...policy, overrides: loweredOff(overrides) } } : policy
}

/** Same policy with the rules set to `ask` turned off: built with it by `rulePolicy`, derived otherwise. */
export const withoutLowered = (active: ActiveRules): ActiveRules =>
  active.withoutLowered ?? { dangerousCommands: active.dangerousCommands, sensitiveFiles: active.sensitiveFiles, overrides: loweredOff(active.overrides ?? new Map()), ...byModel(active) }

/**
 * Setting of a rule: registry rules only; an always-active rule accepts only `deny`, and `model` with
 * `selfProtectionByModel` (never for `USER_ONLY_RULES`).
 */
export function overrideOf(rule: string, active?: ActiveRules): RuleOverride | undefined {
  const override = active?.overrides?.get(rule)
  const feature = RULE_FEATURES.get(rule)
  if (override === undefined || feature === undefined) return undefined
  const byModel = override === "model" && active?.selfProtectionByModel && !USER_ONLY_RULES.has(rule)
  return feature === "always" && override !== "deny" && !byModel ? undefined : override
}

/**
 * Is the rule active? User rules (`rules`, absent from the registry) are always active; otherwise its setting
 * (`off`, or `ask`/`deny`/`model`, which turn it on in a disabled group), then its group switch.
 */
export function ruleEnabled(rule: string, active?: ActiveRules): boolean {
  if (!active) return true
  const feature = RULE_FEATURES.get(rule)
  if (feature === undefined || feature === "always") return true
  const override = overrideOf(rule, active)
  return override === undefined ? active[feature] : override !== "off"
}

/**
 * Ask of an active built-in rule left to the decision model by the settings: `"model"` on the rule, otherwise
 * `localAsks: "model"` for a rule without a setting (always-active rules only with `selfProtectionByModel`). Marked
 * `modelDecides`: the model decides it if it judged the input in full, otherwise the ask remains (`decide.ts`). Applied
 * only where an ask comes from a check carried out to the end (whitelist of findings): never on an ask born from a
 * limit, a value known only at run time, an internal error, a deny found only inside data, a user rule or a script.
 */
export function entrusted<F extends Finding | undefined>(finding: F, active?: ActiveRules): F | Finding {
  if (finding?.verdict !== "ask" || finding.dataOnly || finding.modelDecides !== undefined) return finding
  const feature = RULE_FEATURES.get(finding.rule)
  if (feature === undefined || USER_ONLY_RULES.has(finding.rule)) return finding
  const override = overrideOf(finding.rule, active)
  if (override === "model") return { ...finding, modelDecides: BY_RULE_SETTING }
  if (override === undefined && active?.localAsksByModel && (feature !== "always" || active.selfProtectionByModel)) return { ...finding, modelDecides: BY_LOCAL_ASKS }
  return finding
}

/** Ask left to the decision model by a setting (`entrusted`), not by the rule itself. */
export const bySetting = (finding: Finding): boolean => finding.modelDecides === BY_RULE_SETTING || finding.modelDecides === BY_LOCAL_ASKS

/** Ask of a rule set to `deny`: a deny, without the marks that leave it to the decision model (final). */
export function hardened<F extends Finding | undefined>(finding: F, active?: ActiveRules): F | Finding {
  return finding?.verdict === "ask" && overrideOf(finding.rule, active) === "deny" ? { verdict: "deny", rule: finding.rule, reason: finding.reason } : finding
}

/**
 * Verdict set by `ruleOverrides` on a finding of an active rule, before any combination: deny of a rule set to `ask` →
 * ask without a mark, and so is its own ask that the model could decide (`modelDecides` of CodeMode's `fetch`: the user
 * confirms); ask of a rule set to `deny` → deny. Not for the shell rules, whose denials are lowered at the end of
 * `shellFinding` (a lowered deny must not take the place of another rule's deny in their early exits).
 */
export function overridden<F extends Finding | undefined>(finding: F, active?: ActiveRules): F | Finding {
  if (finding !== undefined && overrideOf(finding.rule, active) === "ask") return { verdict: "ask", rule: finding.rule, reason: finding.reason }
  return hardened(finding, active)
}
