// Feature of each built-in rule, for the `dangerousCommands` and `sensitiveFiles` switches (plugin options), and the
// rule policy (switches, `ruleOverrides`, `localAsks`), applied to each finding before any combination.
// Single registry: a test verifies that every finding produced by the built-in rules carries a name present here.
import type { Finding, Waiver, WaiverContext } from "./types.ts"

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
  /** `exceptions` retained: rule (`TARGETED_RULES`) → real paths whose findings are lifted (asks only). */
  readonly exceptions?: ReadonlyMap<string, ReadonlySet<string>>
  /** `rememberConfirmations` retained (1 to 60 minutes): a confirmed set of targets is not asked again meanwhile. */
  readonly rememberMinutes?: number
}

/** Settings that lift asks of the rules whose findings carry their targets: `exceptions` and `rememberConfirmations`. */
export type Waivers = Pick<ActiveRules, "exceptions" | "rememberMinutes">

/** Rules whose findings carry their targets (real paths of the files): the only ones an exception or the memory reaches. */
export const TARGETED_RULES: ReadonlySet<string> = new Set(["secret-file-read"])

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

/** Exceptions and memory, kept only when set (same object shape as before without them). */
const waiversOf = (waivers: Waivers) => ({
  ...(waivers.exceptions?.size ? { exceptions: waivers.exceptions } : {}),
  ...(waivers.rememberMinutes ? { rememberMinutes: waivers.rememberMinutes } : {}),
})

/** Policy built once from the configuration: the switches alone without a setting (same object shape as before). */
export function rulePolicy(switches: ActiveRules, overrides: ReadonlyMap<string, RuleOverride>, waivers: Waivers = {}): ActiveRules {
  const { dangerousCommands, sensitiveFiles } = switches
  if (overrides.size === 0) return { dangerousCommands, sensitiveFiles, ...byModel(switches), ...waiversOf(waivers) }
  const policy = { dangerousCommands, sensitiveFiles, overrides, ...byModel(switches), ...waiversOf(waivers) }
  return [...overrides.values()].includes("ask") ? { ...policy, withoutLowered: { ...policy, overrides: loweredOff(overrides) } } : policy
}

/** Same policy with the rules set to `ask` turned off: built with it by `rulePolicy`, derived otherwise. */
export const withoutLowered = (active: ActiveRules): ActiveRules =>
  active.withoutLowered ?? {
    dangerousCommands: active.dangerousCommands,
    sensitiveFiles: active.sensitiveFiles,
    overrides: loweredOff(active.overrides ?? new Map()),
    ...byModel(active),
    ...waiversOf(active),
  }

/** The same policy without exceptions or memory, its `withoutLowered` included: no finding is lifted. */
export function withoutWaivers(active: ActiveRules): ActiveRules {
  const { exceptions, rememberMinutes, withoutLowered: lowered, ...kept } = active
  return { ...kept, ...(lowered ? { withoutLowered: withoutWaivers(lowered) } : {}) }
}

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

/**
 * Exception or memory active for a rule that carries its targets, whose ask is not set to `deny` (an exception never lifts
 * a deny): only then are its targets computed (real paths, `real-path.ts` budget), never with the default settings.
 */
export function waivable(rule: string, active?: ActiveRules): boolean {
  if (!TARGETED_RULES.has(rule) || overrideOf(rule, active) === "deny") return false
  return (active?.exceptions?.get(rule)?.size ?? 0) > 0 || (active?.rememberMinutes ?? 0) > 0
}

/**
 * Exception, then memory, for the targets (all known) of an ask of a `waivable` rule, after its setting: every target
 * excepted for the rule, or this exact set confirmed by the user in the session within the delay in force. Reported.
 */
export function waiverOf(rule: string, targets: readonly string[], active: ActiveRules | undefined, ctx: WaiverContext): Waiver | undefined {
  if (targets.length === 0) return undefined
  const excepted = active?.exceptions?.get(rule)
  const minutes = active?.rememberMinutes ?? 0
  const kind = excepted && targets.every((target) => excepted.has(target)) ? "exception" : minutes > 0 && ctx.remembered?.(rule, targets, minutes) ? "remembered" : undefined
  if (!kind) return undefined
  const waiver: Waiver = { rule, kind, targets }
  ctx.waived?.(waiver)
  return waiver
}

/** Exceptions and memory in force, for the start and re-read lines: nothing with the default settings. */
export function waiverSummary(active: ActiveRules): string {
  const count = [...(active.exceptions?.values() ?? [])].reduce((sum, paths) => sum + paths.size, 0)
  return `${count ? `; exceptions: ${count}` : ""}${active.rememberMinutes ? `; confirmations remembered for ${active.rememberMinutes} min` : ""}`
}
