export type Verdict = "deny" | "ask" | "allow"

export interface Finding {
  readonly verdict: "deny" | "ask"
  readonly rule: string
  readonly reason: string
  /** Ask coming only from heredoc bodies read by data commands: the decision model decides. */
  readonly dataOnly?: boolean
  /**
   * Ask that the decision model decides if it judged the input in full (the value is quoted in the reason);
   * truncated input, unreachable or disabled model: the ask remains.
   */
  readonly modelDecides?: string
  /**
   * Real paths of every file the finding is about (`TARGETED_RULES` only), computed only when an exception or the memory
   * of confirmations is active for its rule; absent: unknown (a variable, a pattern, a path not resolved, a limit), and
   * then neither an exception nor the memory lifts it.
   */
  readonly targets?: readonly string[]
}

/** Finding lifted before any combination: all its targets excepted for its rule, or the exact set confirmed earlier. */
export interface Waiver {
  readonly rule: string
  readonly kind: "exception" | "remembered"
  readonly targets: readonly string[]
}

/** Per call, beside the policy: the memory of confirmations of the session, and where lifted findings are reported. */
export interface WaiverContext {
  /** The user confirmed this exact set of targets for the rule in this session, at most `minutes` ago. */
  readonly remembered?: (rule: string, targets: readonly string[], minutes: number) => boolean
  /** Receives each finding lifted (the same one may come from several views of a command). */
  readonly waived?: (waiver: Waiver) => void
}

/** Additional rule provided by the user via the options. */
export interface CustomRule {
  readonly id: string
  readonly verdict: "deny" | "ask"
  readonly reason: string
  readonly pattern: RegExp
  /** Relevant tools (default: `shell`). `*` = all, tested on the serialized input. */
  readonly tools: readonly string[]
}

/** Rule for findings born from an internal error: outside the built-in rule registry, never disabled by options. */
export const INTERNAL_ERROR_RULE = "internal-error"

/**
 * Answer of a budgeted predicate (`real-path.ts`, `credential-content.ts`) whose check reached a limit: distinct from
 * "unknown" and "not recognized", it gives an ask, never a deny (nothing was checked to the end).
 */
export const LIMIT_REACHED: unique symbol = Symbol("limit reached")

/** Ask that the decision model can decide (`dataOnly`, `modelDecides`): weaker than an ask the user confirms. */
export const decidable = (finding: Finding): boolean => finding.verdict === "ask" && (finding.dataOnly === true || finding.modelDecides !== undefined)

/** Deny, then ask without a mark, then ask that the model can decide; at equal strength, the first one. */
export function mostSevere(findings: ReadonlyArray<Finding | undefined>): Finding | undefined {
  let best: Finding | undefined
  for (const finding of findings) {
    if (!finding) continue
    if (finding.verdict === "deny") return finding
    if (!best || (decidable(best) && !decidable(finding))) best = finding
  }
  return best
}
