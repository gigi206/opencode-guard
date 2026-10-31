// Checking of the typed prompt by the decision model (`promptCheck` option, on by default with the decision model). Complement to
// technical redaction, for a secret written in plain words in any language (`mon mot de passe est soleil42`): no
// keyword in the code, the model reads every language. Stage 1 asks whether a part of the prompt gives a credential's
// value; stage 2, only for a part that does, which of its words is the value; the words found are masked. A secret
// seen but not located, a model that fails or a check that takes too long leads to a confirmation: approved, the
// prompt is sent with what was masked; otherwise it is blocked (never sent). The decision model is the trusted zone (it
// may see a value in clear); the conversation model never does. Calibration: dev/plans/prompt-secrets/plan.md.
import type { ModelClient } from "../model/client.ts"
import { DEFAULT_PROMPT_TUNING, type PromptCheckTuning } from "../config.ts"
import { DEFAULT_PROMPT_QUESTIONS, promptQuestions, type PromptQuestionTexts } from "../model/questions.ts"
import { placeholder, type Redactor } from "../secrets/redact.ts"
import type { GuardContext, Logger, PromptEvent } from "../types.ts"
import { guardAction } from "./gate.ts"
import { createSecretChecker, maskWords } from "./secret-check.ts"

export { promptWords } from "./secret-check.ts"

/** Settings of the check (`promptCheck.<name>`, `config.ts`); the defaults are calibrated for nox-4b. */
export type { PromptCheckTuning }
export const PROMPT_CHECK_TUNING = DEFAULT_PROMPT_TUNING

export interface PromptCheckDeps {
  readonly redactor: Redactor
  /** Model client with the decision model's timeout (one call). */
  readonly model: ModelClient
  /** Model name, in reasons. */
  readonly label: string
  readonly threshold: number
  /** Timeout of one call (the whole check: `tuning.deadlineCalls` times it). */
  readonly timeoutMs: number
  readonly askAs: "ask" | "deny"
  readonly log: Logger
  /** Settings and question texts (`promptCheck`); absent = the defaults. */
  readonly tuning?: PromptCheckTuning
  readonly questions?: PromptQuestionTexts
}

/** Outcome of the model's check of a (technically redacted) text; never a word in `cause`. */
export type CheckOutcome =
  | { readonly kind: "clean"; readonly p: number; readonly calls: number }
  | { readonly kind: "masked"; readonly text: string; readonly count: number; readonly p: number; readonly calls: number }
  | { readonly kind: "unresolved"; readonly text: string; readonly count: number; readonly cause: string; readonly calls: number }

export function createPromptChecker(deps: Pick<PromptCheckDeps, "model" | "label" | "threshold" | "timeoutMs" | "tuning" | "questions">) {
  const tuning = deps.tuning ?? DEFAULT_PROMPT_TUNING
  const checker = createSecretChecker({ model: deps.model, label: deps.label, threshold: deps.threshold, tuning, field: "message", questions: promptQuestions(deps.questions ?? DEFAULT_PROMPT_QUESTIONS) })
  const mark = placeholder("prompt_secret")

  /** Never throws: a failure, a refusal or the deadline gives `unresolved`, with what was masked so far. */
  return async function check(text: string): Promise<CheckOutcome> {
    if (text.length > tuning.maxChars) return { kind: "unresolved", text, count: 0, cause: "too long to check", calls: 0 }
    const progress = { found: new Set<string>(), calls: 0 }
    let timer: ReturnType<typeof setTimeout> | undefined
    const deadline = new Promise<"deadline">((resolve) => {
      timer = setTimeout(() => resolve("deadline"), tuning.deadlineCalls * deps.timeoutMs)
      timer.unref?.()
    })
    try {
      const outcome = await Promise.race([checker(text, {}, progress), deadline])
      // Deadline or failure: what was confirmed, and the safety-net words not confirmed (never left in clear unchecked).
      if (outcome === "deadline") {
        const net = new Set([...progress.found, ...checker.netWords(text)])
        return { kind: "unresolved", ...masked(maskWords(text, net, mark)), cause: "check too slow", calls: progress.calls }
      }
      if (outcome.failure) return { kind: "unresolved", ...masked(maskWords(text, new Set([...outcome.found, ...outcome.net]), mark)), cause: outcome.failure, calls: outcome.calls }
      const result = masked(maskWords(text, outcome.found, mark))
      if (outcome.unresolved.length) return { kind: "unresolved", ...result, cause: outcome.unresolved[0]!.cause, calls: outcome.calls }
      if (result.count) return { kind: "masked", ...result, p: outcome.p, calls: outcome.calls }
      return { kind: "clean", p: outcome.p, calls: outcome.calls }
    } catch {
      return { kind: "unresolved", ...masked(maskWords(text, progress.found, mark)), cause: "internal error", calls: progress.calls }
    } finally {
      clearTimeout(timer)
    }
  }
}

const masked = (result: { text: string; count: number }) => ({ text: result.text, count: result.count })

/**
 * Error that blocks the prompt (the hook rejects: OpenCode does not create the message). Never a word of the prompt. The
 * TUI shows only an HTTP error; an agent sees this message when it is its subagent's prompt that is blocked (measured
 * 2026-10-31: told to use a file or a variable, it planned to pass the value that way, and sent the prompt again).
 */
export class PromptBlockedError extends Error {
  override readonly name = "PromptBlockedError"
}

export function blockedMessage(why: string): string {
  return `[guard] Prompt not sent: it may contain a secret in clear that could not be masked, and ${why}. Do not send it again, and do not pass the value another way (a file, a variable, another message): tell the user, who can retype it without the secret.`
}

export interface PromptGate {
  /** Model check then, when needed, confirmation; never throws. `block`: the hook must reject with it. */
  check(event: PromptEvent, text: string): Promise<{ text: string; count: number; block?: PromptBlockedError }>
  /** Confirmation alone (internal error before the check): `undefined` = approved, sent as is. */
  confirm(event: PromptEvent, cause: string): Promise<PromptBlockedError | undefined>
}

export function createPromptGate(ctx: GuardContext, deps: PromptCheckDeps): PromptGate {
  const { log } = deps
  const checker = createPromptChecker(deps)

  async function confirm(event: PromptEvent, cause: string): Promise<PromptBlockedError | undefined> {
    if (deps.askAs === "deny") return new PromptBlockedError(blockedMessage("unattended mode (askAs: deny) blocks it"))
    // The choice first: approving sends what could not be masked.
    const prompt = `approve to send as is (a secret may remain), reject to retype: the prompt may hold a secret (${cause})`
    try {
      await ctx.permission.assert({
        sessionID: event.sessionID,
        action: guardAction(deps.redactor, prompt, "prompt"),
        resources: ["prompt"],
        metadata: { guard: true, reason: `prompt check: ${cause}` },
      })
      log.debug(`prompt check: sent as is by the user (${cause})`)
      return undefined
    } catch (error) {
      const name = (error as { name?: unknown } | undefined)?.name
      log.debug(`prompt check: confirmation not granted (${typeof name === "string" ? name : "error"})`)
      return new PromptBlockedError(blockedMessage("you did not approve sending it"))
    }
  }

  return {
    confirm: async (event, cause) => {
      try {
        return await confirm(event, cause)
      } catch {
        return new PromptBlockedError(blockedMessage("the confirmation could not be asked"))
      }
    },
    async check(event, text) {
      const start = Date.now()
      try {
        const outcome = await checker(text)
        const took = `${outcome.calls} call(s), ${Date.now() - start} ms`
        if (outcome.kind === "clean") {
          log.debug(`prompt check: no secret (${deps.label} ${outcome.p.toFixed(2)}; ${took})`)
          return { text, count: 0 }
        }
        if (outcome.kind === "masked") {
          log.debug(`prompt check: ${outcome.count} word(s) masked (${deps.label} ${outcome.p.toFixed(2)}; ${took})`)
          return { text: outcome.text, count: outcome.count }
        }
        log.debug(`prompt check: unresolved, ${outcome.count} word(s) masked (${outcome.cause}; ${took})`)
        const block = await confirm(event, outcome.cause)
        return { text: outcome.text, count: outcome.count, ...(block ? { block } : {}) }
      } catch {
        // Internal error: the technically redacted text, if confirmed.
        try {
          const block = await confirm(event, "internal error")
          return { text, count: 0, ...(block ? { block } : {}) }
        } catch {
          return { text, count: 0, block: new PromptBlockedError(blockedMessage("the confirmation could not be asked")) }
        }
      }
    },
  }
}
