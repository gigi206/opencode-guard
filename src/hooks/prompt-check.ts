// Checking of the typed prompt by the decision model (`promptCheck` option, disabled by default). Complement to
// technical redaction, for a secret written in plain words in any language (`mon mot de passe est soleil42`): no
// keyword in the code, the model reads every language. Stage 1 asks whether a part of the prompt gives a credential's
// value; stage 2, only for a part that does, which of its words is the value; the words found are masked. A secret
// seen but not located, a model that fails or a check that takes too long leads to a confirmation: approved, the
// prompt is sent with what was masked; otherwise it is blocked (never sent). The decision model is the trusted zone (it
// may see a value in clear); the conversation model never does. Calibration: dev/plans/prompt-secrets/plan.md.
import { ModelError, type ModelClient } from "../model/client.ts"
import { PROMPT_QUESTION_ID, PROMPT_QUESTIONS, PROMPT_VERIFY_QUESTION_ID, PROMPT_VERIFY_QUESTIONS, PROMPT_WORD_QUESTION_ID, promptWordQuestion } from "../model/questions.ts"
import { placeholder, PLACEHOLDER_RE, type Redactor } from "../secrets/redact.ts"
import type { GuardContext, Logger, PromptEvent } from "../types.ts"
import { guardAction } from "./gate.ts"

/** Longer prompts (in parts of 1,000 characters) are not checked: confirmation. */
export const PROMPT_MAX_CHARS = 32_000
/** Simultaneous model calls of one check (the gateway answers them one by one: more only adds queued timeouts). */
const PARALLEL = 4
/** Options of one stage-2 question (the words, then `none`). */
const WORDS_PER_QUESTION = 16
/** Stage 2 then stage 1 again on the part without the words found, at most this many times. */
const ROUNDS = 3
/** Whole check: this many times the timeout of one call. */
const DEADLINE_CALLS = 3
/** Shortest word proposed in stage 2. */
const MIN_WORD = 4
/**
 * Settings of the check, calibrated on 2026-10-31 for nox-4b (dev/tools/prompt-check-calibrate.ts): replaced only by the
 * calibration tool, never by an option.
 */
export interface PromptCheckTuning {
  /** Characters per part sent to the model: a secret buried in a longer part (a pasted log) goes unseen (measured). */
  readonly partChars: number
  /** Stage 2 names at most this many candidates (probability at least `minCandidate`), each checked by stage 3. */
  readonly candidates: number
  readonly minCandidate: number
  /** Stage 3: a candidate is masked from this probability. */
  readonly verify: number
  /**
   * A part seen as holding a secret where no candidate passes stage 3: confirmation from this stage-1 probability, below
   * it the prompt is sent (a weak stage 1 with no word confirmed is mostly a false alarm: measured on real prompts).
   */
  readonly askScore: number
}

export const PROMPT_CHECK_TUNING: PromptCheckTuning = { partChars: 1000, candidates: 3, minCandidate: 0.1, verify: 0.7, askScore: 0.7 }

/**
 * What the model sees in place of a masked secret: a `[[GUARD_REDACTED:…]]` placeholder or a removed word reads as a
 * secret still there (`redis://user:@host` 0.37, `<redacted>` 0.09).
 */
const SHOWN_MASK = "<redacted>"

export interface PromptCheckDeps {
  readonly redactor: Redactor
  /** Model client with the decision model's timeout (one call). */
  readonly model: ModelClient
  /** Model name, in reasons. */
  readonly label: string
  readonly threshold: number
  /** Timeout of one call (the whole check: `DEADLINE_CALLS` times it). */
  readonly timeoutMs: number
  readonly askAs: "ask" | "deny"
  readonly log: Logger
}

/** Outcome of the model's check of a (technically redacted) text; never a word in `cause`. */
export type CheckOutcome =
  | { readonly kind: "clean"; readonly p: number; readonly calls: number }
  | { readonly kind: "masked"; readonly text: string; readonly count: number; readonly p: number; readonly calls: number }
  | { readonly kind: "unresolved"; readonly text: string; readonly count: number; readonly cause: string; readonly calls: number }

interface Token {
  readonly word: string
  readonly start: number
  readonly end: number
}

/** Separators of words: spaces, placeholders, and runs of scripts written without spaces (Chinese, Japanese, Korean). */
const SEPARATORS = new RegExp(`${PLACEHOLDER_RE.source}|[\\p{Script=Han}\\p{Script=Hiragana}\\p{Script=Katakana}\\p{Script=Hangul}\\u3000-\\u303f\\uff00-\\uffef]+|\\s+`, "gu")
const LEADING = /^[("'«“‘[]+/u
const TRAILING = /[)"'»”’\],.;:]+$/u

/** Words of a text with their positions, sentence punctuation around them removed (`printemps2026.`, `'blue-42'`). */
export function promptWords(text: string, from = 0, to = text.length): Token[] {
  const tokens: Token[] = []
  const add = (start: number, end: number) => {
    const raw = text.slice(start, end)
    const lead = raw.match(LEADING)?.[0].length ?? 0
    const word = raw.slice(lead).replace(TRAILING, "")
    if (word && start + lead < to) tokens.push({ word, start: start + lead, end: start + lead + word.length })
  }
  let at = from
  for (const match of text.slice(from, to).matchAll(SEPARATORS)) {
    const start = from + match.index
    if (start > at) add(at, start)
    at = start + match[0].length
  }
  if (to > at) add(at, to)
  return tokens
}

/** Parts of at most `size` characters, cut at a space when there is one in the second half. */
function parts(text: string, size: number): Array<[number, number]> {
  const ranges: Array<[number, number]> = []
  let start = 0
  while (start < text.length) {
    let end = Math.min(start + size, text.length)
    if (end < text.length) {
      const half = Math.floor(size / 2)
      const space = text.slice(start + half, end).search(/\s(?=\S*$)/u)
      if (space >= 0) end = start + half + space + 1
    }
    ranges.push([start, end])
    start = end
  }
  return ranges
}

const isNumber = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value)

export function createPromptChecker(deps: Pick<PromptCheckDeps, "model" | "label" | "threshold" | "timeoutMs"> & { readonly tuning?: PromptCheckTuning }) {
  const tuning = deps.tuning ?? PROMPT_CHECK_TUNING
  let running = 0
  const waiting: Array<() => void> = []
  /** At most `PARALLEL` calls at once (shared by the checks of every session). */
  async function call(request: Parameters<ModelClient>[0]) {
    if (running >= PARALLEL) await new Promise<void>((resolve) => waiting.push(resolve))
    running++
    try {
      return await deps.model(request)
    } finally {
      running--
      waiting.shift()?.()
    }
  }

  /** Model's view of a part: placeholders and words found shown as `<redacted>`. */
  function shown(text: string, [start, end]: [number, number], found: ReadonlySet<string>): string {
    let out = ""
    let at = start
    for (const token of promptWords(text, start, end))
      if (found.has(token.word)) {
        out += text.slice(at, token.start) + SHOWN_MASK
        at = token.end
      }
    return (out + text.slice(at, end)).replace(new RegExp(PLACEHOLDER_RE.source, "g"), SHOWN_MASK)
  }

  /** Stage 1: probability that the part gives a credential's value; throws a `ModelError` on failure. */
  async function stage1(message: string): Promise<number> {
    const answer = (await call({ state: { message }, questions: PROMPT_QUESTIONS })).answers[PROMPT_QUESTION_ID]
    if (answer?.error) throw new ModelError(`question \`${PROMPT_QUESTION_ID}\` refused`)
    if (!isNumber(answer?.noul)) throw new ModelError(`invalid answer: \`${PROMPT_QUESTION_ID}.noul\` missing`)
    return Math.min(Math.max(answer.noul, 0), 1)
  }

  /** Stage 2: the words of the part most likely to be the value, best first (at most `tuning.candidates`). */
  async function stage2(message: string, words: readonly string[]): Promise<{ candidates: string[]; calls: number }> {
    const batches: string[][] = []
    for (let at = 0; at < words.length; at += WORDS_PER_QUESTION) batches.push(words.slice(at, at + WORDS_PER_QUESTION))
    const answers = await Promise.all(
      batches.map(async (batch) => {
        const answer = (await call({ state: { message }, questions: promptWordQuestion(batch) })).answers[PROMPT_WORD_QUESTION_ID]
        if (answer?.error) throw new ModelError(`question \`${PROMPT_WORD_QUESTION_ID}\` refused`)
        const probabilities = answer?.probabilities
        if (!probabilities || typeof probabilities !== "object") throw new ModelError(`invalid answer: \`${PROMPT_WORD_QUESTION_ID}.probabilities\` missing`)
        return batch.flatMap((word, i) => {
          const p = probabilities[`w${i}`]
          return isNumber(p) && p >= tuning.minCandidate ? [{ word, p }] : []
        })
      }),
    )
    const candidates = answers.flat().sort((x, y) => y.p - x.p).slice(0, tuning.candidates).map((item) => item.word)
    return { candidates, calls: batches.length }
  }

  /** Stage 3: the candidates that really are the value. */
  async function stage3(message: string, candidates: readonly string[]): Promise<string[]> {
    const verdicts = await Promise.all(
      candidates.map(async (value) => {
        const answer = (await call({ state: { message, value }, questions: PROMPT_VERIFY_QUESTIONS })).answers[PROMPT_VERIFY_QUESTION_ID]
        if (answer?.error) throw new ModelError(`question \`${PROMPT_VERIFY_QUESTION_ID}\` refused`)
        if (!isNumber(answer?.noul)) throw new ModelError(`invalid answer: \`${PROMPT_VERIFY_QUESTION_ID}.noul\` missing`)
        return answer.noul >= tuning.verify
      }),
    )
    return candidates.filter((_, i) => verdicts[i])
  }

  /** Every occurrence of a word found, as a whole word, replaced with the placeholder. */
  function mask(text: string, found: ReadonlySet<string>): { text: string; count: number } {
    if (!found.size) return { text, count: 0 }
    let out = ""
    let at = 0
    let count = 0
    for (const token of promptWords(text))
      if (found.has(token.word)) {
        out += text.slice(at, token.start) + placeholder("prompt_secret")
        at = token.end
        count++
      }
    return { text: out + text.slice(at), count }
  }

  /** Check of a technically redacted text. Throws only a `ModelError` (failure, refusal, invalid answer). */
  async function run(text: string, state: { calls: number; found: Set<string> }): Promise<CheckOutcome> {
    if (text.length > PROMPT_MAX_CHARS) return { kind: "unresolved", text, count: 0, cause: "too long to check", calls: 0 }
    const ranges = parts(text, tuning.partChars)
    state.calls += ranges.length
    const scores = await Promise.all(ranges.map((range) => stage1(shown(text, range, state.found))))
    const p = Math.max(...scores)
    if (p < deps.threshold) return { kind: "clean", p, calls: state.calls }
    let unresolved: string | undefined
    await Promise.all(
      ranges.map(async (range, i) => {
        if (scores[i]! < deps.threshold) return
        let score = scores[i]!
        for (let round = 0; round < ROUNDS; round++) {
          const words = [...new Set(promptWords(text, ...range).map((token) => token.word))].filter((word) => [...word].length >= MIN_WORD && word !== SHOWN_MASK && !state.found.has(word))
          const message = shown(text, range, state.found)
          const { candidates, calls } = words.length ? await stage2(message, words) : { candidates: [], calls: 0 }
          state.calls += calls + candidates.length
          const confirmed = candidates.length ? await stage3(message, candidates) : []
          if (!confirmed.length) {
            // Seen but no word confirmed: a weak stage 1 is mostly a false alarm; a strong one, a secret not located.
            if (score >= tuning.askScore) unresolved = `${deps.label} ${score.toFixed(2)}, not located`
            return
          }
          for (const word of confirmed) state.found.add(word)
          // Still a value without the words found (a second password): another round.
          state.calls++
          score = await stage1(shown(text, range, state.found))
          if (score < deps.threshold) return
        }
        unresolved = `${deps.label} ${scores[i]!.toFixed(2)}, not all located`
      }),
    )
    const masked = mask(text, state.found)
    if (unresolved) return { kind: "unresolved", ...masked, cause: unresolved, calls: state.calls }
    return { kind: "masked", ...masked, p, calls: state.calls }
  }

  /** Never throws: a failure, a refusal or the deadline gives `unresolved`, with what was masked so far. */
  return async function check(text: string): Promise<CheckOutcome> {
    const state = { calls: 0, found: new Set<string>() }
    let timer: ReturnType<typeof setTimeout> | undefined
    const deadline = new Promise<"deadline">((resolve) => {
      timer = setTimeout(() => resolve("deadline"), DEADLINE_CALLS * deps.timeoutMs)
      timer.unref?.()
    })
    try {
      const outcome = await Promise.race([run(text, state), deadline])
      if (outcome !== "deadline") return outcome
      return { kind: "unresolved", ...mask(text, state.found), cause: "check too slow", calls: state.calls }
    } catch (error) {
      // Class only: a gateway may copy the request, so the prompt, into its error message.
      const cause = error instanceof ModelError ? (error.timeout ? "model timeout" : "model unavailable") : "internal error"
      return { kind: "unresolved", ...mask(text, state.found), cause, calls: state.calls }
    } finally {
      clearTimeout(timer)
    }
  }
}

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
