// Search for a secret written in plain words by the decision model, common to the prompt check and the output check.
// The text (already technically redacted) is cut into parts; stage 1 asks whether a part gives a credential's value;
// stage 2, only for a part that does, which of its words is the value; stage 3 whether that word really is the value.
// Safety net: a word built like a password (at least 8 characters with a lower case letter, an upper case letter, a
// digit and another character) goes to stage 3 even when stage 1 sees nothing; it is never masked without the model,
// except when the model fails. Each part is judged on its own, so that its result can be kept in a cache shared by
// the sessions (outputs: the same file read again). The decision model is the trusted zone: it may see a value in
// clear. Calibration: dev/plans/prompt-secrets/plan.md.
import { createHash } from "node:crypto"
import { ModelError, type ModelClient, type ModelQuestion } from "../model/client.ts"
import type { CheckTuning } from "../config.ts"
import { PLACEHOLDER_RE } from "../secrets/redact.ts"

/**
 * What the model sees in place of a masked secret: a `[[GUARD_REDACTED:…]]` placeholder or a removed word reads as a
 * secret still there (`redis://user:@host` 0.37, `<redacted>` 0.09).
 */
export const SHOWN_MASK = "<redacted>"

export interface Token {
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

/**
 * Safety net: a word built like a password, at least 8 characters with a lower case letter, an upper case letter, a
 * digit and another character. Measured: 6 of 7 real typed secrets; 3,825 of 15,004 parts of real outputs hold one
 * (code), hence never masked on this alone.
 */
export function looksLikePassword(word: string): boolean {
  return [...word].length >= 8 && /\p{Ll}/u.test(word) && /\p{Lu}/u.test(word) && /\p{N}/u.test(word) && /[^\p{L}\p{N}]/u.test(word) && word !== SHOWN_MASK
}

/** Line number prefix of a `read` output (`12: text`). */
const LINE_NUMBER = /^ *\d+: /gm

/** 32-bit FNV-1a: a cheap, stable fingerprint of a line. */
function fingerprint(text: string): number {
  let hash = 0x811c9dc5
  for (let i = 0; i < text.length; i++) hash = Math.imul(hash ^ text.charCodeAt(i), 0x01000193) >>> 0
  return hash
}

/**
 * Parts of at most `size` characters. `space`: cut at the last space of the second half (prompts). `line`: cut at the
 * end of the line of smallest fingerprint in the second half (line numbers ignored), so that the same text read again
 * from another line is cut at the same places (outputs, cache); otherwise at the last space.
 */
export function parts(text: string, size: number, cut: "space" | "line" = "space"): Array<[number, number]> {
  const ranges: Array<[number, number]> = []
  let start = 0
  while (start < text.length) {
    let end = Math.min(start + size, text.length)
    if (end < text.length) {
      const half = Math.floor(size / 2)
      let chosen = -1
      if (cut === "line") {
        let best = Infinity
        let line = text.lastIndexOf("\n", start + half - 1) + 1
        for (let nl = text.indexOf("\n", start + half); nl >= 0 && nl < end; nl = text.indexOf("\n", nl + 1)) {
          const value = fingerprint(text.slice(Math.max(line, start), nl).replace(LINE_NUMBER, ""))
          if (value < best) {
            best = value
            chosen = nl + 1
          }
          line = nl + 1
        }
      }
      if (chosen < 0) {
        const space = text.slice(start + half, end).search(/\s(?=\S*$)/u)
        if (space >= 0) chosen = start + half + space + 1
      }
      if (chosen > start) end = chosen
    }
    ranges.push([start, end])
    start = end
  }
  return ranges
}

/** Questions of the three stages, with the identifiers their answers are read by. */
export interface CheckerQuestions {
  readonly secret: Record<string, ModelQuestion>
  readonly value: Record<string, ModelQuestion>
  readonly word: (words: readonly string[]) => Record<string, ModelQuestion>
  readonly ids: { readonly secret: string; readonly word: string; readonly value: string }
}

export interface SecretCheckerDeps {
  readonly model: ModelClient
  /** Model name, in causes. */
  readonly label: string
  readonly threshold: number
  readonly tuning: CheckTuning
  /** Field of the state that holds the text (`message`: prompts, `output`: tool outputs). */
  readonly field: "message" | "output"
  readonly questions: CheckerQuestions
  readonly cut?: "space" | "line"
  /** Cache of part results shared by every check of this checker; absent = none. */
  readonly cache?: { readonly max: number; readonly ttlMs: number; readonly now?: () => number }
}

/** Result of a part: words confirmed (stages 2-3 and safety net), and why a value seen was not located. */
export interface PartResult {
  readonly score: number
  readonly found: readonly string[]
  readonly unresolved?: string
}

/** Outcome of a check; never a word in a cause. `failure`: the model failed, `found` holds what was confirmed before. */
export interface TextOutcome {
  /** Highest stage-1 score (0 without a part). */
  readonly p: number
  readonly found: ReadonlySet<string>
  /** Parts where a value was seen but not located, with the cause. */
  readonly unresolved: ReadonlyArray<{ readonly start: number; readonly end: number; readonly cause: string }>
  /** Safety-net words of the text not confirmed by the model (masked when the model fails). */
  readonly net: readonly string[]
  readonly failure?: string
  readonly calls: number
}

const isNumber = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value)

/** Causes where the check did not run to its end (model failure, limits): shown in capitals at the head of a confirmation. */
const CHECK_FAILURES = new Set(["model timeout", "model unavailable", "internal error", "check too slow", "too long to check"])

/** A cause as the head of a confirmation's action: a failure of the check in capitals, any other as is. */
export const shownCause = (cause: string) => (CHECK_FAILURES.has(cause) ? cause.toUpperCase() : cause)

/** Failure cause, class only: a gateway may copy the request, so the text, into its error message. */
export const failureCause = (error: unknown) => (error instanceof ModelError ? (error.timeout ? "model timeout" : "model unavailable") : "internal error")

/** Every occurrence of a word of `found`, as a whole word, replaced with `mark`. */
export function maskWords(text: string, found: ReadonlySet<string>, mark: string): { text: string; count: number } {
  if (!found.size) return { text, count: 0 }
  let out = ""
  let at = 0
  let count = 0
  for (const token of promptWords(text))
    if (found.has(token.word)) {
      out += text.slice(at, token.start) + mark
      at = token.end
      count++
    }
  return { text: out + text.slice(at), count }
}

export function createSecretChecker(deps: SecretCheckerDeps) {
  const { tuning, questions, field } = deps
  const ids = questions.ids
  const cut = deps.cut ?? "space"
  const now = deps.cache?.now ?? Date.now
  const cache = new Map<string, { result: PartResult; expires: number }>()
  /** Settings and questions in the cache key: a change of either never reuses an old result. */
  const settings = JSON.stringify([field, cut, deps.threshold, tuning, questions.secret, questions.value, questions.word(["w"])])
  let running = 0
  const waiting: Array<() => void> = []
  /** At most `tuning.parallel` calls at once (shared by the checks of every session). */
  async function call(request: Parameters<ModelClient>[0]) {
    if (running >= tuning.parallel) await new Promise<void>((resolve) => waiting.push(resolve))
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

  type Extra = Readonly<Record<string, string>>
  const state = (extra: Extra, text: string, more: Extra = {}) => ({ ...extra, [field]: text, ...more })

  /** Stage 1: probability that the part gives a credential's value; throws a `ModelError` on failure. */
  async function stage1(extra: Extra, message: string): Promise<number> {
    const answer = (await call({ state: state(extra, message), questions: questions.secret })).answers[ids.secret]
    if (answer?.error) throw new ModelError(`question \`${ids.secret}\` refused`)
    if (!isNumber(answer?.noul)) throw new ModelError(`invalid answer: \`${ids.secret}.noul\` missing`)
    return Math.min(Math.max(answer.noul, 0), 1)
  }

  /** Stage 2: the words of the part most likely to be the value, best first (at most `tuning.candidates`). */
  async function stage2(extra: Extra, message: string, words: readonly string[]): Promise<{ candidates: string[]; calls: number }> {
    const batches: string[][] = []
    for (let at = 0; at < words.length; at += tuning.wordsPerQuestion) batches.push(words.slice(at, at + tuning.wordsPerQuestion))
    const answers = await Promise.all(
      batches.map(async (batch) => {
        const answer = (await call({ state: state(extra, message), questions: questions.word(batch) })).answers[ids.word]
        if (answer?.error) throw new ModelError(`question \`${ids.word}\` refused`)
        const probabilities = answer?.probabilities
        if (!probabilities || typeof probabilities !== "object") throw new ModelError(`invalid answer: \`${ids.word}.probabilities\` missing`)
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
  async function stage3(extra: Extra, message: string, candidates: readonly string[]): Promise<string[]> {
    const verdicts = await Promise.all(
      candidates.map(async (value) => {
        const answer = (await call({ state: state(extra, message, { value }), questions: questions.value })).answers[ids.value]
        if (answer?.error) throw new ModelError(`question \`${ids.value}\` refused`)
        if (!isNumber(answer?.noul)) throw new ModelError(`invalid answer: \`${ids.value}.noul\` missing`)
        return answer.noul >= tuning.verify
      }),
    )
    return candidates.filter((_, i) => verdicts[i])
  }

  /** One part, judged on its own; throws only a `ModelError`. `counter.calls` counts the calls made. */
  async function checkPart(text: string, range: [number, number], extra: Extra, counter: { calls: number }): Promise<PartResult> {
    const found = new Set<string>()
    counter.calls++
    const first = await stage1(extra, shown(text, range, found))
    let unresolved: string | undefined
    if (first >= deps.threshold) {
      let score = first
      unresolved = `${deps.label} ${first.toFixed(2)}, not all located`
      for (let round = 0; round < tuning.rounds; round++) {
        const words = [...new Set(promptWords(text, ...range).map((token) => token.word))].filter((word) => [...word].length >= tuning.minWord && word !== SHOWN_MASK && !found.has(word))
        const message = shown(text, range, found)
        const { candidates, calls } = words.length ? await stage2(extra, message, words) : { candidates: [], calls: 0 }
        counter.calls += calls + candidates.length
        const confirmed = candidates.length ? await stage3(extra, message, candidates) : []
        if (!confirmed.length) {
          // Seen but no word confirmed: a weak stage 1 is mostly a false alarm; a strong one, a secret not located.
          unresolved = score >= tuning.askScore ? `${deps.label} ${score.toFixed(2)}, not located` : undefined
          break
        }
        for (const word of confirmed) found.add(word)
        // Still a value without the words found (a second password): another round.
        counter.calls++
        score = await stage1(extra, shown(text, range, found))
        if (score < deps.threshold) {
          unresolved = undefined
          break
        }
      }
    }
    // Safety net: each word built like a password, not confirmed yet, is put to stage 3.
    const net = [...new Set(promptWords(text, ...range).map((token) => token.word))].filter((word) => looksLikePassword(word) && !found.has(word))
    if (net.length) {
      counter.calls += net.length
      for (const word of await stage3(extra, shown(text, range, found), net)) found.add(word)
    }
    return { score: first, found: [...found], ...(unresolved ? { unresolved } : {}) }
  }

  /** Cache key of a part: its text (line numbers removed for outputs), the extra state, settings and questions. */
  function cacheKey(text: string, [start, end]: [number, number], extra: Extra): string {
    const body = field === "output" ? text.slice(start, end).replace(LINE_NUMBER, "") : text.slice(start, end)
    return createHash("sha256").update(settings).update("\u0000").update(JSON.stringify(extra)).update("\u0000").update(body).digest("hex")
  }

  async function cachedPart(text: string, range: [number, number], extra: Extra, counter: { calls: number }): Promise<PartResult> {
    if (!deps.cache || deps.cache.max <= 0 || deps.cache.ttlMs <= 0) return checkPart(text, range, extra, counter)
    const key = cacheKey(text, range, extra)
    const hit = cache.get(key)
    if (hit && hit.expires > now()) return hit.result
    const result = await checkPart(text, range, extra, counter)
    cache.delete(key)
    if (cache.size >= deps.cache.max) cache.delete(cache.keys().next().value!)
    cache.set(key, { result, expires: now() + deps.cache.ttlMs })
    return result
  }

  /**
   * Check of a technically redacted text; never throws. `progress` receives the words confirmed as parts finish (what a
   * deadline set by the caller can still mask).
   */
  async function check(text: string, extra: Extra = {}, progress: { found: Set<string>; calls: number } = { found: new Set(), calls: 0 }): Promise<TextOutcome> {
    const ranges = parts(text, tuning.partChars, cut)
    const net = netWords(text)
    const unresolved: Array<{ start: number; end: number; cause: string }> = []
    let p = 0
    try {
      await Promise.all(
        ranges.map(async (range) => {
          const result = await cachedPart(text, range, extra, progress)
          p = Math.max(p, result.score)
          for (const word of result.found) progress.found.add(word)
          if (result.unresolved) unresolved.push({ start: range[0], end: range[1], cause: result.unresolved })
        }),
      )
    } catch (error) {
      return { p, found: progress.found, unresolved, net: net.filter((word) => !progress.found.has(word)), failure: failureCause(error), calls: progress.calls }
    }
    unresolved.sort((a, b) => a.start - b.start)
    return { p, found: progress.found, unresolved, net: net.filter((word) => !progress.found.has(word)), calls: progress.calls }
  }
  return Object.assign(check, { netWords })
}

/** Safety-net words of a text. */
export const netWords = (text: string) => [...new Set(promptWords(text).map((token) => token.word).filter(looksLikePassword))]
