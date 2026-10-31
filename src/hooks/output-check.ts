// Checking of tool outputs by the decision model (`outputCheck` option, on by default with the decision model).
// Complement to technical redaction, for a secret written in plain words (`password: chocolat82` in a comment, a log, a
// page): the search of the prompt check (hooks/secret-check.ts) runs on every text the agent would see, cut into parts
// at line ends; the words found are masked in the whole result. Nothing is passed on unchecked, however long: a part
// where a value was seen but not located is masked whole; a model that fails (or answers too late) holds the output
// for a confirmation, with what was masked. Common rule for output hooks: NEVER throw.
import type { CheckTuning } from "../config.ts"
import type { ModelClient } from "../model/client.ts"
import { DEFAULT_OUTPUT_QUESTIONS, DEFAULT_PROMPT_QUESTIONS, outputQuestions, promptQuestions, type OutputQuestionTexts, type PromptQuestionTexts } from "../model/questions.ts"
import { redactToolError } from "../secrets/errors.ts"
import { placeholder, PLACEHOLDER_KEYWORD, PLACEHOLDER_RE, type Redactor } from "../secrets/redact.ts"
import { CODEMODE_TOOL } from "../rules/tools.ts"
import type { GuardContext, Logger, ToolAfterEvent, ToolResult } from "../types.ts"
import { guardAction, summarize, timedMap } from "./gate.ts"
import { REDACTION_NOTE, withRedactionNote } from "./redaction.ts"
import { createSecretChecker, maskWords, type TextOutcome } from "./secret-check.ts"
import type { UnprotectedGate } from "./unprotected.ts"

export interface OutputCheckDeps {
  readonly redactor: Redactor
  /** Model client with the timeout specific to the check (one call). */
  readonly model: ModelClient
  /** Model name, in reasons. */
  readonly label: string
  readonly threshold: number
  readonly tuning: CheckTuning
  /** Tools whose output is not checked. */
  readonly skip: readonly string[]
  readonly askAs: "ask" | "deny"
  readonly log: Logger
  readonly unprotected?: UnprotectedGate
  readonly now?: () => number
  /** Question texts (`outputCheck.questions`); absent = the defaults. */
  readonly questions?: OutputQuestionTexts
  /** Answers of the `question` tool, typed by the user: checked like a prompt (`promptCheck` settings). */
  readonly prompt?: { readonly threshold: number; readonly tuning: CheckTuning; readonly questions?: PromptQuestionTexts }
  /** Cache of part results shared by the sessions; absent = `OUTPUT_CACHE`. */
  readonly cache?: { readonly max: number; readonly ttlMs: number }
}

/** A file read again gives the same parts: their results are kept for a day (measured: 28 to 32 % of parts sent). */
export const OUTPUT_CACHE = { max: 20_000, ttlMs: 24 * 60 * 60 * 1000 }

/** Mark of a word found, and of a part where a value was seen but not located. */
export const OUTPUT_SECRET_MARK = placeholder("output_secret")
export const OUTPUT_UNCHECKED_MARK = placeholder("output_unchecked")

/** Note added once a part is masked whole. Without `[[…]]`, like the redaction note. */
export const UNCHECKED_NOTE = `[guard] An output_unchecked ${PLACEHOLDER_KEYWORD} placeholder replaces a passage where the decision model saw a secret it could not locate. If you need that passage, read a smaller range of it, or ask the user.`

/** Tool of the user's answers. */
const QUESTION_TOOL = "question"

/** Notice seen by the agent in place of a withheld output; strings in other fields replaced by the marker. */
const WITHHELD = "[guard: output withheld]"

export function withheldNotice(tool: string, why: string, feedback?: string): string {
  const base = `[guard] The output of ${tool} was withheld: ${why}. Do not try to obtain it another way; tell the user what you needed it for.`
  return feedback ? `${base} User feedback: ${feedback}` : base
}

/** Redactor substitute: every non-empty string becomes the marker (shape preserved, as with redaction). */
const withholder: Redactor = {
  redactString: (text) => (text ? { value: WITHHELD, count: 1 } : { value: text, count: 0 }),
  redactDeep<T>(value: T) {
    let count = 0
    const seen = new WeakSet<object>()
    const walk = (node: unknown, depth: number): unknown => {
      if (typeof node === "string") {
        if (!node) return node
        count++
        return WITHHELD
      }
      if (node === null || typeof node !== "object") return node
      if (depth > 64 || seen.has(node)) {
        count++
        return WITHHELD
      }
      seen.add(node)
      if (Array.isArray(node)) return node.map((item) => walk(item, depth + 1))
      return Object.fromEntries(Object.entries(node).map(([key, item]) => [key, walk(item, depth + 1)]))
    }
    const result = walk(value, 0) as T
    return { value: result, count }
  },
  containsSecret: () => true,
}

/** Texts seen by the conversation model: `output` when it is a text, and the text parts of `content`. */
function visibleTexts(result: ToolResult): string[] {
  const content = typeof result.content === "string" ? [result.content] : (result.content ?? []).flatMap((part) => {
    const { type, text } = (part ?? {}) as { type?: unknown; text?: unknown }
    return type === "text" && typeof text === "string" ? [text] : []
  })
  return typeof result.output === "string" ? [result.output, ...content] : content
}

/** Strings of a value other than a text (an output object, metadata): each string leaf. */
function leaves(value: unknown, out: string[] = [], depth = 0): string[] {
  if (typeof value === "string") out.push(value)
  else if (value !== null && typeof value === "object" && depth < 64) for (const item of Object.values(value)) leaves(item, out, depth + 1)
  return out
}

/**
 * Messages of a tool error and its cause chain (OpenCode shows the cause message to the model): an
 * `Error`'s `message` is not enumerable and would otherwise be lost. Bounded depth, like error redaction.
 */
function errorMessages(error: { message?: unknown; error?: unknown }): string[] {
  const messages = typeof error.message === "string" ? [error.message] : []
  let cause: unknown = error.error
  for (let depth = 0; depth < 32 && cause !== undefined && cause !== null; depth++) {
    if (typeof cause === "string") {
      messages.push(cause)
      break
    }
    if (typeof cause !== "object") break
    const item = cause as { message?: unknown; cause?: unknown; error?: unknown }
    if (typeof item.message === "string") messages.push(item.message)
    cause = item.cause ?? item.error
  }
  return messages
}

/**
 * Withheld output: notice in its place; never the original output, even if the full replacement fails (defensive fallback,
 * `replaceError` injectable for testing it).
 */
export function withhold(event: ToolAfterEvent, notice: string, replaceError: typeof redactToolError = redactToolError): void {
  if (event.status === "completed") {
    try {
      event.result = {
        ...(event.result.output === undefined ? {} : { output: withholder.redactDeep(event.result.output).value }),
        content: [{ type: "text", text: notice }],
        ...(event.result.metadata === undefined ? {} : { metadata: withholder.redactDeep(event.result.metadata).value }),
      }
    } catch {
      event.result = { content: [{ type: "text", text: notice }] }
    }
    return
  }
  try {
    // Error class kept (OpenCode rethrows it with `yield*` and thus recognizes a rejection), message replaced.
    const replaced = replaceError(event.error, withholder).value
    event.error = Object.assign(replaced, { message: notice })
    if (event.error.message !== notice) throw new Error("message not replaced")
  } catch {
    // Minimal fallback: same prototype, notice only.
    const minimal = Object.create(Object.getPrototypeOf(event.error) as object) as Record<string, unknown>
    Object.defineProperty(minimal, "message", { value: notice, writable: true, configurable: true })
    const tag = (event.error as unknown as { _tag?: unknown })._tag
    if (tag !== undefined) Object.defineProperty(minimal, "_tag", { value: tag, enumerable: true, configurable: true })
    event.error = minimal as unknown as typeof event.error
  }
}

/** Nothing to judge: only placeholders, notes, punctuation and spaces. */
function nothingToJudge(text: string): boolean {
  return !/[\p{L}\p{N}]/u.test(text.split(REDACTION_NOTE).join("").split(UNCHECKED_NOTE).join("").replace(new RegExp(PLACEHOLDER_RE.source, "g"), ""))
}

/** Metadata strings shorter than this are checked together, in one text. */
const SHORT_STRING = 200

/** Lines of an unlocated part long enough to recognize a copy of it elsewhere (a preview in metadata). */
const MIN_COPY_LINE = 16

interface Masks {
  /** Words masked everywhere (confirmed, or safety-net words when the model failed). */
  readonly words: ReadonlySet<string>
  /** Each checked text and its masked version (unlocated parts replaced by position, then the words). */
  readonly texts: ReadonlyMap<string, string>
  /** Text of the unlocated parts, and their long lines. */
  readonly parts: readonly string[]
  readonly lines: readonly string[]
}

/** Masked version of any string of the result: the checked text, a copy of an unlocated part, the words. */
function maskString(text: string, masks: Masks): string {
  const known = masks.texts.get(text)
  if (known !== undefined) return known
  let out = text
  for (const part of masks.parts) if (out.includes(part)) out = out.split(part).join(OUTPUT_UNCHECKED_MARK)
  // A partial copy of an unlocated part (a truncated preview): the whole string.
  if (masks.lines.some((line) => out.includes(line))) return OUTPUT_UNCHECKED_MARK
  return maskWords(out, masks.words, OUTPUT_SECRET_MARK).text
}

/** Redactor applying the masks to every string (result fields, error message, metadata and causes). */
function masker(masks: Masks): Redactor {
  const redactString = (text: string) => {
    const value = maskString(text, masks)
    return { value, count: value === text ? 0 : 1 }
  }
  return {
    redactString,
    redactDeep<T>(value: T) {
      let count = 0
      const seen = new WeakMap<object, unknown>()
      const walk = (node: unknown, depth: number): unknown => {
        if (typeof node === "string") {
          const result = redactString(node)
          count += result.count
          return result.value
        }
        if (node === null || typeof node !== "object") return node
        if (seen.has(node)) return seen.get(node)
        if (depth > 64) {
          count++
          return OUTPUT_UNCHECKED_MARK
        }
        const copy = Array.isArray(node) ? node.map((item) => walk(item, depth + 1)) : Object.fromEntries(Object.entries(node).map(([key, item]) => [key, walk(item, depth + 1)]))
        seen.set(node, copy)
        return copy
      }
      const result = walk(value, 0) as T
      return { value: result, count }
    },
    containsSecret: (value) => leaves(value).some((text) => maskString(text, masks) !== text),
  }
}

/**
 * Something of the masks left in a masked string: a word as a whole word, or a whole unlocated part (its long lines may
 * repeat elsewhere in the output: they only serve to recognize a partial copy, in `maskString`).
 */
function leftIn(text: string, masks: Masks): boolean {
  return masks.parts.some((part) => text.includes(part)) || maskWords(text, masks.words, OUTPUT_SECRET_MARK).count > 0
}

const isNumber = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value)

export async function registerOutputCheck(ctx: GuardContext, deps: OutputCheckDeps): Promise<void> {
  const { log } = deps
  const now = deps.now ?? Date.now
  const cache = { ...(deps.cache ?? OUTPUT_CACHE), now }
  const skip = new Set(deps.skip)
  const outputs = createSecretChecker({ model: deps.model, label: deps.label, threshold: deps.threshold, tuning: deps.tuning, field: "output", questions: outputQuestions(deps.questions ?? DEFAULT_OUTPUT_QUESTIONS), cut: "line", cache })
  const prompt = deps.prompt ?? { threshold: deps.threshold, tuning: deps.tuning }
  const answers = createSecretChecker({ model: deps.model, label: deps.label, threshold: prompt.threshold, tuning: prompt.tuning, field: "message", questions: promptQuestions(prompt.questions ?? DEFAULT_PROMPT_QUESTIONS), cache })
  /** `execute` (CodeMode) calls in progress: their internal calls carry the same identifier and are not checked. */
  const codeMode = timedMap<true>(now)
  /** A single WARN line per series of failures (gateway down: not one line per output). */
  let failing = false
  const key = (sessionID: string, id: string) => `${sessionID}\u0000${id}`

  await ctx.tool.hook("execute.before", (event) => {
    try {
      if (event.tool === CODEMODE_TOOL) codeMode.add(key(event.sessionID, event.id), true)
    } catch (error) {
      log.error("internal error in output check (execute.before)", error)
    }
  })

  /** Confirmation for an output the check could not finish: `undefined` = approved, otherwise why it is withheld. */
  async function confirm(event: ToolAfterEvent, cause: string): Promise<{ why: string; feedback?: string } | undefined> {
    const what = `the output check could not finish (${cause})`
    if (deps.askAs === "deny") return { why: `${what}, and unattended mode (askAs: deny) withholds it` }
    // Relevant call, as in gate asks: summary of the redacted input (fallback: the tool name).
    let resource = `${event.tool}: output check`
    try {
      resource = `${summarize(event.tool, deps.redactor.redactDeep(event.input).value)} (output check)`
    } catch {}
    const reason = `${what}: approve to pass the output of ${event.tool} to the agent with what was masked (a secret may remain), reject to withhold it`
    // The prompt's action, at most 120 characters: the choice first, so that a long tool name never hides it.
    const prompt = `approve to pass on, reject to withhold: ${event.tool} output not fully checked (${cause})`
    try {
      await ctx.permission.assert({
        sessionID: event.sessionID,
        agent: event.agent,
        action: guardAction(deps.redactor, prompt),
        resources: [resource],
        metadata: { guard: true, tool: event.tool, reason },
        source: { type: "tool", messageID: event.messageID, id: event.id },
      })
      log.debug(`${event.tool} → output check: passed on by the user (${cause})`)
      return undefined
    } catch (error) {
      const name = (error as { name?: unknown } | undefined)?.name
      // User comment: passed to the agent (as for native tools), never to the log.
      const raw = name === "Permission.CorrectedError" ? (error as { feedback?: unknown }).feedback : undefined
      log.debug(`${event.tool} → output check: confirmation not granted (${typeof name === "string" ? name : "error"})`)
      const feedback = typeof raw === "string" && raw.trim() ? deps.redactor.redactString(raw.trim()).value : undefined
      return { why: `${what}, and the user did not approve passing it on`, ...(feedback ? { feedback } : {}) }
    }
  }

  await ctx.tool.hook("execute.after", async (event) => {
    try {
      if (await deps.unprotected?.isUnprotected(event.sessionID, event.agent)) return
      const callKey = key(event.sessionID, event.id)
      if (event.tool === CODEMODE_TOOL) codeMode.take(callKey)
      // Internal call of a CodeMode script: the model only sees the result of the outer `execute`.
      else if (codeMode.has(callKey)) return
      // Skipped tools: their successful output only (an `edit` error quotes lines of the file).
      if (skip.has(event.tool) && event.status === "completed") return
      // Technically redacted copy first, regardless of `redactOutputs` and hook order: never a known secret sent, and
      // the texts checked are those of the result that is masked.
      const base = event.status === "completed" ? { result: deps.redactor.redactDeep(event.result).value } : { error: redactToolError(event.error, deps.redactor).value }
      // Texts the agent sees, then the strings of a non-text output and of the metadata: OpenCode sends `metadata.output`
      // of an interrupted call to the model. Short metadata strings (paths, titles) are checked together, in one text.
      const seen = base.result ? [...visibleTexts(base.result), ...(typeof base.result.output === "string" ? [] : leaves(base.result.output))] : errorMessages(base.error!)
      const other = leaves(base.result ? base.result.metadata : (base.error as { metadata?: unknown }).metadata).filter((text) => !nothingToJudge(text))
      const texts = [...new Set([...seen, ...other.filter((text) => text.length >= SHORT_STRING)])].filter((text) => !nothingToJudge(text))
      const short = [...new Set(other.filter((text) => text.length < SHORT_STRING && !texts.includes(text)))]
      if (short.length) texts.push(short.join("\n"))
      if (!texts.length) return
      const start = now()
      const checker = event.tool === QUESTION_TOOL ? answers : outputs
      const extra: Record<string, string> = event.tool === QUESTION_TOOL ? {} : { tool: event.tool }
      const outcomes: TextOutcome[] = await Promise.all(texts.map((text) => checker(text, extra)))
      const failure = outcomes.find((outcome) => outcome.failure)?.failure
      const words = new Set(outcomes.flatMap((outcome) => [...outcome.found, ...(failure ? outcome.net : [])]))
      const unresolved = outcomes.reduce((n, outcome) => n + outcome.unresolved.length, 0)
      const calls = outcomes.reduce((n, outcome) => n + outcome.calls, 0)
      const took = `${calls} call(s), ${now() - start} ms`
      if (failure) {
        if (!failing) log.warn(`output check unavailable (${failure}): each output is held for a confirmation until it answers again`)
        failing = true
      } else {
        if (failing) log.info("output check available again")
        failing = false
      }
      if (!words.size && !unresolved && !failure) {
        log.debug(`${event.tool} → output check: no secret (${deps.label} ${Math.max(...outcomes.map((outcome) => outcome.p)).toFixed(2)}; ${took})`)
        return
      }
      // Masks: unlocated parts by position in their text, then the words, everywhere.
      const parts: string[] = []
      const masked = new Map<string, string>()
      texts.forEach((text, i) => {
        // The short strings checked together: each one masked whole if a value was seen there and not located.
        if (short.length && i === texts.length - 1) {
          if (outcomes[i]!.unresolved.length) for (const item of short) masked.set(item, OUTPUT_UNCHECKED_MARK)
          return
        }
        let out = ""
        let at = 0
        for (const range of outcomes[i]!.unresolved) {
          parts.push(text.slice(range.start, range.end))
          out += text.slice(at, range.start) + OUTPUT_UNCHECKED_MARK + (/\n$/.test(text.slice(range.start, range.end)) ? "\n" : "")
          at = range.end
        }
        masked.set(text, maskWords(out + text.slice(at), words, OUTPUT_SECRET_MARK).text)
      })
      const lines = [...new Set(parts.flatMap((part) => part.split("\n").map((line) => line.trim()).filter((line) => line.length >= MIN_COPY_LINE)))]
      const masks: Masks = { words, texts: masked, parts: parts.filter((part) => part.trim()), lines }
      const mask = masker(masks)
      let notice: string | undefined
      if (event.status === "completed" && base.result) {
        const result = mask.redactDeep(base.result).value
        const shown = visibleTexts(result)
        if ([...shown, ...leaves(result.metadata), ...leaves(result.output)].some((text) => leftIn(text, masks))) notice = "a secret seen in it could not be masked reliably"
        else {
          let content = result.content
          const seen = shown.join("\n")
          if (!seen.includes(REDACTION_NOTE)) content = withRedactionNote(content)
          if (unresolved && !seen.includes(UNCHECKED_NOTE)) content = withNote(content, UNCHECKED_NOTE)
          event.result = { ...result, content }
        }
      } else if (event.status === "error") {
        const error = redactToolError(base.error!, mask).value
        if (errorMessages(error).some((text) => leftIn(text, masks))) notice = "a secret seen in it could not be masked reliably"
        else event.error = error
      }
      log.debug(`${event.tool} → output check: ${words.size} word(s) masked, ${unresolved} part(s) masked whole${failure ? `, not finished (${failure})` : ""} (${took})`)
      if (notice === undefined && failure) {
        const refused = await confirm(event, failure)
        if (refused) withhold(event, withheldNotice(event.tool, refused.why, refused.feedback))
        return
      }
      if (notice !== undefined) {
        withhold(event, withheldNotice(event.tool, notice))
        log.debug(`${event.tool} → output withheld (masks not applied everywhere)`)
      }
    } catch (error) {
      // Internal error: output passed on as is (it has already been redacted by the redaction hook if active).
      log.error("internal error in output check", error)
    }
  })
}

/** `note` appended to the last text part (or to a text content), once. */
function withNote<T>(content: T, note: string): T {
  if (typeof content === "string") return `${content}\n\n${note}` as T
  if (!Array.isArray(content)) return content
  const parts = content as ReadonlyArray<{ type?: unknown; text?: unknown }>
  for (let index = parts.length - 1; index >= 0; index--) {
    const part = parts[index]!
    if (part?.type !== "text" || typeof part.text !== "string") continue
    const next = [...parts]
    next[index] = { ...part, text: `${part.text}\n\n${note}` }
    return next as T
  }
  return content
}
