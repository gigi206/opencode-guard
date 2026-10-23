// Checking of tool outputs by the decision model (`outputCheck` option, disabled by default). Complement to
// deterministic redaction: the model does not locate a secret, it flags an output; the user then decides whether it
// is passed to the agent. Common rule for output hooks: NEVER throw.
import { createHash } from "node:crypto"
import { truncateInput } from "../decide.ts"
import { ModelError, type ModelClient } from "../model/client.ts"
import { OUTPUT_NOTE, OUTPUT_QUESTION_ID, OUTPUT_QUESTIONS } from "../model/questions.ts"
import { redactToolError } from "../secrets/errors.ts"
import { PLACEHOLDER_RE, type Redactor } from "../secrets/redact.ts"
import { CODEMODE_TOOL } from "../rules/tools.ts"
import type { GuardContext, Logger, ToolAfterEvent, ToolResult } from "../types.ts"
import { GUARD_ACTION, summarize, timedMap } from "./gate.ts"
import { REDACTION_NOTE } from "./redaction.ts"
import type { UnprotectedGate } from "./unprotected.ts"

export interface OutputCheckDeps {
  readonly redactor: Redactor
  /** Model client with the timeout specific to the check. */
  readonly model: ModelClient
  /** Model name, in reasons. */
  readonly label: string
  readonly threshold: number
  readonly maxStateChars: number
  readonly askAs: "ask" | "deny"
  readonly cacheTtlMs: number
  readonly cacheMax: number
  readonly log: Logger
  readonly unprotected?: UnprotectedGate
  readonly now?: () => number
}

/**
 * Unchecked outputs: burst reads (same reason as for their inputs), writes (their output repeats what
 * the agent wrote), questions to the user, skills and subagents (each subagent tool is checked),
 * task list (its output repeats the received list).
 */
export const OUTPUT_CHECK_SKIPPED = new Set(["read", "glob", "grep", "edit", "write", "patch", "question", "skill", "subagent", "todowrite"])

/** Notice seen by the agent in place of a withheld output; strings in other fields replaced by the marker. */
const WITHHELD = "[guard: output withheld]"

export function withheldNotice(tool: string, why: string, feedback?: string): string {
  const base = `[guard] The output of ${tool} was withheld: the decision model judged that it may contain a secret in clear, and ${why}. Do not try to obtain it another way; tell the user what you needed it for.`
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

/**
 * Text seen by the conversation model: text parts of `content`, and `output` if it brings something else (a shell output
 * often has the same text in both: sent once, the `maxStateChars` budget is not halved).
 */
function visibleOf(result: ToolResult): unknown {
  const content = typeof result.content === "string" ? [result.content] : (result.content ?? []).flatMap((part) => {
    const { type, text } = (part ?? {}) as { type?: unknown; text?: unknown }
    return type === "text" && typeof text === "string" ? [text] : []
  })
  const joined = content.join("\n")
  if (result.output === undefined || (typeof result.output === "string" && joined.includes(result.output))) return { content }
  return { output: result.output, content }
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

/** Note for the model, with the preceding blank line, as it appears in the serialized text (escaped). */
const SERIALIZED_NOTE = JSON.stringify(`\n\n${REDACTION_NOTE}`).slice(1, -1)

/** Nothing to judge: empty, or only placeholders, the redaction note, and punctuation. */
function nothingToJudge(serialized: string): boolean {
  return !/[A-Za-z0-9]/.test(serialized.split(SERIALIZED_NOTE).join("").replace(new RegExp(PLACEHOLDER_RE.source, "g"), "").replace(/\b(?:output|content|message|error|null)\b/g, ""))
}

const isNumber = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value)

export async function registerOutputCheck(ctx: GuardContext, deps: OutputCheckDeps): Promise<void> {
  const { log } = deps
  const now = deps.now ?? Date.now
  const cache = new Map<string, { p: number; expires: number }>()
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

  /** Probability that an output contains a secret in clear; throws a `ModelError` on failure. */
  async function judge(tool: string, redacted: unknown): Promise<number> {
    const state = { note: OUTPUT_NOTE, tool, output: truncateInput(redacted, deps.maxStateChars) }
    const id = createHash("sha256").update(JSON.stringify(state)).digest("hex")
    const cached = cache.get(id)
    if (cached && cached.expires > now()) return cached.p
    const response = await deps.model({ state, questions: OUTPUT_QUESTIONS })
    const answer = response.answers[OUTPUT_QUESTION_ID]
    if (answer?.error) throw new ModelError(`question \`${OUTPUT_QUESTION_ID}\` refused`)
    if (!isNumber(answer?.noul)) throw new ModelError(`invalid answer: \`${OUTPUT_QUESTION_ID}.noul\` missing`)
    // Out of range: never less strict (a value above 1 still counts as a flag).
    const p = Math.min(Math.max(answer.noul, 0), 1)
    if (deps.cacheMax > 0 && deps.cacheTtlMs > 0) {
      if (cache.size >= deps.cacheMax) cache.delete(cache.keys().next().value!)
      cache.set(id, { p, expires: now() + deps.cacheTtlMs })
    }
    return p
  }

  await ctx.tool.hook("execute.after", async (event) => {
    try {
      if (await deps.unprotected?.isUnprotected(event.sessionID, event.agent)) return
      const callKey = key(event.sessionID, event.id)
      if (event.tool === CODEMODE_TOOL) codeMode.take(callKey)
      // Internal call of a CodeMode script: the model only sees the result of the outer `execute`.
      else if (codeMode.has(callKey)) return
      if (OUTPUT_CHECK_SKIPPED.has(event.tool)) return
      // Redacted copy here, regardless of `redactOutputs` and hook order: never a known secret sent.
      const visible = event.status === "completed" ? visibleOf(event.result) : { messages: errorMessages(event.error) }
      const redacted = deps.redactor.redactDeep(visible).value
      if (nothingToJudge(JSON.stringify(redacted) ?? "")) return
      let p: number
      try {
        p = await judge(event.tool, redacted)
      } catch (error) {
        // Model failure: (redacted) output passed on, reported once per series of failures.
        // Redacted FIRST, then cut (log): cut before, the fragment of an echoed key would no longer be recognized.
        const message = error instanceof ModelError ? deps.redactor.redactString(error.message).value : "internal error"
        const cause = message.length > 160 ? `${message.slice(0, 160)}…` : message
        if (!failing) log.warn(`output check unavailable (${cause}): outputs are passed on unchecked until it answers again`)
        else log.debug(`${event.tool} → output check failed (${cause}): output passed on`)
        failing = true
        return
      }
      if (failing) log.info("output check available again")
      failing = false
      if (p < deps.threshold) {
        log.debug(`${event.tool} → output check: no secret (${deps.label} ${p.toFixed(2)})`)
        return
      }
      // Relevant call, as in gate asks: summary of the redacted input (fallback: the tool name).
      let resource = `${event.tool}: output check`
      try {
        resource = `${summarize(event.tool, deps.redactor.redactDeep(event.input).value)} (output check)`
      } catch {}
      const reason = `the output of ${event.tool} may contain a secret in clear (${deps.label} ${p.toFixed(2)}): approve to pass it to the agent, reject to withhold it`
      let why: string | undefined
      let feedback: string | undefined
      if (deps.askAs === "deny") why = "unattended mode (askAs: deny) withholds it"
      else
        try {
          await ctx.permission.assert({
            sessionID: event.sessionID,
            agent: event.agent,
            action: GUARD_ACTION,
            resources: [resource],
            metadata: { guard: true, tool: event.tool, reason },
            source: { type: "tool", messageID: event.messageID, id: event.id },
          })
        } catch (error) {
          const name = (error as { name?: unknown } | undefined)?.name
          why = "the user did not approve passing it on"
          // User comment: passed to the agent (as for native tools), never to the log.
          const raw = name === "Permission.CorrectedError" ? (error as { feedback?: unknown }).feedback : undefined
          if (typeof raw === "string" && raw.trim()) feedback = deps.redactor.redactString(raw.trim()).value
          log.debug(`${event.tool} → output check: confirmation not granted (${typeof name === "string" ? name : "error"})`)
        }
      if (why === undefined) {
        log.debug(`${event.tool} → output check: passed on by the user (${deps.label} ${p.toFixed(2)})`)
        return
      }
      withhold(event, withheldNotice(event.tool, why, feedback))
      log.debug(`${event.tool} → output withheld (${deps.label} ${p.toFixed(2)})`)
    } catch (error) {
      // Internal error: output passed on as is (it has already been redacted by the redaction hook if active).
      log.error("internal error in output check", error)
    }
  })
}
