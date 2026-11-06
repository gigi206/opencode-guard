import { createHash } from "node:crypto"
import * as zlib from "node:zlib"
import { isSignedBlock, isToolArguments, PLACEHOLDER_KEYWORD, signedContent, type Redactor } from "../secrets/redact.ts"
import { redactToolError } from "../secrets/errors.ts"
import { PROMPT_NOTE } from "../secrets/prompt.ts"
import { CODEMODE_TOOL } from "../rules/tools.ts"
import { timedMap } from "./gate.ts"
import { USER_SHELL_BLOCKED_MESSAGE, USER_SHELL_OPENINGS, UserShellUncheckedError, type UserShellCheck } from "./output-check.ts"
import type { PromptGate } from "./prompt-check.ts"
import type { RelaxationOf } from "../scopes.ts"
import type { UnprotectedGate } from "./unprotected.ts"
import type { GuardContext, Logger } from "../types.ts"

export interface RedactionDeps {
  readonly redactor: Redactor
  readonly redactPrompt: boolean
  /** `redactOutputs` and `redactWire` switches; absent = active. */
  readonly redactOutputs?: boolean
  readonly redactWire?: boolean
  readonly log: Logger
  /** Unprotected agent: no redaction for it; absent = everything is redacted. */
  readonly unprotected?: UnprotectedGate
  /** What an `agents` section relaxes for a call; absent: nothing. */
  readonly relaxation?: RelaxationOf
  /** Check of the typed prompt by the decision model (`promptCheck` option, active); absent = technical redaction only. */
  readonly promptCheck?: PromptGate
  /** Check of the `!` command outputs on the wire (set once the output check is active); absent or empty = none. */
  readonly userShell?: { check?: UserShellCheck }
}

// Common rule: a redaction hook does not throw (an exception in a session hook makes the
// session fail, and again on every retry). The only exception, intentional: the wire safety net (`http.request`,
// `experimental.ws.send`), last line of defense before the provider; an internal error there blocks the request rather than
// letting it leave unredacted (`WIRE_BLOCKED_MESSAGE`). With the prompt check (`promptCheck`), the prompt hook too: a
// prompt the user does not approve is blocked (`PromptBlockedError`), so that it never reaches the provider.

/**
 * Message for a request blocked by an internal error in the safety net: fixed (neither content nor cause, which go to the log); the
 * content causing it stays in the history, so every retry fails the same way.
 */
export const WIRE_BLOCKED_MESSAGE =
  "[guard] Request to the model provider blocked: the guard plugin could not redact secrets from it (internal error), so nothing was sent. Retrying fails the same way while the content that causes it stays in this session: start a new session, or remove that content."

/**
 * Note for the model, added to a redacted output: in session, the model wrote a value, saw it replaced
 * by the placeholder and "fixed" the file twice. Without `[[…]]`: copying it does not trigger the placeholder rule.
 */
export const REDACTION_NOTE =
  `[guard] The ${PLACEHOLDER_KEYWORD} placeholders in this output mask secrets for display only: the file or data itself is unchanged. Do not try to rewrite or "fix" these values, and never write a placeholder into a file.`

/**
 * Valid JSON (a CodeMode script may parse the output of an internal call): no note, except for the result of a
 * script, which only the model reads. Parsing attempted only if the text starts like JSON.
 */
function looksLikeJson(text: string): boolean {
  const trimmed = text.trim()
  if (!/^[[{]/.test(trimmed)) return false
  try {
    JSON.parse(trimmed)
    return true
  } catch {
    return false
  }
}

const withNote = (text: string, json: boolean) => (!json && looksLikeJson(text) ? text : `${text}\n\n${REDACTION_NOTE}`)

/**
 * Appends the note to the end of the last text part (copy, never modified in place; shape preserved).
 * `json`: also on valid JSON (result of a CodeMode script).
 */
export function withRedactionNote<T>(content: T, options: { readonly json?: boolean } = {}): T {
  const json = options.json === true
  if (typeof content === "string") return withNote(content, json) as T
  if (!Array.isArray(content)) return content
  const parts = content as ReadonlyArray<{ type?: unknown; text?: unknown }>
  for (let index = parts.length - 1; index >= 0; index--) {
    const part = parts[index]!
    if (part?.type !== "text" || typeof part.text !== "string") continue
    const text = withNote(part.text, json)
    if (text === part.text) return content
    const next = [...parts]
    next[index] = { ...part, text }
    return next as T
  }
  return content
}

/** Text of the text parts of a tool content (string or array of parts). */
function textOf(content: unknown): string {
  if (typeof content === "string") return content
  if (!Array.isArray(content)) return ""
  return content
    .map((part: { type?: unknown; text?: unknown } | null) => (part?.type === "text" && typeof part.text === "string" ? part.text : ""))
    .join("\n")
}

/** Decompression and recompression of a request body, using the same encoding. */
interface BodyCodec {
  readonly decode: (bytes: Uint8Array) => Uint8Array
  readonly encode: (bytes: Uint8Array) => Uint8Array<ArrayBuffer>
}

type Codec = (bytes: Uint8Array, options?: object) => Uint8Array<ArrayBuffer>
type Zlib = Partial<
  Record<
    | "gunzipSync"
    | "gzipSync"
    | "zstdDecompressSync"
    | "zstdCompressSync"
    | "brotliDecompressSync"
    | "brotliCompressSync"
    | "inflateSync"
    | "deflateSync",
    Codec
  >
>

/** Moderate brotli quality: the default value (11) would block the event loop for several seconds on a large body. */
const BROTLI_QUALITY = 5

/**
 * Encodings produced by OpenCode (`jsonPost`, a provider's `encoding` setting; zstd by default for a
 * ChatGPT connection), plus `br` and `deflate` (standard HTTP encodings, preventive coverage). Functions looked up at call time, like
 * OpenCode's `compressBody`: zstd is missing in some environments.
 */
export function bodyCodec(encoding: string, z: Zlib = zlib as unknown as Zlib): BodyCodec | undefined {
  const pair = (decode?: BodyCodec["decode"], encode?: BodyCodec["encode"]) =>
    decode && encode ? { decode: (bytes: Uint8Array) => decode(bytes), encode: (bytes: Uint8Array) => encode(bytes) } : undefined
  if (encoding === "gzip" || encoding === "x-gzip") return pair(z.gunzipSync, z.gzipSync)
  if (encoding === "zstd") return pair(z.zstdDecompressSync, z.zstdCompressSync)
  if (encoding === "br") {
    const compress = z.brotliCompressSync
    const options = { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: BROTLI_QUALITY } }
    return pair(z.brotliDecompressSync, compress && ((bytes) => compress(bytes, options)))
  }
  // `Content-Encoding: deflate` = zlib format (RFC 1950), the one used by inflateSync/deflateSync.
  if (encoding === "deflate") return pair(z.inflateSync, z.deflateSync)
  return undefined
}

/** Strings of a request body that hold a `!` command text (outside signed blocks, which are never changed). */
function userShellTexts(value: unknown, out: string[] = [], depth = 0): string[] {
  if (typeof value === "string") {
    if (USER_SHELL_OPENINGS.some((opening) => value.includes(opening))) out.push(value)
  } else if (value !== null && typeof value === "object" && depth < 64) {
    if (!Array.isArray(value) && isSignedBlock(value as Record<string, unknown>)) return out
    for (const item of Object.values(value)) userShellTexts(item, out, depth + 1)
  }
  return out
}

/** The body with each checked `!` command text replaced by its masked version. */
function replaceTexts<T>(value: T, masked: ReadonlyMap<string, string>, depth = 0): T {
  if (typeof value === "string") return (masked.get(value) ?? value) as T
  if (value === null || typeof value !== "object" || depth >= 64) return value
  if (Array.isArray(value)) return value.map((item) => replaceTexts(item, masked, depth + 1)) as T
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replaceTexts(item, masked, depth + 1)])) as T
}

/** Blocks and secrets remembered by `signedBlockCheck`, oldest dropped first: about 1 MB at most. */
const SIGNED_SEEN_MAX = 8192

/**
 * Signed blocks leave as they are: a secret in one is reported in the log, by type and number only. These blocks come back
 * in every request of a session: a block already looked at costs its hash, and a secret is reported once per session. The
 * returned function never throws and changes nothing in the request.
 */
function signedBlockCheck(redactor: Redactor, log: Logger) {
  const seen = new Set<string>()
  const isNew = (sessionID: string | undefined, text: string) => {
    const mark = createHash("sha256").update(`${sessionID ?? ""}\u0000`).update(text).digest("base64")
    const known = seen.delete(mark)
    seen.add(mark)
    if (seen.size > SIGNED_SEEN_MAX) seen.delete(seen.values().next().value!)
    return !known
  }
  return (blocks: ReadonlySet<Record<string, unknown>>, sessionID: string | undefined, hook: string) => {
    try {
      const found = new Map<string, number>()
      try {
        for (const block of blocks) {
          const content = signedContent(block)
          if (!isNew(sessionID, JSON.stringify(content))) continue
          redactor.redactDeep(content, {
            onSecret: (type, value) => {
              if (isNew(sessionID, value)) found.set(type, (found.get(type) ?? 0) + 1)
            },
          })
        }
      } finally {
        // Also after an error: these blocks and secrets are marked, nothing would report them later.
        if (found.size) {
          const total = [...found.values()].reduce((sum, count) => sum + count, 0)
          log.warn(`${hook}: ${total} secret(s) in signed blocks sent unmasked (${[...found].map(([type, count]) => `${type} x${count}`).join(", ")})`)
        }
      }
    } catch (error) {
      try {
        log.error(`internal error in ${hook}: signed blocks not checked`, error)
      } catch {}
    }
  }
}

export async function registerRedaction(ctx: GuardContext, deps: RedactionDeps): Promise<void> {
  const { redactor, log } = deps

  // At the source: what is persisted (history, UI) and sent back to the model. `redactOutputs` switch.
  if (deps.redactOutputs !== false) {
    /**
     * `execute` (CodeMode) calls in progress, by session and call identifier: true as soon as one of their internal calls
     * (same identifier) was redacted. The script receives the declared output of the internal call, without the note, and the
     * script result has nothing left to redact: the note is therefore added to that result.
     */
    const codeMode = timedMap<boolean>(Date.now)
    const callKey = (sessionID: string, id: string) => `${sessionID}\u0000${id}`
    await ctx.tool.hook("execute.before", (event) => {
      try {
        if (event.tool === CODEMODE_TOOL) codeMode.add(callKey(event.sessionID, event.id), false)
      } catch (error) {
        log.error("internal error in tool.execute.before (redaction)", error)
      }
    })
    await ctx.tool.hook("execute.after", async (event) => {
      try {
        const key = callKey(event.sessionID, event.id)
        // End of a script: key removed in all cases (success, error, unprotected agent, nothing to redact).
        const script = event.tool === CODEMODE_TOOL
        const innerRedacted = script && codeMode.take(key) === true
        if (await deps.unprotected?.isUnprotected(event.sessionID, event.agent)) return
        if (deps.relaxation?.(event.sessionID, event.agent)?.off.has("redactOutputs")) return
        if (event.status === "completed") {
          const result = redactor.redactDeep(event.result)
          if (result.count && !script && codeMode.has(key)) codeMode.add(key, true)
          if (!result.count && !innerRedacted) return
          const content = result.value.content
          const changed = content !== event.result.content
          if (script && (changed || innerRedacted)) {
            // Script result: note even on JSON, never twice (text of an already annotated internal call).
            event.result = textOf(content).includes(REDACTION_NOTE) ? result.value : { ...result.value, content: withRedactionNote(content, { json: true }) }
          } else {
            // Note only if the text seen by the model changed (not for a literal placeholder already present).
            event.result = changed ? { ...result.value, content: withRedactionNote(content) } : result.value
          }
          if (result.count) log.debug(`execute.after ${event.tool}: ${result.count} secret(s) redacted`)
          return
        }
        // Message, metadata AND cause: OpenCode shows the cause message to the model if it exists.
        const redacted = redactToolError(event.error, redactor)
        if (!redacted.count) return
        // A script may catch an internal call's error and return its message, placeholders included.
        if (!script && codeMode.has(key)) codeMode.add(key, true)
        event.error = redacted.value
        log.debug(`execute.after ${event.tool} (error): ${redacted.count} secret(s) redacted`)
      } catch (error) {
        log.error("internal error in tool.execute.after", error)
      }
    })
  }

  if (deps.redactPrompt || deps.promptCheck) {
    await ctx.session.hook("prompt", async (event) => {
      // With the prompt check, the hook fails closed: the only error it lets out blocks the prompt (OpenCode then does
      // not create the message); it is never an internal error, which leads to a confirmation instead.
      let block: Error | undefined
      try {
        if (await deps.unprotected?.notePrompt(event.sessionID, event.messageID)) return
        const relaxed = deps.relaxation?.(event.sessionID, undefined)?.off
        const result = deps.redactPrompt && !relaxed?.has("redactPrompt") ? redactor.redactString(event.prompt.text) : { value: event.prompt.text, count: 0 }
        let text = result.value
        let count = result.count
        if (count) event.prompt.text = text
        if (deps.promptCheck && !relaxed?.has("promptCheck")) {
          // Words in plain language (`mon mot de passe est soleil42`), any language: the decision model. With `redactPrompt` on,
          // it sees no known secret, even when a relaxation lets the agent's own model see one: then it only decides whether
          // the prompt leaves. With `redactPrompt: false` in the configuration, it reads the prompt as typed.
          const clear = relaxed?.has("redactPrompt")
          const checked = await deps.promptCheck.check(event, clear ? redactor.redactString(text).value : text)
          if (!clear) {
            text = checked.text
            count += checked.count
          }
          block = checked.block
        }
        if (!count) return
        event.prompt.text = `${text}\n\n${PROMPT_NOTE}`
        // Mention offsets no longer match the modified text.
        for (const item of [...(event.prompt.files ?? []), ...(event.prompt.agents ?? []), ...(event.prompt.skills ?? [])])
          delete item.mention
        log.debug(`prompt: ${count} secret(s) redacted`)
      } catch (error) {
        try {
          log.error("internal error in session.prompt", error)
        } catch {}
        if (deps.promptCheck) block = await deps.promptCheck.confirm(event, "internal error")
      } finally {
        if (block) throw block
      }
    })
  }

  // `redactWire` switch: no wire safety net (HTTP requests and WebSocket frames).
  if (deps.redactWire === false) return

  /** Uninspected body (non-JSON type, unknown encoding, unreadable body): reported once per cause, never silently. */
  const warned = new Set<string>()
  const notInspected = (cause: string, hook = "http.request") => {
    if (warned.has(`${hook}\u0000${cause}`)) return
    warned.add(`${hook}\u0000${cause}`)
    log.warn(`${hook}: ${cause}: ${hook === "http.request" ? "request body" : "frame"} not inspected, secrets NOT redacted`)
  }
  const checkSigned = signedBlockCheck(redactor, log)
  /** Technical redaction of a body; the signed blocks it left out go to `checkSigned` once the request is cleared to leave. */
  const redactBody = (json: unknown) => {
    const signed = new Set<Record<string, unknown>>()
    const skip = (node: Record<string, unknown>) => {
      if (!isSignedBlock(node)) return false
      signed.add(node)
      return true
    }
    return { redacted: redactor.redactDeep(json, { skip, unskippable: isToolArguments }), signed }
  }
  /**
   * `!` command texts of a technically redacted body checked by the decision model; `undefined` when nothing changes. A
   * model failure blocks the request (`UserShellUncheckedError`), the user's choice: nothing unchecked leaves.
   */
  const userShell = async (value: unknown, hook: string, relaxed?: ReadonlySet<string>): Promise<{ value: unknown; count: number } | undefined> => {
    const check = deps.userShell?.check
    if (!check || relaxed?.has("outputCheck")) return undefined
    const texts = userShellTexts(value)
    if (!texts.length) return undefined
    let result: Awaited<ReturnType<UserShellCheck>>
    try {
      result = await check(texts)
    } catch (error) {
      if (!(error instanceof UserShellUncheckedError)) throw error
      try {
        log.warn(`${hook}: request blocked: the output of a ! command could not be checked (${error.message})`)
      } catch {}
      throw new Error(USER_SHELL_BLOCKED_MESSAGE)
    }
    if (!result.masked.size) return undefined
    log.debug(`${hook}: ! command output: ${result.words} word(s) masked, ${result.parts} part(s) masked whole`)
    return { value: replaceTexts(value, result.masked), count: result.masked.size }
  }

  /** Internal error in the safety net: the request does not leave; the cause goes to the log only (a logger that throws changes nothing). */
  const blocked = (hook: string, error: unknown): never => {
    // A `!` command output the decision model could not check: its own message, already logged.
    if (error instanceof Error && error.message === USER_SHELL_BLOCKED_MESSAGE) throw error
    try {
      log.error(`internal error in ${hook}: request blocked`, error)
    } catch {}
    throw new Error(WIRE_BLOCKED_MESSAGE)
  }

  // Final safety net: everything that leaves toward the provider over HTTP.
  await ctx.session.hook("http.request", async (event) => {
    try {
      const call = { model: event.model, kind: event.kind }
      if (await deps.unprotected?.isUnprotected(event.sessionID, event.agent, call)) return
      const relaxed = deps.relaxation?.(event.sessionID, event.agent, call)?.off
      if (relaxed?.has("redactWire")) return
      const request = event.request
      if (!request.body) return
      const type = request.headers.get("content-type") ?? ""
      if (type && !/json/i.test(type)) return notInspected(`content-type ${JSON.stringify(type.slice(0, 40))}`)
      // Compressed body (`content-type` stays JSON): decompressed, redacted, then recompressed with the same encoding (the
      // ChatGPT backend refuses uncompressed bodies over ~1 MiB).
      const encoding = (request.headers.get("content-encoding") ?? "").trim().toLowerCase()
      const codec = encoding && encoding !== "identity" ? bodyCodec(encoding) : undefined
      if (encoding && encoding !== "identity" && !codec) return notInspected(`unsupported content-encoding ${JSON.stringify(encoding.slice(0, 40))}`)
      let json: unknown
      try {
        const text = codec
          ? new TextDecoder().decode(codec.decode(new Uint8Array(await request.clone().arrayBuffer())))
          : await request.clone().text()
        json = JSON.parse(text)
      } catch {
        notInspected(codec ? `${encoding} body could not be decoded` : "body is not valid JSON")
        return
      }
      const { redacted, signed } = redactBody(json)
      const checked = await userShell(redacted.value, "http.request", relaxed)
      checkSigned(signed, event.sessionID, "http.request")
      const result = checked ? { value: checked.value, count: redacted.count + checked.count } : redacted
      if (!result.count) return
      const headers = new Headers(request.headers)
      headers.delete("content-length")
      const body = JSON.stringify(result.value)
      event.request = new Request(request, { body: codec ? codec.encode(new TextEncoder().encode(body)) : body, headers })
      log.debug(`http.request (${event.kind}${codec ? `, ${encoding}` : ""}): ${result.count} secret(s) redacted`)
    } catch (error) {
      blocked("session.http.request", error)
    }
  })

  // WebSocket transport (OpenAI, xAI, Azure): not seen by http.request.
  try {
    await ctx.session.hook("experimental.ws.send", async (event) => {
      try {
        const call = { model: event.model, kind: event.kind }
        if (await deps.unprotected?.isUnprotected(event.sessionID, event.agent, call)) return
        const relaxed = deps.relaxation?.(event.sessionID, event.agent, call)?.off
        if (relaxed?.has("redactWire")) return
        let json: unknown
        try {
          json = JSON.parse(event.frame)
        } catch {
          notInspected("frame is not valid JSON", "experimental.ws.send")
          return
        }
        const { redacted, signed } = redactBody(json)
        const checked = await userShell(redacted.value, "experimental.ws.send", relaxed)
        checkSigned(signed, event.sessionID, "experimental.ws.send")
        const result = checked ? { value: checked.value, count: redacted.count + checked.count } : redacted
        if (!result.count) return
        event.frame = JSON.stringify(result.value)
        log.debug(`ws.send (${event.kind}): ${result.count} secret(s) redacted`)
      } catch (error) {
        blocked("session.experimental.ws.send", error)
      }
    })
  } catch (error) {
    log.warn(`experimental.ws.send hook unavailable: WebSocket transport not covered (${String(error)})`)
  }
}
