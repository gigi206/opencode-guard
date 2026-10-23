import * as zlib from "node:zlib"
import { isSignedBlock, isToolArguments, type Redactor } from "../secrets/redact.ts"
import { redactToolError } from "../secrets/errors.ts"
import { PROMPT_NOTE, redactPromptSecrets } from "../secrets/prompt.ts"
import { CODEMODE_TOOL } from "../rules/tools.ts"
import { timedMap } from "./gate.ts"
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
}

// Common rule: a redaction hook does not throw (an exception in a session hook makes the
// session fail, and again on every retry). The only exception, intentional: the wire safety net (`http.request`,
// `experimental.ws.send`), last line of defense before the provider; an internal error there blocks the request rather than
// letting it leave unredacted (`WIRE_BLOCKED_MESSAGE`).

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
  '[guard] The GUARD_REDACTED placeholders in this output mask secrets for display only: the file or data itself is unchanged. Do not try to rewrite or "fix" these values, and never write a placeholder into a file.'

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

  if (deps.redactPrompt) {
    await ctx.session.hook("prompt", async (event) => {
      try {
        if (await deps.unprotected?.notePrompt(event.sessionID, event.messageID)) return
        const result = redactor.redactString(event.prompt.text)
        // Then secrets typed in natural language ("my password is …"), specific to the prompt.
        const typed = redactPromptSecrets(result.value)
        const count = result.count + typed.count
        if (!count) return
        event.prompt.text = `${typed.value}\n\n${PROMPT_NOTE}`
        // Mention offsets no longer match the modified text.
        for (const item of [...(event.prompt.files ?? []), ...(event.prompt.agents ?? []), ...(event.prompt.skills ?? [])])
          delete item.mention
        log.debug(`prompt: ${count} secret(s) redacted`)
      } catch (error) {
        log.error("internal error in session.prompt", error)
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
  /** Internal error in the safety net: the request does not leave; the cause goes to the log only (a logger that throws changes nothing). */
  const blocked = (hook: string, error: unknown): never => {
    try {
      log.error(`internal error in ${hook}: request blocked`, error)
    } catch {}
    throw new Error(WIRE_BLOCKED_MESSAGE)
  }

  // Final safety net: everything that leaves toward the provider over HTTP.
  await ctx.session.hook("http.request", async (event) => {
    try {
      if (await deps.unprotected?.isUnprotected(event.sessionID, event.agent)) return
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
      const result = redactor.redactDeep(json, { skip: isSignedBlock, unskippable: isToolArguments })
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
        if (await deps.unprotected?.isUnprotected(event.sessionID, event.agent)) return
        let json: unknown
        try {
          json = JSON.parse(event.frame)
        } catch {
          notInspected("frame is not valid JSON", "experimental.ws.send")
          return
        }
        const result = redactor.redactDeep(json, { skip: isSignedBlock, unskippable: isToolArguments })
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
