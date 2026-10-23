// Decision model client: "System One" API (e.g. TypeSafe AI's Jev, Nox-4B).
// Two protocols, native fetch without an SDK:
// - "chat": OpenAI-compatible gateway (e.g. https://ai-gateway.example.com/v1, LiteLLM):
//   POST <baseURL>/chat/completions, the {state, questions} request serialized as JSON in the last
//   message; the {model, answers} response as JSON in choices[0].message.content
//   (same convention as LiteLLM gateways);
// - "systemone": direct System One API: POST <baseURL>/systemone (e.g. https://api.typesafe.ai/v1).
// OpenCode imposes no timeout on hooks: ours is mandatory.

export type ModelProtocol = "chat" | "systemone"

export interface ModelConfig {
  readonly protocol: ModelProtocol
  /** Versioned address, without the final path (e.g. https://ai-gateway.example.com/v1). */
  readonly baseURL: string
  readonly model: string
  readonly timeoutMs: number
  /** Key (Bearer header), referenced by `{env:…}` in opencode.json (e.g. `{env:NOX_API_KEY}`); absent = no authentication. */
  readonly apiKey?: string
  readonly headers?: Readonly<Record<string, string>>
}

export type ModelQuestion =
  | { readonly type: "noul"; readonly instructions: string; readonly criteria?: { true: string; false: string } }
  | { readonly type: "score"; readonly instructions: string; readonly criteria: readonly string[] }
  | { readonly type: "choice"; readonly instructions: string; readonly criteria: Readonly<Record<string, string | null>> }

export interface ModelRequest {
  readonly state: unknown
  readonly questions: Readonly<Record<string, ModelQuestion>>
}

export interface ModelAnswer {
  readonly type?: string
  readonly noul?: number
  readonly score?: number
  readonly choice?: string
  readonly confidence?: number
  readonly probabilities?: Record<string, number>
  /** Refused question (e.g. `max_length_exceeded`), under an HTTP 200 status. */
  readonly error?: unknown
}

export interface ModelResponse {
  readonly model?: string
  readonly answers: Record<string, ModelAnswer>
}

export class ModelError extends Error {
  override readonly name = "ModelError"
  /** `timeoutMs` exceeded (request or body read): the only case retried once by the decider. */
  readonly timeout: boolean
  constructor(message: string, options: { timeout?: boolean } = {}) {
    super(message)
    this.timeout = options.timeout === true
  }
}

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>

export function endpoint(config: Pick<ModelConfig, "protocol" | "baseURL">): string {
  const base = config.baseURL.replace(/\/+$/, "")
  return config.protocol === "chat" ? `${base}/chat/completions` : `${base}/systemone`
}

/** Body read limits: error message (short) and normal response (JSON of the question answers). */
const ERROR_BODY_MAX = 16 * 1024
/** Kept length of the server error message, before redaction then cutting by the caller. */
const ERROR_MESSAGE_MAX = 2000
export const RESPONSE_BODY_MAX = 1024 * 1024

/**
 * Body read up to `max` bytes (a large response is never loaded in full); `overflow` if it exceeds that,
 * the stream then being cancelled. The timeout (`AbortSignal.timeout`) also applies to the read.
 */
async function readCapped(response: Response, max: number): Promise<{ text: string; overflow: boolean }> {
  const reader = response.body?.getReader()
  if (!reader) return { text: "", overflow: false }
  const chunks: Uint8Array[] = []
  let size = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > max) {
      chunks.push(value.subarray(0, value.byteLength - (size - max)))
      reader.cancel().catch(() => {})
      return { text: Buffer.concat(chunks).toString("utf8"), overflow: true }
    }
    chunks.push(value)
  }
  return { text: Buffer.concat(chunks).toString("utf8"), overflow: false }
}

const isTimeout = (error: unknown) => {
  const name = (error as { name?: string } | undefined)?.name
  return name === "TimeoutError" || name === "AbortError"
}

/**
 * Error message returned by the server (OpenAI/LiteLLM format `{error: {message}}` or text), bounded but not cut
 * short: the caller redacts it FIRST, then cuts it (`decide.ts`, `hooks/output-check.ts`), otherwise the fragment of an echoed
 * key would no longer be recognized as the known value.
 */
async function errorDetail(response: Response): Promise<string> {
  try {
    // Cut at 16 KiB: a truncated JSON fails to parse and the raw text serves as the message.
    const { text } = await readCapped(response, ERROR_BODY_MAX)
    let message: unknown = text
    try {
      const body = JSON.parse(text) as { error?: { message?: unknown } | string; detail?: unknown }
      message = typeof body.error === "string" ? body.error : (body.error?.message ?? body.detail ?? text)
    } catch {}
    const short = String(message).replace(/\s+/g, " ").trim().slice(0, ERROR_MESSAGE_MAX)
    return short ? `: ${short}` : ""
  } catch {
    return ""
  }
}

/** Text of a content part `{type: "text", text}`; the other parts (reasoning…) are ignored. */
function textPart(part: unknown): string {
  const { type, text } = (part ?? {}) as { type?: unknown; text?: unknown }
  return type === "text" && typeof text === "string" ? text : ""
}

function parseAnswers(body: unknown): ModelResponse {
  const answers = (body as { answers?: unknown } | null)?.answers
  if (!answers || typeof answers !== "object") throw new ModelError("response has no `answers`")
  return body as ModelResponse
}

export function createModelClient(config: ModelConfig, fetchImpl: FetchLike = (input, init) => fetch(input, init)) {
  const url = endpoint(config)

  return async function callModel(request: ModelRequest): Promise<ModelResponse> {
    // Header names are case-insensitive: `Content-Type` or `Authorization` from decision.headers do not duplicate ours.
    const headers: Record<string, string> = {}
    for (const [name, value] of Object.entries(config.headers ?? {})) headers[name.toLowerCase()] = value
    headers["content-type"] = "application/json"
    if (config.apiKey) headers.authorization = `Bearer ${config.apiKey}`
    const payload = { state: request.state, questions: request.questions }
    const body =
      config.protocol === "chat"
        ? { model: config.model, messages: [{ role: "user", content: JSON.stringify(payload) }] }
        : { model: config.model, ...payload }
    let response: Response
    try {
      response = await fetchImpl(url, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(config.timeoutMs),
        // Never followed: toward another address, Node and Bun remove the Authorization header but forward those from
        // `decision.headers` and the body (verified).
        redirect: "manual",
      })
    } catch (error) {
      if (isTimeout(error)) throw new ModelError(`timed out after ${config.timeoutMs} ms`, { timeout: true })
      throw new ModelError(`network: ${(error as Error)?.message ?? String(error)}`)
    }
    // Before any body read: a redirect's body often quotes the destination address. Body cancelled (no
    // connection kept open by a gateway that would redirect every call).
    if ((response.status >= 300 && response.status < 400) || response.type === "opaqueredirect") {
      response.body?.cancel().catch(() => {})
      throw new ModelError(`HTTP ${response.status}: redirect refused (the decision model URL must answer directly)`)
    }
    if (!response.ok) throw new ModelError(`HTTP ${response.status}${await errorDetail(response)}`)
    let received: { text: string; overflow: boolean }
    try {
      received = await readCapped(response, RESPONSE_BODY_MAX)
    } catch (error) {
      if (isTimeout(error)) throw new ModelError(`timed out after ${config.timeoutMs} ms`, { timeout: true })
      throw new ModelError("unreadable response")
    }
    // Oversized response: never loaded in full, never interpreted (→ confirmation request).
    if (received.overflow) throw new ModelError(`response larger than ${RESPONSE_BODY_MAX} bytes`)
    let json: unknown
    try {
      json = JSON.parse(received.text)
    } catch {
      throw new ModelError("non-JSON response")
    }
    if (config.protocol === "systemone") return parseAnswers(json)
    const raw = (json as { choices?: Array<{ message?: { content?: unknown } }> } | null)?.choices?.[0]?.message?.content
    // Some gateways return the content as parts ([{type: "text", text}]) rather than text.
    const content = Array.isArray(raw) ? raw.map(textPart).join("") : raw
    if (typeof content !== "string") throw new ModelError("response has no `choices[0].message.content`")
    try {
      return parseAnswers(JSON.parse(content))
    } catch (error) {
      if (error instanceof ModelError) throw error
      throw new ModelError("response content is not JSON")
    }
  }
}

export type ModelClient = ReturnType<typeof createModelClient>
