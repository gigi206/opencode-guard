import { closeSync, constants, existsSync, mkdirSync, openSync, renameSync, statSync, writeSync } from "node:fs"
import { dirname } from "node:path"

// Structural subset of `Plugin.Context` (@opencode/plugin 2.0.29) used by the plugin.
// The real context is assignable to it (verified by `tsc`), and tests can simulate it.

export type Effect = "allow" | "ask" | "deny"

export interface ToolSource {
  readonly type: "tool"
  readonly messageID: string
  readonly id: string
}

export interface ToolBeforeEvent {
  tool: string
  readonly sessionID: string
  readonly agent: string
  readonly messageID: string
  readonly id: string
  input: unknown
}

export interface ToolResult {
  readonly output?: unknown
  readonly content?: string | ReadonlyArray<unknown>
  readonly metadata?: Readonly<Record<string, unknown>>
}

export interface ToolError {
  readonly message: string
  readonly error?: unknown
  readonly metadata?: Readonly<Record<string, unknown>>
}

interface ToolAfterBase {
  readonly tool: string
  readonly sessionID: string
  readonly agent: string
  readonly messageID: string
  readonly id: string
  readonly input: unknown
}

export type ToolAfterEvent = ToolAfterBase &
  ({ readonly status: "completed"; result: ToolResult } | { readonly status: "error"; error: ToolError })

export interface PermissionEvaluation {
  readonly sessionID: string
  readonly agent?: string
  readonly action: string
  readonly resources: ReadonlyArray<string>
  readonly metadata?: Readonly<Record<string, unknown>>
  readonly source?: ToolSource
  effect: Effect
  message?: string
}

export interface AssertInput {
  readonly sessionID: string
  readonly agent?: string
  readonly action: string
  readonly resources: ReadonlyArray<string>
  readonly save?: ReadonlyArray<string>
  readonly metadata?: Record<string, unknown>
  readonly source?: ToolSource
}

export interface PromptEvent {
  readonly sessionID: string
  readonly messageID?: string
  prompt: {
    text: string
    files?: Array<{ mention?: unknown }>
    agents?: Array<{ mention?: unknown }>
    skills?: Array<{ mention?: unknown }>
  }
}

export interface HttpRequestEvent {
  readonly kind: string
  readonly sessionID?: string
  readonly agent?: string
  request: Request
}

export interface WsSendEvent {
  readonly kind: string
  readonly sessionID?: string
  readonly agent?: string
  frame: string
}

/** Subset of `Agent.Info` (@opencode/schema) modified by the plugin. */
export interface AgentInfoLike {
  mode: string
  description?: string
  permissions: Array<{ action: string; resource: string; effect: string }>
}

export interface AgentEditorLike {
  get(id: string): AgentInfoLike | undefined
  update(id: string, update: (agent: AgentInfoLike) => void): void
}

type Hook<E> = (event: E) => Promise<void> | void

export interface GuardContext {
  readonly options: Readonly<Record<string, unknown>>
  readonly location: { readonly directory: string }
  readonly tool: {
    hook(name: "execute.before", callback: Hook<ToolBeforeEvent>): Promise<unknown>
    hook(name: "execute.after", callback: Hook<ToolAfterEvent>): Promise<unknown>
  }
  readonly permission: {
    hook(name: "evaluate", callback: Hook<PermissionEvaluation>): Promise<unknown>
    assert(input: AssertInput): Promise<void>
  }
  readonly agent: {
    transform(callback: (editor: AgentEditorLike) => void): Promise<unknown>
    get(input: { agentID: string; location?: { directory?: string } }): Promise<{ readonly data: { readonly mode: string } }>
  }
  readonly session: {
    get(input: { sessionID: string }): Promise<{ readonly agent?: string }>
    hook(name: "prompt", callback: Hook<PromptEvent>): Promise<unknown>
    hook(name: "http.request", callback: Hook<HttpRequestEvent>): Promise<unknown>
    hook(name: "experimental.ws.send", callback: Hook<WsSendEvent>): Promise<unknown>
  }
}

export interface Logger {
  debug(message: string): void
  /** Always written (e.g. startup line with the effective mode). */
  info(message: string): void
  warn(message: string): void
  error(message: string, error?: unknown): void
}

const MAX_LOG_BYTES = 5 * 1024 * 1024
/** Size checked every N writes: a server running for days does not let the log grow without end. */
const ROTATE_CHECK_EVERY = 100
/**
 * Maximum length of an entry (after redaction): cut in the middle, the end remains readable (duration of model calls,
 * read by dev/tools/decision-log-stats.mjs).
 */
export const MAX_LOG_LINE = 8192
const LINE_HEAD = 6000
const LINE_TAIL = 2000
/** Append, create if needed, never through a final symbolic link (placed before startup or after). */
const APPEND_FLAGS = constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0)

/** Code of a system error (`EACCES`, `ENOSPC`…): never the message, which may mention other paths. */
const errorCode = (error: unknown) => {
  const code = (error as { code?: unknown } | undefined)?.code
  return typeof code === "string" ? code : "error"
}

export interface LoggerOptions {
  /** Fallback log (OpenCode default) if the configured file is unusable. */
  readonly fallback?: string
}

/**
 * Plugin log: stderr (invisible when OpenCode runs as a service) + optional file.
 * In principle receives no secret (tools, verdicts, reasons, counters); `redact` additionally redacts each line
 * (defense in depth: server response, internal error message).
 */
export function createLogger(
  debug: boolean,
  file?: string,
  redact?: (text: string) => string,
  maxBytes = MAX_LOG_BYTES,
  options: LoggerOptions = {},
): Logger {
  let target = file
  let fileOk = false
  let fellBack = false
  let writes = 0
  /** Only one copy kept (`.1`). Synchronous calls: no interleaving between instances of the same process. */
  const rotate = (path: string) => {
    try {
      if (existsSync(path) && statSync(path).size > maxBytes) renameSync(path, `${path}.1`)
    } catch {
      // The log continues in the current file.
    }
  }
  /** Directory created and rotation done; otherwise the error code. */
  const prepare = (path: string): string | undefined => {
    try {
      mkdirSync(dirname(path), { recursive: true })
    } catch (error) {
      return errorCode(error)
    }
    rotate(path)
    return undefined
  }
  // File reopened by its path at each entry: after a rename, the next write creates the new file.
  // Final symbolic link: rejected (ELOOP), hence the fallback to the default log.
  const append = (path: string, level: string, message: string) => {
    const fd = openSync(path, APPEND_FLAGS)
    try {
      const data = Buffer.from(`${new Date().toISOString()} ${level} ${message}\n`)
      // Partial write possible: up to the last byte, like `appendFileSync`.
      for (let offset = 0; offset < data.length; ) offset += writeSync(fd, data, offset)
    } finally {
      closeSync(fd)
    }
  }
  const sanitize = (raw: string) => {
    let text = raw
    try {
      if (redact) text = redact(raw)
    } catch {
      text = "(log message withheld: redaction failed)"
    }
    // One line per entry: reasons mention paths chosen by the model and server responses.
    text = text.replace(/[\x00-\x1f\x7f\u2028\u2029]+/g, " ")
    // Cut after redaction: a secret straddling the cut has already been replaced.
    if (text.length <= MAX_LOG_LINE) return text
    return `${text.slice(0, LINE_HEAD)} …[${text.length - LINE_HEAD - LINE_TAIL} characters omitted]… ${text.slice(-LINE_TAIL)}`
  }
  /**
   * Unusable file: switches once to the fallback log (marked before any write, so without a
   * loop), with a warning (error code only) and the line that failed; otherwise stderr only.
   */
  const fallBack = (code: string, line?: readonly [string, string]) => {
    fileOk = false
    if (fellBack || !options.fallback || options.fallback === target) return
    fellBack = true
    const failed = target
    target = options.fallback
    if (prepare(target) !== undefined) return
    try {
      append(target, "WARN", sanitize(`log file ${failed} unusable (${code}): logging to ${target}`))
      if (line) append(target, line[0], line[1])
      fileOk = true
    } catch {
      // stderr only.
    }
  }
  if (target) {
    const code = prepare(target)
    if (code === undefined) fileOk = true
    else fallBack(code)
  }
  const write = (level: string, raw: string) => {
    const message = sanitize(raw)
    const line = `[guard] ${message}`
    if (level === "WARN") console.warn(line)
    else console.error(line)
    if (!fileOk || !target) return
    if (++writes % ROTATE_CHECK_EVERY === 0) rotate(target)
    try {
      append(target, level, message)
    } catch (error) {
      fallBack(errorCode(error), [level, message])
    }
  }
  return {
    debug: (message) => {
      if (debug) write("DEBUG", message)
    },
    info: (message) => write("INFO", message),
    warn: (message) => write("WARN", message),
    error: (message, error) => {
      // `String()` can throw (very deeply nested structure, failing `toString`): a redaction hook never throws.
      let detail = ""
      try {
        detail = error instanceof Error ? String(error.message) : error === undefined ? "" : String(error)
      } catch {
        detail = "(unprintable error)"
      }
      write("ERROR", detail ? `${message}: ${detail}` : message)
    },
  }
}
