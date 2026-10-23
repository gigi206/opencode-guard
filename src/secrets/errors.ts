import type { RedactResult, Redactor } from "./redact.ts"

// Redaction of tool errors. OpenCode shows the model the message of the CAUSE (`error.error`)
// instead of the Tool.Error one when it has one (packages/core/src/session/to-session-error.ts):
// the cause must therefore be redacted, recursively, like the message.
// Copies keep the prototype: OpenCode recognizes user rejections by `instanceof`
// (Permission.DeclinedError…), a copy without the prototype would turn a rejection into a plain error.

/** Depth limit for cause chains; beyond it, the remaining cause is replaced (never returned as is). */
const MAX_CAUSE_DEPTH = 32
const CYCLE_PLACEHOLDER = "[[GUARD_REDACTED:cause_cycle]]"
const TOO_DEEP_PLACEHOLDER = "[[GUARD_REDACTED:cause_too_deep]]"

type ErrorChanges = Record<PropertyKey, unknown>

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (value === null || typeof value !== "object") return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

/** Copy of `original` (same prototype, same own properties) with the changed fields. */
export function cloneWith<T extends object>(original: T, changes: ErrorChanges): T {
  const copy = Object.create(Object.getPrototypeOf(original)) as T
  const replaced = new Set(Reflect.ownKeys(changes).filter((key) => changes[key] !== undefined))
  for (const key of Reflect.ownKeys(original)) {
    // Replaced keys are not copied: a non-configurable property of the original
    // would make redefinition fail and let the secret leave again.
    if (replaced.has(key)) continue
    const descriptor = Object.getOwnPropertyDescriptor(original, key)
    if (descriptor) Object.defineProperty(copy, key, descriptor)
  }
  for (const key of replaced) {
    const value = changes[key]
    // `message` and `stack` of Errors are non-enumerable; prototype getters (AIError.message) are redacted.
    const own = Object.getOwnPropertyDescriptor(original, key)
    const enumerable = own ? own.enumerable === true : key !== "message" && key !== "stack"
    Object.defineProperty(copy, key, { value, writable: true, configurable: true, enumerable })
  }
  return copy
}

/**
 * Result of walking a node. `changed`: the value is a redacted copy. `unsafe`: the subtree contains
 * a back reference (cycle); its value is then a copy where that reference is replaced, to be used if the
 * parent is copied (a copy must never point to an original, which could contain the secret).
 */
interface Walk {
  readonly value: unknown
  readonly count: number
  readonly changed: boolean
  readonly unsafe: boolean
}

const NONE: Walk = { value: undefined, count: 0, changed: false, unsafe: false }

/**
 * State of a walk: `path` = ancestors (cycles), `memo` = nodes already walked. AIError exposes the same object under
 * `reason` and `cause`: a single copy, counted once.
 */
interface WalkState {
  readonly path: Set<object>
  readonly memo: Map<object, Walk>
}

const fromResult = (result: RedactResult<unknown>, original: unknown): Walk => ({
  value: result.value,
  count: result.count,
  changed: result.value !== original,
  unsafe: false,
})

/** Binary data, dates, and promises: never walked (cost, and no text readable by the model). */
function isOpaque(value: object): boolean {
  return ArrayBuffer.isView(value) || value instanceof ArrayBuffer || value instanceof Date || value instanceof Promise
}

/** Value of a field, a Map entry, or a Set element: redacted string, walked object, otherwise unchanged. */
function walkValue(value: unknown, redactor: Redactor, depth: number, state: WalkState): Walk {
  if (typeof value === "string") return fromResult(redactor.redactString(value), value)
  if (value !== null && typeof value === "object" && !isOpaque(value)) return nested(value, redactor, depth, state)
  return { value, count: 0, changed: false, unsafe: false }
}

/** Entries of a Map (keys and values) or elements of a Set: copy only if something changes. */
function walkCollection(collection: Map<unknown, unknown> | Set<unknown>, redactor: Redactor, depth: number, state: WalkState): Walk {
  let count = 0
  let changed = false
  let unsafe = false
  const step = (item: unknown) => {
    const walk = walkValue(item, redactor, depth, state)
    count += walk.count
    changed ||= walk.changed
    unsafe ||= walk.unsafe
    return walk.value
  }
  const value =
    collection instanceof Map
      ? new Map([...collection].map(([key, item]) => [step(key), step(item)] as const))
      : new Set([...collection].map(step))
  return changed ? { value, count, changed, unsafe } : { value: collection, count: 0, changed: false, unsafe: false }
}

function nested(field: unknown, redactor: Redactor, depth: number, state: WalkState): Walk {
  if (field === undefined) return NONE
  if (field !== null && typeof field === "object") {
    if (state.path.has(field)) return { value: CYCLE_PLACEHOLDER, count: 0, changed: true, unsafe: true }
    const seen = state.memo.get(field)
    if (seen) return { ...seen, count: 0 }
  }
  // Node not examined: replaced and counted, so it never leaves as is.
  if (depth >= MAX_CAUSE_DEPTH) return { value: TOO_DEEP_PLACEHOLDER, count: 1, changed: true, unsafe: false }
  return walkError(field, redactor, depth + 1, state)
}

/** Protected read: a getter that throws does not make redaction fail (OpenCode would throw the same way reading it). */
function read(record: object, key: PropertyKey): { ok: boolean; value?: unknown } {
  try {
    return { ok: true, value: (record as Record<PropertyKey, unknown>)[key] }
  } catch {
    return { ok: false }
  }
}

/**
 * Redacted fields of an error: message, stack, metadata, `error` (OpenCode) and `cause` (standard) chains, any
 * other enumerable own field (`details`, `reason`, and `body` of AIError…) and symbol-keyed fields: Effect
 * errors keep their arguments under `Symbol(effect/Data/Error/plainArgs)`, re-read by `toJSON()`.
 */
function errorParts(record: object, redactor: Redactor, depth: number, state: WalkState): { changes: ErrorChanges; count: number; unsafe: boolean } {
  const changes: ErrorChanges = {}
  let count = 0
  let unsafe = false
  const keys = new Set<PropertyKey>(["message", "stack", "error", "cause", "metadata", ...Object.keys(record), ...Object.getOwnPropertySymbols(record)])
  for (const key of keys) {
    const field = read(record, key)
    if (!field.ok || field.value === undefined) continue
    const value = field.value
    let walk: Walk
    if (key === "metadata" && typeof value !== "string") walk = fromResult(redactor.redactDeep(value), value)
    else walk = walkValue(value, redactor, depth, state)
    count += walk.count
    unsafe ||= walk.unsafe
    if (walk.changed) changes[key] = walk.value
  }
  return { changes, count, unsafe }
}

function walkError(value: unknown, redactor: Redactor, depth: number, state: WalkState): Walk {
  if (typeof value === "string") return fromResult(redactor.redactString(value), value)
  if (value === null || typeof value !== "object" || isOpaque(value)) return { value, count: 0, changed: false, unsafe: false }
  // Regular expression whose source contains a secret: replaced by its redacted text.
  if (value instanceof RegExp) {
    const source = redactor.redactString(value.source)
    return source.count ? { value: `/${source.value}/${value.flags}`, count: source.count, changed: true, unsafe: false } : { value, count: 0, changed: false, unsafe: false }
  }
  if (value instanceof Map || value instanceof Set) {
    state.path.add(value)
    try {
      const walk = walkCollection(value, redactor, depth, state)
      state.memo.set(value, walk)
      return walk
    } finally {
      state.path.delete(value)
    }
  }
  if ((Array.isArray(value) || isPlainObject(value)) && !("message" in value) && !("error" in value) && !("cause" in value))
    return fromResult(redactor.redactDeep(value), value)
  state.path.add(value)
  let walk: Walk
  try {
    const parts = errorParts(value, redactor, depth, state)
    walk = Reflect.ownKeys(parts.changes).length
      ? { value: cloneWith(value, parts.changes), count: parts.count, changed: true, unsafe: parts.unsafe }
      : { value, count: 0, changed: false, unsafe: false }
  } finally {
    state.path.delete(value)
  }
  state.memo.set(value, walk)
  return walk
}

/**
 * Redacts an error or a cause: message, stack, metadata, and cause chains, without losing the class.
 * With no secret, returns the same reference (including for a cyclic string: the original contains nothing).
 */
export function redactErrorLike(value: unknown, redactor: Redactor): RedactResult<unknown> {
  const walk = walkError(value, redactor, 0, { path: new Set(), memo: new Map() })
  return walk.count ? { value: walk.value, count: walk.count } : { value, count: 0 }
}

/**
 * Redacts a Tool.Error. First tries its constructor (validated in real conditions), then a copy
 * that keeps the prototype; never lets the original error through if it contains a secret.
 */
export function redactToolError<E extends { message: string; error?: unknown; metadata?: unknown; stack?: unknown }>(
  error: E,
  redactor: Redactor,
): RedactResult<E> {
  const { changes, count } = errorParts(error, redactor, 0, { path: new Set<object>([error]), memo: new Map() })
  if (!count) return { value: error, count: 0 }
  const message = changes.message ?? error.message
  const props: Record<string, unknown> = { message }
  if (error.error !== undefined) props.error = changes.error ?? error.error
  if (error.metadata !== undefined) props.metadata = changes.metadata ?? error.metadata
  try {
    // Original constructor: new stack, built on the redacted message.
    const ErrorClass = error.constructor as new (props: Record<string, unknown>) => E
    const rebuilt = new ErrorClass(props)
    if (rebuilt.message === message && !(typeof rebuilt.stack === "string" && redactor.containsSecret(rebuilt.stack)))
      return { value: rebuilt, count }
  } catch {
    // constructor unavailable or validation refused: copy below
  }
  return { value: cloneWith(error, changes), count }
}
