import { constants as zlibConstants, gunzipSync, inflateRawSync } from "node:zlib"
import { type NamedSecret, OPENCODE_PATTERNS } from "./opencode-service.ts"
import { BUILTIN_PATTERNS, envSecretValues, MIN_KNOWN_SECRET, type SecretPattern } from "./patterns.ts"

// Type bounded to 256 characters: without the bound, every unclosed marker in a long text scanned everything that followed it.
// `placeholder` always produces a recognized type (at most 200 characters, without `]`); those of existing sessions are
// at most 20 characters.
export const PLACEHOLDER_RE = /\[\[GUARD_REDACTED:[^\]]{0,256}\]\]/
export const placeholder = (type: string) => `[[GUARD_REDACTED:${type.replace(/]/g, "_").slice(0, 200)}]]`
/** Splits a capture into placeholders and intermediate fragments. */
const PLACEHOLDER_FRAGMENTS = /\[\[GUARD_REDACTED:[^\]]{0,256}\]\]|(?:(?!\[\[GUARD_REDACTED:[^\]]{0,256}\]\])[\s\S])+/g

export interface RedactResult<T> {
  readonly value: T
  readonly count: number
}

export interface RedactDeepOptions {
  /** Objects to leave intact (e.g. signed reasoning blocks). */
  readonly skip?: (node: Record<string, unknown>) => boolean
  /** Children (key of a non-skipped object) under which `skip` no longer applies, e.g. tool call arguments. */
  readonly unskippable?: (parent: Record<string, unknown>, key: string) => boolean
}

export interface Redactor {
  redactString(text: string): RedactResult<string>
  redactDeep<T>(value: T, options?: RedactDeepOptions): RedactResult<T>
  containsSecret(value: unknown): boolean
}

export interface RedactorOptions {
  readonly extraPatterns?: readonly SecretPattern[]
  readonly allowlist?: readonly string[]
  readonly env?: Record<string, string | undefined>
  /** Configuration secrets (decision model key, headers): redacted identically. */
  readonly knownSecrets?: ReadonlyArray<{ readonly name: string; readonly value: string }>
  /**
   * Secrets read at runtime (OpenCode service password: `serviceSecretSource`), redacted identically; called
   * once per public call, it returns the same array as long as nothing has changed. Without it, no file is read.
   */
  readonly runtimeSecrets?: () => readonly NamedSecret[]
}

const MAX_DEPTH = 64
/** Maximum number of values learned on sight (beyond that, formats stay redacted, but the bare value no longer is). */
const MAX_LEARNED = 1000

/**
 * Binary `data:` URL (image, audio, video, font, PDF, archive): no analysis, risk of corruption.
 * Only if the ENTIRE string is such a well-formed URL: a `data:image/…` prefix followed by something else
 * (`printf 'data:image/png;base64,'; cat .env`) no longer disables redaction.
 */
const BINARY_DATA_URL =
  /^data:(?:(?:image|audio|video|font)\/[^\s,;]*|application\/(?:pdf|octet-stream|zip))(?:;[^\s,;]+)*;base64,[A-Za-z0-9+/]*={0,2}$/i

function isBinaryBlob(text: string): boolean {
  return text.startsWith("data:") && BINARY_DATA_URL.test(text)
}

/**
 * Base64 blocks (standard alphabet, url-safe excluded: `-`/`_` are everywhere in identifiers), including the output of
 * `base64` wrapped at 76 characters (short last line included) and indented lines (YAML `data: |`, markdown);
 * a continuation line must be entirely base64.
 */
// Anchored at word start (lookbehind): no retry at every position of a long identifier.
const BASE64_BLOCK = /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?:\r?\n[ \t]*[A-Za-z0-9+/]+={0,2}(?=\r?\n|$))*/g
const PURE_BASE64 = /^[A-Za-z0-9+/=\r\n]+$/
const BASE64_MIN = 24
/** Beyond this, no decoding (cost): the block remains subject to the patterns. */
const BASE64_MAX = 2_000_000
/** Double encoding covered; beyond that, we stop. */
const BASE64_DEPTH = 2

/**
 * Placeholder encoded in base64 in content to be written (Kubernetes Secret `data:` values, `.dockerconfigjson`):
 * writing it would destroy the real secret, like the placeholder in clear text. Without `decodeBase64`'s
 * "digit, `+` or `/`" filter: in the middle of a longer value (encoded JSON), the placeholder does not always contain those characters.
 */
export function containsEncodedPlaceholder(text: string, depth = 0): boolean {
  if (!text || depth >= BASE64_DEPTH) return false
  for (const match of text.matchAll(BASE64_BLOCK)) {
    let compact = match[0].replace(/\s+/g, "")
    if (compact.length < BASE64_MIN || compact.length > BASE64_MAX) continue
    if (compact.endsWith("=")) compact = compact.slice(compact.length % 4)
    const decoded = Buffer.from(compact, "base64").toString("latin1")
    if (PLACEHOLDER_RE.test(decoded) || containsEncodedPlaceholder(decoded, depth + 1)) return true
  }
  return false
}

function decodeBase64(block: string): Buffer | undefined {
  let compact = block.replace(/\s+/g, "")
  if (compact.length < BASE64_MIN || compact.length > BASE64_MAX) return undefined
  // A code identifier (`createRedactorWithOptions`) has neither a digit nor `+`/`/`; a real 30-character base64 block
  // lacks them in ~0.2% of cases: no useless decoding.
  if (!/[0-9+/]/.test(compact)) return undefined
  // Glued prefix (`xx<base64>==`): with padding, the useful length is a multiple of 4.
  if (compact.endsWith("=")) compact = compact.slice(compact.length % 4)
  return Buffer.from(compact, "base64")
}

/** Decoded content compressed with gzip (`1f 8b` header): decompressed before the search, size capped. */
const GZIP_MAX = 4_000_000

function inflated(bytes: Buffer): Buffer {
  if (bytes.length < 18 || bytes[0] !== 0x1f || bytes[1] !== 0x8b) return bytes
  try {
    return gunzipSync(bytes, { maxOutputLength: GZIP_MAX })
  } catch {
    // Truncated stream, followed by extra bytes (neighboring line read with the base64 block), or content larger than GZIP_MAX once
    // decompressed: raw deflate stream after the header, read without requiring its end, at least its beginning.
    try {
      const offset = gzipPayloadOffset(bytes)
      if (offset === undefined) return bytes
      return inflatedPrefix(bytes.subarray(offset)) ?? bytes
    } catch {
      return bytes
    }
  }
}

/**
 * Raw deflate stream decompressed up to GZIP_MAX. Beyond that (highly compressible content) or on a later error, the
 * longest prefix of the stream, size doubled at each attempt, whose output stays under the cap: the beginning of the content
 * is examined instead of nothing.
 */
function inflatedPrefix(payload: Buffer): Buffer | undefined {
  const inflate = (input: Buffer) => inflateRawSync(input, { finishFlush: zlibConstants.Z_SYNC_FLUSH, maxOutputLength: GZIP_MAX })
  try {
    return inflate(payload)
  } catch {}
  let best: Buffer | undefined
  // First attempt of 1 KiB: deflate does not exceed a ratio of about 1,032, so at most ~1 MB of output.
  for (let size = 1024; size < payload.length; size *= 2) {
    try {
      best = inflate(payload.subarray(0, size))
    } catch {
      break
    }
  }
  return best
}

/** Start of the deflate stream of a gzip member (RFC 1952): 10-byte header then optional fields according to FLG. */
function gzipPayloadOffset(bytes: Buffer): number | undefined {
  if (bytes[2] !== 8) return undefined
  const flags = bytes[3]!
  let offset = 10
  if (flags & 4) offset += 2 + (bytes[offset] ?? 0) + ((bytes[offset + 1] ?? 0) << 8)
  for (const flag of [8, 16]) {
    if (!(flags & flag)) continue
    while (offset < bytes.length && bytes[offset] !== 0) offset++
    offset++
  }
  if (flags & 2) offset += 2
  return offset < bytes.length ? offset : undefined
}

/**
 * Hexadecimal dump (`xxd`, `hexdump -C`): 7-8 hexadecimal digit address, then bytes in hexadecimal.
 * Cheap anchored pre-test, run on every examined string.
 */
const HEXDUMP_HINT = /^[0-9a-fA-F]{7,8}:? {1,2}[0-9a-fA-F]{2}/m
const HEXDUMP_LINE = /^[0-9a-fA-F]{7,8}:?[ \t]+(?=[0-9a-fA-F]{2})/
/** Bytes read at most per line (`xxd -c` goes up to 256; beyond that, the end of the line is not read). */
const HEXDUMP_LINE_BYTES = 64

/** Bytes of a dump line: hexadecimal groups after the address, up to the text column. */
function hexDumpBytes(line: string): number[] {
  const bytes: number[] = []
  const start = line.match(HEXDUMP_LINE)
  if (!start) return bytes
  // Hexadecimal area alone: the text column (16 possible hexadecimal characters) would distort the bytes. `xxd`
  // (address followed by `:`) separates it with two spaces, never present between its groups; `hexdump -C` surrounds it with `|`.
  const rest = line.slice(start[0].length)
  const area = start[0].includes(":") ? rest.split("  ")[0]! : rest.split("|")[0]!
  for (const token of area.split(/[ \t]+/)) {
    if (!/^(?:[0-9a-fA-F]{2})+$/.test(token) || bytes.length >= HEXDUMP_LINE_BYTES) break
    for (let i = 0; i < token.length; i += 2) bytes.push(Number.parseInt(token.slice(i, i + 2), 16))
  }
  return bytes
}

/**
 * Printable runs of the decoded content (like `strings`, lines included): what a model would read. A binary at the
 * start (`(head -c 3000 /dev/urandom; cat .env) | base64`) or an archive (`tar c .env | base64`) does not hide the text.
 */
function printableText(bytes: Buffer): string {
  return (bytes.toString("utf8").match(/[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F�]{8,}/g) ?? []).join("\n")
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

const escapeRegExp = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")

interface KnownValue {
  readonly type: string
  readonly value: string
  readonly regex: RegExp
}

/** Exact values and their index by the last 3 characters (`presentKnown`). */
interface KnownValues {
  readonly items: readonly KnownValue[]
  readonly byTail: ReadonlyMap<number, readonly KnownValue[]>
  /** Values shorter than 3 characters (none in practice: length bounds upstream), searched one by one. */
  readonly short: readonly KnownValue[]
}

/** Number of exact values up to which each is searched with the native search (`includes`). */
const NATIVE_SEARCH_MAX = 64

/** Exact key of the 3 UTF-16 units that end at `end` (48 bits, represented exactly by a number). */
const tailKey = (text: string, end: number) => text.charCodeAt(end - 3) * 4294967296 + text.charCodeAt(end - 2) * 65536 + text.charCodeAt(end - 1)

/**
 * Index by the end of values: the end of a token is random, whereas its beginning is often the format prefix
 * shared by learned values; the buckets stay small.
 */
function indexKnown(items: readonly KnownValue[]): KnownValues {
  const byTail = new Map<number, KnownValue[]>()
  const short: KnownValue[] = []
  for (const item of items) {
    if (item.value.length < 3) {
      short.push(item)
      continue
    }
    const key = tailKey(item.value, item.value.length)
    const bucket = byTail.get(key)
    if (bucket) bucket.push(item)
    else byTail.set(key, [item])
  }
  return { items, byTail, short }
}

/**
 * Values present in `text`, in a single scan (instead of one scan per value: cost multiplied by the number of
 * learned values, up to 1,000, on each examined string).
 */
function presentKnown(known: KnownValues, text: string): Set<KnownValue> {
  const found = new Set<KnownValue>()
  if (!known.items.length) return found
  // Few values (the common case: environment, configuration, service): the native search for each is faster
  // than a character-by-character walk; the index is only used beyond that (learned values in number).
  if (known.items.length <= NATIVE_SEARCH_MAX) {
    for (const item of known.items) if (text.includes(item.value)) found.add(item)
    return found
  }
  for (const item of known.short) if (text.includes(item.value)) found.add(item)
  if (!known.byTail.size) return found
  for (let end = 3; end <= text.length; end++) {
    const bucket = known.byTail.get(tailKey(text, end))
    if (!bucket) continue
    for (const item of bucket) if (end >= item.value.length && text.startsWith(item.value, end - item.value.length)) found.add(item)
  }
  return found
}

export function createRedactor(options: RedactorOptions = {}): Redactor {
  const allow = new Set(options.allowlist ?? [])
  // OpenCode formats first: an identifier value that happens to contain the beginning of a known format (`sk-` in the
  // middle of a random key) is redacted and learned whole, instead of being cut by that format's pattern.
  const patterns = [...OPENCODE_PATTERNS, ...BUILTIN_PATTERNS, ...(options.extraPatterns ?? [])]
  const fixed = [
    ...envSecretValues(options.env ?? {}).map((item) => ({ name: `env:${item.name}`, value: item.value })),
    ...(options.knownSecrets ?? []).filter((item) => item.value.length >= MIN_KNOWN_SECRET).map((item) => ({ name: `config:${item.name}`, value: item.value })),
  ]
  // Values learned on sight (`learn`): value → type; bounded, never forgotten before restart.
  const learned = new Map<string, string>()
  let runtime: readonly NamedSecret[] = []
  let known = buildKnown()

  function buildKnown(): KnownValues {
    const values = new Set<string>()
    const items = [
      ...fixed,
      ...runtime.filter((item) => item.value.length >= MIN_KNOWN_SECRET).map((item) => ({ name: `opencode:${item.name}`, value: item.value })),
      ...[...learned].map(([value, name]) => ({ name, value })),
    ]
      .filter((item) => !allow.has(item.value) && !values.has(item.value) && values.add(item.value))
      .sort((a, b) => b.value.length - a.value.length)
      .map((item) => ({ type: item.name, value: item.value, regex: new RegExp(escapeRegExp(item.value), "g") }))
    return indexKnown(items)
  }

  /**
   * Exact values, longest to shortest (a value contained in another does not cut it); only those
   * present in the text (`presentKnown`) are replaced: same result as one pass per value, in a single scan.
   */
  function replaceKnown(text: string): RedactResult<string> {
    const present = presentKnown(known, text)
    if (!present.size) return { value: text, count: 0 }
    let count = 0
    let out = text
    for (const item of known.items) {
      if (!present.has(item)) continue
      out = out.replace(item.regex, () => {
        count++
        return placeholder(item.type)
      })
    }
    return { value: out, count }
  }

  /** Secrets read at runtime, checked once per public call (not once per string). */
  function refresh(): void {
    if (!options.runtimeSecrets) return
    let next: readonly NamedSecret[]
    try {
      next = options.runtimeSecrets()
    } catch {
      return
    }
    if (next === runtime) return
    runtime = next
    known = buildKnown()
  }

  function redactString(text: string): RedactResult<string> {
    refresh()
    return redactText(text, 0)
  }

  function redactText(text: string, depth: number): RedactResult<string> {
    if (!text || isBinaryBlob(text)) return { value: text, count: 0 }
    // Large string entirely base64 (raw image in a request's JSON, output of `base64`): decoded in one go;
    // the patterns are not run on the base64 text itself (costly over megabytes, and pointless).
    if (text.length >= 10_000 && PURE_BASE64.test(text)) {
      const bytes = depth < BASE64_DEPTH ? decodeBase64(text) : undefined
      if (bytes && redactText(printableText(inflated(bytes)), depth + 1).count) return { value: placeholder("base64"), count: 1 }
      // Exact values also searched in the text itself (alphanumeric key on its own line of a list):
      // replaced alone, never the whole block for an accidental match in an image.
      return replaceKnown(text)
    }
    let count = 0
    let out = text
    // Base64 first (a placeholder inserted by the patterns would make the block undecodable): a block whose decoded
    // content contains a secret is replaced whole, visibly (not re-encoded: the placeholder rule must see it).
    if (depth < BASE64_DEPTH) {
      out = out.replace(BASE64_BLOCK, (block) => {
        const bytes = decodeBase64(block)
        if (!bytes || !redactText(printableText(inflated(bytes)), depth + 1).count) return block
        count++
        return placeholder("base64")
      })
    }
    // Hexadecimal dump: the same text that the model would read in the right column, reconstructed from the bytes.
    if (depth < BASE64_DEPTH && HEXDUMP_HINT.test(out)) {
      const dump = redactHexDumps(out, depth)
      out = dump.value
      count += dump.count
    }
    // Exact values first: they are the user's real secrets.
    const exact = replaceKnown(out)
    out = exact.value
    count += exact.count
    const fresh: Array<[string, string]> = []
    for (const pattern of patterns) {
      if (pattern.hint && !pattern.hint.test(out)) continue
      out = out.replace(pattern.regex, (...args: unknown[]) => {
        const match = args[0] as string
        const last = args[args.length - 1]
        const groups = (typeof last === "object" && last !== null ? last : undefined) as
          | Record<string, string | undefined>
          | undefined
        const captured = groups?.secret ?? match
        // Placeholder in the capture (`PASSWORD=[[…]]s3cret`): the fragments around it are judged one by one;
        // already-redacted output stays unchanged (idempotence).
        if (PLACEHOLDER_RE.test(captured)) {
          const rebuilt = captured.replace(PLACEHOLDER_FRAGMENTS, (fragment: string) => {
            if (PLACEHOLDER_RE.test(fragment)) return fragment
            const secret = pattern.trim ? pattern.trim(fragment) : fragment
            if (secret.length < 3 || allow.has(secret) || (pattern.accept && !pattern.accept(secret))) return fragment
            count++
            // Trimmed value at the start of the fragment (after a possible opener): not a repetition further on.
            const at = fragment.indexOf(secret)
            return fragment.slice(0, at) + placeholder(pattern.type) + fragment.slice(at + secret.length)
          })
          if (rebuilt === captured) return match
          const at = match.lastIndexOf(captured)
          return match.slice(0, at) + rebuilt + match.slice(at + captured.length)
        }
        const secret = pattern.trim ? pattern.trim(captured) : captured
        if (!secret || allow.has(secret)) return match
        if (pattern.accept && !pattern.accept(secret)) return match
        count++
        if (pattern.learn && !learned.has(secret) && learned.size < MAX_LEARNED) fresh.push([secret, pattern.type])
        // Position in the capture (last occurrence in the match: the capture is at the end of the pattern, followed by
        // at most one closing quote): the trimmed value is at its start, after a possible opener (`trimBrackets`); a
        // search in the whole match would find a repetition further on.
        const at = match.lastIndexOf(captured) + captured.indexOf(secret)
        return match.slice(0, at) + placeholder(pattern.type) + match.slice(at + secret.length)
      })
    }
    // Learned value: also redacted where it appears alone in the same text, then everywhere afterwards.
    if (fresh.length) {
      for (const [value, type] of fresh) {
        if (learned.has(value) || learned.size >= MAX_LEARNED) continue
        learned.set(value, type)
        const parts = out.split(value)
        count += parts.length - 1
        out = parts.join(placeholder(type))
      }
      known = buildKnown()
    }
    return { value: count ? out : text, count }
  }

  /** Runs of at least two dump lines: a block whose bytes contain a secret is replaced whole. */
  function redactHexDumps(text: string, depth: number): RedactResult<string> {
    const lines = text.split("\n")
    let count = 0
    const out: string[] = []
    for (let i = 0; i < lines.length; ) {
      let end = i
      while (end < lines.length && hexDumpBytes(lines[end]!).length) end++
      if (end - i < 2) {
        out.push(lines[i]!)
        i = Math.max(end, i + 1)
        continue
      }
      const bytes = Buffer.from(lines.slice(i, end).flatMap(hexDumpBytes))
      if (redactText(printableText(inflated(bytes)), depth + 1).count) {
        count++
        out.push(placeholder("hexdump"))
      } else out.push(...lines.slice(i, end))
      i = end
    }
    return { value: count ? out.join("\n") : text, count }
  }

  /**
   * Subtree beyond MAX_DEPTH: serialized and tested in one go; replaced if it contains a secret (never
   * returned as is), or if it is not serializable (impossible to examine).
   */
  function deepSubtree(node: object): { value: unknown; count: number } {
    let text: string | undefined
    try {
      const visited = new WeakSet<object>()
      text = JSON.stringify(node, (_key, item: unknown) => {
        if (item === null || typeof item !== "object") return item
        if (visited.has(item)) return undefined
        visited.add(item)
        return item
      })
    } catch {
      return { value: placeholder("too_deep"), count: 1 }
    }
    const count = text === undefined ? 0 : redactText(text, 0).count
    return count ? { value: placeholder("too_deep"), count } : { value: node, count: 0 }
  }

  function redactDeep<T>(value: T, deepOptions: RedactDeepOptions = {}): RedactResult<T> {
    // Copy memoized per object and per skip state: a shared reference (`{a: X, b: X}`) receives the same
    // redacted copy everywhere, and not the original at its second occurrence.
    refresh()
    const memo = [new Map<object, unknown>(), new Map<object, unknown>()] as const
    const ancestors = new Set<object>()
    let total = 0
    const walk = (node: unknown, depth: number, skipping: boolean): unknown => {
      if (typeof node === "string") {
        const result = redactText(node, 0)
        total += result.count
        return result.value
      }
      if (node === null || typeof node !== "object") return node
      // Map and Set traversed too (error field, tool metadata); other objects: left as is.
      if (!(Array.isArray(node) || isPlainObject(node) || node instanceof Map || node instanceof Set)) return node
      const cache = memo[skipping ? 1 : 0]
      if (cache.has(node)) return cache.get(node)
      // Cycle: never the original (a copy would point to it with its secret); not counted, it does not create a copy on its own.
      if (ancestors.has(node)) return placeholder("cycle")
      let out: unknown = node
      if (depth > MAX_DEPTH) {
        const deep = deepSubtree(node)
        total += deep.count
        out = deep.value
      } else if (Array.isArray(node)) {
        ancestors.add(node)
        const next = node.map((item) => walk(item, depth + 1, skipping))
        ancestors.delete(node)
        if (next.some((item, index) => item !== node[index])) out = next
      } else if (node instanceof Map) {
        ancestors.add(node)
        let changed = false
        const next = new Map<unknown, unknown>()
        for (const [key, item] of node) {
          const k = walk(key, depth + 1, skipping)
          const v = walk(item, depth + 1, skipping)
          if (k !== key || v !== item) changed = true
          next.set(k, v)
        }
        ancestors.delete(node)
        if (changed) out = next
      } else if (node instanceof Set) {
        ancestors.add(node)
        const items = [...node]
        const next = items.map((item) => walk(item, depth + 1, skipping))
        ancestors.delete(node)
        if (next.some((item, index) => item !== items[index])) out = new Set(next)
      } else if (!(skipping && deepOptions.skip?.(node))) {
        ancestors.add(node)
        let changed = false
        const next: Record<string, unknown> = {}
        for (const [key, item] of Object.entries(node)) {
          const result = walk(item, depth + 1, skipping && !deepOptions.unskippable?.(node, key))
          if (result !== item) changed = true
          next[key] = result
        }
        ancestors.delete(node)
        if (changed) out = next
      }
      cache.set(node, out)
      return out
    }
    const learnedBefore = learned.size
    let out = walk(value, 0, true) as T
    // Value learned during the walk: a second pass also redacts the leaves seen before the one that carried the
    // format, within the same call.
    if (learned.size > learnedBefore) {
      memo[0].clear()
      memo[1].clear()
      out = walk(out, 0, true) as T
    }
    return { value: total ? out : value, count: total }
  }

  function containsSecret(value: unknown): boolean {
    return redactDeep(value).count > 0
  }

  return { redactString, redactDeep, containsSecret }
}

/**
 * Sentinel documented by Google, added by OpenCode to replayed calls to Gemini 3 without a signature
 * (packages/ai/src/protocols/gemini.ts): it is not a signature, the part can be redacted.
 */
const GEMINI_NO_SIGNATURE = "skip_thought_signature_validator"

/** Blocks signed by the provider: modifying them invalidates the signature (HTTP 400 on every retry). */
export function isSignedBlock(node: Record<string, unknown>): boolean {
  const type = node.type
  if (type === "thinking" || type === "redacted_thinking" || type === "reasoning") return true
  if ("signature" in node || "encrypted_content" in node) return true
  return "thoughtSignature" in node && node.thoughtSignature !== GEMINI_NO_SIGNATURE
}

/**
 * Arguments of a tool call, serialized as is from the tool input (v2.0.29: Anthropic
 * `tool_use.input`, Bedrock `toolUse.input`, Gemini `functionCall.args`) and never signed: a `signature`
 * key crafted by the model inside must not exempt them from redaction.
 */
export function isToolArguments(parent: Record<string, unknown>, key: string): boolean {
  if (key === "input") return parent.type === "tool_use" || parent.type === "server_tool_use" || typeof parent.toolUseId === "string"
  if (key === "args") return typeof parent.name === "string" && Object.keys(parent).every((k) => k === "id" || k === "name" || k === "args")
  return false
}
