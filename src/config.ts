import type { ModelConfig } from "./model/client.ts"
import { DEFAULT_THRESHOLDS, type Thresholds } from "./model/questions.ts"
import { MIN_KNOWN_SECRET, type SecretPattern } from "./secrets/patterns.ts"
import type { CustomRule } from "./rules/types.ts"

/**
 * Per-feature switches (boolean plugin options, `true` by default). Always active: the
 * placeholder rule, self-protection, the user's `rules`, and redaction of what is sent to the decision model and of the log.
 */
export interface Features {
  /** Local rules for dangerous actions (destruction, system, executed downloads, network, persistence). */
  readonly dangerousCommands: boolean
  /** Rules for credential files and secrets leaving the machine. */
  readonly sensitiveFiles: boolean
  /** Calls to the decision model (its `decision` configuration is kept). */
  readonly decisionModel: boolean
  /** Tracking of scripts written then executed (rules on their content, `executed_scripts`). */
  readonly scripts: boolean
  /** Redaction at the source of tool results and errors. */
  readonly redactOutputs: boolean
  readonly redactPrompt: boolean
  /** Wire safety net: HTTP requests and WebSocket frames to the provider. */
  readonly redactWire: boolean
}

export const FEATURE_NAMES = ["dangerousCommands", "sensitiveFiles", "decisionModel", "scripts", "redactOutputs", "redactPrompt", "redactWire"] as const

export interface GuardConfig {
  /** Decision model (`decision` option, or `jev`, its former name); `undefined` = disabled (local rules only). */
  readonly decision?: ModelConfig
  readonly thresholds: Thresholds
  readonly features: Features
  /** Same value as `features.redactPrompt` (legacy option). */
  readonly redactPrompt: boolean
  readonly debug: boolean
  /** "deny": unattended mode, every confirmation request becomes a rejection. */
  readonly askAs: "ask" | "deny"
  /** Plugin log file; `undefined` = stderr only. */
  readonly logFile?: string
  readonly maxStateChars: number
  readonly cacheTtlMs: number
  readonly cacheMax: number
  readonly secretPatterns: readonly SecretPattern[]
  readonly allowlist: readonly string[]
  readonly rules: readonly CustomRule[]
  /** Primary agent with no checks and no redaction (chosen by the user, e.g. Shift+Tab); absent = disabled. */
  readonly unprotectedAgent?: string
  /**
   * Checking of tool outputs by the decision model (`outputCheck` option); absent = not requested. Effective
   * only if the global configuration file also declares it, with the same address (`output-check.ts`).
   */
  readonly outputCheck?: OutputCheckConfig
}

export interface OutputCheckConfig {
  /** Probability from which an output is flagged. */
  readonly threshold: number
  /** Timeout specific to one check, without retry. */
  readonly timeoutMs: number
}

/**
 * Calibrated on 2026-10-17 for nox-4b on 100 real shell outputs (planted fake secrets): at threshold 0.45, 2% false
 * positives (upper bound) and 90% of fake secrets detected at the start and middle; timeout ≈ 1.5 × the 99th percentile (722 ms).
 */
export const DEFAULT_OUTPUT_CHECK: OutputCheckConfig = { threshold: 0.45, timeoutMs: 1100 }

type Options = Readonly<Record<string, unknown>>

// All configuration comes from the plugin options (opencode.json). Environment-specific
// values are referenced there with {env:VAR} or {file:path}, which OpenCode substitutes in the
// file text before parsing it: a missing variable becomes "" (treated as "not set").

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value)

const isEmpty = (value: unknown) => value === undefined || (typeof value === "string" && value.trim() === "")
const text = (value: unknown) => (typeof value === "string" ? value.trim() : "")
/** Value quoted in a warning: never the content of an object or array (misplaced settings, key included). */
const shown = (value: unknown) => (Array.isArray(value) ? "an array" : value !== null && typeof value === "object" ? "an object" : JSON.stringify(value))

/** Number, or numeric string (`"0.7"`, `"0,7"`) coming from a {env:…} substitution. */
function num(value: unknown, fallback: number, name: string, warnings: string[], min = 0, max = Infinity): number {
  if (isEmpty(value)) return fallback
  const parsed = typeof value === "string" ? Number(value.trim().replace(",", ".")) : value
  if (typeof parsed === "number" && Number.isFinite(parsed) && parsed >= min && parsed <= max) return parsed
  warnings.push(`invalid value for ${name} (${shown(value)}), using default ${fallback}`)
  return fallback
}

/** Boolean, or `true`/`false` string (any case) or `1`/`0` coming from a {env:…} substitution. */
function bool(value: unknown, fallback: boolean, name: string, warnings: string[]): boolean {
  if (isEmpty(value)) return fallback
  if (typeof value === "boolean") return value
  const raw = text(value).toLowerCase()
  if (raw === "true" || raw === "1") return true
  if (raw === "false" || raw === "0") return false
  warnings.push(`invalid value for ${name} (${shown(value)}), using default ${fallback}`)
  return fallback
}

/** Compiles a user regex without the `g` flag (for `.test`) or with it (for replacement). */
function regex(source: unknown, flags: string, name: string, warnings: string[]): RegExp | undefined {
  if (typeof source !== "string" || !source) {
    warnings.push(`${name}: missing pattern`)
    return undefined
  }
  try {
    return new RegExp(source, flags)
  } catch (error) {
    warnings.push(`${name}: invalid regex (${(error as Error).message})`)
    return undefined
  }
}

/** Address displayable in the log: without credentials (`user:pass@`), query, or fragment (a key may be there). */
export function displayURL(raw: string): string {
  try {
    const url = new URL(raw)
    return `${url.protocol}//${url.host}${url.pathname}`
  } catch {
    return raw.replace(/\/\/[^/@\s]*@/, "//***@").replace(/[?#].*$/, "")
  }
}

/** Local machine (`hostname` of a URL, already lowercase; `127.1` becomes `127.0.0.1`, IPv6 in brackets). */
export function isLocalHost(hostname: string): boolean {
  return hostname === "localhost" || hostname.endsWith(".localhost") || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname) || hostname === "[::1]"
}

/** Next to the OpenCode log: $XDG_DATA_HOME/opencode/log/guard.log (default value, not a setting). */
export function defaultLogFile(env: Record<string, string | undefined>): string | undefined {
  const data = env.XDG_DATA_HOME || (env.HOME ? `${env.HOME}/.local/share` : undefined)
  return data ? `${data}/opencode/log/guard.log` : undefined
}

/** Algorithmic defaults only; the address, model, and key come from the settings. */
export const DEFAULT_DECISION = {
  protocol: "chat",
  timeoutMs: 5000,
} as const

/** `jev`: former name of `decision`, still accepted; `decision` wins, even when invalid (never a silent fallback). */
function decisionOption(options: Options, warnings: string[]): ModelConfig | undefined {
  if (options.decision === undefined) return parseDecision(options.jev, "jev", warnings)
  if (options.jev !== undefined) warnings.push("jev (former name of decision) ignored: decision is set")
  return parseDecision(options.decision, "decision", warnings)
}

/** `name`: option name in opencode.json, repeated in warnings so the setting can be found. */
function parseDecision(value: unknown, name: "decision" | "jev", warnings: string[]): ModelConfig | undefined {
  if (value === undefined) return undefined
  if (!isRecord(value)) {
    // Boolean: probably the `decisionModel` switch confused with the settings.
    const hint = typeof value === "boolean" ? '; to turn the model off, use "decisionModel": false' : ""
    warnings.push(`invalid value for ${name} (object expected): decision model disabled${hint}`)
    return undefined
  }
  warnUnknown(value, DECISION_KEYS, `${name}.`, warnings)
  const baseURL = text(value.baseURL)
  if (!baseURL) {
    warnings.push(`${name}.baseURL is empty or missing: decision model disabled`)
    return undefined
  }
  let url: URL
  try {
    url = new URL(baseURL)
    if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("not an HTTP protocol")
  } catch {
    warnings.push(`invalid ${name}.baseURL (${displayURL(baseURL)}): decision model disabled`)
    return undefined
  }
  // Warning only: a server on the local network may be intentional.
  if (url.protocol === "http:" && !isLocalHost(url.hostname))
    warnings.push(`${name}.baseURL uses plain HTTP to a host that is not local: the key and the redacted tool calls are sent unencrypted`)
  const model = text(value.model)
  if (!model) {
    warnings.push(`${name}.model is empty or missing: decision model disabled`)
    return undefined
  }
  let protocol: ModelConfig["protocol"] = DEFAULT_DECISION.protocol
  const rawProtocol = text(value.protocol)
  if (rawProtocol === "chat" || rawProtocol === "systemone") protocol = rawProtocol
  else if (rawProtocol) warnings.push(`invalid ${name}.protocol (${JSON.stringify(rawProtocol)}), using "chat"`)
  // apiKey absent or null: no authentication. "": the {env:…} variable is not set in
  // the server environment; without a key, every call would fail (401) and every action would become
  // a confirmation request. Never the value in a warning.
  let apiKey: string | undefined
  if (value.apiKey !== undefined && value.apiKey !== null) {
    if (typeof value.apiKey !== "string") {
      warnings.push(`invalid value for ${name}.apiKey (string expected): decision model disabled`)
      return undefined
    }
    if (!value.apiKey.trim()) {
      warnings.push(
        `${name}.apiKey is empty (is the variable referenced with {env:…} set in the OpenCode server environment?): decision model disabled`,
      )
      return undefined
    }
    apiKey = value.apiKey.trim()
    // Configuration secrets replaced verbatim only from 8 characters (redact.ts): any shorter, the
    // key is never redacted. Neither the value nor its exact length in the warning.
    if (apiKey.length < MIN_KNOWN_SECRET)
      warnings.push(`${name}.apiKey is shorter than ${MIN_KNOWN_SECRET} characters: it cannot be redacted verbatim (logs, requests)`)
  }
  const headers: Record<string, string> = {}
  if (value.headers !== undefined && !isRecord(value.headers)) warnings.push(`invalid value for ${name}.headers (object expected), ignored`)
  if (isRecord(value.headers))
    for (const [key, item] of Object.entries(value.headers)) {
      if (typeof item !== "string") warnings.push(`invalid value for ${name}.headers.${key} (string expected), ignored`)
      else if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(key)) warnings.push(`invalid header name ${name}.headers.${JSON.stringify(key)}, ignored`)
      // Value never quoted: it may contain a secret.
      else if (/[\r\n\0]/.test(item)) warnings.push(`invalid value for ${name}.headers.${key} (line break), ignored`)
      else if (item.trim()) {
        headers[key] = item.trim()
        if (/auth|key|token|secret|cookie/i.test(key) && headers[key]!.length < MIN_KNOWN_SECRET)
          warnings.push(`${name}.headers.${key} is shorter than ${MIN_KNOWN_SECRET} characters: it cannot be redacted verbatim (logs, requests)`)
      }
    }
  return {
    protocol,
    baseURL,
    model,
    timeoutMs: num(value.timeoutMs, DEFAULT_DECISION.timeoutMs, `${name}.timeoutMs`, warnings, 100, 60_000),
    apiKey,
    headers,
  }
}

/** OpenCode v1 tool names (`core/src/database/v1-migration.bun.ts:899-901`, v2.0.29). */
// Map (not an object): `constructor` or `toString` must not find anything.
const V1_TOOL_NAMES: ReadonlyMap<string, string> = new Map([
  ["bash", "shell"],
  ["task", "subagent"],
  ["apply_patch", "patch"],
])
/** v1 tools present in v2 only conditionally: `todowrite` requires `experimental.todo` (v2.1.1). */
const V1_CONDITIONAL_TOOLS = new Set(["todowrite"])
/** Arguments renamed in v2 (same file): `filePath` → `path` (read, edit, write), `subagent_type` → `agent`. */
const V1_ARGUMENTS: ReadonlyArray<readonly [string, string]> = [
  ["filePath", "path"],
  ["subagent_type", "agent"],
]

/** Verdict cache bounds: a verdict stays at most 1 h, memory usage stays bounded. */
export const MAX_CACHE_TTL_MS = 3_600_000
export const MAX_CACHE_ENTRIES = 10_000

/** Beyond this, the decision model is less accurate (long `state`) and an overly long state leads to an ask. */
const LARGE_STATE_CHARS = 8000

function maxStateCharsOption(value: unknown, warnings: string[]): number {
  const chars = num(value, 4000, "maxStateChars", warnings, 200, 100_000)
  if (chars > LARGE_STATE_CHARS)
    warnings.push(`maxStateChars above ${LARGE_STATE_CHARS}: the decision model is less accurate with a long state, and a state over its limit leads to a confirmation`)
  return chars
}

/** Trimmed values: a detected secret never contains whitespace. Non-text entry reported (index and type only). */
function allowlistOption(value: unknown, warnings: string[]): string[] {
  if (value === undefined) return []
  if (!Array.isArray(value)) {
    warnings.push("allowlist must be an array of strings, ignored")
    return []
  }
  value.forEach((item, index) => {
    if (typeof item !== "string") warnings.push(`allowlist[${index}] ignored (string expected, got ${item === null ? "null" : typeof item})`)
  })
  return value.filter((item): item is string => typeof item === "string").map((item) => item.trim()).filter(Boolean)
}

const OPTION_KEYS = [
  "askAs",
  "decision",
  "jev",
  "thresholds",
  "redactPrompt",
  "dangerousCommands",
  "sensitiveFiles",
  "decisionModel",
  "scripts",
  "redactOutputs",
  "redactWire",
  "debug",
  "logFile",
  "maxStateChars",
  "cacheTtlMs",
  "cacheMax",
  "secretPatterns",
  "allowlist",
  "rules",
  "unprotectedAgent",
  "outputCheck",
]
const DECISION_KEYS = ["baseURL", "protocol", "model", "apiKey", "timeoutMs", "headers"]
const THRESHOLD_KEYS = ["denyNoul", "askNoul", "askExfiltration", "denyRisk", "askRisk", "minConfidence"]

/** A misspelled option would otherwise be silently ignored. */
function warnUnknown(value: Record<string, unknown>, known: readonly string[], prefix: string, warnings: string[]) {
  for (const key of Object.keys(value)) if (!known.includes(key)) warnings.push(`unknown option ${prefix}${key}, ignored`)
}

/**
 * `outputCheck` requested: `true` (or `"true"`, `"1"`), or an object whose `enabled` is not false. Same reading for the
 * options received and for the global file re-read by the plugin.
 */
export function outputCheckRequested(value: unknown): boolean {
  if (value === true) return true
  if (typeof value === "string") return ["true", "1"].includes(value.trim().toLowerCase())
  if (!isRecord(value)) return false
  const enabled = value.enabled
  if (enabled === undefined || isEmpty(enabled)) return true
  return enabled === true || (typeof enabled === "string" && ["true", "1"].includes(enabled.trim().toLowerCase()))
}

const OUTPUT_CHECK_KEYS = ["enabled", "threshold", "timeoutMs"]

function outputCheckOption(value: unknown, warnings: string[]): OutputCheckConfig | undefined {
  if (value === undefined || isEmpty(value) || value === false) return undefined
  if (isRecord(value)) {
    warnUnknown(value, OUTPUT_CHECK_KEYS, "outputCheck.", warnings)
    if (!outputCheckRequested(value)) return undefined
    return {
      threshold: num(value.threshold, DEFAULT_OUTPUT_CHECK.threshold, "outputCheck.threshold", warnings, 0, 1),
      timeoutMs: num(value.timeoutMs, DEFAULT_OUTPUT_CHECK.timeoutMs, "outputCheck.timeoutMs", warnings, 100, 60_000),
    }
  }
  if (outputCheckRequested(value)) return DEFAULT_OUTPUT_CHECK
  const raw = text(value).toLowerCase()
  if (raw !== "false" && raw !== "0") warnings.push(`invalid value for outputCheck (${shown(value)}): output check not requested`)
  return undefined
}

/** "" (missing {env:…} variable) → "ask". Any case: `Deny` must not leave an unattended run in ask mode. */
function askAsOption(value: unknown, warnings: string[]): "ask" | "deny" {
  const raw = text(value).toLowerCase()
  if (raw === "ask" || raw === "deny") return raw
  if (raw || (value !== undefined && typeof value !== "string")) warnings.push(`invalid value for askAs (${shown(value)}), using "ask"`)
  return "ask"
}

/** Agent ID (config key); never a built-in agent, which would remove protection from the primary agent. */
function unprotectedAgentOption(value: unknown, warnings: string[]): string | undefined {
  if (isEmpty(value)) return undefined
  const id = text(value)
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(id)) {
    warnings.push(`invalid value for unprotectedAgent (${shown(value)}): no unprotected agent`)
    return undefined
  }
  if (["build", "plan", "general", "explore", "title", "compaction", "summary"].includes(id)) {
    warnings.push(`unprotectedAgent cannot be the built-in agent "${id}": no unprotected agent`)
    return undefined
  }
  return id
}

function logFileOption(value: unknown, env: Record<string, string | undefined>, warnings: string[]): string | undefined {
  if (value === false || text(value).toLowerCase() === "false") return undefined
  if (isEmpty(value)) return defaultLogFile(env)
  if (typeof value === "string") {
    // `~` is expanded by neither OpenCode nor the filesystem (a `~` directory would be created in the current directory).
    let path = value.trim()
    if ((path === "~" || path.startsWith("~/")) && env.HOME) path = `${env.HOME}${path.slice(1)}`
    if (!path.startsWith("/") && !/^[A-Za-z]:[\\/]/.test(path))
      warnings.push("logFile is not an absolute path: it is resolved against the OpenCode server's working directory")
    return path
  }
  warnings.push(`invalid value for logFile (${shown(value)}), using the default`)
  return defaultLogFile(env)
}

/** `env` is only used for the default log path: configuration comes solely from `options`. */
export function parseConfig(
  options: Options,
  env: Record<string, string | undefined> = {},
): { config: GuardConfig; warnings: string[] } {
  const warnings: string[] = []
  warnUnknown(options, OPTION_KEYS, "", warnings)
  if (options.thresholds !== undefined && !isRecord(options.thresholds)) warnings.push("invalid value for thresholds (object expected), using defaults")
  const t = isRecord(options.thresholds) ? options.thresholds : {}
  warnUnknown(t, THRESHOLD_KEYS, "thresholds.", warnings)
  const threshold = (key: keyof Thresholds, max: number) => num(t[key], DEFAULT_THRESHOLDS[key], `thresholds.${key}`, warnings, 0, max)
  const thresholds: Thresholds = {
    denyNoul: threshold("denyNoul", 1),
    askNoul: threshold("askNoul", 1),
    askExfiltration: threshold("askExfiltration", 1),
    denyRisk: threshold("denyRisk", 3),
    askRisk: threshold("askRisk", 3),
    minConfidence: threshold("minConfidence", 1),
  }
  if (thresholds.askNoul > thresholds.denyNoul || thresholds.askExfiltration > thresholds.denyNoul || thresholds.askRisk > thresholds.denyRisk)
    warnings.push("inconsistent thresholds: an \"ask\" threshold is above the matching \"deny\" threshold (it will never trigger)")

  const secretPatterns: SecretPattern[] = []
  // A single value (object or string) instead of an array: reported, never silently ignored.
  if (options.secretPatterns !== undefined && !Array.isArray(options.secretPatterns))
    warnings.push("secretPatterns must be an array, ignored")
  if (Array.isArray(options.secretPatterns)) {
    options.secretPatterns.forEach((item, index) => {
      const entry: Record<string, unknown> = isRecord(item) ? item : { pattern: item }
      const compiled = regex(entry.pattern, "g", `secretPatterns[${index}]`, warnings)
      if (compiled) secretPatterns.push({ type: typeof entry.type === "string" ? entry.type : "custom", regex: compiled })
    })
  }

  const rules: CustomRule[] = []
  // A single rule (object) instead of an array: reported (a deny rule silently lost would be a hole).
  if (options.rules !== undefined && !Array.isArray(options.rules)) warnings.push("rules must be an array, ignored")
  if (Array.isArray(options.rules)) {
    options.rules.forEach((item, index) => {
      if (!isRecord(item)) return warnings.push(`invalid rules[${index}]`)
      const verdict = item.verdict === "deny" || item.verdict === "ask" ? item.verdict : undefined
      // `g` and `y` make `test()` depend on `lastIndex` (every other command would escape the rule).
      const compiled = regex(item.pattern, typeof item.flags === "string" ? item.flags.replace(/[gy]/g, "") : "", `rules[${index}]`, warnings)
      if (!verdict) return warnings.push(`rules[${index}].verdict must be "deny" or "ask"`)
      if (!compiled) return
      // `"tools": "*"` (single string) is equivalent to `["*"]`; any other type would otherwise be silently reduced to `["shell"]`.
      let tools = ["shell"]
      if (typeof item.tools === "string" && item.tools.trim()) tools = [item.tools.trim()]
      else if (Array.isArray(item.tools)) {
        const names = item.tools.filter((tool): tool is string => typeof tool === "string").map((tool) => tool.trim())
        tools = names.filter(Boolean)
        if (tools.length < item.tools.length) warnings.push(`rules[${index}].tools: empty or non-string tool names ignored`)
        if (!tools.length) {
          warnings.push(`rules[${index}].tools has no valid tool name, using ["shell"]`)
          tools = ["shell"]
        }
      } else if (item.tools !== undefined) warnings.push(`rules[${index}].tools must be a tool name or an array of tool names, using ["shell"]`)
      // Rule copied from OpenCode v1: without the alias, a rule on `bash` would never apply (ineffective deny).
      for (const name of [...tools]) {
        const renamed = V1_TOOL_NAMES.get(name)
        if (renamed) {
          if (!tools.includes(renamed)) tools.push(renamed)
          warnings.push(`rules[${index}].tools: "${name}" is the OpenCode v1 name of "${renamed}": the rule applies to "${renamed}"`)
        } else if (V1_CONDITIONAL_TOOLS.has(name))
          warnings.push(`rules[${index}].tools: "${name}" exists in OpenCode v2 only when "experimental.todo" is enabled`)
      }
      for (const [old, current] of V1_ARGUMENTS)
        if (compiled.source.includes(old)) warnings.push(`rules[${index}].pattern mentions "${old}", renamed "${current}" in OpenCode v2`)
      // `placeholder` is the identifier of the built-in redaction marker rule, which the tracked-script
      // check (decide.ts) excludes and whose rejection message omits the instruction not to bypass (gate.ts): reused
      // by a user rule, it would make that rule ineffective in a script and weaken its message.
      let id = typeof item.id === "string" ? item.id : `custom-${index}`
      if (id === "placeholder") {
        id = `custom-${index}`
        warnings.push(`rules[${index}].id "placeholder" is reserved for the built-in redaction placeholder rule, using "${id}"`)
      }
      rules.push({
        id,
        verdict,
        reason: typeof item.reason === "string" ? item.reason : `custom rule ${index}`,
        pattern: compiled,
        tools,
      })
    })
  }

  // Model settings placed under the switch (confusion between the two names): dedicated message, never taken as configuration.
  const misplaced = isRecord(options.decisionModel)
  if (misplaced) warnings.push('decisionModel is an on/off switch (true or false); the decision model settings go under "decision"')
  const features = Object.fromEntries(
    FEATURE_NAMES.map((name) => [name, bool(name === "decisionModel" && misplaced ? undefined : options[name], true, name, warnings)]),
  ) as unknown as Features

  return {
    config: {
      decision: decisionOption(options, warnings),
      thresholds,
      features,
      redactPrompt: features.redactPrompt,
      debug: bool(options.debug, false, "debug", warnings),
      askAs: askAsOption(options.askAs, warnings),
      logFile: logFileOption(options.logFile, env, warnings),
      maxStateChars: maxStateCharsOption(options.maxStateChars, warnings),
      cacheTtlMs: num(options.cacheTtlMs, 600_000, "cacheTtlMs", warnings, 0, MAX_CACHE_TTL_MS),
      cacheMax: num(options.cacheMax, 500, "cacheMax", warnings, 0, MAX_CACHE_ENTRIES),
      secretPatterns,
      allowlist: allowlistOption(options.allowlist, warnings),
      rules,
      unprotectedAgent: unprotectedAgentOption(options.unprotectedAgent, warnings),
      outputCheck: outputCheckOption(options.outputCheck, warnings),
    },
    warnings,
  }
}
