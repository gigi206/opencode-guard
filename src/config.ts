import type { ModelConfig } from "./model/client.ts"
import { DEFAULT_THRESHOLDS, type Thresholds } from "./model/questions.ts"
import { MIN_KNOWN_SECRET, type SecretPattern } from "./secrets/patterns.ts"
import { DENY_ONLY_RULES, RULE_FEATURES, USER_ONLY_RULES, entrusted, overridden, ruleEnabled, rulePolicy, type ActiveRules, type RuleOverride } from "./rules/features.ts"
import { INTERNAL_ERROR_RULE, type CustomRule, type Finding } from "./rules/types.ts"

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

/** `profile` option: `credentials-only` sets the default of the switches below to `false` (an explicit option wins). */
export type Profile = "standard" | "credentials-only"
const CREDENTIALS_ONLY_OFF: ReadonlySet<string> = new Set(["dangerousCommands", "decisionModel", "scripts"])

/** Plugin entry re-read from the global or system configuration (`output-check.ts`): its options, or why there are none. */
export interface PluginDeclaration {
  readonly label: string
  readonly options?: Readonly<Record<string, unknown>>
  readonly reason?: string
}

export interface GuardConfig {
  /** Decision model (`decision` option, or `jev`, its former name); `undefined` = disabled (local rules only). */
  readonly decision?: ModelConfig
  readonly thresholds: Thresholds
  readonly features: Features
  /** Profile retained (`credentials-only` only if the global or system configuration declares it too). */
  readonly profile: Profile
  /** Rule policy: `dangerousCommands` and `sensitiveFiles` switches and retained `ruleOverrides`, built once. */
  readonly policy: ActiveRules
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
  /** Inputs of the settings by agent and by project, read at startup (`setupGuard` only): `scopes.ts` re-resolves them. */
  readonly layers?: Layers
  /** Startup version of these settings when a guard.json file, `agents`, `projects` or `trustedProjects` exists. */
  readonly version?: Version
  /**
   * The decision model may allow an ask (heredoc data, CodeMode's `fetch`, asks left to it by a setting) at the top level:
   * its configuration (address, model, and what else decides its verdict) is the one a global source declares, and the
   * system configuration, when it declares the plugin, or else the global sources switch it on; or the project is
   * trusted. Otherwise it may still deny, and such asks stay with the user. Per call: `Scope.modelGrants`.
   */
  readonly modelGrants: boolean
  /** Why it may not (in words, never a value); absent when it may. */
  readonly modelWithheld?: string
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

/** Comparable address: protocol, host (lowercase), path without trailing slash, query. */
export function normalizedURL(raw: unknown): string | undefined {
  if (typeof raw !== "string" || !raw.trim()) return undefined
  try {
    const url = new URL(raw.trim())
    return `${url.protocol}//${url.host}${url.pathname.replace(/\/+$/, "")}${url.search}`
  } catch {
    return undefined
  }
}

/** `decision` of a plugin entry re-read from a global source; `jev` (former name) only without `decision`, as in the effective configuration. */
export function declaredDecision(options: Readonly<Record<string, unknown>>): Record<string, unknown> | undefined {
  return isRecord(options.decision) ? options.decision : isRecord(options.jev) && options.decision === undefined ? options.jev : undefined
}

/** What the decision model's verdict depends on: who answers and when (`decision`), what it sees, how its answers are read. */
interface ModelSettings {
  readonly decision: ModelConfig
  readonly maxStateChars: number
  readonly thresholds: Thresholds
  /** Extra patterns: they redact what the model receives, so a project's own could hide data from it. */
  readonly secretPatterns: readonly SecretPattern[]
}

/**
 * Is this decision model's configuration the one a global or system plugin entry declares: address (compared as for
 * `outputCheck`) and model, then protocol, timeout, key and headers, `maxStateChars`, `secretPatterns` and `thresholds`,
 * each read like the effective option? Reason in words otherwise (never a value).
 */
function undeclaredModel(declarations: readonly PluginDeclaration[] | string, effective: ModelSettings): string | undefined {
  if (typeof declarations === "string") return declarations
  const reasons: string[] = []
  for (const entry of declarations) {
    const raw = entry.options && declaredDecision(entry.options)
    if (!entry.options) reasons.push(`${entry.label} configuration: ${entry.reason ?? "not read"}`)
    else if (JSON.stringify([raw, entry.options.maxStateChars, entry.options.thresholds, entry.options.secretPatterns]).includes("{file:"))
      reasons.push(`${entry.label} configuration: its decision model uses a {file:…} reference`)
    else if (!raw || normalizedURL(raw.baseURL) !== normalizedURL(effective.decision.baseURL) || text(raw.model) !== effective.decision.model)
      reasons.push(`${entry.label} configuration: ${raw ? "another decision model address or model" : "no decision model"}`)
    else {
      const other = otherModelSettings(entry.options, raw, effective)
      if (!other.length) return undefined
      reasons.push(`${entry.label} configuration: other values for ${other.join(", ")}`)
    }
  }
  return reasons.join("; ")
}

/** `secretPatterns` option: each entry an object `{ type, pattern }` or the pattern source alone (type `custom`). */
function secretPatternsOption(value: unknown, warnings: string[]): SecretPattern[] {
  const secretPatterns: SecretPattern[] = []
  // A single value (object or string) instead of an array: reported, never silently ignored.
  if (value !== undefined && !Array.isArray(value)) warnings.push("secretPatterns must be an array, ignored")
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      const entry: Record<string, unknown> = isRecord(item) ? item : { pattern: item }
      const compiled = regex(entry.pattern, "g", `secretPatterns[${index}]`, warnings)
      if (compiled) secretPatterns.push({ type: typeof entry.type === "string" ? entry.type : "custom", regex: compiled })
    })
  }
  return secretPatterns
}

/** Settings besides the address and model whose value, read from a plugin entry, differs from the effective one. */
function otherModelSettings(options: Readonly<Record<string, unknown>>, raw: Readonly<Record<string, unknown>>, effective: ModelSettings): string[] {
  const declared = parseDecision(raw, "decision", [])
  if (!declared) return ["decision"]
  // As the client sends them: names in lowercase, the last one wins.
  const headers = (config: ModelConfig) => JSON.stringify(Object.entries(Object.fromEntries(Object.entries(config.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value]))).sort())
  const thresholds = thresholdsOption(options.thresholds, [])
  const patterns = (list: readonly SecretPattern[]) => JSON.stringify(list.map(({ type, regex }) => [type, regex.source, regex.flags]))
  const differences: Array<[string, boolean]> = [
    ["decision.protocol", declared.protocol !== effective.decision.protocol],
    ["decision.timeoutMs", declared.timeoutMs !== effective.decision.timeoutMs],
    ["decision.apiKey", declared.apiKey !== effective.decision.apiKey],
    ["decision.headers", headers(declared) !== headers(effective.decision)],
    ["maxStateChars", maxStateCharsOption(options.maxStateChars, []) !== effective.maxStateChars],
    ["secretPatterns", patterns(secretPatternsOption(options.secretPatterns, [])) !== patterns(effective.secretPatterns)],
    ["thresholds", (Object.keys(DEFAULT_THRESHOLDS) as Array<keyof Thresholds>).some((key) => thresholds[key] !== effective.thresholds[key])],
  ]
  return differences.flatMap(([name, differs]) => (differs ? [name] : []))
}

/** The model switched on by a plugin entry's own options (`credentials-only` turns it off unless it is set). */
const modelSwitchedOn = (options: Readonly<Record<string, unknown>>) => flag(options.decisionModel) ?? profileValue(options.profile) !== "credentials-only"
/** Plugin entry of a global source (`global` or `system`), if it declares the plugin. */
const entryOf = (declarations: readonly PluginDeclaration[] | string, label: string) => (typeof declarations === "string" ? undefined : declarations.find((entry) => entry.label === label)?.options)
/** The system configuration's switch of the model, when it declares the plugin (loaded last by OpenCode, it decides). */
function systemSwitch(declarations: readonly PluginDeclaration[] | string): boolean | undefined {
  const options = entryOf(declarations, "system")
  return options === undefined ? undefined : modelSwitchedOn(options)
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

function thresholdsOption(value: unknown, warnings: string[]): Thresholds {
  if (value !== undefined && !isRecord(value)) warnings.push("invalid value for thresholds (object expected), using defaults")
  const t = isRecord(value) ? value : {}
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
  return thresholds
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
  "profile",
  "ruleOverrides",
  "localAsks",
  "selfProtectionByModel",
  "agents",
  "projects",
  "trustedProjects",
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

/** Profile read like `askAs` (any case); `undefined`: not set; `null`: invalid. Same reading for the global file. */
function profileValue(value: unknown): Profile | undefined | null {
  if (isEmpty(value)) return undefined
  const raw = text(value).toLowerCase()
  return typeof value === "string" && (raw === "standard" || raw === "credentials-only") ? raw : null
}

/** Setting of one rule, any case, `allow` read as `off`; `undefined` otherwise. Same reading for the global file. */
function overrideValue(value: unknown): RuleOverride | undefined {
  const raw = text(value).toLowerCase()
  return raw === "allow" ? "off" : raw === "off" || raw === "ask" || raw === "deny" || raw === "model" ? raw : undefined
}

/** `localAsks` read like `askAs` (any case); `undefined`: not set; `null`: invalid. Same reading for the global file. */
function localAsksValue(value: unknown): "ask" | "model" | undefined | null {
  if (isEmpty(value)) return undefined
  const raw = text(value).toLowerCase()
  return typeof value === "string" && (raw === "ask" || raw === "model") ? raw : null
}

/** Setting as written (any case), for warnings: `allow` stays `allow`. */
const writtenOverride = (value: unknown) => (text(value).toLowerCase() === "allow" ? "allow" : overrideValue(value))

/**
 * `ruleOverrides`: built-in rule identifier → `off` (or `allow`, same setting), `ask`, `deny` or `model`. Ignored with a warning (never the value of another
 * field): unknown identifier, invalid value, one of the user's rules (even under a built-in name: the setting would apply
 * to it), internal errors, `off` or `ask` on an always-active rule (`model` there: checked with `selfProtectionByModel`),
 * `model` on a rule that only denies (no ask to leave to the decision model).
 */
function ruleOverridesOption(value: unknown, userRules: readonly CustomRule[], warnings: string[]): Map<string, RuleOverride> {
  const overrides = new Map<string, RuleOverride>()
  if (value === undefined || isEmpty(value)) return overrides
  if (!isRecord(value)) {
    warnings.push('ruleOverrides must be an object (rule identifier: "off", "allow", "ask", "deny" or "model"), ignored')
    return overrides
  }
  for (const [rule, raw] of Object.entries(value)) {
    const setting = overrideValue(raw)
    const feature = RULE_FEATURES.get(rule)
    const name = feature === undefined && rule !== INTERNAL_ERROR_RULE ? `ruleOverrides[${JSON.stringify(rule)}]` : `ruleOverrides.${rule}`
    if (userRules.some((custom) => custom.id === rule)) warnings.push(`${name} ignored: it names one of your rules (set its verdict in rules)`)
    else if (rule === INTERNAL_ERROR_RULE) warnings.push(`${name} ignored: an internal error always asks`)
    else if (feature === undefined) warnings.push(`${name} ignored: unknown rule (identifiers are listed in docs/rules.md)`)
    else if (!setting) warnings.push(`invalid value for ${name} (${shown(raw)}): "off", "allow", "ask", "deny" or "model" expected, ignored`)
    else if (setting === "model" && USER_ONLY_RULES.has(rule))
      warnings.push(`${name} "model" ignored: this rule is about ${USER_ONLY_RULES.get(rule)}, never left to the decision model`)
    else if (setting === "model" && DENY_ONLY_RULES.has(rule))
      warnings.push(`${name} "model" ignored: this rule only denies, it has no confirmation to leave to the decision model`)
    else if (feature === "always" && setting !== "deny" && setting !== "model")
      warnings.push(`${name} "${writtenOverride(raw)}" ignored: this rule is always active (only "deny" is accepted)`)
    else overrides.set(rule, setting)
  }
  return overrides
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

/**
 * `env` is only used for the default log path: configuration comes solely from `options`. `declared`: plugin entries
 * of the global and system configurations, read only if a relaxation is requested (absent or failing: relaxations
 * ignored).
 */
export function parseConfig(
  options: Options,
  env: Record<string, string | undefined> = {},
  declared?: () => readonly PluginDeclaration[],
  inputs?: ScopeInputs,
): { config: GuardConfig; warnings: string[] } {
  const warnings: string[] = []
  warnUnknown(options, OPTION_KEYS, "", warnings)
  const thresholds = thresholdsOption(options.thresholds, warnings)

  const secretPatterns = secretPatternsOption(options.secretPatterns, warnings)

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

  // Relaxations (`profile`, rules set to `off`, `ask` or `model`, `localAsks: "model"`, `selfProtectionByModel`): a
  // project's opencode.json can replace the plugin's options, so each one is kept only if the global or system
  // configuration declares the plugin with the same value (`deny`: from anywhere). Files read once, only if one is
  // requested; at the slightest doubt, the relaxation is ignored.
  const overrides = ruleOverridesOption(options.ruleOverrides, rules, warnings)
  const wanted = profileValue(options.profile)
  if (wanted === null) warnings.push(`invalid value for profile (${shown(options.profile)}), using "standard"`)
  let profile: Profile = wanted ?? "standard"
  let declarations: readonly PluginDeclaration[] | string | undefined
  const loaded = () => {
    if (declarations === undefined)
      try {
        declarations = declared?.() ?? "the global configuration was not checked"
      } catch {
        declarations = "the global and system configurations could not be read"
      }
    return declarations
  }
  const refusal = (matches: (options: Readonly<Record<string, unknown>>) => boolean): string | undefined => {
    const declarations = loaded()
    if (typeof declarations === "string") return declarations
    if (declarations.some((entry) => entry.options && matches(entry.options))) return undefined
    const found = declarations.map((entry) => `${entry.label} configuration: ${entry.options ? "it does not set this value" : entry.reason}`)
    return `a relaxation counts only if the global or system configuration sets it too (${found.join("; ")})`
  }
  // Settings by agent and by project: inputs read once (global and system files read now); when a guard.json file,
  // `agents`, `projects` or `trustedProjects` exists, the layered resolution replaces the checks below, whose warnings
  // are then dropped.
  // The decision model allows an ask only with the global sources' address and model (user's decision): read here.
  const decision = decisionOption(options, warnings)
  const maxStateChars = maxStateCharsOption(options.maxStateChars, warnings)
  const modelUndeclared = decision ? undeclaredModel(loaded(), { decision, maxStateChars, thresholds, secretPatterns }) : "no decision model"
  const layers = inputs && scopeLayers(options, { rules, overrides: new Map(overrides), profile, refusal, declarations: loaded(), modelUndeclared }, inputs, warnings)
  const version = layers && (inputs!.files.length > 0 || layers.keyed) ? resolveVersion(layers, inputs!.files) : undefined
  const certification = version ? [] : warnings
  if (profile !== "standard") {
    const why = refusal((declaration) => profileValue(declaration.profile) === profile)
    if (why) {
      certification.push(`profile "${profile}" ignored: ${why}`)
      profile = "standard"
    }
  }
  const asks = localAsksValue(options.localAsks)
  if (asks === null) warnings.push(`invalid value for localAsks (${shown(options.localAsks)}), using "ask"`)
  let localAsksByModel = asks === "model"
  if (localAsksByModel) {
    const why = refusal((declaration) => localAsksValue(declaration.localAsks) === "model")
    if (why) {
      certification.push(`localAsks "model" ignored: ${why}`)
      localAsksByModel = false
    }
  }
  let selfProtectionByModel = bool(options.selfProtectionByModel, false, "selfProtectionByModel", warnings)
  if (selfProtectionByModel) {
    const why = refusal((declaration) => bool(declaration.selfProtectionByModel, false, "", []))
    if (why) {
      certification.push(`selfProtectionByModel ignored: ${why}`)
      selfProtectionByModel = false
    }
  }
  for (const [rule, setting] of overrides) {
    if (setting === "model" && RULE_FEATURES.get(rule) === "always" && !selfProtectionByModel) {
      certification.push(`ruleOverrides.${rule} "model" ignored: this rule is always active ("model" needs selfProtectionByModel)`)
      overrides.delete(rule)
      continue
    }
    if (setting === "deny") continue
    const why = refusal((declaration) => isRecord(declaration.ruleOverrides) && overrideValue(declaration.ruleOverrides[rule]) === setting)
    if (why) {
      certification.push(`ruleOverrides.${rule} "${writtenOverride((options.ruleOverrides as Record<string, unknown>)[rule])}" ignored: ${why}`)
      overrides.delete(rule)
    }
  }

  // Model settings placed under the switch (confusion between the two names): dedicated message, never taken as configuration.
  const misplaced = isRecord(options.decisionModel)
  if (misplaced) warnings.push('decisionModel is an on/off switch (true or false); the decision model settings go under "decision"')
  const defaultOf = (name: string) => !(profile === "credentials-only" && CREDENTIALS_ONLY_OFF.has(name))
  const parsed = Object.fromEntries(
    FEATURE_NAMES.map((name) => [name, bool(name === "decisionModel" && misplaced ? undefined : options[name], defaultOf(name), name, warnings)]),
  ) as unknown as Features
  // Layered: the policy switches are those of the startup version (redaction switches unchanged).
  if (version) warnings.push(...version.warnings)
  const base = version?.base
  const features: Features = base
    ? { ...parsed, dangerousCommands: base.policy.dangerousCommands, sensitiveFiles: base.policy.sensitiveFiles, decisionModel: base.decisionModel, scripts: base.scripts }
    : parsed
  // Without layers: switched on by the system configuration when it declares the plugin, otherwise by the global file
  // (absent: on).
  const modelGrants = base ? base.modelGrants : modelUndeclared === undefined && (systemSwitch(loaded()) ?? modelSwitchedOn(entryOf(loaded(), "global") ?? {}))
  const modelWithheld = modelGrants
    ? undefined
    : (modelUndeclared ?? `the ${systemSwitch(loaded()) === false ? "system" : "global"} configuration turns it off (decisionModel or profile), and this project is not trusted`)

  return {
    config: {
      decision,
      thresholds,
      features,
      profile: version?.profile ?? profile,
      policy: base?.policy ?? rulePolicy({ ...features, localAsksByModel, selfProtectionByModel }, overrides),
      redactPrompt: features.redactPrompt,
      debug: bool(options.debug, false, "debug", warnings),
      askAs: askAsOption(options.askAs, warnings),
      logFile: logFileOption(options.logFile, env, warnings),
      maxStateChars,
      cacheTtlMs: num(options.cacheTtlMs, 600_000, "cacheTtlMs", warnings, 0, MAX_CACHE_TTL_MS),
      cacheMax: num(options.cacheMax, 500, "cacheMax", warnings, 0, MAX_CACHE_ENTRIES),
      secretPatterns,
      allowlist: allowlistOption(options.allowlist, warnings),
      rules,
      unprotectedAgent: unprotectedAgentOption(options.unprotectedAgent, warnings),
      outputCheck: outputCheckOption(options.outputCheck, warnings),
      ...(layers ? { layers } : {}),
      ...(version ? { version } : {}),
      modelGrants,
      ...(modelWithheld === undefined ? {} : { modelWithheld }),
    },
    warnings,
  }
}

// Settings by agent and by project (`guard.json`, `agents`, `projects`, `trustedProjects`). Two layers: the global one
// (global file < global guard.json < `projects` sections matching the session directory, then their sections of the
// main agent and of the subagent) and the project one (what the effective options change from the global file < the
// project guard.json files, then their sections), laid over it key by key: for a project that is not trusted, a key
// that would make any finding less severe is dropped with a warning, whatever its source in the project layer.

/** Policy settings: the only ones a guard.json file, an `agents` section or a `projects` section accepts. */
export const POLICY_KEYS = ["profile", "ruleOverrides", "localAsks", "selfProtectionByModel", "dangerousCommands", "sensitiveFiles", "scripts", "decisionModel"]
const POLICY_SWITCHES = ["dangerousCommands", "sensitiveFiles", "scripts", "decisionModel"] as const
type PolicySwitch = (typeof POLICY_SWITCHES)[number]
/** Read only from the global sources (global file, system file, global guard.json): a project cannot trust itself. */
const GLOBAL_ONLY_KEYS = ["trustedProjects", "projects"]

/** Settings of one call: rule policy, decision model, checks of scripts written then run. */
export interface Scope {
  readonly policy: ActiveRules
  readonly decisionModel: boolean
  readonly scripts: boolean
  /** The decision model may allow an ask (`GuardConfig.modelGrants`). */
  readonly modelGrants: boolean
}

/** A guard.json file present (`guard-file.ts`): its content, or why it is ignored as a whole. */
export interface GuardFile {
  readonly label: string
  readonly global: boolean
  /** Project file: the directory holding its `.opencode` (its own trust decides whether it may relax). */
  readonly dir?: string
  readonly data?: Readonly<Record<string, unknown>>
  readonly reason?: string
}

/** Inputs of `parseConfig` for these settings (`setupGuard`). */
export interface ScopeInputs {
  readonly files: readonly GuardFile[]
  /** Real path of the session directory, read once at startup; unknown: no `projects` section matches, not trusted. */
  readonly project?: string
  /** Real path of a listed directory; missing or unreadable: `undefined`. */
  readonly realPath: (path: string) => string | undefined
  /** Origin shown for the keys of the effective options (`guard show`); absent: plugin options. */
  readonly origin?: string
}

/** What a source or a section sets: `rule:<id>` (`none`: setting removed), `localAsks`, `selfProtectionByModel`, a switch. */
type Entries = ReadonlyMap<string, string | boolean>
interface Section {
  readonly entries: Entries
  readonly profile?: Profile
  /** Source and section, for `guard show`. */
  readonly label: string
}
interface ProjectSection {
  readonly dir: string
  readonly label: string
  readonly top: Section
  readonly agents: ReadonlyMap<string, Section>
}
/** Global file, system file or guard.json: top level, `agents` sections, and for a global source `projects` and `trustedProjects`. */
interface Source {
  readonly label: string
  readonly top: Section
  readonly agents: ReadonlyMap<string, Section>
  readonly projects: readonly ProjectSection[]
  readonly trusted: readonly string[]
}

/**
 * One key of the project layer; `certify`: why a global source does not declare it (`undefined`: it does); `free`: never
 * checked; `trusted`: its source is in a trusted directory.
 */
interface Op {
  readonly key: string
  readonly value: string | boolean
  readonly text: string
  readonly label?: string
  readonly certify?: () => string | undefined
  readonly free?: boolean
  readonly trusted?: boolean
}

/** What the effective options change from the global file; the profile and switches need the version's trust. */
interface EffectiveChanges {
  readonly profile: Profile
  readonly globalProfile: Profile
  readonly certifyProfile: () => string | undefined
  readonly switches: Partial<Record<PolicySwitch, boolean>>
  readonly globalSwitches: Partial<Record<PolicySwitch, boolean>>
  readonly ops: readonly Op[]
  readonly agents: ReadonlyMap<string, readonly Op[]>
  /** Origin of their keys (`ScopeInputs.origin`). */
  readonly label?: string
}

/** Inputs of the layered resolution that stay the same while the plugin runs. */
export interface Layers {
  readonly rules: readonly CustomRule[]
  readonly globalFile: Source
  readonly systemFile: Source
  readonly effective: EffectiveChanges
  readonly project?: string
  readonly realPath: (path: string) => string | undefined
  /** `agents`, `projects` or `trustedProjects` in the effective options or the global or system file. */
  readonly keyed: boolean
  /** Why the effective decision model's address or model is not one a global source declares; absent: it is. */
  readonly modelUndeclared?: string
  /** The system configuration's switch of the model, when it declares the plugin: it decides over the global stack. */
  readonly systemModel?: boolean
}

/** Resolved settings of one version (startup, then each change of a guard.json file). */
export interface Version {
  readonly base: Scope
  /** Main agent and subagent whose sections count, agent of the call whose sections only harden (not the recorded one). */
  scope(main: string | undefined, sub: string | undefined, call: string | undefined): Scope
  /** Agents with a section in some source. */
  readonly agents: ReadonlySet<string>
  /** Some scope checks scripts: the files written are tracked. */
  readonly tracking: boolean
  readonly profile: Profile
  readonly trusted: boolean
  readonly warnings: readonly string[]
  /** Sources, sections and trust, for the log. */
  readonly summary: string
  /** Trusted directories listed by the global sources (real paths, or `*`); `resolveVersion` only. */
  readonly listed?: readonly string[]
  /** Policy settings in force for a main agent (none: the top level), with the source and section that set each one. */
  settings?(main: string | undefined): ReadonlyArray<{ readonly key: string; readonly value: string | boolean; readonly origin: string }>
}

interface PolicyState {
  readonly switches: Readonly<Record<PolicySwitch, boolean>>
  readonly overrides: ReadonlyMap<string, RuleOverride>
  readonly localAsksByModel: boolean
  readonly selfProtectionByModel: boolean
  /** Key → source and section that set its value (`guard show`); absent: default. */
  readonly origins: ReadonlyMap<string, string>
}
const DEFAULT_STATE: PolicyState = {
  switches: { dangerousCommands: true, sensitiveFiles: true, scripts: true, decisionModel: true },
  overrides: new Map(),
  localAsksByModel: false,
  selfProtectionByModel: false,
  origins: new Map(),
}
/** Origin of a key of the effective options (project layer). */
const PLUGIN_OPTIONS = "plugin options"
/** Scopes kept per version (main agent, subagent, agent of the call). */
const MAX_SCOPES = 256

/** Boolean read like `bool`, without a default: `undefined` not set, `null` invalid. */
function flag(value: unknown): boolean | undefined | null {
  if (isEmpty(value)) return undefined
  if (typeof value === "boolean") return value
  const raw = text(value).toLowerCase()
  return raw === "true" || raw === "1" ? true : raw === "false" || raw === "0" ? false : null
}

function applied(state: PolicyState, key: string, value: string | boolean, origin?: string): PolicyState {
  const origins = new Map(state.origins)
  if (origin === undefined || value === "none") origins.delete(key)
  else origins.set(key, origin)
  if (key.startsWith("rule:")) {
    const overrides = new Map(state.overrides)
    if (value === "none") overrides.delete(key.slice(5))
    else overrides.set(key.slice(5), value as RuleOverride)
    return { ...state, overrides, origins }
  }
  if (key === "localAsks") return { ...state, localAsksByModel: value === "model", origins }
  if (key === "selfProtectionByModel") return { ...state, selfProtectionByModel: value === true, origins }
  return { ...state, switches: { ...state.switches, [key]: value === true }, origins }
}

const scopeOf = (state: PolicyState, modelGrants = false): Scope => ({
  policy: rulePolicy(
    { dangerousCommands: state.switches.dangerousCommands, sensitiveFiles: state.switches.sensitiveFiles, localAsksByModel: state.localAsksByModel, selfProtectionByModel: state.selfProtectionByModel },
    state.overrides,
  ),
  decisionModel: state.switches.decisionModel,
  scripts: state.switches.scripts,
  modelGrants,
})

/**
 * Outcome of every finding a setting can change, from the real policy functions: an ask and a deny of each built-in
 * rule (3 deny, 2 ask, 1 left to the decision model, 0 nothing), a call no rule matches (1 judged by the model, 0
 * allowed) and the scripts run (1 checked, 0 not).
 */
function outcomes(state: PolicyState): number[] {
  const { policy, decisionModel, scripts } = scopeOf(state)
  const result: number[] = []
  for (const rule of RULE_FEATURES.keys())
    for (const verdict of ["ask", "deny"] as const) {
      if (!ruleEnabled(rule, policy)) {
        result.push(0)
        continue
      }
      const finding: Finding = overridden({ verdict, rule, reason: "" } as Finding, policy)
      result.push(finding.verdict === "deny" ? 3 : entrusted(finding, policy).modelDecides !== undefined && decisionModel ? 1 : 2)
    }
  result.push(decisionModel ? 1 : 0, scripts ? 1 : 0)
  return result
}

/** Rules, then `localAsks` and `selfProtectionByModel`, then the switches, `decisionModel` last (it may hand asks to the model). */
const rank = (key: string) => (key.startsWith("rule:") ? 0 : key === "localAsks" ? 1 : key === "selfProtectionByModel" ? 2 : 3 + POLICY_SWITCHES.indexOf(key as PolicySwitch))

/** Project layer laid over `state`: its last value of each key; unless trusted, free or certified, a key that relaxes is dropped. */
function laid(state: PolicyState, ops: readonly Op[], warn?: (line: string) => void): PolicyState {
  const last = new Map<string, Op>()
  for (const op of ops) {
    last.delete(op.key)
    last.set(op.key, op)
  }
  let before = outcomes(state)
  for (const op of [...last.values()].sort((a, b) => rank(a.key) - rank(b.key))) {
    const candidate = applied(state, op.key, op.value, op.label ?? PLUGIN_OPTIONS)
    const after = outcomes(candidate)
    const why = op.trusted || op.free || after.every((value, index) => value >= before[index]!) ? undefined : op.certify ? op.certify() : "project"
    if (why === undefined) {
      state = candidate
      before = after
    } else
      warn?.(
        why === "project"
          ? `${op.label}: ${op.text} ignored: its directory is not trusted, so its settings can only harden (trustedProjects, in the global configuration)`
          : `${op.text} ignored: ${why}`,
      )
  }
  return state
}

const stacked = (state: PolicyState, section: Section) => [...section.entries].reduce((acc, [key, value]) => applied(acc, key, value, section.label), state)

function described(key: string, value: string | boolean): string {
  if (key.startsWith("rule:")) return value === "none" ? `ruleOverrides.${key.slice(5)} unset` : `ruleOverrides.${key.slice(5)} "${value}"`
  if (key === "localAsks") return `localAsks "${value}"`
  if (key === "selfProtectionByModel") return value ? "selfProtectionByModel" : "selfProtectionByModel false"
  return `${key} ${value}`
}

const opsOf = (section: Section | undefined, label: string, trusted = false): Op[] =>
  section ? [...section.entries].map(([key, value]) => ({ key, value, label, text: described(key, value), trusted })) : []

/** Policy settings of a source or a section; the profile sets the switches the same object leaves unset. */
function readSection(value: Readonly<Record<string, unknown>>, where: string, rules: readonly CustomRule[], warnings: string[], accepted: readonly string[]): Section {
  const local: string[] = []
  for (const key of Object.keys(value))
    if (accepted.includes(key)) continue
    else if (GLOBAL_ONLY_KEYS.includes(key)) local.push(`${key} ignored: it counts only in the global configuration (global opencode.json, system configuration, global guard.json)`)
    else if (OPTION_KEYS.includes(key)) local.push(`${key} ignored: only the plugin options in opencode.json accept it`)
    else local.push(`unknown option ${key}, ignored`)
  const entries = new Map<string, string | boolean>()
  for (const [rule, setting] of ruleOverridesOption(value.ruleOverrides, rules, local)) entries.set(`rule:${rule}`, setting)
  const asks = localAsksValue(value.localAsks)
  if (asks === null) local.push(`invalid value for localAsks (${shown(value.localAsks)}), ignored`)
  else if (asks) entries.set("localAsks", asks)
  for (const name of ["selfProtectionByModel", ...POLICY_SWITCHES]) {
    const set = flag(value[name])
    if (set === null) local.push(`invalid value for ${name} (${shown(value[name])}), ignored`)
    else if (set !== undefined) entries.set(name, set)
  }
  const profile = profileValue(value.profile)
  if (profile === null) local.push(`invalid value for profile (${shown(value.profile)}), ignored`)
  else if (profile) for (const name of CREDENTIALS_ONLY_OFF) if (!entries.has(name)) entries.set(name, profile === "standard")
  warnings.push(...local.map((line) => `${where}: ${line}`))
  return { entries, ...(profile ? { profile } : {}), label: where }
}

/** `agents` sections: agent name → policy settings. */
function readAgents(value: unknown, where: string, rules: readonly CustomRule[], warnings: string[]): Map<string, Section> {
  const agents = new Map<string, Section>()
  if (value === undefined) return agents
  if (!isRecord(value)) {
    warnings.push(`${where}: agents must be an object (agent name: settings), ignored`)
    return agents
  }
  for (const [name, section] of Object.entries(value))
    if (!isRecord(section)) warnings.push(`${where}: agents[${JSON.stringify(name)}] must be an object, ignored`)
    else agents.set(name, readSection(section, `${where}, agents.${name}`, rules, warnings, POLICY_KEYS))
  return agents
}

/** Global source or guard.json; `report`: warnings of the top level and `agents` (the global file's repeat the effective options'). */
function readSource(data: Readonly<Record<string, unknown>>, label: string, global: boolean, rules: readonly CustomRule[], warnings: string[], report = true): Source {
  const local = report ? warnings : []
  const top = readSection(data, label, rules, local, [...POLICY_KEYS, "agents", ...(global ? GLOBAL_ONLY_KEYS : [])])
  const agents = readAgents(data.agents, label, rules, local)
  const projects: ProjectSection[] = []
  const trusted: string[] = []
  if (global && data.projects !== undefined) {
    if (!isRecord(data.projects)) warnings.push(`${label}: projects must be an object (absolute directory: settings), ignored`)
    else
      for (const [dir, section] of Object.entries(data.projects)) {
        const where = `${label}, projects[${JSON.stringify(dir)}]`
        if (!dir.startsWith("/")) warnings.push(`${where} ignored: the directory must be an absolute path`)
        else if (!isRecord(section)) warnings.push(`${where} ignored: it must be an object`)
        else projects.push({ dir, label: where, top: readSection(section, where, rules, warnings, [...POLICY_KEYS, "agents"]), agents: readAgents(section.agents, where, rules, warnings) })
      }
  }
  if (global && data.trustedProjects !== undefined) {
    const list = data.trustedProjects === "*" ? ["*"] : data.trustedProjects
    if (!Array.isArray(list)) warnings.push(`${label}: trustedProjects must be "*" or an array of absolute directories, ignored`)
    else
      list.forEach((entry, index) => {
        if (entry === "*" || (typeof entry === "string" && entry.startsWith("/"))) trusted.push(entry)
        else warnings.push(`${label}: trustedProjects[${index}] ignored: "*" or an absolute directory expected`)
      })
  }
  return { label, top, agents, projects, trusted }
}

/** Same directory or below (real paths). */
const within = (project: string, dir: string) => project === dir || project.startsWith(dir.endsWith("/") ? dir : `${dir}/`)

/** Static inputs: global and system files, what the effective options change from the global file (B rule kept for it). */
function scopeLayers(
  options: Options,
  parsed: {
    readonly rules: readonly CustomRule[]
    readonly overrides: ReadonlyMap<string, RuleOverride>
    readonly profile: Profile
    readonly refusal: (matches: (options: Readonly<Record<string, unknown>>) => boolean) => string | undefined
    readonly declarations: readonly PluginDeclaration[] | string
    readonly modelUndeclared: string | undefined
  },
  inputs: ScopeInputs,
  warnings: string[],
): Layers {
  const { rules, refusal } = parsed
  const label = inputs.origin === undefined ? {} : { label: inputs.origin }
  const optionsOf = (label: string) => entryOf(parsed.declarations, label) ?? {}
  const [globalOptions, systemOptions] = [optionsOf("global"), optionsOf("system")]
  const globalFile = readSource(globalOptions, "global configuration", true, rules, warnings, false)
  const systemFile = readSource(systemOptions, "system configuration", true, rules, warnings, false)
  for (const key of GLOBAL_ONLY_KEYS)
    if (options[key] !== undefined && ![globalOptions, systemOptions].some((source) => JSON.stringify(source[key]) === JSON.stringify(options[key])))
      warnings.push(`${key} ignored: it counts only in the global configuration (global opencode.json, system configuration, global guard.json)`)
  // Top level: absent = default; a key set by the effective options but not by the global file changes it too.
  const ops: Op[] = []
  const globalRules = new Map([...globalFile.top.entries].filter(([key]) => key.startsWith("rule:")))
  const written = isRecord(options.ruleOverrides) ? options.ruleOverrides : {}
  for (const rule of new Set([...parsed.overrides.keys(), ...[...globalRules.keys()].map((key) => key.slice(5))])) {
    const value = parsed.overrides.get(rule) ?? "none"
    if (value === (globalRules.get(`rule:${rule}`) ?? "none")) continue
    const matches = (declaration: Readonly<Record<string, unknown>>) => ((isRecord(declaration.ruleOverrides) && overrideValue(declaration.ruleOverrides[rule])) || "none") === value
    ops.push({ key: `rule:${rule}`, value, text: value === "none" ? `ruleOverrides.${rule} unset` : `ruleOverrides.${rule} "${writtenOverride(written[rule])}"`, certify: () => refusal(matches), ...label })
  }
  const asks = localAsksValue(options.localAsks) || "ask"
  if (asks !== (globalFile.top.entries.get("localAsks") ?? "ask") || (localAsksValue(options.localAsks) && !globalFile.top.entries.has("localAsks")))
    ops.push({ key: "localAsks", value: asks, text: `localAsks "${asks}"`, certify: () => refusal((declaration) => (localAsksValue(declaration.localAsks) || "ask") === asks), ...label })
  const byModel = flag(options.selfProtectionByModel) === true
  if (byModel !== (globalFile.top.entries.get("selfProtectionByModel") ?? false) || (typeof flag(options.selfProtectionByModel) === "boolean" && !globalFile.top.entries.has("selfProtectionByModel")))
    ops.push({ key: "selfProtectionByModel", value: byModel, text: described("selfProtectionByModel", byModel), certify: () => refusal((declaration) => (flag(declaration.selfProtectionByModel) === true) === byModel), ...label })
  const explicit = (source: Readonly<Record<string, unknown>>) =>
    Object.fromEntries(POLICY_SWITCHES.flatMap((name) => (typeof flag(source[name]) === "boolean" ? [[name, flag(source[name])]] : []))) as Partial<Record<PolicySwitch, boolean>>
  // `agents` sections: only what differs from the global file's (a section left out keeps the global file's).
  const effectiveAgents = readAgents(options.agents, "agents", rules, warnings)
  const agents = new Map<string, readonly Op[]>()
  for (const [name, section] of effectiveAgents) {
    const global = globalFile.agents.get(name)?.entries
    const changed = [...section.entries].filter(([key, value]) => global?.get(key) !== value)
    const declares = (declaration: Readonly<Record<string, unknown>>, key: string, value: string | boolean) =>
      readAgents(declaration.agents, "", rules, []).get(name)?.entries.get(key) === value
    if (changed.length)
      agents.set(
        name,
        changed.map(([key, value]) => ({ key, value, text: `agents.${name} ${described(key, value)}`, certify: () => refusal((declaration) => declares(declaration, key, value)), ...label })),
      )
  }
  return {
    rules,
    globalFile,
    systemFile,
    effective: {
      profile: parsed.profile,
      globalProfile: profileValue(globalOptions.profile) || "standard",
      certifyProfile: () => refusal((declaration) => profileValue(declaration.profile) === "credentials-only"),
      switches: explicit(options),
      globalSwitches: explicit(globalOptions),
      ops,
      agents,
      ...label,
    },
    ...(inputs.project ? { project: inputs.project } : {}),
    realPath: inputs.realPath,
    keyed: [options, globalOptions, systemOptions].some((source) => ["agents", ...GLOBAL_ONLY_KEYS].some((key) => source[key] !== undefined)),
    ...(parsed.modelUndeclared === undefined ? {} : { modelUndeclared: parsed.modelUndeclared }),
    ...(systemSwitch(parsed.declarations) === undefined ? {} : { systemModel: systemSwitch(parsed.declarations) }),
  }
}

/** Resolves the settings for the guard.json files present: never throws on their content (each problem is a warning). */
export function resolveVersion(layers: Layers, files: readonly GuardFile[]): Version {
  const warnings: string[] = []
  const sources = files.flatMap((file) => {
    if (file.data) return [{ file, source: readSource(file.data, file.label, file.global, layers.rules, warnings) }]
    warnings.push(`${file.label} ignored: ${file.reason ?? "it cannot be read"}`)
    return []
  })
  const globalGuards = sources.filter((item) => item.file.global).map((item) => item.source)
  const globalSources = [layers.globalFile, layers.systemFile, ...globalGuards]
  const { project, realPath } = layers
  const real = (dir: string, where: string) => {
    const path = realPath(dir)
    if (path === undefined) warnings.push(`${where}: ${JSON.stringify(dir)} does not exist, ignored`)
    return path
  }
  // Trusted directories (real paths): the session directory, and each project guard.json's own directory (a file in a
  // `.opencode` above the trusted directory, `/tmp` or the home directory for instance, only hardens).
  const listed = globalSources.flatMap((source) => source.trusted.flatMap((dir) => (dir === "*" ? [dir] : (real(dir, `${source.label}, trustedProjects`) ?? []))))
  const isTrusted = (path: string | undefined) => path !== undefined && listed.some((dir) => dir === "*" || within(path, dir))
  const trusted = isTrusted(project)
  const projectGuards = sources
    .filter((item) => !item.file.global)
    .map((item) => ({ ...item.source, trusted: item.file.dir !== undefined && isTrusted(realPath(item.file.dir)) }))
  // Matching `projects` sections, the outermost directory first (the closest one wins).
  const matched = globalSources
    .flatMap((source) => source.projects)
    .flatMap((section) => {
      const path = real(section.dir, section.label)
      return path !== undefined && project !== undefined && within(project, path) ? [{ section, depth: path.split("/").length }] : []
    })
    .sort((a, b) => a.depth - b.depth)
    .map((item) => item.section)
  const globalTops = [layers.globalFile.top, ...globalGuards.map((source) => source.top), ...matched.map((section) => section.top)]
  const withAgents = [layers.globalFile, ...globalGuards, ...matched]
  // The effective options' profile and switches: the profile is a relaxation counted like the others.
  const { effective } = layers
  let profile = effective.profile
  if (profile === "credentials-only" && effective.globalProfile !== profile && !trusted) {
    const why = effective.certifyProfile()
    if (why) {
      warnings.push(`profile "credentials-only" ignored: ${why}`)
      profile = "standard"
    }
  }
  const switchOf = (explicit: Partial<Record<PolicySwitch, boolean>>, of: Profile, name: PolicySwitch) =>
    explicit[name] ?? !(of === "credentials-only" && CREDENTIALS_ONLY_OFF.has(name))
  // Switches of the effective options: accepted as before, whatever the project's trust.
  const switchOps: Op[] = POLICY_SWITCHES.flatMap((name) => {
    const value = switchOf(effective.switches, profile, name)
    const changed = value !== switchOf(effective.globalSwitches, effective.globalProfile, name) || (name in effective.switches && !(name in effective.globalSwitches))
    return changed ? [{ key: name, value, text: `${name} ${value}`, free: true, ...(effective.label === undefined ? {} : { label: effective.label }) }] : []
  })
  // The effective options' keys take the session directory's trust (their `.opencode` cannot be told apart).
  const topOps = [
    ...switchOps,
    ...effective.ops.map((op) => ({ ...op, trusted })),
    ...projectGuards.flatMap((source) => opsOf(source.top, source.label, source.trusted)),
  ]
  const projectSectionOps = (agent: string) => [
    ...(effective.agents.get(agent) ?? []).map((op) => ({ ...op, trusted })),
    ...projectGuards.flatMap((source) => opsOf(source.agents.get(agent), `${source.label}, agents.${agent}`, source.trusted)),
  ]
  const globalSections = (agent: string | undefined) => (agent === undefined ? [] : withAgents.flatMap((source) => source.agents.get(agent) ?? []))
  const globalState = (main: string | undefined, sub: string | undefined) => [...globalTops, ...globalSections(main), ...globalSections(sub)].reduce(stacked, DEFAULT_STATE)
  // The model allows an ask with the global sources' configuration (declared by one of them, switched on by the system
  // configuration when it declares the plugin, loaded last, otherwise by the global stack), or in a trusted project.
  const grants = (main: string | undefined, sub: string | undefined) =>
    trusted || (layers.modelUndeclared === undefined && (layers.systemModel ?? globalState(main, sub).switches.decisionModel))
  const stateFor = (main: string | undefined, sub: string | undefined, call: string | undefined, warn?: (line: string) => void) => {
    let state = globalState(main, sub)
    const ops = [...topOps, ...(main === undefined ? [] : projectSectionOps(main)), ...(sub === undefined ? [] : projectSectionOps(sub))]
    state = laid(state, ops, warn)
    // Agent of the call that is not the recorded one: every source's sections, hardenings only.
    if (call !== undefined)
      state = laid(
        state,
        [...withAgents.flatMap((source) => opsOf(source.agents.get(call), source.label)), ...projectSectionOps(call)].map(({ key, value, text, label }) => ({ key, value, text, ...(label ? { label } : {}) })),
      )
    // Like the top level of the options: "model" on an always-active rule needs selfProtectionByModel.
    for (const [rule, setting] of state.overrides)
      if (setting === "model" && RULE_FEATURES.get(rule) === "always" && !state.selfProtectionByModel) {
        warn?.(`ruleOverrides.${rule} "model" ignored: this rule is always active ("model" needs selfProtectionByModel)`)
        state = applied(state, `rule:${rule}`, "none")
      }
    return state
  }
  const base = scopeOf(stateFor(undefined, undefined, undefined, (line) => warnings.push(line)), grants(undefined, undefined))
  const agents = new Set([
    ...withAgents.flatMap((source) => [...source.agents.keys()]),
    ...effective.agents.keys(),
    ...projectGuards.flatMap((source) => [...source.agents.keys()]),
  ])
  const scopes = new Map<string, Scope>()
  const scope = (main: string | undefined, sub: string | undefined, call: string | undefined, warn?: (line: string) => void): Scope => {
    if (agents.size === 0) return base
    const key = JSON.stringify([main, sub, call])
    let found = scopes.get(key)
    if (!found) {
      found = scopeOf(stateFor(main, sub, call, warn), grants(main, sub))
      if (scopes.size >= MAX_SCOPES) scopes.delete(scopes.keys().next().value!)
      scopes.set(key, found)
    }
    return found
  }
  // Each agent's section as the main agent, once: its dropped relaxations are reported with the version.
  for (const agent of agents) scope(agent, undefined, undefined, (line) => warnings.push(line))
  const sections = [...withAgents, ...projectGuards].flatMap((source) => [...source.agents.values()])
  // Profile shown in the start line: the last one that counts at the top level.
  let shownProfile: Profile = globalTops.reduce<Profile>((last, section) => section.profile ?? last, "standard")
  if (profile !== effective.globalProfile) shownProfile = profile
  for (const source of projectGuards) if (source.top.profile === "standard" || (source.top.profile && source.trusted)) shownProfile = source.top.profile
  const read = sources.map((item) => item.source.label)
  return {
    base,
    scope: (main, sub, call) => scope(main, sub, call),
    agents,
    tracking: base.scripts || [...effective.agents.values()].flat().some((op) => op.key === "scripts" && op.value === true) || sections.some((section) => section.entries.get("scripts") === true),
    profile: shownProfile,
    trusted,
    warnings: [...new Set(warnings)],
    listed,
    settings(main) {
      const state = stateFor(main, undefined, undefined)
      const value = (key: string, current: string | boolean) => ({ key: key.startsWith("rule:") ? `ruleOverrides.${key.slice(5)}` : key, value: current, origin: state.origins.get(key) ?? "default" })
      return [
        ...POLICY_SWITCHES.map((name) => value(name, state.switches[name])),
        value("localAsks", state.localAsksByModel ? "model" : "ask"),
        value("selfProtectionByModel", state.selfProtectionByModel),
        ...[...RULE_FEATURES.keys()].flatMap((rule) => (state.overrides.has(rule) ? [value(`rule:${rule}`, state.overrides.get(rule)!)] : [])),
      ]
    },
    summary: `guard.json: ${read.length ? read.join(", ") : "none"}; agent sections: ${agents.size ? [...agents].join(", ") : "none"}; project sections: ${matched.length ? matched.map((section) => section.dir).join(", ") : "none"}; this project: ${trusted ? "trusted" : "not trusted"}`,
  }
}
