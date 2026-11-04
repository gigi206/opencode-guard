// `guard options`: every option of the plugin with its type, the value in force, its default and where it comes from;
// `--explain` adds what it does and what it accepts. Defaults are never written here: they come from `parseConfig` given no
// option, and the value in force from the same reading as the plugin, so that neither can drift from the code. The text of an
// entry (type, range, values) is checked against `parseConfig` by `test/cli-options.test.ts`. A secret is never printed:
// such an entry has a `shown` that gives only its state. Options merged from a project's opencode.json are not seen.
import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { DEFAULT_DECISION, DEFAULT_OUTPUT_CHECK, DEFAULT_PROMPT_TUNING, parseConfig, resolveVersion, type GuardConfig } from "../config.ts"
import { guardPaths, readGuardFiles } from "../guard-file.ts"
import { isRegularFile } from "../real-path.ts"
import { CliError, readSources, realOrUndefined, type CliIo, type Pretty } from "./context.ts"
import { heading, rowLines, title } from "./pretty.ts"
import { configurationFile } from "./show.ts"
import type { Style } from "./style.ts"

export interface OptionEntry {
  readonly name: string
  readonly type: string
  /** Bounds a number must keep; beyond them the default stays. */
  readonly range?: readonly [number, number]
  /** Closed list of values, with their meaning. */
  readonly values?: ReadonlyArray<readonly [string, string]>
  readonly what: string
  readonly where: string
  /** When a value that loosens a protection counts. */
  readonly relaxing?: string
  readonly read: (config: GuardConfig) => unknown
  /** Instead of the value: a secret, or a list too long for a row. */
  readonly shown?: (value: unknown) => string
}

const PLUGIN = "plugin options (opencode.json)"
const POLICY = "plugin options, guard.json, or an agent or project section of it"
const SWITCH_RELAX = "false counts only if the global or system configuration sets it too; a project may only set it to true"
const SAME_VALUE = "kept only if the global or system configuration sets the same value; otherwise the default"
const count = (noun: string) => (value: unknown) => {
  const size = Array.isArray(value) ? value.length : value instanceof Map ? value.size : value !== null && typeof value === "object" ? Object.keys(value).length : 0
  return size ? `${size} ${noun}${size === 1 ? "" : "s"}` : "none"
}
const isSet = (value: unknown) => (value === undefined ? "not set" : "set")
const customized = (value: unknown) => (value ? "custom" : "default")
const feature = (name: keyof GuardConfig["features"], what: string, policy: boolean): OptionEntry => ({
  name,
  type: "boolean",
  what,
  where: policy ? POLICY : PLUGIN,
  relaxing: SWITCH_RELAX,
  read: (config) => config.features[name],
})
const threshold = (name: keyof GuardConfig["thresholds"], max: number, what: string): OptionEntry => ({
  name: `thresholds.${name}`,
  type: "number",
  range: [0, max],
  what,
  where: PLUGIN,
  read: (config) => config.thresholds[name],
})

/** Settings of the output and prompt checks (`docs/decision-model.md`); the keys are checked against the defaults. */
const TUNING: Readonly<Record<string, { readonly type: string; readonly range: readonly [number, number]; readonly what: string }>> = {
  partChars: { type: "integer", range: [200, 20_000], what: "Characters per part sent to the model." },
  candidates: { type: "integer", range: [1, 10], what: "Stage 2: at most this many words, each checked by stage 3." },
  minCandidate: { type: "number", range: [0, 1], what: "Stage 2: smallest probability of a candidate." },
  verify: { type: "number", range: [0, 1], what: "Stage 3: probability from which a word is masked." },
  askScore: { type: "number", range: [0, 2], what: "Stage 1 probability from which a part with no confirmed word asks (prompts) or is masked whole (outputs); above 1: never." },
  rounds: { type: "integer", range: [1, 10], what: "Stage 2 and stage 1 again, to find a second secret, at most this many times." },
  wordsPerQuestion: { type: "integer", range: [2, 50], what: "Words offered in one stage 2 question." },
  minWord: { type: "integer", range: [1, 20], what: "Shortest word offered." },
  parallel: { type: "integer", range: [1, 16], what: "Simultaneous calls of the check." },
  maxChars: { type: "integer", range: [1000, 1_000_000], what: "Longer prompts are not checked: confirmation." },
  deadlineCalls: { type: "integer", range: [1, 20], what: "The whole prompt check takes at most this many times decision.timeoutMs." },
}
const tuning = (check: "outputCheck" | "promptCheck", keys: readonly string[]): OptionEntry[] =>
  keys.map((key) => ({
    name: `${check}.${key}`,
    ...TUNING[key]!,
    where: PLUGIN,
    relaxing: SAME_VALUE,
    read: (config) => (config[check]?.tuning as unknown as Record<string, number> | undefined)?.[key],
  }))

export const OPTIONS: readonly OptionEntry[] = [
  { name: "askAs", type: "string", values: [["ask", "confirmations are asked"], ["deny", "every confirmation becomes a refusal (unattended mode)"]], what: "What a confirmation request becomes. Case does not matter; empty means ask.", where: PLUGIN, read: (config) => config.askAs },
  { name: "decision.baseURL", type: "string (URL)", what: "Versioned address of the decision model, without the final path. Missing or invalid: the model is disabled, only the local rules apply.", where: PLUGIN, read: (config) => config.decision?.baseURL },
  { name: "decision.protocol", type: "string", values: [["chat", "OpenAI-compatible gateway"], ["systemone", "direct System One API"]], what: "Protocol of the decision model.", where: PLUGIN, read: (config) => config.decision?.protocol },
  { name: "decision.model", type: "string", what: "Model name. Missing or empty: the decision model is disabled.", where: PLUGIN, read: (config) => config.decision?.model },
  { name: "decision.apiKey", type: "string", what: "Key sent as a Bearer header, normally a reference such as {env:NAME}. Never printed.", where: PLUGIN, read: (config) => config.decision?.apiKey, shown: isSet },
  { name: "decision.timeoutMs", type: "integer", range: [100, 60_000], what: "Timeout per call, in ms. A call that times out is retried once.", where: PLUGIN, read: (config) => config.decision?.timeoutMs },
  { name: "decision.headers", type: "object", what: "Extra HTTP headers. Values are never printed.", where: PLUGIN, read: (config) => config.decision?.headers, shown: count("header") },
  { name: "jev", type: "object", what: "Former name of decision, same settings. If both are set, decision is used.", where: PLUGIN, read: () => undefined, shown: isSet },
  threshold("denyNoul", 1, "Deny when a probability reaches this."),
  threshold("askNoul", 1, "Ask when a probability reaches this."),
  threshold("askExfiltration", 1, "Ask when the exfiltration probability reaches this; never below askNoul."),
  threshold("denyRisk", 3, "Deny when the risk (0 to 3) reaches this."),
  threshold("askRisk", 3, "Ask when the risk (0 to 3) reaches this."),
  threshold("minConfidence", 1, "Ask when the confidence is below this; 0 disables it."),
  feature("dangerousCommands", "Built-in local rules for dangerous actions.", true),
  feature("sensitiveFiles", "Built-in local rules for credential files and outgoing secrets.", true),
  feature("decisionModel", "Calls to the decision model; its decision settings are kept.", true),
  feature("scripts", "Checks of scripts written then run.", true),
  feature("redactOutputs", "Redaction of tool results and errors at the source.", false),
  feature("redactWire", "The safety net on model requests.", false),
  { name: "redactPrompt", type: "boolean", what: "Redaction of the typed prompt; the redacted text is what gets stored.", where: PLUGIN, relaxing: SWITCH_RELAX, read: (config) => config.redactPrompt },
  { name: "profile", type: "string", values: [["standard", "every feature on"], ["credentials-only", "dangerousCommands, decisionModel and scripts default to false"]], what: "A set of defaults for the feature switches.", where: POLICY, relaxing: "credentials-only counts only if the global or system configuration sets it too", read: (config) => config.profile },
  { name: "ruleOverrides", type: "object: rule → off | ask | deny | model", what: "One built-in rule set by its identifier (guard rules lists them); each one set appears on its own row.", where: POLICY, relaxing: "off, ask and model count only if the global or system configuration sets them too; deny counts from anywhere", read: (config) => config.policy.overrides, shown: count("rule") },
  { name: "exceptions", type: "object: rule → array of absolute paths", what: "Files whose confirmation by a rule is not asked, only for secret-file-read.", where: POLICY, relaxing: "a path counts only if a global source lists it, or in a trusted project", read: () => undefined, shown: () => "see rows below" },
  { name: "rememberConfirmations", type: "integer (minutes), 0 is off", range: [0, 60], what: "A set of credential files you confirmed is not asked again in the session during this delay.", where: POLICY, relaxing: "counts only from a global source, or in a trusted project", read: () => undefined },
  { name: "localAsks", type: "string", values: [["ask", "the confirmations of built-in rules stay with you"], ["model", "the decision model decides those without a setting"]], what: "Who decides the confirmations of built-in rules.", where: POLICY, relaxing: "model counts only if the global or system configuration sets it too", read: () => undefined },
  { name: "selfProtectionByModel", type: "boolean", what: "localAsks model and model in ruleOverrides also reach self-protection, except a change of the plugin's settings.", where: POLICY, relaxing: "true counts only if the global or system configuration sets it too", read: () => undefined },
  { name: "agents", type: "object: agent → settings", what: "Settings for one agent; guard agent writes them.", where: "plugin options or guard.json", relaxing: "only a global source relaxes an agent; a project only hardens", read: () => undefined, shown: count("agent") },
  { name: "projects", type: "object: directory → settings", what: "Settings for a project directory.", where: "global or system configuration, global guard.json", read: () => undefined, shown: count("project") },
  { name: "trustedProjects", type: "array of strings", what: "Projects whose own settings may relax.", where: "global or system configuration, global guard.json", read: () => undefined, shown: count("project") },
  { name: "debug", type: "boolean", what: "Also log allowed actions and redaction counts.", where: PLUGIN, read: (config) => config.debug },
  { name: "logFile", type: "string, or false for stderr only", what: "Plugin log file. A credential file or a protected location is refused.", where: PLUGIN, read: (config) => config.logFile },
  { name: "maxStateChars", type: "integer", range: [200, 100_000], what: "Maximum size of the redacted input sent to the decision model.", where: PLUGIN, read: (config) => config.maxStateChars },
  { name: "cacheTtlMs", type: "integer", range: [0, 3_600_000], what: "How long a verdict is cached, in ms.", where: PLUGIN, read: (config) => config.cacheTtlMs },
  { name: "cacheMax", type: "integer", range: [0, 10_000], what: "Maximum number of cached verdicts.", where: PLUGIN, read: (config) => config.cacheMax },
  { name: "unprotectedAgent", type: "string", what: "Agent for which the plugin does nothing (no rules, no model, no redaction). Built-in agents are refused.", where: PLUGIN, read: (config) => config.unprotectedAgent },
  { name: "rules", type: "array of objects", what: "Extra local rules; guard rules prints them.", where: "plugin options or global guard.json", read: (config) => config.rules, shown: count("rule") },
  { name: "secretPatterns", type: "array of objects or strings", what: "Extra secret patterns; guard redaction prints them.", where: PLUGIN, read: (config) => config.secretPatterns, shown: count("pattern") },
  { name: "redactionOff", type: "array of strings", what: "Built-in redaction formats turned off, by name.", where: "global or system configuration, global guard.json", read: (config) => config.disabledPatterns },
  { name: "allowlist", type: "array of strings", what: "Strings that are never redacted. Never printed.", where: PLUGIN, relaxing: "each entry counts only if a global source lists it", read: (config) => config.allowlist, shown: count("entry") },
  { name: "outputCheck", type: "boolean or object", values: [["true", "on, set explicitly"], ["false", "off"]], what: "Tool outputs checked by the decision model.", where: PLUGIN, relaxing: SAME_VALUE, read: (config) => config.outputCheck !== undefined },
  { name: "outputCheck.enabled", type: "boolean", what: "false turns the check off, inside the object form.", where: PLUGIN, read: (config) => config.outputCheck !== undefined },
  { name: "outputCheck.threshold", type: "number", range: [0, 1], what: "Stage 1: probability from which a part holds a secret.", where: PLUGIN, relaxing: SAME_VALUE, read: (config) => config.outputCheck?.threshold },
  { name: "outputCheck.timeoutMs", type: "integer", range: [100, 60_000], what: "Timeout of one call; a call that fails holds the output for a confirmation.", where: PLUGIN, relaxing: SAME_VALUE, read: (config) => config.outputCheck?.timeoutMs },
  { name: "outputCheck.skip", type: "array of strings", what: "Tools whose output is not checked; replaces the default list.", where: PLUGIN, relaxing: SAME_VALUE, read: (config) => config.outputCheck?.skip },
  { name: "outputCheck.questions", type: "object", what: "Questions asked to the model.", where: PLUGIN, relaxing: SAME_VALUE, read: (config) => config.outputCheck?.custom, shown: customized },
  ...tuning("outputCheck", Object.keys(DEFAULT_OUTPUT_CHECK.tuning)),
  { name: "promptCheck", type: "boolean or object", values: [["true", "on, set explicitly"], ["false", "off"]], what: "Typed prompts checked by the decision model.", where: PLUGIN, relaxing: SAME_VALUE, read: (config) => config.promptCheck !== undefined },
  { name: "promptCheck.enabled", type: "boolean", what: "false turns the check off, inside the object form.", where: PLUGIN, read: (config) => config.promptCheck !== undefined },
  { name: "promptCheck.threshold", type: "number", range: [0, 1], what: "Stage 1: probability from which a part holds a secret.", where: PLUGIN, relaxing: SAME_VALUE, read: (config) => config.promptCheck?.threshold },
  { name: "promptCheck.questions", type: "object", what: "Questions asked to the model.", where: PLUGIN, relaxing: SAME_VALUE, read: (config) => config.promptCheck?.custom, shown: customized },
  ...tuning("promptCheck", Object.keys(DEFAULT_PROMPT_TUNING)),
]

const NOT_READ = "Not read: the plugin options OpenCode merges from a project's opencode.json (.opencode included) or from OPENCODE_CONFIG_CONTENT."

type State = "default" | "same as default" | "overridden" | "ignored"
export interface OptionRow {
  readonly entry?: OptionEntry
  readonly name: string
  readonly value: string
  readonly fallback: string
  readonly origin: string
  readonly state: State
  /** The value written, when another one is retained, and why. */
  readonly written?: string
  /** The `{env:…}` reference it was read from. */
  readonly reference?: string
}

const printed = (value: unknown): string => {
  if (value === undefined || value === null) return "none"
  if (Array.isArray(value)) return value.length ? value.join(", ") : "none"
  return typeof value === "object" ? JSON.stringify(value) : String(value)
}
const at = (options: Readonly<Record<string, unknown>>, name: string): unknown =>
  name.split(".").reduce<unknown>((node, key) => (node !== null && typeof node === "object" ? (node as Record<string, unknown>)[key] : undefined), options)

/** An origin named by its file. */
const fileOf = (origin: string) => origin.replace(/^(global|system) configuration/, "$1 opencode.json")

/** Every row, from the same reading as the plugin; `{env:…}` references are looked up in the raw configuration file. */
export function optionRows(io: CliIo, agent: string | undefined) {
  const sources = readSources(io)
  const directory = realOrUndefined(io.cwd) ?? resolve(io.cwd)
  const files = readGuardFiles(guardPaths(directory, sources.globalDir, io.systemDir))
  const parsed = parseConfig(sources.options, io.env, () => sources.declarations, {
    files,
    project: directory,
    realPath: realOrUndefined,
    regularFile: isRegularFile,
    ...(sources.origin ? { origin: sources.origin } : {}),
  })
  const defaults = parseConfig({}, io.env, () => sources.declarations).config
  const version = resolveVersion(parsed.config.layers!, files)
  const policy = new Map((version.settings?.(agent) ?? []).map((row) => [row.key, row]))
  const defaultPolicy = new Map((resolveVersion(parseConfig({}, io.env, () => [], { files: [], realPath: realOrUndefined, regularFile: isRegularFile }).config.layers!, []).settings?.(agent) ?? []).map((row) => [row.key, row]))
  let raw = ""
  try {
    raw = readFileSync(configurationFile(sources.globalDir), "utf8")
  } catch {
    // No raw file: no reference shown.
  }
  const section = (name: string) => files.find((file) => file.global)?.data?.[name]
  const rows: OptionRow[] = []
  for (const entry of OPTIONS) {
    const written = at(sources.options, entry.name) ?? section(entry.name)
    const row = policy.get(entry.name)
    const held = row ? row.value : entry.read(parsed.config)
    const leaf = entry.name.split(".").pop()!
    // Without a decision model, its defaults are not in the configuration read.
    const standard = row ? defaultPolicy.get(entry.name)?.value : (entry.read(defaults) ?? (entry.name.startsWith("decision.") ? (DEFAULT_DECISION as Record<string, unknown>)[leaf] : undefined))
    const origin = row ? fileOf(row.origin) : written === undefined ? "default" : (sources.origin ? "system opencode.json" : "global opencode.json")
    const rejected = !row && !entry.shown && written !== undefined && typeof written !== "object" && printed(written) !== printed(held)
    const same = printed(held) === printed(standard)
    const reference = new RegExp(`"${leaf}"\\s*:\\s*"(\\{env:[^}"]+\\})"`).exec(raw)?.[1]
    rows.push({
      entry,
      name: entry.name,
      value: entry.shown ? entry.shown(held ?? written) : printed(held),
      fallback: entry.shown ? entry.shown(standard) : printed(standard),
      origin,
      state: rejected ? "ignored" : origin === "default" ? "default" : same ? "same as default" : "overridden",
      ...(rejected ? { written: printed(written) } : {}),
      ...(reference ? { reference } : {}),
    })
  }
  for (const [key, row] of policy)
    if (key.startsWith("ruleOverrides.") || key.startsWith("exceptions."))
      rows.push({ name: key, value: String(row.value), fallback: "none", origin: fileOf(row.origin), state: "overridden" })
  return { rows, warnings: [...parsed.warnings, ...version.warnings] }
}

const STYLES: Readonly<Record<State, Style>> = { default: "dim", "same as default": "dim", overridden: "good", ignored: "warn" }
const MAX_CELL = 26
const cut = (text: string) => (text.length > MAX_CELL ? `${text.slice(0, MAX_CELL - 1)}…` : text)
const typeOf = (entry: OptionEntry | undefined) => (entry ? entry.type.split(/[ ,:(]/)[0]! : "-")

function prettyList(pretty: Pretty, rows: readonly OptionRow[]) {
  const cells = rows.map((row) => ({ row, name: pretty.clean(row.name), type: typeOf(row.entry), value: cut(pretty.clean(row.value)), fallback: cut(pretty.clean(row.fallback)), origin: pretty.clean(row.origin) }))
  const width = (pick: (cell: (typeof cells)[number]) => string, label: string) => Math.max(label.length, ...cells.map((cell) => pick(cell).length))
  const columns = [width((c) => c.name, "Option"), width((c) => c.type, "Type"), width((c) => c.value, "In force"), width((c) => c.fallback, "Default")]
  pretty.line([["    "], [["Option".padEnd(columns[0]!), "Type".padEnd(columns[1]!), "In force".padEnd(columns[2]!), "Default".padEnd(columns[3]!), "From"].join("  "), "group"]])
  const column = 4 + columns.reduce((sum, size) => sum + size + 2, 0)
  for (const { row, name, type, value, fallback, origin } of cells) {
    const text = `${origin}${row.state === "default" ? "" : `, ${row.state}`}`
    for (const line of rowLines(pretty, [["    "], [name.padEnd(columns[0]!)], ["  "], [type.padEnd(columns[1]!), "dim"], ["  "], [value.padEnd(columns[2]!), STYLES[row.state]], ["  "], [fallback.padEnd(columns[3]!), "dim"], ["  "]], column, text, STYLES[row.state])) pretty.line(line)
  }
}

/** The table of every option. */
export function options(io: CliIo, agent: string | undefined): void {
  const { rows, warnings } = optionRows(io, agent)
  if (io.pretty) {
    title(io.pretty, "Options", agent === undefined ? "" : `main agent ${io.pretty.clean(agent)}`, "settings")
    io.pretty.line([])
    prettyList(io.pretty, rows)
    io.pretty.line([])
    for (const line of rowLines(io.pretty, [["    "]], 4, NOT_READ, "dim")) io.pretty.line(line)
    for (const line of rowLines(io.pretty, [["    "]], 4, "guard options --explain <option>: what it does and what it accepts.", "dim")) io.pretty.line(line)
  } else {
    const cells = rows.map((row) => [row.name, typeOf(row.entry), row.value, row.fallback, row.origin, row.state])
    const widths = [0, 1, 2, 3, 4].map((index) => Math.max(...cells.map((cell) => cell[index]!.length)))
    for (const cell of cells) io.out(cell.map((text, index) => text.padEnd(widths[index] ?? 0)).join("  "))
    io.out(NOT_READ)
  }
  if (warnings.length) io.err(`${warnings.length} warning(s): guard show lists them.`)
}

/** What one option does, what it accepts, and its state here; `all` for every option. */
export function explainOption(io: CliIo, name: string, agent: string | undefined): void {
  const { rows } = optionRows(io, agent)
  const chosen = name === "all" ? rows.filter((row) => row.entry) : rows.filter((row) => row.name === name)
  if (!chosen.length) throw new CliError(`no option named ${name}`)
  for (const row of chosen) {
    const entry = row.entry
    const fields: Array<readonly [string, string]> = [
      ...(entry ? ([["Type", entry.type], ...(entry.range ? [["Range", `${entry.range[0]} to ${entry.range[1]}`] as const] : [])] as const) : []),
      ["Default", row.fallback],
      ["In force", row.written ? `${row.value} (written: ${row.written}, ignored: not accepted, see guard show)` : row.value],
      ["From", row.origin],
      ...(row.reference ? ([["Reference", `${row.reference}, resolved here with the terminal's environment and service.json; the server's may differ`]] as const) : []),
      ...(entry ? ([["Where", entry.where], ...(entry.relaxing ? [["Relaxing", entry.relaxing] as const] : [])] as const) : []),
    ]
    if (io.pretty) {
      const pretty = io.pretty
      title(pretty, row.name, "", "settings")
      if (entry) for (const line of rowLines(pretty, [["  "]], 2, pretty.clean(entry.what))) pretty.line(line)
      pretty.line([])
      for (const [label, text] of fields) for (const line of rowLines(pretty, [["  "], [label.padEnd(10), "group"]], 12, pretty.clean(text))) pretty.line(line)
      if (entry?.values) {
        heading(pretty, "Values")
        for (const [value, meaning] of entry.values) for (const line of rowLines(pretty, [["    "], [value.padEnd(18), "good"]], 22, pretty.clean(meaning))) pretty.line(line)
      }
      pretty.line([])
      continue
    }
    io.out(row.name)
    if (entry) io.out(`  ${entry.what}`)
    for (const [label, text] of fields) io.out(`  ${label}: ${text}`)
    for (const [value, meaning] of entry?.values ?? []) io.out(`  Value ${value}: ${meaning}`)
  }
}
