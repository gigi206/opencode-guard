// `guard show`: the policy settings in force for the current directory (and a main agent), each with the file and
// section it comes from, the exceptions retained, the project's trust and the settings set aside with the reason (the
// warnings of the plugin's resolution). Only from the files read faithfully here; no other option of the configuration is
// ever printed.
import { existsSync } from "node:fs"
import { join, resolve } from "node:path"
import { parseConfig, RELAX_SWITCHES, type GuardConfig, type Version } from "../config.ts"
import { guardPaths, readGuardFiles } from "../guard-file.ts"
import { declaredOutputCheck } from "../output-check.ts"
import { UNSEEN_CONTENT_RULES } from "../rules/features.ts"
import { PLUGIN_DIR, readSources, realOrUndefined, resolution, serverEnv, type CliIo, type Pretty, type Sources } from "./context.ts"
import { heading, rowLines, title } from "./pretty.ts"
import type { Segment, Style } from "./style.ts"
import { pluginVersion, runGit } from "./version.ts"

const NOT_READ =
  "Not read: the plugin options OpenCode merges from a project's opencode.json (.opencode included) or from OPENCODE_CONFIG_CONTENT; where they are set, the plugin may run with other settings (its log shows them at startup)."

/** The configuration file of a directory: the one that exists, in the order the plugin reads them, else the usual name. */
export function configurationFile(directory: string | undefined): string {
  if (directory === undefined) return "opencode.json"
  const [file, ...others] = ["opencode.json", "opencode.jsonc"].map((name) => join(directory, name))
  return [file!, ...others].find((path) => existsSync(path)) ?? file!
}

export function show(io: CliIo, agent: string | undefined, offline = false): void {
  showSettings(io, agent, offline)
  io.out("All the settings, with their defaults: guard settings")
}

function showSettings(io: CliIo, agent: string | undefined, offline: boolean): void {
  const sources = readSources(io)
  const directory = realOrUndefined(io.cwd) ?? resolve(io.cwd)
  const paths = guardPaths(directory, sources.globalDir, io.systemDir)
  const files = readGuardFiles(paths)
  const version = resolution(io, sources, directory, files)
  // Each source read, with its state: `good` read, `dim` absent, `warn` ignored or not declaring the plugin.
  const read: Array<{ readonly name: string; readonly state: string; readonly style: Style }> = sources.declarations.map((entry) => ({
    name: `${entry.label} configuration (${configurationFile(entry.label === "system" ? io.systemDir : sources.globalDir)})`,
    state: entry.options ? "declares the plugin" : (entry.reason ?? "not read"),
    style: entry.options ? "good" : "warn",
  }))
  const global = files.find((file) => file.global)
  if (paths.global)
    read.push({ name: `global guard.json (${paths.global})`, state: !global ? "absent" : global.data ? "read" : `ignored, ${global.reason}`, style: !global ? "dim" : global.data ? "good" : "warn" })
  for (const file of files.filter((item) => !item.global)) read.push({ name: file.label, state: file.data ? "read" : `ignored, ${file.reason}`, style: file.data ? "good" : "warn" })
  const plugin = pluginVersion(PLUGIN_DIR, io.git ?? runGit, offline)
  read.push({ name: plugin.source, state: plugin.state, style: plugin.style })
  const listed = version.listed?.length ? version.listed.join(", ") : "none"
  const patterns = redactionSettings(io, sources)
  const formatsOff = (version.redactionOff ?? []).map((type) => ({ key: `redactionOff.${type}`, value: "off", origin: "global guard.json" }))
  const rows = [...startRows(io, sources, version, agent), ...relaxationRows(version, agent)]
  // Exceptions apart: a path would widen every column of the settings.
  const settings = [...rows.filter((row) => !row.key.startsWith(EXCEPTIONS)), ...patterns.rows, ...formatsOff]
  const exceptions = rows.filter((row) => row.key.startsWith(EXCEPTIONS)).map((row) => ({ rule: row.key.slice(EXCEPTIONS.length), path: String(row.value), origin: row.origin }))
  const warnings = [...version.warnings, ...patterns.warnings]
  if (io.pretty)
    return prettyShow(io.pretty, {
      title: `${directory}${agent === undefined ? "" : `, main agent ${agent}`}`,
      read,
      trusted: Boolean(version.trusted),
      listed,
      settings,
      exceptions,
      warnings,
    })
  io.out(`Settings for ${directory}${agent === undefined ? "" : ` with the main agent ${agent}`}, read from:`)
  for (const source of read) io.out(`  ${source.name}: ${source.state}`)
  io.out(`  ${NOT_READ}`)
  io.out(`This project: ${version.trusted ? "trusted" : "not trusted"} (trustedProjects: ${listed})`)
  io.out("Settings in force:")
  const width = (pick: (row: (typeof settings)[number]) => string) => Math.max(...settings.map((row) => pick(row).length))
  const [key, value] = [width((row) => row.key), width((row) => String(row.value))]
  for (const row of settings) io.out(`  ${row.key.padEnd(key)}  ${String(row.value).padEnd(value)}  ${row.origin}`)
  io.out(`Exceptions in force:${exceptions.length ? "" : " none"}`)
  const [rule, path] = [Math.max(0, ...exceptions.map((row) => row.rule.length)), Math.max(0, ...exceptions.map((row) => row.path.length))]
  for (const row of exceptions) io.out(`  ${row.rule.padEnd(rule)}  ${row.path.padEnd(path)}  ${row.origin}`)
  if (warnings.length) {
    io.out("Set aside:")
    for (const warning of warnings) io.out(`  ${warning}`)
  }
}

const READ_AT_START: readonly string[] = RELAX_SWITCHES

/**
 * The settings, with what the files alone cannot say. The switches read at start say so (the running plugin may hold
 * another value: its state is not known here). A check that is on but finds no model it may use does not show as on.
 */
function startRows(io: CliIo, sources: Sources, version: Version, agent: string | undefined) {
  const env = serverEnv(io.env, sources.globalDir)
  const served = readSources({ ...io, env })
  const { config } = parseConfig(served.options, env, () => served.declarations)
  const idle = (option: "outputCheck" | "promptCheck") => {
    const enabledBySection = version.sectionChecks?.includes(option) ?? false
    const state = version.base.decisionModel && config.decision ? declaredOutputCheck({ option, enabledBySection, pluginDir: PLUGIN_DIR, effectiveBaseURL: config.decision.baseURL, globalDir: sources.globalDir, systemDir: io.systemDir, env }) : { active: false, reason: "no decision model" }
    return state.active ? undefined : state.reason
  }
  return (version.settings?.(agent) ?? []).map((row) => {
    if (!READ_AT_START.includes(row.key)) return row
    const reason = row.value === true && (row.key === "outputCheck" || row.key === "promptCheck") ? idle(row.key) : undefined
    const origin = `${row.origin} (read when the plugin starts)`
    return reason === undefined ? { ...row, origin } : { ...row, value: "inactive", origin: `${origin}: ${reason}` }
  })
}

/**
 * Redaction settings of the global or system entry, read as the plugin reads them: the number of your patterns, each
 * built-in format turned off, and the `secretPatterns` entries set aside (`guard redaction` lists them all).
 */
function redactionSettings(io: CliIo, sources: ReturnType<typeof readSources>): { rows: Array<{ key: string; value: unknown; origin: string }>; warnings: string[] } {
  try {
    const { config, warnings } = parseConfig(sources.options, io.env, () => sources.declarations)
    const origin = sources.origin ?? "global configuration"
    const rows = [
      ...(config.secretPatterns.length ? [{ key: "secretPatterns", value: `${config.secretPatterns.length} pattern${config.secretPatterns.length === 1 ? "" : "s"}`, origin }] : []),
      ...config.disabledPatterns.map((type) => ({ key: `redactionOff.${type}`, value: "off", origin })),
    ]
    return { rows, warnings: warnings.filter((warning) => warning.startsWith("secretPatterns") || warning.startsWith("redactionOff")) }
  } catch {
    return { rows: [], warnings: [] }
  }
}

/** `guard show` in a terminal: the sources read, the project's trust, the settings and exceptions in force, those set aside. */
function prettyShow(
  pretty: Pretty,
  data: {
    readonly title: string
    readonly read: ReadonlyArray<{ readonly name: string; readonly state: string; readonly style: Style }>
    readonly trusted: boolean
    readonly listed: string
    readonly settings: ReadonlyArray<{ readonly key: string; readonly value: unknown; readonly origin: string }>
    readonly exceptions: ReadonlyArray<{ readonly rule: string; readonly path: string; readonly origin: string }>
    readonly warnings: readonly string[]
  },
): void {
  title(pretty, "Settings", pretty.clean(data.title), "settings")
  pretty.line([])
  heading(pretty, "Read from")
  const read = data.read.map((source) => ({ name: pretty.clean(source.name), state: pretty.clean(source.state), style: source.style }))
  // A long name (a path) keeps its state beside it when both fit; otherwise it is printed alone, wrapped at its spaces,
  // its state on the next line under the column.
  const name = Math.min(Math.max(0, ...read.map((source) => source.name.length)), 40)
  const column = 4 + name + 2
  for (const source of read) {
    if (4 + source.name.length + 2 + source.state.length > pretty.width && source.name.length > name) {
      for (const line of rowLines(pretty, [["    "]], 4, source.name)) pretty.line(line)
      for (const line of rowLines(pretty, [[" ".repeat(column)]], column, source.state, source.style)) pretty.line(line)
    } else {
      const cell = source.name.padEnd(name)
      for (const line of rowLines(pretty, [["    "], [cell], ["  "]], 4 + cell.length + 2, source.state, source.style)) pretty.line(line)
    }
  }
  for (const line of rowLines(pretty, [["    "]], 4, NOT_READ, "dim")) pretty.line(line)
  pretty.line([])
  heading(pretty, "This project")
  pretty.line([["    "], [data.trusted ? "trusted" : "not trusted", data.trusted ? "good" : "warn"]])
  for (const line of rowLines(pretty, [["    "]], 4, `trustedProjects: ${pretty.clean(data.listed)}`, "dim")) pretty.line(line)
  pretty.line([])
  heading(pretty, "Settings in force")
  const rows = data.settings.map((row) => ({ key: pretty.clean(row.key), value: pretty.clean(String(row.value)), origin: pretty.clean(row.origin), relaxes: relaxes(row.key, String(row.value)) }))
  const [key, value] = [Math.max(0, ...rows.map((row) => row.key.length)), Math.max(0, ...rows.map((row) => row.value.length))]
  // A column for the `relaxes` mark, only when a setting relaxes a protection.
  const mark = rows.some((row) => row.relaxes) ? RELAXES.length + 2 : 0
  for (const row of rows) {
    const cells: Segment[] = [["    "], [row.key.padEnd(key), "rule"], ["  "], [row.value.padEnd(value), valueStyle(row.value)], ["  "]]
    if (mark) cells.push(row.relaxes ? [RELAXES, "warn"] : [" ".repeat(RELAXES.length)], ["  "])
    for (const line of rowLines(pretty, cells, 4 + key + 2 + value + 2 + mark, row.origin, "dim")) pretty.line(line)
  }
  if (pretty.color && rows.length) {
    const legend: Segment[] = [["    "]]
    for (const [word, style] of VALUE_STYLES) legend.push([word, style], [" "])
    pretty.line([...legend, ...(mark || data.exceptions.length ? ([["· ", "dim"], [RELAXES, "warn"], [": the setting relaxes a protection", "dim"]] as Segment[]) : [])])
  }
  pretty.line([])
  heading(pretty, "Exceptions in force")
  const exceptions = data.exceptions.map((row) => ({ rule: pretty.clean(row.rule), path: pretty.clean(row.path), origin: pretty.clean(row.origin) }))
  if (!exceptions.length) pretty.line([["    "], ["none", "dim"]])
  // Each one relaxes a protection: the path after the mark, its origin on the next line under it (a long path stays whole).
  const rule = Math.max(0, ...exceptions.map((row) => row.rule.length))
  const start = 4 + rule + 2 + RELAXES.length + 2
  for (const row of exceptions) {
    for (const line of rowLines(pretty, [["    "], [row.rule.padEnd(rule), "rule"], ["  "], [RELAXES, "warn"], ["  "]], start, row.path)) pretty.line(line)
    for (const line of rowLines(pretty, [[" ".repeat(start)]], start, row.origin, "dim")) pretty.line(line)
  }
  if (data.warnings.length) {
    pretty.line([])
    heading(pretty, "Set aside", "", "warn")
    for (const warning of data.warnings) for (const line of rowLines(pretty, [["    "]], 4, pretty.clean(warning), "warn")) pretty.line(line)
  }
}

/** One color per value (a rule's setting in the colors of `guard rules`), in the legend's order. */
const VALUE_STYLES: ReadonlyArray<readonly [string, Style]> = [
  ["true", "good"],
  ["false", "bad"],
  ["deny", "deny"],
  ["ask", "ask"],
  ["model", "model"],
  ["off", "dim"],
]
const valueStyle = (value: string): Style | undefined => VALUE_STYLES.find(([word]) => word === value)?.[1]

/** Switches whose `true` keeps a protection on (`Version.settings`). */
const PROTECTIVE = new Set(["dangerousCommands", "sensitiveFiles", "scripts", "decisionModel", ...RELAX_SWITCHES])
const RELAXES = "relaxes"
const EXCEPTIONS = "exceptions."

/** What the global sources relax by agent (all of them, or the main agent given), and for which models. */
function relaxationRows(version: Version, agent: string | undefined) {
  return [...(version.relaxations ?? [])].flatMap(([name, relaxed]) => {
    if (agent !== undefined && agent !== name) return []
    const row = (key: string, value: string) => ({ key: `agents.${name}.${key}`, value, origin: relaxed.origins.get(key) ?? "default" })
    return [
      ...(relaxed.guardOff ? [row("guard", "off")] : []),
      ...[...relaxed.off].map((key) => row(key, "false")),
      row("models", relaxed.models ? relaxed.models.join(", ") || "none" : "any model"),
    ]
  })
}

/**
 * Names of what relaxes this agent besides the switches of its section (`Version.relaxations`): the policy settings in
 * force for it, wherever they are set, the exceptions, the global redaction switches and formats, `unprotectedAgent`.
 */
export function stillRelaxed(version: Version, config: GuardConfig, agent: string): string[] {
  return [
    ...(version.settings?.(agent) ?? []).filter((row) => row.key.startsWith(EXCEPTIONS) || relaxes(row.key, String(row.value))).map((row) => row.key),
    ...(version.redactionOff ?? []).map((type) => `redactionOff.${type}`),
    ...(config.unprotectedAgent === agent ? ["unprotectedAgent"] : []),
  ]
}

/**
 * Does the setting relax a protection: a protective switch off, self-protection or local confirmations left to the
 * decision model, a rule turned off or left to the model (`model` asks like `ask` on `UNSEEN_CONTENT_RULES`), a redaction format turned off, confirmations remembered?
 */
function relaxes(key: string, value: string): boolean {
  if (key.startsWith("agents.")) return value === "off" || value === "false"
  if (key.startsWith("ruleOverrides.")) return value === "off" || (value === "model" && !UNSEEN_CONTENT_RULES.has(key.slice("ruleOverrides.".length)))
  if (key.startsWith("redactionOff.")) return value === "off"
  if (PROTECTIVE.has(key)) return value === "false"
  if (key === "selfProtectionByModel") return value === "true"
  if (key === "localAsks") return value === "model"
  if (key === "rememberConfirmations") return value !== "off"
  return false
}
