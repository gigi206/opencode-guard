// `guard show`: the policy settings in force for the current directory (and a main agent), each with the file and
// section it comes from, the project's trust and the settings set aside with the reason (the warnings of the plugin's
// resolution). Only from the files read faithfully here; no other option of the configuration is ever printed.
import { resolve } from "node:path"
import { guardPaths, readGuardFiles } from "../guard-file.ts"
import { readSources, realOrUndefined, resolution, type CliIo, type Pretty } from "./context.ts"
import { heading, rowLines, title } from "./pretty.ts"
import type { Segment, Style } from "./style.ts"

const NOT_READ =
  "Not read: the plugin options OpenCode merges from a project's opencode.json (.opencode included) or from OPENCODE_CONFIG_CONTENT; where they are set, the plugin may run with other settings (its log shows them at startup)."

export function show(io: CliIo, agent: string | undefined): void {
  const sources = readSources(io)
  const directory = realOrUndefined(io.cwd) ?? resolve(io.cwd)
  const paths = guardPaths(directory, sources.globalDir, io.systemDir)
  const files = readGuardFiles(paths)
  const version = resolution(io, sources, directory, files)
  // Each source read, with its state: `good` read, `dim` absent, `warn` ignored or not declaring the plugin.
  const read: Array<{ readonly name: string; readonly state: string; readonly style: Style }> = sources.declarations.map((entry) => ({
    name: `${entry.label} configuration (opencode.json)`,
    state: entry.options ? "declares the plugin" : (entry.reason ?? "not read"),
    style: entry.options ? "good" : "warn",
  }))
  const global = files.find((file) => file.global)
  if (paths.global)
    read.push({ name: `global guard.json (${paths.global})`, state: !global ? "absent" : global.data ? "read" : `ignored, ${global.reason}`, style: !global ? "dim" : global.data ? "good" : "warn" })
  for (const file of files.filter((item) => !item.global)) read.push({ name: file.label, state: file.data ? "read" : `ignored, ${file.reason}`, style: file.data ? "good" : "warn" })
  const listed = version.listed?.length ? version.listed.join(", ") : "none"
  const settings = version.settings?.(agent) ?? []
  if (io.pretty)
    return prettyShow(io.pretty, {
      title: `${directory}${agent === undefined ? "" : `, main agent ${agent}`}`,
      read,
      trusted: Boolean(version.trusted),
      listed,
      settings,
      warnings: version.warnings,
    })
  io.out(`Settings for ${directory}${agent === undefined ? "" : ` with the main agent ${agent}`}, read from:`)
  for (const source of read) io.out(`  ${source.name}: ${source.state}`)
  io.out(`  ${NOT_READ}`)
  io.out(`This project: ${version.trusted ? "trusted" : "not trusted"} (trustedProjects: ${listed})`)
  io.out("Settings in force:")
  const width = (pick: (row: (typeof settings)[number]) => string) => Math.max(...settings.map((row) => pick(row).length))
  const [key, value] = [width((row) => row.key), width((row) => String(row.value))]
  for (const row of settings) io.out(`  ${row.key.padEnd(key)}  ${String(row.value).padEnd(value)}  ${row.origin}`)
  if (version.warnings.length) {
    io.out("Set aside:")
    for (const warning of version.warnings) io.out(`  ${warning}`)
  }
}

/** `guard show` in a terminal: the sources read, the project's trust, the settings in force and those set aside. */
function prettyShow(
  pretty: Pretty,
  data: {
    readonly title: string
    readonly read: ReadonlyArray<{ readonly name: string; readonly state: string; readonly style: Style }>
    readonly trusted: boolean
    readonly listed: string
    readonly settings: ReadonlyArray<{ readonly key: string; readonly value: unknown; readonly origin: string }>
    readonly warnings: readonly string[]
  },
): void {
  title(pretty, "Settings", pretty.clean(data.title), "settings")
  pretty.line([])
  heading(pretty, "Read from")
  const read = data.read.map((source) => ({ name: pretty.clean(source.name), state: pretty.clean(source.state), style: source.style }))
  // A long name (a path) is printed alone, wrapped at its spaces, its state on the next line under the column.
  const name = Math.min(Math.max(0, ...read.map((source) => source.name.length)), 40)
  const column = 4 + name + 2
  for (const source of read) {
    if (source.name.length > name) {
      for (const line of rowLines(pretty, [["    "]], 4, source.name)) pretty.line(line)
      for (const line of rowLines(pretty, [[" ".repeat(column)]], column, source.state, source.style)) pretty.line(line)
    } else for (const line of rowLines(pretty, [["    "], [source.name.padEnd(name)], ["  "]], column, source.state, source.style)) pretty.line(line)
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
    pretty.line([...legend, ...(mark ? ([["· ", "dim"], [RELAXES, "warn"], [": the setting relaxes a protection", "dim"]] as Segment[]) : [])])
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

/** Switches whose `true` keeps a protection on (`policy` switches of `config.ts`). */
const PROTECTIVE = new Set(["dangerousCommands", "sensitiveFiles", "scripts", "decisionModel"])
const RELAXES = "relaxes"

/**
 * Does the setting relax a protection: a protective switch off, self-protection or local confirmations left to the
 * decision model, a rule turned off or left to the model?
 */
function relaxes(key: string, value: string): boolean {
  if (key.startsWith("ruleOverrides.")) return value === "off" || value === "model"
  if (PROTECTIVE.has(key)) return value === "false"
  if (key === "selfProtectionByModel") return value === "true"
  if (key === "localAsks") return value === "model"
  return false
}
