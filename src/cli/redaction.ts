// `guard redaction`: the redaction formats, like `guard rules` for the rules. The built-in formats (`secrets/patterns.ts`)
// with their state (on, or off when the global or system configuration turns them off: read as the plugin reads it),
// OpenCode's own formats (always on), then the user's patterns (`secretPatterns` option), each with its regular
// expression, and those set aside. `--explain <format>`: one format and every pattern of its type.
import { join } from "node:path"
import { parseConfig, REDACTION_OFF, redactionOffOption } from "../config.ts"
import { GUARD_FILE, readGuardFiles } from "../guard-file.ts"
import { OPENCODE_FORMAT_SUMMARIES, OPENCODE_PATTERNS } from "../secrets/opencode-service.ts"
import { BUILTIN_PATTERNS, FORMAT_SUMMARIES, type SecretPattern } from "../secrets/patterns.ts"
import { placeholder } from "../secrets/redact.ts"
import { CliError, readSources, type CliIo, type Pretty } from "./context.ts"
import { heading, rowLines, title } from "./pretty.ts"
import type { Segment } from "./style.ts"

/** The plugin's warnings about its `secretPatterns` and `redactionOff` options: each one starts with the option's name. */
const PATTERNS_WARNING = /^(?:secretPatterns|redactionOff)\b/
const NOT_SHOWN =
  "Not shown: a project's opencode.json can add patterns of its own, and they then apply in that project (never turn a format off)."
const TURN_OFF =
  'Turned off by guard redaction off <format> (redactionOff in the global guard.json, back on with guard redaction on <format>), or by "redactionOff": ["<format>"] in the plugin options of the global or system configuration (elsewhere: ignored, with a warning). Off, its patterns no longer redact anything: tool outputs, prompts (the prompt check may still mask such a value), the wire, the log; the rules no longer see it as a secret (secret-network and the like), and the decision model receives it in clear.'

const source = (pattern: SecretPattern) => `/${pattern.regex.source}/${pattern.regex.flags}`

/** The formats and the user's patterns as the plugin reads them (global or system entry, with its declarations). */
type Formats =
  | {
      readonly origin: string
      readonly off: ReadonlySet<string>
      readonly custom: ReadonlyArray<{ readonly type: string; readonly pattern: string }>
      readonly setAside: readonly string[]
    }
  | { readonly unread: string; readonly off: ReadonlySet<string> }

function formats(io: CliIo): Formats {
  try {
    const sources = readSources(io)
    const from = (label: string) => sources.declarations.find((entry) => entry.label === label)
    const origin = from("system")?.options ? "system configuration, which replaces the global entry" : from("global")?.options ? "global configuration" : undefined
    if (!origin) {
      const reasons = sources.declarations.map((entry) => `${entry.label} configuration: ${entry.reason ?? "not read"}`)
      return { unread: `none read, the plugin is not declared (${reasons.join("; ")})`, off: new Set() }
    }
    const { config, warnings } = parseConfig(sources.options, io.env, () => sources.declarations)
    return {
      origin,
      off: new Set([...config.disabledPatterns, ...guardOff(sources.globalDir)]),
      custom: config.secretPatterns.map((pattern) => ({ type: pattern.type, pattern: source(pattern) })),
      setAside: warnings.filter((warning) => PATTERNS_WARNING.test(warning)),
    }
  } catch (error) {
    return { unread: `the configuration could not be read (${error instanceof Error ? error.message : String(error)})`, off: new Set() }
  }
}

/** Formats turned off by the global guard.json (`redactionOff`), read like the plugin reads them; unreadable: none. */
function guardOff(globalDir: string | undefined): string[] {
  if (!globalDir) return []
  const [file] = readGuardFiles({ global: join(globalDir, GUARD_FILE), projects: [], roots: [] })
  return redactionOffOption(file?.data?.[REDACTION_OFF], "global guard.json", [])
}

/** Built-in formats then OpenCode's, with their state. */
function builtinRows(off: ReadonlySet<string>): Array<{ readonly type: string; readonly state: "on" | "off" | "always"; readonly description: string }> {
  return [
    ...[...FORMAT_SUMMARIES].map(([type, description]) => ({ type, state: off.has(type) ? ("off" as const) : ("on" as const), description })),
    ...[...OPENCODE_FORMAT_SUMMARIES].map(([type, description]) => ({ type, state: "always" as const, description })),
  ]
}

const count = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`

/** One line per item (output that is not a terminal). */
export function redactionLines(io: CliIo, builtins: boolean, custom: boolean): string[] {
  const data = formats(io)
  const lines: string[] = []
  if (builtins) {
    const rows = builtinRows(data.off)
    const [type, state] = [Math.max(...rows.map((row) => row.type.length)), Math.max(...rows.map((row) => row.state.length))]
    lines.push("Built-in redaction formats:", ...rows.map((row) => `  ${row.type.padEnd(type)}  ${row.state.padEnd(state)}  ${row.description}`))
  }
  if (custom) {
    if ("unread" in data) lines.push(`Your redaction patterns: ${data.unread}`)
    else {
      const type = Math.max(0, ...data.custom.map((row) => row.type.length))
      lines.push(
        `Your redaction patterns (secretPatterns option of the ${data.origin}):`,
        ...(data.custom.length ? data.custom.map((row) => `  ${row.type.padEnd(type)}  ${row.pattern}`) : ["  none"]),
        ...(data.setAside.length ? ["  Set aside:", ...data.setAside.map((warning) => `    ${warning}`)] : []),
        `  ${NOT_SHOWN}`,
      )
    }
  }
  return lines
}

const stateStyle = (state: string) => (state === "off" ? "bad" : state === "on" ? "good" : "dim")

/** The formats for a terminal: built-in ones with their state, then the user's, each pattern alone on the next line. */
export function prettyRedaction(io: CliIo, pretty: Pretty, builtins: boolean, custom: boolean): void {
  const data = formats(io)
  if (builtins) {
    const rows = builtinRows(data.off).map((row) => ({ ...row, type: pretty.clean(row.type), description: pretty.clean(row.description) }))
    const type = Math.max(...rows.map((row) => row.type.length))
    const column = 4 + type + 2 + 6 + 2
    const off = rows.filter((row) => row.state === "off").length
    title(pretty, "Redaction formats", `${count(rows.length, "format")}${off ? `, ${off} off` : ""}`, "builtins")
    for (const [group, label, members] of [
      ["built-in", "turned off only by the global or system configuration", rows.filter((row) => row.state !== "always")],
      ["OpenCode", "always active", rows.filter((row) => row.state === "always")],
    ] as const) {
      pretty.line([])
      pretty.line([["  "], [group, "group"], [`  ${label} (${members.length})`, "dim"]])
      for (const row of members)
        for (const line of rowLines(pretty, [["    "], [row.type.padEnd(type), "rule"], ["  "], [row.state.padEnd(6), stateStyle(row.state)], ["  "]], column, row.description)) pretty.line(line)
    }
  }
  if (builtins && custom) for (let blank = 0; blank < 2; blank++) pretty.line([])
  if (!custom) return
  if ("unread" in data) {
    title(pretty, "Your redaction patterns", "secretPatterns option", "custom")
    pretty.line([])
    for (const line of rowLines(pretty, [["  "]], 2, pretty.clean(data.unread), "warn")) pretty.line(line)
    return
  }
  title(pretty, "Your redaction patterns", `${count(data.custom.length, "pattern")}, from the secretPatterns option of the ${pretty.clean(data.origin)}`, "custom")
  pretty.line([])
  if (!data.custom.length) pretty.line([["    "], ["none", "dim"]])
  for (const row of data.custom) {
    pretty.line([["    "], [pretty.clean(row.type), "rule"]])
    pretty.line([["      "], [pretty.clean(row.pattern), "dim"]])
  }
  if (data.setAside.length) {
    pretty.line([])
    pretty.line([["  "], ["Set aside", "warn"]])
    for (const warning of data.setAside) for (const line of rowLines(pretty, [["    "]], 4, pretty.clean(warning), "warn")) pretty.line(line)
  }
  pretty.line([])
  for (const line of rowLines(pretty, [["  "]], 2, NOT_SHOWN, "dim")) pretty.line(line)
}

/** Is this the name of a format (built-in or OpenCode's)? */
export const isFormat = (type: string) => FORMAT_SUMMARIES.has(type) || OPENCODE_FORMAT_SUMMARIES.has(type)

/** One format explained: what it catches, its state, every pattern of its type, how to turn it off. */
export function explainFormat(io: CliIo, type: string): void {
  const opencode = OPENCODE_FORMAT_SUMMARIES.has(type)
  const description = FORMAT_SUMMARIES.get(type) ?? OPENCODE_FORMAT_SUMMARIES.get(type)
  if (!description) throw new CliError(`no redaction format named ${type}`)
  const patterns = (opencode ? OPENCODE_PATTERNS : BUILTIN_PATTERNS).filter((pattern) => pattern.type === type)
  const state = opencode ? "always active" : formats(io).off.has(type) ? "off" : "on"
  const checked = patterns.some((pattern) => pattern.accept || pattern.trim)
  // A `secret` group: only the value is replaced, its prefix (`Bearer `, `name=`) kept.
  const part = patterns.every((pattern) => pattern.regex.source.includes("(?<secret>")) ? "the value (its prefix kept)" : patterns.some((pattern) => pattern.regex.source.includes("(?<secret>")) ? "the match, or only its value when the pattern names one" : "the whole match"
  const how = `${count(patterns.length, "pattern")}${patterns.length > 1 && !opencode ? ", all turned off together" : ""}; ${part} replaced by ${placeholder(type)}${checked ? ", once it passes the format's own checks (what it catches says which)" : ""}.`
  const setting = opencode ? "Cannot be turned off: it protects OpenCode's own credentials." : TURN_OFF.replaceAll("<format>", type)
  if (io.pretty) {
    const pretty = io.pretty
    title(pretty, `Format ${pretty.clean(type)}`, opencode ? "OpenCode, always active" : `built-in, ${state}`, "builtins")
    const block = (name: string, text: string) => {
      pretty.line([])
      heading(pretty, name)
      for (const line of rowLines(pretty, [["    "]], 4, pretty.clean(text))) pretty.line(line)
    }
    block("What it catches", description)
    block("How it redacts", how)
    pretty.line([])
    heading(pretty, "Patterns")
    for (const pattern of patterns) pretty.line([["    "], [pretty.clean(source(pattern)), "dim"]] as Segment[])
    block("Setting", setting)
    return
  }
  io.out(`Format: ${type}`)
  io.out(`  State: ${state}`)
  io.out(`  What it catches: ${description}`)
  io.out(`  How it redacts: ${how}`)
  io.out("  Patterns:")
  for (const pattern of patterns) io.out(`    ${source(pattern)}`)
  io.out(`  Setting: ${setting}`)
}
