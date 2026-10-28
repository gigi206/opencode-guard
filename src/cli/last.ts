// `guard last [N]`: the latest asks and denials of the plugin's log, with their time, rule and reason as logged. Same
// file as the plugin (`logFile` included, checked the same way); read from the end, at most `TAIL_BYTES` of the current
// file, then of its previous copy (`.1`) if it holds fewer.
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs"
import { defaultLogFile, parseConfig } from "../config.ts"
import { checkedLogFile } from "../index.ts"
import { CONTROL_CHARACTERS } from "../types.ts"
import { CliError, PLUGIN_DIR, readSources, realOrUndefined, type CliIo, type Pretty } from "./context.ts"
import { heading, rowLines, title } from "./pretty.ts"
import type { Segment } from "./style.ts"

export const DEFAULT_LAST = 20
export const MAX_LAST = 200
const TAIL_BYTES = 2 * 1024 * 1024

/** Decision line of the plugin: `<time> <LEVEL> <tool> → ask|deny (<source>[, rule <id>]…): <reason>`. */
const DECISION = /^(\S+) [A-Z]+ (.*?) → (ask|deny) \(([^)]*)\): (.*)$/

/** Lines of the end of the file; absent: `undefined`. */
function tail(path: string): string[] | undefined {
  let fd: number
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0))
  } catch (error) {
    if ((error as { code?: unknown } | undefined)?.code === "ENOENT") return undefined
    throw new CliError(`${path} cannot be read`)
  }
  try {
    const stat = fstatSync(fd)
    if (!stat.isFile()) throw new CliError(`${path} is not a regular file`)
    const length = Math.min(stat.size, TAIL_BYTES)
    const start = stat.size - length
    const buffer = Buffer.alloc(length)
    let read = 0
    while (read < length) {
      const count = readSync(fd, buffer, read, length - read, start + read)
      if (count === 0) break
      read += count
    }
    const lines = buffer.toString("utf8", 0, read).split("\n")
    // Cut inside a line: its end only.
    if (start > 0) lines.shift()
    return lines
  } finally {
    closeSync(fd)
  }
}

interface Decision {
  readonly time: string
  readonly verdict: string
  readonly rule: string
  /** Where the verdict comes from (`local`, `model`, `cache`…): shown in a terminal when no rule gave it. */
  readonly source: string
  readonly subject: string
  readonly reason: string
}

const decisions = (lines: readonly string[]): Decision[] =>
  lines.flatMap((line) => {
    const match = DECISION.exec(line)
    if (!match) return []
    const [, time, subject, verdict, source, reason] = match
    return [{ time: time!, verdict: verdict!, rule: /(?:^|, )rule ([^,]+)/.exec(source!)?.[1] ?? "-", source: source!.split(",")[0]!.trim(), subject: subject!, reason: reason! }]
  })

// Control characters are never printed to the terminal.
const flat = (entry: Decision) => `${entry.time}  ${entry.verdict}  ${entry.rule}  ${entry.subject}: ${entry.reason}`.replace(CONTROL_CHARACTERS, " ")

export function last(io: CliIo, count: number): void {
  const sources = readSources(io)
  const { config } = parseConfig(sources.options, io.env)
  const fallback = defaultLogFile(io.env)
  const protectedDirs = [PLUGIN_DIR, realOrUndefined(PLUGIN_DIR), sources.globalDir, sources.globalDir && realOrUndefined(sources.globalDir)].filter((dir): dir is string => !!dir)
  const file = checkedLogFile(config.logFile, fallback, io.env.HOME, [...new Set(protectedDirs)], [], io.cwd)
  if (file === undefined) {
    if (config.logFile === undefined && fallback !== undefined) io.out("The plugin writes no log file (logFile: false).")
    else throw new CliError("the plugin's log file is unknown: neither XDG_DATA_HOME nor HOME is set")
    return
  }
  const current = tail(file)
  if (current === undefined) {
    io.out(`No log file yet: ${file}`)
    return
  }
  let found = decisions(current)
  if (found.length < count) found = [...decisions(tail(`${file}.1`) ?? []), ...found]
  if (found.length === 0) {
    io.out(`No ask or deny in ${file}`)
    return
  }
  const shown = found.slice(-count)
  if (io.pretty) return prettyLast(io.pretty, file, shown)
  io.out(`Latest asks and denials (${file}):`)
  for (const entry of shown) io.out(flat(entry))
}

/**
 * `guard last` in a terminal: by day, each entry on a line (time, verdict, rule, tool), its reason wrapped below it.
 * The time is the log's (UTC), without its fraction of a second.
 */
function prettyLast(pretty: Pretty, file: string, entries: readonly Decision[]): void {
  title(pretty, "Latest asks and denials", `${entries.length} ${entries.length === 1 ? "entry" : "entries"}`, "log")
  for (const line of rowLines(pretty, [["  "]], 2, `from ${pretty.clean(file)}`, "dim")) pretty.line(line)
  const rows = entries.map((entry) => {
    const [, day = "", time = entry.time] = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/.exec(entry.time) ?? []
    const rule = entry.rule === "-" ? `(${entry.source})` : entry.rule
    return { day: pretty.clean(day), time: pretty.clean(time === entry.time ? entry.time : `${time}Z`), verdict: entry.verdict, rule: pretty.clean(rule), byRule: entry.rule !== "-", subject: pretty.clean(entry.subject), reason: pretty.clean(entry.reason) }
  })
  const [time, rule] = [Math.max(0, ...rows.map((row) => row.time.length)), Math.max(0, ...rows.map((row) => row.rule.length))]
  const column = 4 + time + 2
  let day: string | undefined
  for (const row of rows) {
    if (row.day !== day) {
      day = row.day
      pretty.line([])
      heading(pretty, day || "undated")
    }
    const cells: Segment[] = [["    "], [row.time.padEnd(time), "dim"], ["  "], [row.verdict.padEnd(4), row.verdict === "deny" ? "deny" : "ask"], ["  "], [row.rule.padEnd(rule), row.byRule ? "rule" : "dim"], ["  "]]
    pretty.line([...cells, [row.subject, "dim"]])
    for (const line of rowLines(pretty, [[" ".repeat(column)]], column, row.reason)) pretty.line(line)
  }
}
