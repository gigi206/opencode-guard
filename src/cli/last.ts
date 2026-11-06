// `guard last [N]`: the latest asks and denials of the plugin's log, with their time, rule and reason as logged. Same
// file as the plugin (`logFile` included, checked the same way); read from the end, at most `TAIL_BYTES` of the current
// file, then of its previous copy (`.1`) if it holds fewer. A previous copy the checks refuse is left out.
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs"
import { defaultLogFile, parseConfig } from "../config.ts"
import { CONTROL_CHARACTERS } from "../types.ts"
import { checkedLog, CliError, readSources, type CliIo, type Pretty } from "./context.ts"
import { heading, rowLines, title } from "./pretty.ts"
import type { Segment } from "./style.ts"

export const DEFAULT_LAST = 20
export const MAX_LAST = 200
export const TAIL_BYTES = 2 * 1024 * 1024

/** Decision line of the plugin: `<time> <LEVEL> <tool> → ask|deny (<source>[, rule <id>]…): <reason>`. */
const DECISION = /^(\S+) [A-Z]+ (.*?) → (ask|deny) \(([^)]*)\): (.*)$/

/** Lines of the end of the file; absent: `undefined`. Never through a final symbolic link, like the plugin's writes. */
function tail(path: string): string[] | undefined {
  let fd: number
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0))
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

/**
 * A log time (UTC) in the terminal's time zone (`TZ`, otherwise the system's), with its offset: `2026-10-31`,
 * `22:08:39`, `+01:00` (an hour repeats when clocks go back). A time that cannot be read, or an unknown zone: as logged.
 */
export function localTime(iso: string, env: Record<string, string | undefined>): { day: string; time: string; offset: string } | undefined {
  const date = new Date(iso)
  if (!/^\d{4}-\d{2}-\d{2}T/.test(iso) || Number.isNaN(date.getTime())) return undefined
  const format = (timeZone: string | undefined) =>
    new Intl.DateTimeFormat("en-CA", { ...(timeZone ? { timeZone } : {}), year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23", timeZoneName: "longOffset" }).formatToParts(date)
  let parts: Intl.DateTimeFormatPart[]
  try {
    parts = format(env.TZ?.trim() || undefined)
  } catch {
    // `TZ` the runtime does not know (`:/etc/localtime`): the system's zone.
    parts = format(undefined)
  }
  const part = (type: Intl.DateTimeFormatPartTypes) => parts.find((item) => item.type === type)?.value ?? ""
  const offset = part("timeZoneName").replace(/^GMT/, "") || "+00:00"
  return { day: `${part("year")}-${part("month")}-${part("day")}`, time: `${part("hour")}:${part("minute")}:${part("second")}`, offset }
}

const shownTime = (entry: Decision, env: Record<string, string | undefined>) => {
  const local = localTime(entry.time, env)
  return local ? `${local.day} ${local.time} ${local.offset}` : entry.time
}

// Control characters are never printed to the terminal.
const flat = (entry: Decision, env: Record<string, string | undefined>) => `${shownTime(entry, env)}  ${entry.verdict}  ${entry.rule}  ${entry.subject}: ${entry.reason}`.replace(CONTROL_CHARACTERS, " ")

/**
 * The plugin's log file, read as the plugin does (`logFile`, checked the same way), and the lines of its end (the
 * previous copy before them when `previous` is asked); a message instead when there is none to read.
 */
export function logLines(io: CliIo): { file: string; lines: string[]; previous: () => string[] } | { message: string } {
  const sources = readSources(io)
  const { config } = parseConfig(sources.options, io.env)
  const fallback = defaultLogFile(io.env)
  const checked = (path: string | undefined, other: string | undefined) => checkedLog(io, sources, path, other)
  const file = checked(config.logFile, fallback)
  if (file === undefined) {
    if (config.logFile === undefined && fallback !== undefined) return { message: "The plugin writes no log file (logFile: false)." }
    throw new CliError("the plugin's log file is unknown: neither XDG_DATA_HOME nor HOME is set")
  }
  const lines = tail(file)
  if (lines === undefined) return { message: `No log file yet: ${file}` }
  const previous = () => {
    const copy = `${file}.1`
    // The copy of the default log is the default for this check, as that log is; refused, the result is another path.
    if (checked(copy, fallback && `${fallback}.1`) !== copy) return []
    try {
      return tail(copy) ?? []
    } catch (error) {
      if (error instanceof CliError) return []
      throw error
    }
  }
  return { file, lines, previous }
}

export function last(io: CliIo, count: number): void {
  const log = logLines(io)
  if ("message" in log) {
    io.out(log.message)
    return
  }
  const { file, lines: current } = log
  let found = decisions(current)
  if (found.length < count) found = [...decisions(log.previous()), ...found]
  if (found.length === 0) {
    io.out(`No ask or deny in ${file}`)
    return
  }
  const shown = found.slice(-count)
  if (io.pretty) return prettyLast(io.pretty, file, shown, io.env)
  io.out(`Latest asks and denials (${file}):`)
  for (const entry of shown) io.out(flat(entry, io.env))
}

/** The duration of the model calls that ends a decision line (`[model 540 ms]`, `, 2 attempts` after a retry). */
const TIMING = / \[(model \d+ ms(?:, \d+ attempts)?)\]$/
/** The model's opinion added to a local confirmation: `<reason> — <model> opinion: …`. */
const OPINION = / — (\S+ opinion: .*)$/

/**
 * `guard last` in a terminal: by day, each entry on a line (time, verdict, rule, tool, duration of the model calls), its
 * reason wrapped below it, then the model's opinion, dimmed. The time is the terminal's local time (the day's heading
 * gives its offset), without its fraction of a second. The reason is split once redacted.
 */
function prettyLast(pretty: Pretty, file: string, entries: readonly Decision[], env: Record<string, string | undefined>): void {
  title(pretty, "Latest asks and denials", `${entries.length} ${entries.length === 1 ? "entry" : "entries"}`, "log")
  for (const line of rowLines(pretty, [["  "]], 2, `from ${pretty.clean(file)}`, "dim")) pretty.line(line)
  const rows = entries.map((entry) => {
    const local = localTime(entry.time, env)
    const rule = entry.rule === "-" ? `(${entry.source})` : entry.rule
    return { day: pretty.clean(local ? `${local.day} (UTC${local.offset})` : ""), time: pretty.clean(local ? local.time : entry.time), verdict: entry.verdict, rule: pretty.clean(rule), byRule: entry.rule !== "-", subject: pretty.clean(entry.subject), reason: pretty.clean(entry.reason) }
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
    const timing = TIMING.exec(row.reason)
    const reason = timing ? row.reason.slice(0, timing.index) : row.reason
    const opinion = OPINION.exec(reason)
    pretty.line([...cells, [row.subject, "dim"], ...(timing ? ([[`  ${timing[1]}`, "dim"]] as Segment[]) : [])])
    for (const line of rowLines(pretty, [[" ".repeat(column)]], column, opinion ? reason.slice(0, opinion.index) : reason)) pretty.line(line)
    if (opinion) for (const line of rowLines(pretty, [[" ".repeat(column)]], column, opinion[1]!, "dim")) pretty.line(line)
  }
}
