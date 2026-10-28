// `guard last [N]`: the latest asks and denials of the plugin's log, with their time, rule and reason as logged. Same
// file as the plugin (`logFile` included, checked the same way); read from the end, at most `TAIL_BYTES` of the current
// file, then of its previous copy (`.1`) if it holds fewer.
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs"
import { defaultLogFile, parseConfig } from "../config.ts"
import { checkedLogFile } from "../index.ts"
import { CONTROL_CHARACTERS } from "../types.ts"
import { CliError, PLUGIN_DIR, readSources, realOrUndefined, type CliIo } from "./context.ts"

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

const decisions = (lines: readonly string[]) =>
  lines.flatMap((line) => {
    const match = DECISION.exec(line)
    if (!match) return []
    const [, time, subject, verdict, source, reason] = match
    const rule = /(?:^|, )rule ([^,]+)/.exec(source!)?.[1] ?? "-"
    // Control characters are never printed to the terminal.
    return [`${time}  ${verdict}  ${rule}  ${subject}: ${reason}`.replace(CONTROL_CHARACTERS, " ")]
  })

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
  io.out(`Latest asks and denials (${file}):`)
  for (const line of found.slice(-count)) io.out(line)
}
