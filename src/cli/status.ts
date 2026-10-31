// `guard status`: what the plugin's log says of its latest starts, the errors and warnings written since, whether the
// plugin's files changed after the latest start (OpenCode reloads it on its own), and whether the decision model answers.
// Read only; exit code 0 whatever the state. Several OpenCode instances may write the same log: their lines carry no
// name, so the starts are listed, and the errors after them may come from any of them.
import { readdirSync, statSync } from "node:fs"
import { join } from "node:path"
import { displayURL, parseConfig } from "../config.ts"
import { createModelClient, ModelError, type ModelClient } from "../model/client.ts"
import { QUESTIONS, STATE_NOTE } from "../model/questions.ts"
import { PLUGIN_DIR, readSources, type CliIo } from "./context.ts"
import { localTime, logLines, TAIL_BYTES } from "./last.ts"
import { heading, title } from "./pretty.ts"
import type { Segment, Style } from "./style.ts"
import { serverEnv } from "./test.ts"

/** Starts listed, newest last; runtime errors and warnings shown. */
const STARTS = 5
const MESSAGES = 5

/** A log line: `<time> <LEVEL> <text>`. */
const LINE = /^(\d{4}-\d{2}-\d{2}T\S+) (DEBUG|INFO|WARN|ERROR) (.*)$/
const START = /^active \((.*)\)$/

interface Entry {
  readonly time: string
  readonly ms: number
  readonly level: string
  readonly text: string
}

export interface LogState {
  /** Latest starts (the text inside `active (…)`), newest last. */
  readonly starts: ReadonlyArray<{ readonly time: string; readonly details: string }>
  /** ERROR and WARN lines after the latest start, those written by a start excluded. */
  readonly errors: number
  readonly warnings: number
  readonly messages: readonly Entry[]
}

/**
 * Starts and what follows the latest one. A start writes its warnings within the same moment just before its `active`
 * line: those (within a second before it) are not runtime warnings.
 */
export function logState(lines: readonly string[]): LogState {
  const entries = lines.flatMap((line): Entry[] => {
    const match = LINE.exec(line)
    return match ? [{ time: match[1]!, ms: Date.parse(match[1]!), level: match[2]!, text: match[3]! }] : []
  })
  const startIndexes = entries.flatMap((entry, i) => (entry.level === "INFO" && START.test(entry.text) ? [i] : []))
  const startup = new Set<number>()
  for (const index of startIndexes)
    for (let i = index - 1; i >= 0 && entries[index]!.ms - entries[i]!.ms <= 1000; i--) startup.add(i)
  const latest = startIndexes.at(-1)
  const after = latest === undefined ? [] : entries.slice(latest + 1).filter((entry, i) => !startup.has(latest + 1 + i) && (entry.level === "ERROR" || entry.level === "WARN"))
  return {
    starts: startIndexes.slice(-STARTS).map((index) => ({ time: entries[index]!.time, details: START.exec(entries[index]!.text)![1]! })),
    errors: after.filter((entry) => entry.level === "ERROR").length,
    warnings: after.filter((entry) => entry.level === "WARN").length,
    messages: after.slice(-MESSAGES),
  }
}

/** Newest modification of the files the plugin loads (`index.ts`, `src/` but the command line's `src/cli/`). */
export function pluginFilesChanged(dir: string = PLUGIN_DIR): number {
  let newest = 0
  const visit = (path: string) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const full = join(path, entry.name)
      if (entry.isDirectory()) {
        if (full !== join(dir, "src", "cli")) visit(full)
      } else if (entry.isFile() && entry.name.endsWith(".ts")) newest = Math.max(newest, statSync(full).mtimeMs)
    }
  }
  try {
    newest = statSync(join(dir, "index.ts")).mtimeMs
    visit(join(dir, "src"))
  } catch {}
  return newest
}

export type ModelProbe = { readonly configured: false } | { readonly configured: true; readonly model: string; readonly url: string; readonly ms?: number; readonly failure?: string }

/** One decision request on a harmless call, answered or not: its duration, or the class of its failure (never its message). */
export async function probeModel(io: CliIo, client?: ModelClient): Promise<ModelProbe> {
  const env = serverEnv(io.env, readSources(io).globalDir)
  const sources = readSources({ ...io, env })
  const { config } = parseConfig(sources.options, env, () => sources.declarations)
  if (!config.decision) return { configured: false }
  const base = { configured: true as const, model: config.decision.model, url: displayURL(config.decision.baseURL) }
  const model = client ?? createModelClient(config.decision)
  const start = Date.now()
  try {
    await model({ state: { note: STATE_NOTE, tool: "shell", input: { command: "true" } }, questions: QUESTIONS })
    return { ...base, ms: Date.now() - start }
  } catch (error) {
    const failure = error instanceof ModelError ? (error.timeout ? "timeout" : (/^(?:HTTP \d{3}|network)/.exec(error.message)?.[0] ?? "unavailable")) : "unavailable"
    return { ...base, failure }
  }
}

const when = (time: string, env: Record<string, string | undefined>) => {
  const local = localTime(time, env)
  return local ? `${local.day} ${local.time} ${local.offset}` : time
}

export async function status(io: CliIo, options: { readonly offline: boolean }, client?: ModelClient): Promise<void> {
  const log = logLines(io)
  const state = "message" in log ? undefined : logState(log.lines)
  const stale = state?.starts.length ? pluginFilesChanged() > Date.parse(state.starts.at(-1)!.time) : false
  const probe = options.offline ? undefined : await probeModel(io, client)
  const rows: Array<{ label: string; value: string; style?: Style }> = []
  if ("message" in log) rows.push({ label: "log", value: log.message, style: "warn" })
  else {
    rows.push({ label: "log", value: log.file, style: "dim" })
    if (!state!.starts.length) rows.push({ label: "start", value: `no start in the last ${TAIL_BYTES / 1024 / 1024} MiB of the log`, style: "warn" })
    for (const start of state!.starts) rows.push({ label: "start", value: `${when(start.time, io.env)}  ${start.details}`, style: /UNAVAILABLE|INCOMPLETE|NO protection/.test(start.details) ? "bad" : undefined })
    if (state!.starts.length) {
      rows.push({ label: "since", value: `${state!.errors} error(s), ${state!.warnings} warning(s) after the latest start (from any OpenCode instance writing this log)`, style: state!.errors ? "bad" : state!.warnings ? "warn" : "good" })
      for (const entry of state!.messages) rows.push({ label: entry.level.toLowerCase(), value: `${when(entry.time, io.env)}  ${entry.text}`, style: entry.level === "ERROR" ? "bad" : "warn" })
      rows.push(stale ? { label: "files", value: "plugin files changed after the latest start: not loaded yet (OpenCode reloads the plugin by itself)", style: "warn" } : { label: "files", value: "no plugin file changed since the latest start", style: "good" })
    }
  }
  if (options.offline) rows.push({ label: "model", value: "not asked (--offline)", style: "dim" })
  else if (!probe!.configured) rows.push({ label: "model", value: "no decision model configured: local rules only", style: "dim" })
  else if (probe!.failure) rows.push({ label: "model", value: `${probe!.model} via ${probe!.url}: no answer (${probe!.failure})`, style: "bad" })
  else rows.push({ label: "model", value: `${probe!.model} via ${probe!.url}: answers in ${probe!.ms} ms`, style: "good" })
  if (io.pretty) {
    const pretty = io.pretty
    title(pretty, "Plugin status", "from its log and the decision model", "log")
    let group = ""
    for (const row of rows) {
      const name = row.label === "model" ? "Decision model" : "Log"
      if (name !== group) {
        group = name
        heading(pretty, name)
      }
      const segments: Segment[] = [["    "], [row.label.padEnd(6), "dim"], ["  "], [pretty.clean(row.value), row.style]]
      pretty.line(segments)
    }
    return
  }
  for (const row of rows) io.out(`${row.label}: ${row.value}`)
}
