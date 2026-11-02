// What the command line reads, as the plugin does: OpenCode's global configuration directory (from the terminal's
// environment, which may differ from the server's), the system one, the plugin's entry in their opencode.json, the
// guard.json files and their layered resolution (config.ts). A project's opencode.json is never read: OpenCode merges it
// into the options the plugin receives, and its discovery is not reimplemented here.
import { lstatSync, readFileSync, realpathSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { parseConfig, resolveVersion, type GuardFile, type PluginDeclaration, type Version } from "../config.ts"
import { knownSecrets } from "../index.ts"
import { declaredPluginOptions, globalConfigDirectory } from "../output-check.ts"
import { isRegularFile } from "../real-path.ts"
import { createRedactor, type Redactor } from "../secrets/redact.ts"
import type { Segment, Terminal } from "./style.ts"

export interface CliIo {
  /** Environment of the terminal, given explicitly (never `process.env` by default). */
  readonly env: Record<string, string | undefined>
  readonly cwd: string
  /** OpenCode's system configuration directory (`systemConfigDirectory`). */
  readonly systemDir: string
  readonly out: (line: string) => void
  readonly err: (line: string) => void
  /** The terminal, when the standard output is one (`terminalOf`, decided by the launcher): grouped, colored layout. */
  readonly terminal?: Terminal
  /** Set by `main` around the redaction, for a terminal only. */
  readonly pretty?: Pretty
}

/** Layout for a terminal: each field cleaned (redacted, control characters removed) before it is wrapped, then painted. */
export interface Pretty {
  readonly width: number
  /** Colors wanted: a legend is printed only then. */
  readonly color: boolean
  readonly clean: (text: string) => string
  /** One line: painted only if the redaction leaves each segment and the whole line unchanged, otherwise printed plain. */
  readonly line: (segments: readonly Segment[]) => void
}

/** The plugin's directory (this file is in `src/cli/`). */
export const PLUGIN_DIR = resolve(fileURLToPath(new URL("../..", import.meta.url)))

export function realOrUndefined(path: string): string | undefined {
  try {
    return realpathSync(path)
  } catch {
    return undefined
  }
}

/** Refusal or usage error, in words: printed, exit code 1. */
export class CliError extends Error {}

export interface Sources {
  readonly globalDir: string | undefined
  readonly declarations: readonly PluginDeclaration[]
  /** Options the plugin gets without a project's opencode.json: the system entry's (loaded last), else the global one's. */
  readonly options: Readonly<Record<string, unknown>>
  /** Origin of the keys they set beyond the global file's: the system configuration when they are its. */
  readonly origin?: string
}

export function readSources(io: CliIo): Sources {
  const globalDir = globalConfigDirectory(io.env)
  const declarations = declaredPluginOptions({ pluginDir: PLUGIN_DIR, globalDir, systemDir: io.systemDir, env: io.env })
  const system = declarations.find((entry) => entry.label === "system")?.options
  const options = system ?? declarations.find((entry) => entry.label === "global")?.options ?? {}
  return { globalDir, declarations, options, ...(system ? { origin: "system configuration" } : {}) }
}

/**
 * The plugin's redactor for every line printed (with the server's environment): its default patterns, the `secretPatterns` and the decision model's key
 * and headers of the global and system configurations, the terminal's environment. Configuration that cannot be read:
 * the default patterns (never a line in clear).
 */
export function outputRedactor(terminal: CliIo): Redactor {
  // The server's environment: the decision model's key may be only in service.json (`guard test`, `guard status`).
  let io = terminal
  try {
    io = { ...terminal, env: serverEnv(terminal.env, readSources(terminal).globalDir) }
  } catch {}
  try {
    const configs = readSources(io).declarations.flatMap((entry) => (entry.options ? [parseConfig(entry.options, io.env).config] : []))
    return createRedactor({ extraPatterns: configs.flatMap((config) => config.secretPatterns), env: io.env, knownSecrets: configs.flatMap(knownSecrets) })
  } catch {
    return createRedactor({ env: io.env })
  }
}

/** Settings resolved like the plugin for a session directory (real path; absent: no project) and these guard.json files. */
export function resolution(io: CliIo, sources: Sources, project: string | undefined, files: readonly GuardFile[]): Version {
  const { config } = parseConfig(sources.options, io.env, () => sources.declarations, {
    files,
    ...(project ? { project } : {}),
    realPath: realOrUndefined,
    regularFile: isRegularFile,
    ...(sources.origin ? { origin: sources.origin } : {}),
  })
  return resolveVersion(config.layers!, files)
}

/**
 * The global guard.json's rules a running plugin may keep while this reading sets them aside (`Version.mayKeep`): their
 * identifiers only, never a pattern.
 */
export function mayKeepNote(version: Version): string | undefined {
  const kept = version.mayKeep
  if (kept === undefined) return undefined
  if (kept === "all") return "its rules is not a list: a running plugin may keep the rules it read from it last, until it is valid again"
  const which = kept.length === 1 ? `entry ${JSON.stringify(kept[0])}` : `entries ${kept.map((id) => JSON.stringify(id)).join(", ")}`
  return `${which} set aside: a running plugin may keep the rule it read last under ${kept.length === 1 ? "that identifier" : "each"}, until it is valid again`
}

/** Project of the current directory: the first one, going up, that holds a `.git` entry; otherwise the current directory. */
export function projectDirectory(cwd: string): string {
  const start = realOrUndefined(cwd) ?? resolve(cwd)
  for (let dir = start; ; dir = dirname(dir)) {
    try {
      lstatSync(join(dir, ".git"))
      return dir
    } catch {}
    if (dirname(dir) === dir) return start
  }
}

/**
 * The server's environment: the terminal's, completed by the `env` of OpenCode's `service.json` in the global directory
 * (the service starts the server with it: the decision model's key is often only there). Unreadable: the terminal's.
 */
export function serverEnv(env: Record<string, string | undefined>, globalDir: string | undefined): Record<string, string | undefined> {
  if (!globalDir) return env
  try {
    const service = JSON.parse(readFileSync(join(globalDir, "service.json"), "utf8")) as { env?: unknown }
    const extra = service.env && typeof service.env === "object" ? Object.entries(service.env).filter((entry): entry is [string, string] => typeof entry[1] === "string") : []
    return { ...Object.fromEntries(extra), ...env }
  } catch {
    return env
  }
}

