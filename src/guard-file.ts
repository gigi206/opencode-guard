// guard.json files (settings by agent and by project): the global one, in OpenCode's global configuration directory,
// and one in each `.opencode` directory OpenCode 2.2.0 reads for the session directory (packages/core/src/config/discovery.ts:
// every ancestor up to `/`, none when the directory is itself the global or system one, a `.opencode` that resolves to
// them skipped). OpenCode itself neither loads nor reports these files.
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from "node:fs"
import { dirname, isAbsolute, join, resolve } from "node:path"
import type { GuardFile } from "./config.ts"

export const GUARD_FILE = "guard.json"
/** Larger: ignored (a settings file stays small). */
export const MAX_GUARD_FILE_BYTES = 65_536

export interface GuardPaths {
  readonly global?: string
  /** Outermost first: the closest one wins. */
  readonly projects: readonly string[]
  /** Real paths of the global and system directories. */
  readonly roots: readonly string[]
}

function realOrUndefined(path: string): string | undefined {
  try {
    return realpathSync(path)
  } catch {
    return undefined
  }
}

/** Candidate paths, computed once at startup: absent ones included, a file created later is seen at the next check. */
export function guardPaths(directory: string, globalDir: string | undefined, systemDir: string | undefined): GuardPaths {
  const roots = [globalDir, systemDir].flatMap((dir) => (dir ? [realOrUndefined(dir) ?? resolve(dir)] : []))
  const projects: string[] = []
  if (isAbsolute(directory) && !roots.includes(realOrUndefined(directory) ?? resolve(directory)))
    for (let dir = resolve(directory); ; dir = dirname(dir)) {
      projects.push(join(dir, ".opencode", GUARD_FILE))
      if (dirname(dir) === dir) break
    }
  return { ...(globalDir ? { global: join(globalDir, GUARD_FILE) } : {}), projects: projects.reverse(), roots }
}

/** Identity of every candidate, absent ones included: a change is seen without reading the files. */
export function guardIdentity(paths: GuardPaths): string {
  return [paths.global, ...paths.projects]
    .map((path) => {
      if (!path) return "-"
      try {
        const stat = lstatSync(path)
        return `${stat.dev}:${stat.ino}:${stat.mode}:${stat.size}:${stat.mtimeMs}:${stat.ctimeMs}`
      } catch (error) {
        return String((error as { code?: unknown } | undefined)?.code ?? "error")
      }
    })
    .join("|")
}

/**
 * One file: absent → `undefined`; otherwise its JSON object, or why it is ignored as a whole (never its content, nor the
 * parser's message, which may quote it). Never through a final symbolic link; a FIFO does not block the opening.
 */
function readGuardFile(path: string, label: string, global: boolean): GuardFile | undefined {
  let fd: number
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0))
  } catch (error) {
    const code = (error as { code?: unknown } | undefined)?.code
    if (code === "ENOENT" || code === "ENOTDIR") return undefined
    return { label, global, reason: code === "ELOOP" ? "it is a symbolic link" : "it cannot be read" }
  }
  try {
    if (!fstatSync(fd).isFile()) return { label, global, reason: "it is not a regular file" }
    const buffer = Buffer.alloc(MAX_GUARD_FILE_BYTES + 1)
    let length = 0
    while (length < buffer.length) {
      const read = readSync(fd, buffer, length, buffer.length - length, null)
      if (read === 0) break
      length += read
    }
    if (length > MAX_GUARD_FILE_BYTES) return { label, global, reason: `it is larger than ${MAX_GUARD_FILE_BYTES} bytes` }
    let data: unknown
    try {
      data = JSON.parse(buffer.toString("utf8", 0, length))
    } catch {
      return { label, global, reason: "it is not valid JSON" }
    }
    if (data === null || typeof data !== "object" || Array.isArray(data)) return { label, global, reason: "it is not a JSON object" }
    return { label, global, data: data as Record<string, unknown> }
  } catch {
    return { label, global, reason: "it cannot be read" }
  } finally {
    try {
      closeSync(fd)
    } catch {}
  }
}

/** Files present, the global one first, then the project ones outermost first. */
export function readGuardFiles(paths: GuardPaths): GuardFile[] {
  const files: GuardFile[] = []
  const global = paths.global ? readGuardFile(paths.global, "global guard.json", true) : undefined
  if (global) files.push(global)
  for (const path of paths.projects) {
    const dir = realOrUndefined(dirname(path))
    if (dir !== undefined && paths.roots.includes(dir)) continue
    const file = readGuardFile(path, `project guard.json (${path})`, false)
    if (file) files.push({ ...file, dir: dirname(dirname(path)) })
  }
  return files
}
