// Real paths of a write, to recognize a protected location reached through a symbolic link. Resolution
// component by component like the kernel (`lstat` + `readlink`): under Bun, `realpathSync` and `realpathSync.native`
// normalize before following links (a `..` after a link would go up into the link's directory, not that of
// its target). The rules stay pure: they receive the predicate built here, per tool call.
import { lstatSync, readlinkSync } from "node:fs"
import { posix } from "node:path"

/** Lookups (`lstat`) per tool call. */
export const MAX_LOOKUPS = 512
/** Links followed per path, like the kernel (beyond that, the write would fail). */
const MAX_LINKS = 40
/** Longest path accepted by the kernel. */
const PATH_MAX = 4096

/** File operations (injectable for tests). */
export interface LinkIo {
  readonly lstat: (path: string) => { isSymbolicLink(): boolean }
  readonly readlink: (path: string) => string
}

const nodeIo: LinkIo = {
  lstat: (path) => lstatSync(path),
  readlink: (path) => readlinkSync(path),
}

export interface RealPathOptions {
  /**
   * Call directories: replace `/proc/self/cwd` (read by the plugin, this link would lead to its own directory, not
   * the command's).
   */
  readonly directories?: readonly string[]
  /**
   * Plugin process directory, added to the `/proc/self/cwd` candidates: the edit, write, and patch tools write
   * from the server, where the plugin is imported. Default: `process.cwd()`.
   */
  readonly processDirectory?: string
  readonly io?: LinkIo
}

/** Components in reverse order: the next one to process is at the end of the array. */
const reversed = (path: string) => path.split("/").reverse()

/**
 * `/proc/self` entry (or `/proc/thread-self`, i.e. `task/<n>`) designated by the following components:
 * empty and `.` components skipped, `task/<n>/` traversed, a `..` leaving `/proc/self` returned as is (back to
 * `/proc`). `undefined`: no entry (directory only).
 */
function selfEntry(parts: string[], thread: boolean): string | undefined {
  let level = thread ? 2 : 0
  for (;;) {
    const entry = parts.pop()
    if (entry === undefined) return undefined
    if (entry === "" || entry === ".") continue
    if (entry === "..") {
      if (level === 0) return ".."
      level--
    } else if ((level === 0 && entry === "task") || level === 1) level++
    else return entry
  }
}

function processCwd(): string | undefined {
  try {
    return process.cwd()
  } catch {
    // Deleted directory: nothing to add.
    return undefined
  }
}

/**
 * Predicate for a tool call: possible real paths of a non-normalized absolute path (several if `/proc/self/cwd`
 * points to the call directories and the server one). Missing or unreadable component: the rest, to be created, is resolved lexically.
 * `undefined`: unknown (limits, link loop, open descriptor of a process); the caller then keeps only the
 * lexical comparison. Results memoized.
 */
export function createRealPath(options: RealPathOptions = {}): (absolute: string) => readonly string[] | undefined {
  const io = options.io ?? nodeIo
  const own = options.processDirectory ?? processCwd()
  const candidates = [...(options.directories ?? []), ...(own ? [own] : [])]
  const seen = new Map<string, readonly string[] | undefined>()
  let lookups = 0

  /** Walk of `parts` (reverse order) from `current`, real path without links (`""`: root). */
  function walk(current: string, parts: string[], links: number): string[] | undefined {
    while (parts.length > 0) {
      const part = parts.pop()!
      if (part === "" || part === ".") continue
      if (part === "..") {
        current = current.slice(0, Math.max(current.lastIndexOf("/"), 0))
        continue
      }
      // Process of the command (shell) or the server (tools), not of the plugin reading: only the directory (the call ones
      // and the server one) and the root can be transposed.
      if (current === "/proc" && (part === "self" || part === "thread-self")) {
        const entry = selfEntry(parts, part === "thread-self")
        if (entry === "..") continue
        if (entry === "root") {
          current = ""
          continue
        }
        if (entry !== "cwd" || candidates.length === 0) return undefined
        const results: string[] = []
        for (const directory of candidates) {
          const branch = walk("", [...parts, ...reversed(directory)], links)
          if (!branch) return undefined
          results.push(...branch)
        }
        return results
      }
      const next = `${current}/${part}`
      if (lookups >= MAX_LOOKUPS) return undefined
      lookups++
      let link: boolean
      try {
        link = io.lstat(next).isSymbolicLink()
      } catch {
        // Missing or unreadable: file or directories to create.
        return [posix.resolve(next, ...parts.reverse())]
      }
      if (!link) {
        current = next
        continue
      }
      if (++links > MAX_LINKS) return undefined
      let target: string
      try {
        target = io.readlink(next)
      } catch {
        return undefined
      }
      if (target.startsWith("/")) current = ""
      parts.push(...reversed(target))
    }
    return [current || "/"]
  }

  return (absolute) => {
    if (seen.has(absolute)) return seen.get(absolute)
    const found = absolute.startsWith("/") && absolute.length <= PATH_MAX ? walk("", reversed(absolute), 0) : undefined
    seen.set(absolute, found)
    return found
  }
}
