// Tracking of files created in full by the agent in a session: when they are run, their content is submitted to the local
// shell rules (at most one ask) and, if unchanged since a call judged in full by the decision model,
// shown to it. A file that can no longer be read (too large, link…), or named by a successful `patch` call whose text
// lacks the known grammar: unverifiable, its execution asks.
import { createHash } from "node:crypto"
import { closeSync, constants, lstatSync, openSync, readSync, realpathSync, fstatSync } from "node:fs"
import { join, resolve } from "node:path"
import { isSecretFile } from "./rules/sensitive-paths.ts"
import { directoryTargets, leadingCdChain, mayChangeDirectory, mentionsDirectoryChange } from "./rules/shell.ts"

/** Maximum size of a read script (beyond: unverifiable). */
export const SCRIPT_MAX_BYTES = 64 * 1024
const MAX_SESSIONS = 1000
const MAX_FILES_PER_SESSION = 200

/** OpenCode resolution (`core/src/file-access.ts`, `resolvePath`): `~` and `~/` expanded, then relative to the directory. */
export function resolveLike(directory: string, input: string, home?: string): string | undefined {
  if (input === "~" || input.startsWith("~/")) return home ? (input === "~" ? home : join(home, input.slice(2))) : undefined
  return resolve(directory, input)
}

/**
 * Directories from which a shell command's relative paths can start (protected-write rules). Like OpenCode
 * (`core/src/tool/plugin/shell.ts`, verified in 2.0.31): `workdir` resolved from the session directory, otherwise that
 * directory. A single directory when proven: no directory change possible, or leading `cd <path> &&`
 * followed only by `&&` and pipes (`leadingCdChain`). Otherwise all candidates, session directory included:
 * nothing it reported is lost.
 */
export function shellDirectories(command: string, workdir: unknown, directory: string, home?: string): string[] {
  const base = typeof workdir === "string" && workdir ? resolveLike(directory, workdir, home) : directory
  if (base === undefined) return [directory]
  if (!mayChangeDirectory(command)) return [base]
  const lead = leadingCdChain(command)
  const target = lead && resolveLike(base, lead.path, home)
  if (target) return [target]
  return unique([base, directory, ...resolvedTargets(command, [base], home)])
}

/** Directories of the content of an executed script: the command's and the session's, plus its own literal `cd`s. */
export function scriptDirectories(content: string, commandDirectories: readonly string[], directory: string, home?: string): string[] {
  const targets = mentionsDirectoryChange(content) ? resolvedTargets(content, commandDirectories, home) : []
  return unique([...commandDirectories, directory, ...targets])
}

function resolvedTargets(command: string, bases: readonly string[], home?: string): string[] {
  const out: string[] = []
  for (const target of directoryTargets(command))
    for (const base of bases) {
      const absolute = resolveLike(base, target, home)
      if (absolute) out.push(absolute)
    }
  return out
}

const unique = (values: readonly string[]) => [...new Set(values)]

/** Script read by a shell when launched by its path: shell shebang, or no shebang (the shell runs it). */
export function isShellScript(content: string): boolean {
  if (!content.startsWith("#!")) return true
  return /^#!\s*(?:\S*\/)?(?:env\s+(?:-\S+\s+)*)?(?:\S*\/)?(?:sh|bash|zsh|dash|ksh|mksh|ash|yash)(?=\s|$)/.test(content)
}

export interface TrackedFile {
  readonly content: string
  /** Content already judged in full by the decision model: it can be shown to it. */
  readonly judged: boolean
}

/**
 * Cause for which an existing file cannot be checked by tracking: unreadable, or named by a successful `patch`
 * call whose text lacks the OpenCode 2.0.31 grammar (`patch`: another OpenCode version, created, modified, or
 * moved files unknown).
 */
export type UnverifiableCause = "too-large" | "link" | "not-regular" | "credential" | "unreadable" | "patch"

/** File created by the agent, existing, but whose content can no longer be read. */
export interface UnverifiableFile {
  readonly unverifiable: UnverifiableCause
}

export interface RecordCheck {
  /** The call was judged in full by the model (opinion obtained, input not truncated). */
  readonly judged: boolean
  /** Call content: `judged` is kept only if the file is identical to it (BOM ignored). */
  readonly equals?: string
  /** File tracked only if it is identical to `equals` (heredoc: otherwise, something else wrote it). */
  readonly exact?: boolean
  /** Texts the file must contain after a modification (edit, patch): otherwise `judged` is not kept. */
  readonly contains?: readonly string[]
}

export interface ScriptTracker {
  /** Session with at least one tracked or unverifiable file (otherwise no command analysis). */
  has(sessionID: string): boolean
  /** Records the file's fingerprint. True if the file is tracked. */
  record(sessionID: string, path: string, check: RecordCheck): boolean
  /**
   * File tracked by this session: content (changed since by something other than a tracked modification: `judged` false,
   * tracking continues on that content), or cause if it can no longer be read; missing or untracked: nothing (tracking stopped).
   */
  read(sessionID: string, path: string): TrackedFile | UnverifiableFile | undefined
  /** Stops tracking (file deleted, moved, or modified while it was no longer tracked). */
  forget(sessionID: string, path: string): void
  /**
   * Marks an existing file unverifiable (cause `patch`), even if readable, until its tracked rewrite or modification
   * (`record`), its move, or its deletion; missing: tracking stopped. True if the file is marked.
   */
  distrust(sessionID: string, path: string): boolean
}

const withoutBom = (text: string) => (text.startsWith("\uFEFF") ? text.slice(1) : text)

export function createScriptTracker(options: { home?: string; maxBytes?: number } = {}): ScriptTracker {
  const maxBytes = options.maxBytes ?? SCRIPT_MAX_BYTES
  const sessions = new Map<string, Map<string, { digest: string; judged: boolean } | UnverifiableFile>>()
  const digest = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex")

  /**
   * Bytes of a regular file (not a symbolic link, nor a FIFO), at most `maxBytes`, that is not a credential
   * file (given path and real path), or cause of the failure. `O_NOFOLLOW` + `fstat`: no substitution between
   * check and read.
   */
  function load(path: string): { bytes: Buffer } | { failure: UnverifiableCause | "missing" } {
    let fd: number | undefined
    try {
      let stat
      try {
        stat = lstatSync(path)
      } catch (error) {
        const code = (error as { code?: unknown } | undefined)?.code
        return { failure: code === "ENOENT" || code === "ENOTDIR" ? "missing" : "unreadable" }
      }
      if (stat.isSymbolicLink()) return { failure: "link" }
      if (!stat.isFile()) return { failure: "not-regular" }
      if (isSecretFile(path, options.home) || isSecretFile(realpathSync(path), options.home)) return { failure: "credential" }
      fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0))
      if (!fstatSync(fd).isFile()) return { failure: "not-regular" }
      const buffer = Buffer.alloc(maxBytes + 1)
      let length = 0
      while (length < buffer.length) {
        const read = readSync(fd, buffer, length, buffer.length - length, length)
        if (read === 0) break
        length += read
      }
      return length > maxBytes ? { failure: "too-large" } : { bytes: buffer.subarray(0, length) }
    } catch {
      return { failure: "unreadable" }
    } finally {
      if (fd !== undefined)
        try {
          closeSync(fd)
        } catch {}
    }
  }

  /** Session entry (created as needed, limits: the oldest session or oldest file evicted). */
  function store(sessionID: string, path: string, entry: { digest: string; judged: boolean } | UnverifiableFile) {
    let files = sessions.get(sessionID)
    if (!files) {
      if (sessions.size >= MAX_SESSIONS) sessions.delete(sessions.keys().next().value!)
      files = new Map()
      sessions.set(sessionID, files)
    }
    files.delete(path)
    if (files.size >= MAX_FILES_PER_SESSION) files.delete(files.keys().next().value!)
    files.set(path, entry)
  }

  return {
    has: (sessionID) => (sessions.get(sessionID)?.size ?? 0) > 0,
    record(sessionID, path, check) {
      const loaded = load(path)
      if ("failure" in loaded) {
        // Creation established by the tool (write, patch, tracked modification): exists but unreadable → unverifiable.
        // Heredoc (`exact`): only a match with the body would establish that the agent wrote it → nothing kept; an
        // existing entry (already tracked file) remains, and the next read will find it unreadable.
        if (loaded.failure === "missing") sessions.get(sessionID)?.delete(path)
        else if (!check.exact) store(sessionID, path, { unverifiable: loaded.failure })
        return false
      }
      const text = loaded.bytes.toString("utf8")
      const same = check.equals !== undefined && withoutBom(text) === withoutBom(check.equals)
      if (check.exact && !same) return false
      const judged =
        check.judged && (check.equals === undefined || same) && (check.contains ?? []).every((part) => text.includes(part))
      store(sessionID, path, { digest: digest(loaded.bytes), judged })
      return true
    },
    read(sessionID, path) {
      const files = sessions.get(sessionID)
      const entry = files?.get(path)
      if (!files || entry === undefined) return undefined
      const loaded = load(path)
      // Named by an unreadable patch: unverifiable even if readable (no tracked call established its content).
      const distrusted = "unverifiable" in entry && entry.unverifiable === "patch"
      if ("failure" in loaded) {
        if (loaded.failure === "missing") {
          files.delete(path)
          return undefined
        }
        if (distrusted) return { unverifiable: "patch" }
        files.set(path, { unverifiable: loaded.failure })
        return { unverifiable: loaded.failure }
      }
      if (distrusted) return { unverifiable: "patch" }
      const content = loaded.bytes.toString("utf8")
      const current = digest(loaded.bytes)
      if ("digest" in entry && entry.digest === current) return { content, judged: entry.judged }
      // Changed since by something other than a tracked modification, or readable again: current content for the local
      // rules, never shown to the model (it did not judge it).
      files.set(path, { digest: current, judged: false })
      return { content, judged: false }
    },
    forget(sessionID, path) {
      sessions.get(sessionID)?.delete(path)
    },
    distrust(sessionID, path) {
      try {
        lstatSync(path)
      } catch (error) {
        const code = (error as { code?: unknown } | undefined)?.code
        if (code === "ENOENT" || code === "ENOTDIR") {
          sessions.get(sessionID)?.delete(path)
          return false
        }
      }
      store(sessionID, path, { unverifiable: "patch" })
      return true
    },
  }
}
