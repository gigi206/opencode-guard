// Private keys recognized by their content, whatever their name: complements the known names and extensions of
// `isSecretFile`. Local rules stay pure: they receive the predicate built here, per tool call.
// Bounded read (first 4 KiB of a regular file), never kept, logged, or sent.
import { closeSync, constants, fstatSync, openSync, readSync, statSync } from "node:fs"
import { resolveLike } from "./scripts.ts"

/** Bytes read at the start of the file: a key header is on the first line (after any attributes). */
const HEAD_BYTES = 4096
/** Lookups (`stat`) per tool call: a missing file costs only a few microseconds. */
export const MAX_LOOKUPS = 512
/** Regular files actually opened per tool call. */
export const MAX_OPENED = 32

/** PEM private key header (RSA, EC, DSA, OpenSSH, encrypted or unencrypted PKCS#8, SSH2), private PGP block, or PuTTY. */
const PRIVATE_KEY_LINE = /^\s*(?:-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----|PuTTY-User-Key-File-\d)/
const PEM_BEGIN = /^-----BEGIN [A-Z0-9 ]{1,60}-----\s*$/
const PEM_END = /^-----END [A-Z0-9 ]{1,60}-----\s*$/
/** Lines OpenSSL writes before an exported key: attributes, their indented continuations, subject and issuer. */
const EXPORT_ATTRIBUTE = /^(?:Bag|Key) Attributes\b|^(?:subject|issuer)=|^\s/

/** File operations (injectable for tests). */
export interface ContentIo {
  readonly stat: (path: string) => { isFile(): boolean }
  readonly open: (path: string) => number
  readonly isFile: (fd: number) => boolean
  readonly read: (fd: number, buffer: Buffer) => number
  readonly close: (fd: number) => void
}

const nodeIo: ContentIo = {
  stat: (path) => statSync(path),
  open: (path) => openSync(path, constants.O_RDONLY | constants.O_NONBLOCK),
  isFile: (fd) => fstatSync(fd).isFile(),
  read: (fd, buffer) => readSync(fd, buffer, 0, buffer.length, 0),
  close: (fd) => closeSync(fd),
}

/**
 * Start of a file already recognized as regular by `stat` (the caller never opens it otherwise: opening a named pipe
 * would unblock a waiting writer); the check is repeated on the descriptor (race between the two).
 * `undefined`: no longer a regular file, or error.
 */
function readHead(path: string, io: ContentIo): string | undefined {
  let fd: number | undefined
  try {
    fd = io.open(path)
    if (!io.isFile(fd)) return undefined
    const buffer = Buffer.alloc(HEAD_BYTES)
    return buffer.toString("latin1", 0, io.read(fd, buffer))
  } catch {
    return undefined
  } finally {
    if (fd !== undefined)
      try {
        io.close(fd)
      } catch {
        // Descriptor already invalid: nothing to do.
      }
  }
}

/**
 * Key file: the header opens the file, preceded only by blank lines, OpenSSL-exported attributes, or
 * complete PEM blocks (certificate before the key). A header quoted in code or a document (test data) does
 * not count. A single pass over the lines of the read header.
 */
export function hasPrivateKeyHeader(head: string): boolean {
  let block = false
  for (const raw of head.split("\n")) {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw
    if (block) {
      if (PEM_END.test(line)) block = false
      continue
    }
    if (line.trim() === "") continue
    if (PRIVATE_KEY_LINE.test(line)) return true
    if (PEM_BEGIN.test(line)) block = true
    else if (!EXPORT_ATTRIBUTE.test(line)) return false
  }
  return false
}

export interface CredentialContentOptions {
  /** Directories from which relative paths start (`shellDirectories` for the shell, the session directory otherwise). */
  readonly directories: readonly string[]
  readonly home?: string
  readonly io?: ContentIo
}

/**
 * Predicate for a tool call: true if the token denotes a regular file starting with a private key. Literal tokens
 * only (no variable, wildcard, substitution, URL, or `~user`, at most 1,024 characters);
 * `/dev`, `/proc`, and `/sys` ignored; beyond the limits, only known names count. Results memoized.
 */
export function createCredentialContent(options: CredentialContentOptions): (token: string) => boolean {
  const io = options.io ?? nodeIo
  const seen = new Map<string, boolean>()
  let lookups = 0
  let opened = 0
  return (token) => {
    const known = seen.get(token)
    if (known !== undefined) return known
    let found = false
    if (token.length <= 1024 && !/[$`*?[\]{}\\]|:\/\//.test(token) && !/^~[^/]/.test(token)) {
      for (const directory of token.startsWith("/") ? ["/"] : options.directories) {
        const path = resolveLike(directory, token, options.home)
        if (!path || /^\/(?:dev|proc|sys)(?:\/|$)/.test(path)) continue
        if (lookups >= MAX_LOOKUPS || opened >= MAX_OPENED) break
        lookups++
        let regular = false
        try {
          regular = io.stat(path).isFile()
        } catch {
          // Missing or unreadable.
        }
        if (!regular) continue
        opened++
        const head = readHead(path, io)
        if (head !== undefined && hasPrivateKeyHeader(head)) {
          found = true
          break
        }
      }
    }
    seen.set(token, found)
    return found
  }
}
