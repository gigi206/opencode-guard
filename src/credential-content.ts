// Private keys recognized by their content, whatever their name: complements the known names and extensions of
// `isSecretFile`. Local rules stay pure: they receive the predicate built here, per tool call.
// Bounded read (first 4 KiB of a regular file), never kept, logged, or sent.
import { closeSync, constants, fstatSync, openSync, readSync, statSync } from "node:fs"
import { LIMIT_REACHED } from "./rules/types.ts"
import { resolveLike } from "./scripts.ts"

/** Bytes read at the start of the file: a key header is on the first line (after any attributes). */
const HEAD_BYTES = 4096
/** Lookups (`stat`) per tool call: a missing file costs only a few microseconds. */
export const MAX_LOOKUPS = 2048
/** Regular files actually opened per tool call. */
export const MAX_OPENED = 128

/** PEM private key header (RSA, EC, DSA, OpenSSH, encrypted or unencrypted PKCS#8, SSH2), private PGP block, or PuTTY. */
const PRIVATE_KEY_LINE = /^\s*(?:-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----|PuTTY-User-Key-File-\d)/
/** Start of a file that is a JSON object. */
const JSON_OBJECT = /^\s*\{/
/** A key in such a file (a Google service account file): its `private_key` value, wherever it stands in the head. */
const JSON_PRIVATE_KEY = /"private_key"\s*:\s*"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----/
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
 * complete PEM blocks (certificate before the key), or the file is a JSON object with a `private_key`. A header
 * quoted in code or a document (test data) does not count. A single pass over the lines of the read header.
 */
export function hasPrivateKeyHeader(head: string): boolean {
  if (JSON_OBJECT.test(head) && JSON_PRIVATE_KEY.test(head)) return true
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

/** What OpenCode's `read` sends as an attachment, from the first bytes as it does (read in OpenCode 2.2.5), whatever the name. */
export function attachedKind(head: string): "document" | "image" | undefined {
  if (head.startsWith("%PDF-")) return "document"
  const webp = head.startsWith("RIFF") && head.startsWith("WEBP", 8)
  return head.startsWith("\x89PNG\r\n\x1a\n") || head.startsWith("\xff\xd8\xff") || head.startsWith("GIF8") || webp ? "image" : undefined
}

export interface CredentialContentOptions {
  /** Directories from which relative paths start (`shellDirectories` for the shell, the session directory otherwise). */
  readonly directories: readonly string[]
  readonly home?: string
  readonly io?: ContentIo
}

/**
 * Predicate for a tool call: true if the token denotes a regular file starting with a private key. Literal tokens
 * only (no variable, wildcard, substitution, URL, or `~user`); `/dev`, `/proc`, and `/sys` ignored.
 * `LIMIT_REACHED`: literal token of more than 1,024 characters, or check interrupted by a limit before finding;
 * the caller asks. Results memoized.
 */
export function createCredentialContent(options: CredentialContentOptions): (token: string) => boolean | typeof LIMIT_REACHED {
  const io = options.io ?? nodeIo
  const seen = new Map<string, boolean | typeof LIMIT_REACHED>()
  let lookups = 0
  let opened = 0
  return (token) => {
    const known = seen.get(token)
    if (known !== undefined) return known
    const literal = !/[$`*?[\]{}\\]|:\/\//.test(token) && !/^~[^/]/.test(token)
    let found: boolean | typeof LIMIT_REACHED = literal && token.length > 1024 ? LIMIT_REACHED : false
    if (literal && token.length <= 1024) {
      for (const directory of token.startsWith("/") ? ["/"] : options.directories) {
        const path = resolveLike(directory, token, options.home)
        if (!path || /^\/(?:dev|proc|sys)(?:\/|$)/.test(path)) continue
        if (lookups >= MAX_LOOKUPS || opened >= MAX_OPENED) {
          found = LIMIT_REACHED
          break
        }
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

/**
 * Kind of attachment of the regular file `read` names, from each directory, within the bounds of `createCredentialContent`;
 * past them, or for a longer path, `undefined`: the name alone decides.
 */
export function createAttachmentKind(options: CredentialContentOptions): (path: string) => "document" | "image" | undefined {
  const io = options.io ?? nodeIo
  let lookups = 0
  let opened = 0
  return (path) => {
    if (path.length > 1024) return undefined
    for (const directory of path.startsWith("/") ? ["/"] : options.directories) {
      const absolute = resolveLike(directory, path, options.home)
      if (!absolute || /^\/(?:dev|proc|sys)(?:\/|$)/.test(absolute)) continue
      if (lookups >= MAX_LOOKUPS || opened >= MAX_OPENED) return undefined
      lookups++
      try {
        if (!io.stat(absolute).isFile()) continue
      } catch {
        continue
      }
      opened++
      const head = readHead(absolute, io)
      const kind = head === undefined ? undefined : attachedKind(head)
      if (kind) return kind
    }
    return undefined
  }
}
