// OpenCode secrets with no recognizable format (OpenCode 2.1.1): the service password and the remote access
// route, read from the service files; credential export values and the pairing code, recognized
// by their format then learned (redacted everywhere afterwards, until restart).
import { closeSync, constants, fstatSync, openSync, readdirSync, readSync } from "node:fs"
import { join } from "node:path"
import { entropy, type SecretPattern } from "./patterns.ts"

export type NamedSecret = { readonly name: string; readonly value: string }

/**
 * Service file directories, like OpenCode 2.1.1 (`util/src/global-roots.ts`): configuration
 * (`cli/src/services/service-config.ts`, password and route; `OPENCODE_CONFIG_DIR` replaces it when
 * set, `util/src/global.ts`, the default directory is kept in addition) and state (service registration file,
 * with the password: `client/src/effect/service.ts`); server environment.
 */
export function serviceDirectories(env: Record<string, string | undefined>): string[] {
  const home = env.HOME
  const config = env.XDG_CONFIG_HOME || (home ? join(home, ".config") : undefined)
  const state = env.XDG_STATE_HOME || (home ? join(home, ".local", "state") : undefined)
  const dirs = [config, state].flatMap((dir) => (dir ? [join(dir, "opencode")] : []))
  return [...new Set([...(env.OPENCODE_CONFIG_DIR ? [env.OPENCODE_CONFIG_DIR] : []), ...dirs])]
}

// `service.json` (latest, dev, beta, next channels), `service-<channel>.json`, former `service-<fingerprint>.json`.
const SERVICE_FILE = /^service(?:-[A-Za-z0-9._-]+)?\.json$/
const MAX_SERVICE_FILE = 1 << 20
/** Service values kept at most (like the redactor's learned values). */
export const MAX_SERVICE_SECRETS = 1000
const MAX_SERVICE_FILES = 32

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value)

function secretsOf(data: unknown): NamedSecret[] {
  if (!isRecord(data)) return []
  const out: NamedSecret[] = []
  if (typeof data.password === "string" && data.password) out.push({ name: "service-password", value: data.password })
  if (isRecord(data.remote) && typeof data.remote.route === "string" && data.remote.route)
    out.push({ name: "remote-route", value: data.remote.route })
  return out
}

/**
 * Reads a service file if it changed: non-blocking open (a named pipe put in its place does not freeze the server),
 * then check and bounded read on the same descriptor (no race between check and read). Returns
 * `undefined` for a file to ignore or unchanged; throws on a read error.
 */
function readChanged(file: string, previous: string | undefined): { signature: string; text: string } | undefined {
  const fd = openSync(file, constants.O_RDONLY | constants.O_NONBLOCK)
  try {
    const stat = fstatSync(fd)
    if (!stat.isFile() || stat.size > MAX_SERVICE_FILE) return undefined
    const signature = `${stat.ino}:${stat.mtimeMs}:${stat.size}`
    if (signature === previous) return undefined
    // Seen size plus one byte: a file that grows during the read is ignored, and re-read on the next task
    // (signature not kept).
    const buffer = Buffer.alloc(stat.size + 1)
    let length = 0
    for (let n; length < buffer.length && (n = readSync(fd, buffer, length, buffer.length - length, null)) > 0; )
      length += n
    if (length > stat.size) return undefined
    return { signature, text: buffer.toString("utf8", 0, length) }
  } finally {
    closeSync(fd)
  }
}

/**
 * Source of the service secrets for `createRedactor` (`runtimeSecrets`). A file is re-read when it changes (OpenCode
 * writes it through a renamed temporary file: new inode); the check is done once per synchronous task, which
 * covers the password created during the tool call. A failed read or parse keeps the values already seen
 * (re-read on the next call), and a seen value stays redacted until restart (old password in the history).
 * Returns the same array as long as nothing new has been seen.
 */
export function serviceSecretSource(dirs: readonly string[]): () => readonly NamedSecret[] {
  const seen = new Map<string, string>()
  const signatures = new Map<string, string>()
  let list: readonly NamedSecret[] = []
  let checked = false
  return () => {
    if (checked) return list
    checked = true
    queueMicrotask(() => {
      checked = false
    })
    let added = false
    for (const dir of dirs) {
      let names: string[]
      try {
        names = readdirSync(dir)
      } catch {
        continue
      }
      // Bounded number of files read (one check per file and per task); `service.json` first.
      const files = names.filter((name) => SERVICE_FILE.test(name) && name !== "service.json").sort()
      if (names.includes("service.json")) files.unshift("service.json")
      for (const name of files.slice(0, MAX_SERVICE_FILES)) {
        const file = join(dir, name)
        let read: { signature: string; text: string } | undefined
        let data: unknown
        try {
          read = readChanged(file, signatures.get(file))
          if (!read) continue
          data = JSON.parse(read.text)
        } catch {
          continue
        }
        signatures.set(file, read.signature)
        for (const secret of secretsOf(data)) {
          if (seen.has(secret.value)) continue
          // Bounded memory (files endlessly rewritten by an external writer): the oldest value gives way,
          // never the new one (the current password matters more than an old one left in the history).
          if (seen.size >= MAX_SERVICE_SECRETS) seen.delete(seen.keys().next().value!)
          seen.set(secret.value, secret.name)
          added = true
        }
      }
    }
    if (added) list = [...seen].map(([value, name]) => ({ name, value }))
    return list
  }
}

// Credential value: JSON string shaped like a token (characters of keys, OAuth tokens, and JWTs, without
// whitespace or escapes), at least 20 characters, captured without its quotes. The field name precedes each look
// behind: under Bun, a lookbehind at the start would be tried at every position.
const TOKEN_STRING = String.raw`"(?<secret>[A-Za-z0-9._~+/=:-]{20,4096})"`
const acceptRandom = (value: string) => entropy(value) >= 3
// A learned value is then redacted everywhere, including in what the decision model receives: neither a keyboard
// shortcut, nor an address, nor most paths, host names, and word names, which a text written in this format would
// otherwise make it learn. The rules follow key alphabets: standard base64 (the only one with `/`) never mixes `/`
// with `.`, `_`, `-`, `~`, or `:`; a dot appears only in JWTs and dotted-prefix tokens, with uppercase letters and
// digits; a key without uppercase (hexadecimal, lowercase alphanumeric, UUID) has a long segment with a digit.
// Shortcut: the whole value is made of short words separated by `+` or `-`, including a modifier (a random key
// that happens to contain such a word between dashes is not discarded).
const SHORTCUT_SHAPE = /^(?:[A-Za-z0-9]{1,16}[+-]){1,5}[A-Za-z0-9]{1,16}$/
const MODIFIER = /(?:^|[+-])(?:ctrl|control|alt|option|opt|shift|meta|cmd|command|super|win|hyper|mod)(?:[+-]|$)/i
const isShortcut = (value: string) => SHORTCUT_SHAPE.test(value) && MODIFIER.test(value)
function acceptToken(value: string): boolean {
  if (!acceptRandom(value) || isShortcut(value) || value.includes("://") || value.startsWith("~")) return false
  const upper = /[A-Z]/.test(value)
  const digit = /\d/.test(value)
  if (value.includes("/") && !(/^[A-Za-z0-9+/=]+$/.test(value) && upper && digit)) return false
  if (value.includes(".") && !(upper && digit)) return false
  return upper || (digit && value.split(/[-_.:]/).some((part) => part.length >= 12 && /\d/.test(part)))
}

/**
 * OpenCode 2.1.1 formats whose value is learned (`learn`):
 * - credential entry of the export and of the API list (`schema/src/credential.ts`): `key` in an object of type
 *   `key`, `refresh` and `access` in an object of type `oauth`, in both orders, object without nested braces
 *   up to the field; value shaped like a token (see `acceptToken`);
 * - pairing code (`server/src/pairing.ts`, 22 base64url characters) in an `/auth/connect/<code>` link and in the
 *   API response (`code` next to `expires_in`).
 * The pairing QR code (half-blocks from `uqr`, margin 2: `cli/src/commands/handlers/pair.ts`) is replaced as a
 * whole: at least 10 lines of at least 20 characters after the first block, made only of blocks and spaces; the
 * smallest real rendering (code and addresses in JSON, at least 21 modules) exceeds them, a histogram of a few lines
 * does not (each line scanned once, without an overlapping final class).
 */
export const OPENCODE_PATTERNS: readonly SecretPattern[] = [
  {
    type: "opencode_credential",
    hint: /"type"/,
    regex: new RegExp(String.raw`"key"(?<="type"\s*:\s*"key"[^{}]{0,400}"key")\s*:\s*` + TOKEN_STRING, "g"),
    accept: acceptToken,
    learn: true,
  },
  {
    type: "opencode_credential",
    hint: /"type"/,
    regex: new RegExp(String.raw`"key"\s*:\s*` + TOKEN_STRING + String.raw`(?=[^{}]{0,400}"type"\s*:\s*"key")`, "g"),
    accept: acceptToken,
    learn: true,
  },
  {
    type: "opencode_credential",
    hint: /"type"/,
    regex: new RegExp(
      String.raw`"(?:refresh|access)"(?<="type"\s*:\s*"oauth"[^{}]{0,600}"(?:refresh|access)")\s*:\s*` + TOKEN_STRING,
      "g",
    ),
    accept: acceptToken,
    learn: true,
  },
  {
    type: "opencode_credential",
    hint: /"type"/,
    regex: new RegExp(
      String.raw`"(?:refresh|access)"\s*:\s*` + TOKEN_STRING + String.raw`(?=[^{}]{0,600}"type"\s*:\s*"oauth")`,
      "g",
    ),
    accept: acceptToken,
    learn: true,
  },
  {
    type: "opencode_pairing",
    hint: /\/auth\/connect\//,
    regex: /\/auth\/connect\/(?<secret>[A-Za-z0-9_-]{22})(?![A-Za-z0-9_-])/g,
    accept: acceptRandom,
    learn: true,
  },
  {
    type: "opencode_pairing",
    hint: /"expires_in"/,
    regex: /"code"(?<="expires_in"[^{}]{0,200}"code")\s*:\s*"(?<secret>[A-Za-z0-9_-]{22})"/g,
    accept: acceptRandom,
    learn: true,
  },
  {
    type: "opencode_pairing",
    hint: /"expires_in"/,
    regex: /"code"\s*:\s*"(?<secret>[A-Za-z0-9_-]{22})"(?=[^{}]{0,200}"expires_in")/g,
    accept: acceptRandom,
    learn: true,
  },
  { type: "qr_code", hint: /[█▀▄]/, regex: /(?:^ *[█▀▄][█▀▄ ]{19,}\n){9,}^ *[█▀▄][█▀▄ ]{19,}$/gm },
]
