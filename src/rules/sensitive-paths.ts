// Files typically containing credentials (read → confirmation request)
// and sensitive write locations (persistence, hooks, system, OpenCode config, plugin).
import { isAbsolute, resolve } from "node:path"

const ENV_SAFE_SUFFIXES = new Set(["example", "sample", "template", "dist", "defaults"])

const SECRET_BASENAMES = new Set([
  ".netrc",
  ".npmrc",
  ".pypirc",
  ".pgpass",
  ".git-credentials",
  "id_rsa",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
])

// `.p8`: PKCS#8 keys (Apple, signing) — also PICO-8 cartridges (read → ask); `.ppk`: PuTTY; `.pk8`:
// Android signing; `.keytab`: Kerberos; `.kdbx`/`.kdb`: KeePass databases; `.heapsnapshot`: V8 heap snapshots (OpenCode
// `debug heap-dump`, Node), a copy of the process memory with the secrets it holds. Not `.asc`/`.crt`/`.cer`/`.gpg`
// (mostly public or encrypted; a private PGP key block is redacted by its content).
const SECRET_EXTENSIONS = [".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".p8", ".ppk", ".pk8", ".keytab", ".kdbx", ".kdb", ".heapsnapshot"]

// Files without a trailing `/` (their `….bak` copies remain targeted), directories with one (a neighboring directory with an extended
// name, `oauth-backup/`, is not). Default locations, whatever the HOME.
const SECRET_SEGMENTS = [
  "/.ssh/",
  "/.gnupg/",
  "/.aws/credentials",
  "/.aws/config",
  "/.kube/config",
  "/.docker/config.json",
  "/.config/gh/hosts.yml",
  // OpenCode: `auth.json` (imported into `opencode.db` by V2), `mcp-auth.json` (cc-safety-net list; absent from
  // the 2.0.29 code), `account.json` (API keys; no longer read by 2.0.29, may remain on disk).
  "/.local/share/opencode/auth.json",
  "/.local/share/opencode/mcp-auth.json",
  "/.local/share/opencode/account.json",
  // Credentials of other coding agents: list adapted from cc-safety-net 2.6.12 (`SECRET_CODING_CLI_RULES`, level
  // "credential"; MIT, © 2026 J Liew).
  "/.claude/.credentials.json",
  "/.codex/auth.json",
  "/.codex/.credentials.json",
  "/.codex/secrets/",
  "/.codex/.sandbox-secrets/",
  "/.gemini/oauth_creds.json",
  "/.gemini/mcp-oauth-tokens.json",
  "/.gemini/a2a-oauth-tokens.json",
  "/.gemini/gemini-credentials.json",
  "/.copilot/config.json",
  "/.copilot/mcp-oauth-config/",
  "/.copilot/mcp-secrets/",
  "/.kimi-code/server.token",
  "/.kimi-code/credentials/",
  "/.kimi/credentials/",
  "/.kimi/mcp-oauth/",
  "/.pi/agent/auth.json",
  "/.local/share/amp/secrets.json",
  "/.amp/oauth/",
  "/.cursor/auth.json",
  "/.config/cursor/auth.json",
  "/.grok/auth.json",
  "/.grok/mcp_credentials.json",
  "/.factory/auth.encrypted",
  "/.factory/auth.v2.file",
  "/.factory/auth.v2.key",
  "/.factory/auth.v2.loginkeychain",
  "/.local/share/devin/credentials.toml",
  "/.local/share/devin/mcp/oauth/",
]

/** Segments without a trailing `/`: the directory itself (`~/.ssh`) is targeted. */
const SECRET_SEGMENT_ENDS = SECRET_SEGMENTS.map((segment) => segment.replace(/\/$/, ""))

// OpenCode V2 database: provider credentials, OAuth tokens of MCP servers and of the account (`credential`
// and `account` tables); one name per channel (`opencode-<channel>.db`). Prefix: `-wal`, `-shm`, `-journal`, and copies included.
// Cursor: per-project MCP tokens. Bounded quantifiers (linear cost on a long word).
const SECRET_PATH_PATTERNS = [
  /\/\.local\/share\/opencode\/opencode(?:-[\w.-]{1,64})?\.db/,
  /\/\.cursor\/projects\/[^/]{1,255}\/mcp-auth\.json/,
]

/**
 * Suffix of a backup copy (cc-safety-net list), anchored at the end of the name: behind it, only forms
 * without a new extension (`.bak1`, `.bak-20261016`, `.bak.2`), otherwise `x.key.tmp.sh` would be a credential name.
 */
const BACKUP_SUFFIX = /\.(?:bak|backup|copy|disabled|old|orig|save|tmp)\d*(?:[-_][\w-]*|\.[\d-]+)?$/i

/** Longest file name on Linux: beyond it, no stem (bounded cost). */
const NAME_MAX = 255

const PROTECTED_WRITE_BASENAMES = new Set([
  ".bashrc",
  ".bash_profile",
  ".bash_login",
  ".profile",
  ".zshrc",
  ".zprofile",
  ".zshenv",
  ".zlogin",
])

const PROTECTED_WRITE_SEGMENTS = [
  "/.ssh/",
  "/.git/hooks/",
  "/.config/autostart/",
  "/.config/systemd/",
]

/** OpenCode config: the agent must not be able to disable the guardrail without confirmation. */
const OPENCODE_WRITE_SEGMENTS = ["/.config/opencode/", "/.opencode/"]

const PROTECTED_WRITE_FILES = new Set(["opencode.json", "opencode.jsonc"])

export interface WritePathContext {
  /** Working directory for resolving relative paths. */
  readonly cwd?: string
  /**
   * Possible directories of a shell command (`shellDirectories`): a relative path is protected if it is from one
   * of them. Absent or empty: `cwd`.
   */
  readonly cwds?: readonly string[]
  /** Absolute directories protected against writes (e.g. plugin directory, hot-reloaded). */
  readonly protectedDirs?: readonly string[]
  /**
   * Real paths of an absolute path (`real-path.ts`, built per tool call): protected location reached
   * through a symbolic link. Absent: lexical comparison only; `undefined` (unknown): same for that path.
   */
  readonly realPaths?: (absolute: string) => readonly string[] | undefined
}

const QUOTES = "\"'`"

/** OpenCode service files: `service.json`, `service-<channel>.json` (server password, environment). */
const SERVICE_BASENAME = /^service(?:-[\w.-]+)?\.json$/

/** Quotes removed at both ends, using loops (a repeated class anchored at the end costs quadratic time). */
function strip(raw: string): string {
  const text = raw.trim()
  let start = 0
  let end = text.length
  while (start < end && QUOTES.includes(text[start]!)) start++
  while (end > start && QUOTES.includes(text[end - 1]!)) end--
  return start === 0 && end === text.length ? text : text.slice(start, end)
}

/** Normalizes `~`, `$HOME`, `${HOME}`, and separators; adds a leading `/` for segment tests. */
export function normalizePath(raw: string, home?: string): string {
  let p = strip(raw).replace(/\\/g, "/")
  const h = home ?? "~"
  p = p.replace(/^(~|\$HOME|\$\{HOME\})(?=\/|$)/, h)
  return p.startsWith("/") ? p : `/${p}`
}

function basename(p: string): string {
  const parts = p.split("/").filter(Boolean)
  return parts[parts.length - 1] ?? ""
}

/** Credential names (path `p` locates `service.json`). */
function isSecretBasename(base: string, p: string): boolean {
  if (base === ".env") return true
  if (base.startsWith(".env.")) return !ENV_SAFE_SUFFIXES.has(base.slice(5).toLowerCase())
  if (SECRET_BASENAMES.has(base)) return true
  // OpenCode service: server password (access to its API) and environment variables (decision model key).
  if (SERVICE_BASENAME.test(base) && (p.includes("/.config/opencode/") || p.includes("/.local/state/opencode/"))) return true
  if (/^id_(rsa|dsa|ecdsa|ed25519)(?!\.pub$)/.test(base)) return true
  return SECRET_EXTENSIONS.some((ext) => base.toLowerCase().endsWith(ext))
}

/** Names of which `base` is a backup copy: `.netrc.bak` → `.netrc`, `.netrc.old.bak` → `.netrc.old`, `.netrc`. */
function backupStems(base: string): string[] {
  const stems: string[] = []
  if (base.length > NAME_MAX) return stems
  let stem = base
  for (let round = 0; round < 3; round++) {
    let end = stem.length
    while (end > 0 && stem[end - 1] === "~") end--
    const trimmed = stem.slice(0, end)
    const match = BACKUP_SUFFIX.exec(trimmed)
    const next = match ? trimmed.slice(0, match.index) : trimmed
    if (next === stem || next === "") break
    stems.push(next)
    stem = next
  }
  return stems
}

export function isSecretFile(raw: string, home?: string): boolean {
  const p = normalizePath(raw, home)
  const base = basename(p)
  if (isSecretBasename(base, p)) return true
  // Segments and patterns all start with `/.`: test avoided for most words of a command.
  if (p.includes("/.")) {
    if (SECRET_SEGMENTS.some((segment, index) => p.includes(segment) || p.endsWith(SECRET_SEGMENT_ENDS[index]!))) return true
    if (SECRET_PATH_PATTERNS.some((pattern) => pattern.test(p))) return true
  }
  return backupStems(base).some((stem) => isSecretBasename(stem, p))
}

export interface CredentialContext {
  readonly home?: string
  /**
   * Private key recognized by its content (`credential-content.ts`, built per tool call with its directories);
   * absent: known names and extensions only.
   */
  readonly credentialContent?: (path: string) => boolean
  /**
   * Directories of the OpenCode service files resolved from the server environment (`OPENCODE_CONFIG_DIR`,
   * `XDG_CONFIG_HOME`, `XDG_STATE_HOME`): `service.json` recognized under them, not only under the default directories.
   */
  readonly serviceDirs?: readonly string[]
}

/** `service.json` (or a backup copy) under a service directory resolved from the environment. */
function isServiceFile(raw: string, ctx: CredentialContext): boolean {
  if (!ctx.serviceDirs?.length) return false
  const p = normalizePath(raw, ctx.home)
  if (!ctx.serviceDirs.some((dir) => p.startsWith(`${dir}/`))) return false
  const base = basename(p)
  return [base, ...backupStems(base)].some((name) => SERVICE_BASENAME.test(name))
}

/**
 * Credential file: known name or extension (`isSecretFile`), `service.json` under a service directory, or private
 * key recognized by its content.
 */
export const isCredentialFile = (raw: string, ctx: CredentialContext) =>
  isSecretFile(raw, ctx.home) || isServiceFile(raw, ctx) || ctx.credentialContent?.(raw) === true

export function isProtectedWritePath(raw: string, home?: string, context: WritePathContext = {}): boolean {
  return protectedWriteKind(raw, home, context) !== undefined
}

export type WriteKind = "opencode" | "system"

const KIND_RANK: Record<WriteKind, number> = { opencode: 2, system: 1 }

/** Strictest kind: self-protection, then protected location, then nothing (explicit maximum, not the first found). */
export function strictestKind(...kinds: ReadonlyArray<WriteKind | undefined>): WriteKind | undefined {
  let strictest: WriteKind | undefined
  for (const kind of kinds) if (kind !== undefined && (strictest === undefined || KIND_RANK[kind] > KIND_RANK[strictest])) strictest = kind
  return strictest
}

/**
 * Kind of path `p` (`normalizePath` form, or already-resolved absolute path) based on its names, prefixes, and segments, and
 * its absolute forms `absolutes` (protected directories).
 */
function kindOf(p: string, absolutes: readonly string[], protectedDirs: readonly string[] | undefined): WriteKind | undefined {
  const base = basename(p)
  if (PROTECTED_WRITE_FILES.has(base) || p === "/etc/opencode" || p.startsWith("/etc/opencode/")) return "opencode"
  if (OPENCODE_WRITE_SEGMENTS.some((segment) => p.includes(segment) || p.endsWith(segment.slice(0, -1)))) return "opencode"
  if (protectedDirs?.length && absolutes.some((absolute) => protectedDirs.some((dir) => absolute === dir || absolute.startsWith(`${dir}/`))))
    return "opencode"
  if (PROTECTED_WRITE_BASENAMES.has(base) || p.startsWith("/etc/")) return "system"
  if (PROTECTED_WRITE_SEGMENTS.some((segment) => p.includes(segment) || p.endsWith(segment.slice(0, -1)))) return "system"
  return undefined
}

/**
 * Kind of a protected write location: `opencode` (OpenCode configuration, plugin directory: self-protection,
 * always active) or `system` (startup files, `~/.ssh/`, git hooks, `/etc`…: `dangerousCommands` switch).
 * Forms classified: the written form, the form resolved lexically from each base directory and, with `realPaths`,
 * the real paths that differ from it. The strictest wins (`strictestKind`).
 */
export function protectedWriteKind(raw: string, home?: string, context: WritePathContext = {}): WriteKind | undefined {
  const expanded = strip(raw).replace(/^(~|\$HOME|\$\{HOME\})(?=\/|$)/, home ?? "~")
  const bases = isAbsolute(expanded) ? ["/"] : context.cwds?.length ? context.cwds : context.cwd ? [context.cwd] : []
  const lexical = bases.map((base) => resolve(base, expanded))
  // Resolved form classified by all families, before real paths: it is the path written by OpenCode
  // tools and, without a link, the kernel (`//`, `.`, `..`, relative path going up, base directory located in
  // the protected location). It remains classified when real paths are unknown (limit, loop).
  let kind = strictestKind(
    kindOf(normalizePath(raw, home), lexical, context.protectedDirs),
    ...lexical.map((form) => kindOf(form, [form], context.protectedDirs)),
  )
  if (kind === "opencode" || !context.realPaths) return kind
  // Raw form (the shell lets the kernel follow a `..` placed after a link) and normalized form (OpenCode tools
  // normalize before writing).
  for (const [index, base] of bases.entries()) {
    for (const form of [`${base}/${expanded}`, lexical[index]!]) {
      for (const real of context.realPaths(form) ?? []) {
        // Identical to the resolved form: already classified.
        if (real === lexical[index]) continue
        kind = strictestKind(kind, kindOf(real, [real], context.protectedDirs))
        if (kind === "opencode") return kind
      }
    }
  }
  return kind
}

/**
 * Kind of an absolute path as written by OpenCode's `edit`, `write`, and `patch` tools (exact form, computed
 * by the caller): classified as is by all families, without trimming whitespace or quotes or expanding
 * `$HOME` (for OpenCode, a name ending in a space or a quote is a real name), then its real paths.
 */
export function exactWriteKind(absolute: string, context: WritePathContext = {}): WriteKind | undefined {
  let kind = kindOf(absolute, [absolute], context.protectedDirs)
  if (kind === "opencode" || !context.realPaths) return kind
  for (const real of context.realPaths(absolute) ?? []) {
    if (real === absolute) continue
    kind = strictestKind(kind, kindOf(real, [real], context.protectedDirs))
    if (kind === "opencode") return kind
  }
  return kind
}

/** Splits a command into candidate words (paths) for the sensitive file search. */
export function pathTokens(command: string): string[] {
  return command
    .split(/[\s'"`;|&<>()=,]+/)
    .map((token) => token.replace(/^-[^@]*@/, "").replace(/^@/, "")) // curl -d @file, -d@file
    .filter((token) => token.length > 0 && !token.startsWith("-"))
}
