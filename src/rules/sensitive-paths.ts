// Files typically containing credentials (read → confirmation request)
// and sensitive write locations (persistence, hooks, system, OpenCode config, plugin).
import { isAbsolute, resolve } from "node:path"
import { GUARD_FILE } from "../guard-file.ts"
import type { ActiveRules } from "./features.ts"
import { LIMIT_REACHED } from "./types.ts"

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

/** The plugin's settings, recognized by name wherever they are (a directory known only once expanded included). */
const PROTECTED_WRITE_FILES = new Set(["opencode.json", "opencode.jsonc", GUARD_FILE])

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
  /** The plugin's own directories among `protectedDirs` (they hold its settings); absent: all of them count. */
  readonly pluginDirs?: readonly string[]
  /**
   * Rule policy of the call: only with `selfProtectionByModel` are real paths followed past an OpenCode location to
   * find the plugin's settings (otherwise both stay with the user alike, and nothing more is looked up).
   */
  readonly active?: ActiveRules
  /**
   * Real paths of an absolute path (`real-path.ts`, built per tool call): protected location reached
   * through a symbolic link. Absent: lexical comparison only; `undefined` (unknown): same for that path;
   * `LIMIT_REACHED` (limit): `unchecked` kind, unless self-protection is already recognized.
   */
  readonly realPaths?: (absolute: string) => readonly string[] | undefined | typeof LIMIT_REACHED
  /** Directories of the OpenCode service files (`CredentialContext`): writing one of these files holds its settings. */
  readonly serviceDirs?: readonly string[]
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
   * absent: known names and extensions only; `LIMIT_REACHED`: content not checked (limit).
   */
  readonly credentialContent?: (path: string) => boolean | typeof LIMIT_REACHED
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
 * key recognized by its content; `LIMIT_REACHED`: neither a known name nor a service file, content not checked (limit of
 * the predicate). The content is consulted only if the name is not enough.
 */
export const credentialFile = (raw: string, ctx: CredentialContext): boolean | typeof LIMIT_REACHED =>
  isSecretFile(raw, ctx.home) || isServiceFile(raw, ctx) || (ctx.credentialContent?.(raw) ?? false)

/** Recognized credential file (`credentialFile`); content not checked does not make one. */
export const isCredentialFile = (raw: string, ctx: CredentialContext) => credentialFile(raw, ctx) === true

/** Reason of the ask for content not checked (`credentialFile` returns `LIMIT_REACHED`), path quoted or not. */
export const uncheckedCredentialReason = (path?: string) =>
  `access to a file that could not be checked for a private key${path === undefined ? "" : ` (${path})`}: the plugin's limit on file checks was reached, or the name is too long to check: confirmation required`

export function isProtectedWritePath(raw: string, home?: string, context: WritePathContext = {}): boolean {
  return protectedWriteKind(raw, home, context) !== undefined
}

/**
 * `unchecked`: real path of a form not known, limit reached (`LIMIT_REACHED`); it could lead to self-protection
 * (always active): ranked between it and the plain protected location.
 */
export type WriteKind = "opencode" | "unchecked" | "system"

/**
 * Kind refined for self-protection: `settings` is an `opencode` location that holds the plugin's settings (any
 * `opencode.json`, `opencode.jsonc` or `guard.json`, a configuration directory itself, the plugin directory, the OpenCode
 * service file and its environment) or code OpenCode loads (the `plugin` and `plugins` directories of a configuration
 * directory), or an `opencode` location whose real paths reached a limit (it may lead to them), never left to the
 * decision model (user's decision); `protectedWriteKind` reports it as `opencode`.
 */
export type WriteClass = WriteKind | "settings"

const KIND_RANK: Record<WriteClass, number> = { settings: 4, opencode: 3, unchecked: 2, system: 1 }

/** Reason of the ask for the `unchecked` kind (`self-protection` rule): `subject` designates the write, path quoted or not. */
export const uncheckedWriteReason = (subject: string, path?: string) =>
  `${subject} whose real path could not be fully resolved${path === undefined ? "" : ` (${path})`}: the plugin's limit on link checks was reached, or the path is too long to check, so it could not be compared with OpenCode's configuration, the guard plugin and protected locations: confirmation required`

/**
 * Strictest kind: self-protection, then unchecked real path, then protected location, then nothing (explicit maximum,
 * not the first found).
 */
export function strictestKind<K extends WriteClass>(...kinds: ReadonlyArray<K | undefined>): K | undefined {
  let strictest: K | undefined
  for (const kind of kinds) if (kind !== undefined && (strictest === undefined || KIND_RANK[kind] > KIND_RANK[strictest])) strictest = kind
  return strictest
}

/**
 * Kind of path `p` (`normalizePath` form, or already-resolved absolute path) based on its names, prefixes, and segments, and
 * its absolute forms `absolutes` (protected directories); `settings` among the `opencode` ones.
 */
function kindOf(p: string, absolutes: readonly string[], context: WritePathContext): WriteClass | undefined {
  const base = basename(p)
  const within = (dirs: readonly string[] | undefined) => !!dirs?.length && absolutes.some((absolute) => dirs.some((dir) => absolute === dir || absolute.startsWith(`${dir}/`)))
  if (PROTECTED_WRITE_FILES.has(base) || within(context.pluginDirs ?? context.protectedDirs) || serviceFile(base, absolutes, context)) return "settings"
  // A configuration directory itself (moved or removed with its settings).
  const directory =
    p === "/etc/opencode" || OPENCODE_WRITE_SEGMENTS.some((segment) => p.endsWith(segment.slice(0, -1))) || absolutes.some((absolute) => context.protectedDirs?.includes(absolute))
  if (directory || p.startsWith("/etc/opencode/") || OPENCODE_WRITE_SEGMENTS.some((segment) => p.includes(segment)) || within(context.protectedDirs))
    return directory || NON_LITERAL_NAME.test(base) || pluginSource(p, absolutes, context) ? "settings" : "opencode"
  return systemLocation(p, base) ? "system" : undefined
}

/** Protected location of the `system` kind (startup files, `/etc`, `~/.ssh`, git hooks…), OpenCode's configuration included. */
function systemLocation(p: string, base = basename(p)): boolean {
  return PROTECTED_WRITE_BASENAMES.has(base) || p.startsWith("/etc/") || PROTECTED_WRITE_SEGMENTS.some((segment) => p.includes(segment) || p.endsWith(segment.slice(0, -1)))
}

/** The OpenCode service file (`service.json`, a variant or a backup copy) under a service directory, in one of the `absolutes`. */
function serviceFile(base: string, absolutes: readonly string[], context: WritePathContext): boolean {
  const dirs = context.serviceDirs
  if (!dirs?.length || ![base, ...backupStems(base)].some((name) => SERVICE_BASENAME.test(name))) return false
  return absolutes.some((absolute) => dirs.some((dir) => absolute.startsWith(`${dir}/`)))
}

/** A final name the shell or a program expands (pattern, variable, quotes): it may be any file of its directory. */
const NON_LITERAL_NAME = /[*?[\]{}$`"'\\]/

/** First name under a configuration directory (`/etc/opencode`, `~/.config/opencode`, a `.opencode`, nested ones included). */
const CONFIG_CHILD = /(?:^\/etc\/opencode|\/\.config\/opencode|\/\.opencode)(?=\/([^/]+))/g

/** `plugin` or `plugins`, whose code OpenCode loads, or a name that may expand to them (`NON_LITERAL_NAME`). */
const PLUGIN_SOURCE_NAME = /^plugins?$|[*?[\]{}$`"'\\]/

/**
 * Path at or under the `plugin` or `plugins` directory of a configuration directory: named in `p`, or under a protected
 * directory (OpenCode's global configuration directory resolved from the environment) in one of the `absolutes`.
 */
function pluginSource(p: string, absolutes: readonly string[], context: WritePathContext): boolean {
  for (const match of p.matchAll(CONFIG_CHILD)) if (PLUGIN_SOURCE_NAME.test(match[1]!)) return true
  return absolutes.some((absolute) =>
    (context.protectedDirs ?? []).some((dir) => absolute.startsWith(`${dir}/`) && PLUGIN_SOURCE_NAME.test(absolute.slice(dir.length + 1).split("/")[0]!)),
  )
}

/** `settings` reported as `opencode`. */
const asKind = (kind: WriteClass | undefined): WriteKind | undefined => (kind === "settings" ? "opencode" : kind)

/**
 * Kind of a protected write location: `opencode` (OpenCode configuration, plugin directory: self-protection,
 * always active) or `system` (startup files, `~/.ssh/`, git hooks, `/etc`…: `dangerousCommands` switch).
 * Forms classified: the written form, the form resolved lexically from each base directory and, with `realPaths`,
 * the real paths that differ from it. The strictest wins (`strictestKind`); a form whose real paths reached a limit
 * counts as `unchecked`, and an `opencode` location then as `settings`.
 */
export function protectedWriteKind(raw: string, home?: string, context: WritePathContext = {}): WriteKind | undefined {
  return asKind(protectedWriteClass(raw, home, context))
}

/** Strictest class reached: `settings`, or `opencode` when the call's policy does not tell them apart. */
const reached = (kind: WriteClass | undefined, context: WritePathContext) => kind === "settings" || (kind === "opencode" && !context.active?.selfProtectionByModel)

/**
 * `protectedWriteKind` with `settings`: with `selfProtectionByModel`, real paths are followed until a form holds the
 * plugin's settings (a link from another OpenCode location to them counts).
 */
export function protectedWriteClass(raw: string, home?: string, context: WritePathContext = {}): WriteClass | undefined {
  const { lexical, linked } = writeForms(raw, home, context)
  // Resolved form classified by all families, before real paths: it is the path written by OpenCode
  // tools and, without a link, the kernel (`//`, `.`, `..`, relative path going up, base directory located in
  // the protected location). It remains classified when real paths are unknown (limit, loop).
  let kind = strictestKind(kindOf(normalizePath(raw, home), lexical, context), ...lexical.map((form) => kindOf(form, [form], context)))
  if (reached(kind, context) || !context.realPaths) return kind
  let limited = false
  for (const [index, forms] of linked.entries()) {
    for (const form of forms) {
      const reals = context.realPaths(form)
      if (reals === LIMIT_REACHED) {
        limited = true
        kind = strictestKind(kind, "unchecked")
        continue
      }
      for (const real of reals ?? []) {
        // Identical to the resolved form: already classified.
        if (real === lexical[index]) continue
        kind = strictestKind(kind, kindOf(real, [real], context))
        if (reached(kind, context)) return kind
      }
    }
  }
  return limitedClass(kind, limited)
}

/**
 * Forms of a written path resolved from each base directory: `lexical`, and for each the forms whose real paths count,
 * raw (the shell lets the kernel follow a `..` placed after a link) and normalized (OpenCode tools normalize before
 * writing).
 */
function writeForms(raw: string, home: string | undefined, context: WritePathContext) {
  const expanded = strip(raw).replace(/^(~|\$HOME|\$\{HOME\})(?=\/|$)/, home ?? "~")
  const bases = isAbsolute(expanded) ? ["/"] : context.cwds?.length ? context.cwds : context.cwd ? [context.cwd] : []
  const lexical = bases.map((base) => resolve(base, expanded))
  return { lexical, linked: bases.map((base, index) => [`${base}/${expanded}`, lexical[index]!]) }
}

/**
 * Some form of the path, written, lexical or real, in a `system` location (`protected-write`), whatever the strictest
 * class: `protectedWriteClass` stops at the plugin's settings and ranks OpenCode's configuration first. A limit reached
 * while following real paths finds nothing there (its own ask remains).
 */
export function systemWrite(raw: string, home?: string, context: WritePathContext = {}): boolean {
  const { lexical, linked } = writeForms(raw, home, context)
  if (systemLocation(normalizePath(raw, home)) || lexical.some((form) => systemLocation(form))) return true
  return linked.some((forms) => forms.some((form) => systemReal(form, context)))
}

/** `systemWrite` for the exact form of OpenCode's tools (`exactWriteClass`). */
export const exactSystemWrite = (absolute: string, context: WritePathContext = {}): boolean => systemLocation(absolute) || systemReal(absolute, context)

/** A real path of `form` in a `system` location. */
function systemReal(form: string, context: WritePathContext): boolean {
  const reals = context.realPaths?.(form)
  return reals !== LIMIT_REACHED && (reals ?? []).some((real) => systemLocation(real))
}

/**
 * Class once a limit was reached while following real paths: an `opencode` location may lead to the plugin's settings
 * (a link to them), so it counts as `settings` (only `selfProtectionByModel` follows real paths past an `opencode` one).
 */
const limitedClass = (kind: WriteClass | undefined, limited: boolean): WriteClass | undefined => (limited && kind === "opencode" ? "settings" : kind)

/**
 * Kind of an absolute path as written by OpenCode's `edit`, `write`, and `patch` tools (exact form, computed
 * by the caller): classified as is by all families, without trimming whitespace or quotes or expanding
 * `$HOME` (for OpenCode, a name ending in a space or a quote is a real name), then its real paths.
 */
export function exactWriteKind(absolute: string, context: WritePathContext = {}): WriteKind | undefined {
  return asKind(exactWriteClass(absolute, context))
}

/** `exactWriteKind` with `settings` (like `protectedWriteClass`). */
export function exactWriteClass(absolute: string, context: WritePathContext = {}): WriteClass | undefined {
  let kind = kindOf(absolute, [absolute], context)
  if (reached(kind, context) || !context.realPaths) return kind
  const reals = context.realPaths(absolute)
  if (reals === LIMIT_REACHED) return limitedClass(strictestKind(kind, "unchecked"), true)
  for (const real of reals ?? []) {
    if (real === absolute) continue
    kind = strictestKind(kind, kindOf(real, [real], context))
    if (reached(kind, context)) return kind
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
