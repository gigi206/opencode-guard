import { posix } from "node:path"
import { containsEncodedPlaceholder, PLACEHOLDER_RE, type Redactor } from "../secrets/redact.ts"
import { decodeUnicodeEscapes, NETWORK_FUNCTION } from "./code-network.ts"
import { ruleEnabled, type ActiveRules } from "./features.ts"
import { isCredentialFile, pathTokens, protectedWriteKind, type CredentialContext, type WritePathContext } from "./sensitive-paths.ts"
import { mostSevere, type CustomRule, type Finding } from "./types.ts"

export interface ShellRuleContext extends WritePathContext, CredentialContext {
  readonly redactor: Redactor
  readonly home?: string
  readonly custom?: readonly CustomRule[]
  /** `dangerousCommands` / `sensitiveFiles` switches: a disabled rule is not evaluated; absent = all. */
  readonly active?: ActiveRules
}

/**
 * Isolated word: start, or after a space, a separator, a substitution (argument included) or an attached `{`
 * (zsh runs `{sudo …}`), but not `${…}`.
 */
const word = (names: string) => new RegExp(`(?:^|[\\s;&|(\`]|(?<!\\$)\\{)(?:${names})(?=\\s|$|[;&|)])`)

/**
 * Long option, abbreviations included (`--rec` for `--recursive`): getopt_long (GNU coreutils), clap (Rust coreutils) and
 * git accept any unambiguous prefix. Single-letter prefixes count: if ambiguous, the tool fails (one ask
 * too many, never a missed deny).
 */
export function isLongOption(token: string, name: string): boolean {
  if (!token.startsWith("--")) return false
  const given = token.slice(2).split("=")[0]!
  return given.length > 0 && name.startsWith(given)
}

/** Same test as an expression (regex rules): `--r(?:e(?:c…)?)?`, followed by an option end (neither a letter nor `-`). */
export function longOptionPattern(name: string): string {
  const chars = [...name]
  let tail = ""
  for (let i = chars.length - 1; i >= 1; i--) tail = `(?:${chars[i]}${tail})?`
  return `--${chars[0]}${tail}(?![\\w-])`
}

const NETWORK_TOOLS = "curl|wget|nc|ncat|netcat|socat|telnet|ftp|lftp|sftp|scp|rsync|ssh|http|https|xh|aria2c|mail|sendmail|mutt"

/** Network tool name anywhere, even as an argument (`grep http .env`): enough only to ask. */
const NETWORK_WORD = word(NETWORK_TOOLS)

const WRAPPERS = "sudo|doas|env|command|exec|nohup|time|timeout|nice|ionice|stdbuf|xargs|watch|setsid|torsocks|proxychains4?|unbuffer"

/** Path before a command name; does not cross separators (linear cost). */
const COMMAND_PATH = "(?:[^\\s;&|()`{}]*/)?"

/**
 * Launched command (not a mere argument): start, after a separator, `(`, `$(`, a backtick,
 * `sh -c "…"` or `find -exec`; possibly behind a wrapper (sudo, timeout, xargs…) and at most
 * 8 arguments (bound: otherwise quadratic cost on a booby-trapped command; beyond it, a plain ask), with a
 * path (`/usr/bin/curl`), a bypassed alias (`\curl`) or zsh's `=curl` (command path); never
 * after an identifier (`PAGER=less` is not run). `after`: tail required after the name. `lineBlanks`: the blanks
 * after the opener do not absorb the newline, which is itself an opener (same result; without it, each newline in a
 * long tail rescans it, quadratic cost).
 */
const commandRegex = (names: string, after = "(?=\\s|$|[;&|)])", lineBlanks = false) =>
  new RegExp(
    `(?:^|[;&|(\`\\n{]|-[a-zA-Z]*c\\s+["']|-(?:exec|execdir|ok|okdir)\\s+)${lineBlanks ? "[^\\S\\n]*" : "\\s*"}` +
      `(?:[\\\\=]?${COMMAND_PATH}(?:${WRAPPERS})(?:\\s+[^\\s;&|]+){0,8}?\\s+)?` +
      `[\\\\=]?${COMMAND_PATH}(?:${names})${after}`,
  )

const NETWORK_COMMAND = commandRegex(NETWORK_TOOLS)

/** bash network redirection (`> /dev/tcp/host/port`): equivalent to a launched network tool. */
const NETWORK_DEVICE = /\/dev\/(?:tcp|udp)\//

const runsNetwork = (command: string) => NETWORK_COMMAND.test(command) || NETWORK_DEVICE.test(command)

const mentionsNetwork = (command: string) => runsNetwork(command) || NETWORK_WORD.test(command)

/**
 * Another OpenCode agent or server launched by the agent: a nested `opencode run --auto` would approve all
 * requests, and OPENCODE_CONFIG / OPENCODE_CONFIG_CONTENT / OPENCODE_CONFIG_DIR can remove the plugin from it.
 */
const NESTED_OPENCODE = commandRegex("opencode", "(?:\\s+(?:run|serve|web|acp|attach)\\b|(?=[^;&|\\n]{0,500}?\\s--auto\\b))")
const OPENCODE_CONFIG_VARIABLE = /\bOPENCODE_CONFIG(?:_DIR|_CONTENT)?=/

const PLACEHOLDER_REASON =
  "the command contains a redacted secret ([[GUARD_REDACTED:…]]): writing it would destroy the real secret. Make a targeted edit that does not include the placeholder"
const PLACEHOLDER_ENCODED_REASON =
  "the command contains a redacted secret encoded in base64 (a [[GUARD_REDACTED:…]] placeholder once decoded): writing it would destroy the real secret. Make a targeted edit that does not include it"

/** Simple segments: shell separators + contents of `$(…)` and backticks. */
export function segments(command: string): string[] {
  const parts = command.split(/\|\||&&|;|\||&|\n/)
  for (const match of command.matchAll(/[$<>]\(([^()]*)\)|`([^`]*)`/g)) parts.push(match[1] ?? match[2] ?? "")
  return parts.map((part) => part.trim()).filter(Boolean)
}

/** Undeveloped HOME forms (HOME unknown); absolute paths go through CRITICAL_DIRS. */
const CRITICAL_TARGETS = new Set(["~", "~/", "~/*", "$HOME", "$HOME/", "$HOME/*", "${HOME}", "${HOME}/", "${HOME}/*"])

const CRITICAL_DIRS = new Set([
  "/",
  "/home",
  "/Users",
  "/root",
  "/etc",
  "/usr",
  "/var",
  "/boot",
  "/bin",
  "/sbin",
  "/lib",
  "/lib64",
  "/opt",
  "/srv",
  "/dev",
  "/proc",
  "/sys",
])

/** Cleaned target: quotes, leading `(`, trailing `)` and unmatched trailing `}` (zsh's `{rm -rf /}`). */
function cleanTarget(token: string): string {
  let target = token.replace(/["']/g, "").replace(/^\(+|\)+$/g, "")
  while (target.endsWith("}") && (target.match(/\{/g)?.length ?? 0) < (target.match(/\}/g)?.length ?? 0)) target = target.slice(0, -1)
  return target
}

/**
 * Critical target after lexical normalization (`//`, `/tmp/../*`, `~/../..` → `/`): absolute paths and HOME
 * only, never resolved against the current directory (not reliably known: workdir, `cd`).
 */
const canonicalPath = (path: string) => posix.normalize(path).replace(/\/\*$/, "").replace(/\/+$/, "") || "/"

function isCriticalTarget(target: string, home?: string): boolean {
  if (CRITICAL_TARGETS.has(target)) return true
  const expanded = home ? target.replace(/^(?:~|\$HOME|\$\{HOME\})(?=\/|$)/, home) : target
  if (!expanded.startsWith("/")) return false
  const normalized = canonicalPath(expanded)
  return CRITICAL_DIRS.has(normalized) || (home !== undefined && normalized === canonicalPath(home))
}

/** Critical target, or top-level HOME entry (`~/Documents`, `$HOME/x`, `<home>/x`). */
function isHomeLevelTarget(target: string, home?: string): boolean {
  if (isCriticalTarget(target, home)) return true
  if (/^(?:~|\$HOME|\$\{HOME\})\/[^/]+\/?(?:\*)?$/.test(target)) return true
  if (!home) return false
  const expanded = target.replace(/^(?:~|\$HOME|\$\{HOME\})(?=\/|$)/, home)
  return expanded.startsWith("/") && posix.dirname(canonicalPath(expanded)) === canonicalPath(home)
}

/** Command start for rm/chmod/dd: start, space, `(`, backtick, quote, `{` (zsh), `=cmd` (zsh) outside an assignment. */
const COMMAND_START = "(?:^|[\\s(`'\"{]|(?<![\\w])=)"

function rmFinding(segment: string, home?: string): Finding | undefined {
  // A quote immediately before also counts: `bash -c "rm -rf ~"`, `sh -c 'rm -rf /'`.
  const match = segment.match(new RegExp(`${COMMAND_START}rm\\s+(.*)$`))
  if (!match) return undefined
  let recursive = false
  let force = false
  let noPreserve = false
  const targets: string[] = []
  for (const token of (match[1] ?? "").split(/\s+/).filter(Boolean)) {
    if (token === "--") continue
    if (token.startsWith("--")) {
      // These are the only rm options on those initials: `--r`, `--f`, `--n` suffice (`--recursive=…`, rejected by rm, also counts).
      if (isLongOption(token, "recursive")) recursive = true
      else if (isLongOption(token, "force")) force = true
      else if (isLongOption(token, "no-preserve-root")) noPreserve = true
    } else if (token.startsWith("-") && token.length > 1) {
      if (/[rR]/.test(token)) recursive = true
      if (/f/.test(token)) force = true
    } else targets.push(cleanTarget(token))
  }
  const critical = targets.some((target) => isCriticalTarget(target, home))
  if (noPreserve || (recursive && critical))
    return { verdict: "deny", rule: "rm-critical", reason: "recursive deletion of a system directory or HOME" }
  if (recursive || force) return { verdict: "ask", rule: "rm", reason: "file deletion (rm -r/-f)" }
  return undefined
}

/**
 * Deletion or destruction of a file by the command actually launched (wrappers included): `rm` without -r or -f
 * (those cases belong to `rmFinding`), `unlink`, `shred` (content destroyed, with or without `-u`; a device is denied
 * above). `git rm`, `docker rm` or the word "rm" in some text are not the rm command.
 */
function deletionFinding(segment: string): Finding | undefined {
  const { name, args } = commandOf(segment)
  if (!args.some((arg) => !arg.startsWith("-") && !/^(?:\d*|&)[<>]/.test(arg))) return undefined
  if (name === "rm") {
    const options = args.filter((arg) => arg.startsWith("-") && arg !== "-" && arg !== "--")
    const handled = options.some((option) =>
      option.startsWith("--") ? isLongOption(option, "recursive") || isLongOption(option, "force") : /[rRf]/.test(option),
    )
    return handled ? undefined : { verdict: "ask", rule: "file-delete", reason: "file deletion (rm)" }
  }
  if (name === "unlink") return { verdict: "ask", rule: "file-delete", reason: "file deletion (unlink)" }
  if (name === "shred") return { verdict: "ask", rule: "file-delete", reason: "file destruction (shred)" }
  return undefined
}

/**
 * Moving HOME, a top-level HOME entry or a system directory by the launched mv command: the
 * sources are the arguments other than the destination (last argument, or all with `-t`/`--target-directory`).
 */
function moveFinding(segment: string, home?: string): Finding | undefined {
  const { name, args } = commandOf(segment)
  if (name !== "mv") return undefined
  const positional: string[] = []
  let targetOption = false
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!
    if (arg === "--") continue
    if (/^-[a-zA-Z]*t$/.test(arg) || (arg.startsWith("--") && !arg.includes("=") && isLongOption(arg, "target-directory"))) {
      targetOption = true
      i++
    } else if (arg.startsWith("--target-directory=") || (arg.startsWith("--t") && arg.includes("=") && isLongOption(arg, "target-directory")))
      targetOption = true
    else if (/^-[a-zA-Z]*S$/.test(arg)) i++ // -S suffix
    else if (!arg.startsWith("-") && !/^(?:\d*|&)[<>]/.test(arg)) positional.push(arg)
  }
  const sources = targetOption ? positional : positional.slice(0, -1)
  return sources.some((source) => isHomeLevelTarget(cleanTarget(source), home))
    ? { verdict: "ask", rule: "home-move", reason: "moving a home or system directory" }
    : undefined
}

/** Recursive option of chmod/chown/chgrp: `-R` (grouped included) or abbreviated `--recursive`. Same source as the ask. */
const isRecursivePermissionOption = (token: string) => /^-[a-zA-Z]*R/.test(token) || isLongOption(token, "recursive")
const RECURSIVE_PERMISSION_OPTION = `(?:-[a-zA-Z]*R|${longOptionPattern("recursive")})`

/** Recursive chmod/chown/chgrp on `/`, HOME or a system directory: same severity as rm. */
function permissionFinding(segment: string, home?: string): Finding | undefined {
  const match = segment.match(new RegExp(`${COMMAND_START}(?:chmod|chown|chgrp)\\s+(.*)$`))
  if (!match) return undefined
  const tokens = (match[1] ?? "").split(/\s+/).filter(Boolean)
  if (!tokens.some((token) => isRecursivePermissionOption(token))) return undefined
  // All positions: the mode or owner (`755`, `root:root`) is never a critical path, and a mode given as an
  // option (`chmod -R -w /`) or `--reference` leaves none before the targets. File of `--reference FILE` skipped.
  const targets: string[] = []
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]!
    if (token.startsWith("-")) {
      if (isLongOption(token, "reference") && !token.includes("=")) i++
      continue
    }
    targets.push(cleanTarget(token))
  }
  const critical = targets.some((target) => isCriticalTarget(target, home))
  return critical
    ? { verdict: "deny", rule: "permissions-critical", reason: "recursive permission change on / , HOME or a system directory" }
    : undefined
}

interface RegexRule {
  readonly id: string
  readonly verdict: "deny" | "ask"
  readonly reason: string
  readonly test: (command: string, ctx: ShellRuleContext) => boolean
}

const re = (regex: RegExp) => (command: string) => regex.test(command)

const WRITE_COMMANDS = new Set(["cp", "mv", "ln", "install", "rm", "unlink", "truncate", "tee", "touch", "rsync"])
const unquote = (token: string) => token.replace(/^["']+|["']+$/g, "")

/** Wrappers that launch the next command, with their options followed by a value (`sudo -u bob`, `timeout -s KILL`). */
const PREFIX_OPTIONS: Readonly<Record<string, ReadonlySet<string>>> = {
  sudo: new Set(["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-T", "-U"]),
  doas: new Set(["-u", "-C"]),
  env: new Set(["-u", "-C", "-S"]),
  timeout: new Set(["-s", "-k"]),
  nice: new Set(["-n"]),
  ionice: new Set(["-c", "-n", "-p"]),
  stdbuf: new Set(["-i", "-o", "-e"]),
  time: new Set(["-f", "-o"]),
  exec: new Set(["-a"]),
  command: new Set(),
  nohup: new Set(),
  setsid: new Set(),
  torsocks: new Set(),
  unbuffer: new Set(),
}
/** Structural words before a command (`{ cmd; }`, `if cmd`, `! cmd`). */
const GROUPING_WORDS = new Set(["{", "(", "!", "if", "then", "elif", "else", "do", "while", "until"])

/** Command as launched (path included), without attached `{`/`(`/`$(`/quotes, `=` (zsh), `\` or closing characters. */
const commandToken = (token: string) => token.replace(/^(?:\$?\(|[{=\\"'`])+/, "").replace(/[)}"'`]+$/, "")

/** Bare name: without attached `{`/`(`/`$(`/quotes, `=` (zsh), `\`, path, or trailing `)`/`}`/quotes (`sh')"`). */
const commandName = (token: string) => commandToken(token).split("/").pop() ?? ""

/**
 * Command of a segment and its arguments, after structural words, assignments (`A=1 cmd`) and
 * wrappers with their options (`sudo -E -u bob cmd`, `timeout -s KILL 5 cmd`). `path`: the command as
 * launched (`./build.sh`, `/usr/bin/python3`).
 */
export function commandOf(segment: string): { name: string; args: string[]; path: string } {
  const tokens = segment.split(/\s+/).filter(Boolean).map(unquote)
  let i = 0
  let wrapper: string | undefined
  while (i < tokens.length) {
    const token = tokens[i]!
    const name = commandName(token)
    if (GROUPING_WORDS.has(token) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) i++
    else if (name in PREFIX_OPTIONS) {
      wrapper = name
      i++
    } else if (wrapper && token.startsWith("-") && token !== "-") i += PREFIX_OPTIONS[wrapper]!.has(token) ? 2 : 1
    else if (wrapper === "timeout" && /^\d+(?:\.\d+)?[smhd]?$/.test(token)) {
      wrapper = undefined
      i++
    } else break
  }
  return { name: commandName(tokens[i] ?? ""), args: tokens.slice(i + 1), path: commandToken(tokens[i] ?? "") }
}

/**
 * Actually written targets: redirections to a file (not `2>&1` or `/dev/null`), arguments of
 * write commands, and files modified in place (`sed -i`, `perl -i`).
 */
export function writeTargets(command: string): string[] {
  const targets: string[] = []
  for (const match of command.matchAll(/(?:^|[^<>])(?:\d|&)?>>?\|?\s*([^\s;&|<>()]+)/g)) targets.push(unquote(match[1] ?? ""))
  for (const segment of segments(command)) {
    const { name, args: tokens } = commandOf(segment)
    const args = tokens.filter((token) => !token.startsWith("-") && !/^\d*>/.test(token))
    const inPlace = (name === "sed" || name === "perl") && tokens.some((t) => /^-[a-zA-Z]*i/.test(t) || t.startsWith("--in-place"))
    if (WRITE_COMMANDS.has(name) || inPlace) targets.push(...args)
  }
  return targets.filter((target) => target && !target.startsWith("/dev/"))
}

/**
 * Write target of a copy command: `-t`/`--target-directory` (cp, mv, install; for rsync, `-t` preserves
 * the dates), otherwise the last argument (if there is a source).
 */
function copyDestination(args: readonly string[], targetOption: boolean): string | undefined {
  const positional: string[] = []
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!
    if (targetOption && (arg === "-t" || arg === "--target-directory" || /^-[a-zA-Z]+t$/.test(arg))) return args[i + 1]
    if (targetOption && arg.startsWith("--target-directory=")) return arg.slice("--target-directory=".length)
    if (!arg.startsWith("-")) positional.push(arg)
  }
  return positional.length >= 2 ? positional[positional.length - 1] : undefined
}

const COPY_COMMANDS = new Set(["cp", "mv", "install", "rsync"])

/** Write to a device by a command: `tee` (all its targets), cp/mv/install/rsync (destination). */
function writesDevice(command: string): boolean {
  const device = new RegExp(`^${DEVICE}`)
  return segments(command).some((segment) => {
    const { name, args } = commandOf(segment)
    if (name === "tee") return args.some((arg) => !arg.startsWith("-") && device.test(arg))
    if (!COPY_COMMANDS.has(name)) return false
    const destination = copyDestination(args, name !== "rsync")
    return destination !== undefined && device.test(destination)
  })
}

/**
 * Environment display: `printenv`, `env` (options only: `env -0`), `export`/`export -p`, bare `set`,
 * `declare -x`/`-p`, `/proc/<pid>/environ`. `set -e` or `env FOO=1 cmd` display nothing.
 */
const ENV_DUMP = new RegExp(
  "(?:^|[\\s;&|(`{])(?:printenv\\b|(?:env(?:\\s+-[^\\s;&|()<>]+)*|export(?:\\s+-p)?|set|(?:declare|typeset)\\s+-[a-zA-Z]*[px][a-zA-Z]*)(?=\\s*(?:[|;&)<>]|$)))" +
    "|/proc/[^\\s/]+/environ\\b",
)

/**
 * Components of a variable name that denote a secret, case ignored: `$OPENAI_API_KEY`, `$GITHUB_TOKEN`,
 * `$githubToken`. AUTH followed by the SOCK component (`$SSH_AUTH_SOCK`, ssh agent socket) is not one.
 */
const SECRET_VARIABLE_PARTS = new Set([
  "KEY",
  "KEYS",
  "APIKEY",
  "PRIVATEKEY",
  "TOKEN",
  "TOKENS",
  "SECRET",
  "SECRETS",
  "PASSWORD",
  "PASSWORDS",
  "PASSWD",
  "PASSPHRASE",
  "PASS",
  "CREDENTIAL",
  "CREDENTIALS",
  "CREDS",
  "BEARER",
  "AUTH",
])
/** Components recognized only when written in uppercase: `$GITHUB_PAT`, but not `$pat` (loop pattern). */
const UPPERCASE_SECRET_PARTS = new Set(["PAT"])
/** camelCase split: `githubToken` → `github`, `Token`; `APIKey` → `API`, `Key`. */
const CAMEL_BOUNDARY = /(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])/

const isSecretPart = (part: string) => UPPERCASE_SECRET_PARTS.has(part) || SECRET_VARIABLE_PARTS.has(part.toUpperCase())
/** AUTH followed by the SOCK component; the next component is computed (`next`) only for AUTH. */
const authBeforeSock = (part: string, next: () => string | undefined) => part.toUpperCase() === "AUTH" && next()?.toUpperCase() === "SOCK"

/**
 * Secret name: a whole part between `_`, or one of its camelCase pieces when it has several, is a
 * secret component (AUTH before SOCK excluded).
 */
function isSecretName(name: string): boolean {
  const parts = name.split("_")
  return parts.some((part, index) => {
    const following = () => parts[index + 1]?.split(CAMEL_BOUNDARY)[0]
    if (isSecretPart(part) && !authBeforeSock(part, following)) return true
    const pieces = part.split(CAMEL_BOUNDARY)
    return pieces.length > 1 && pieces.some((piece, i) => isSecretPart(piece) && !authBeforeSock(piece, () => pieces[i + 1] ?? following()))
  })
}

/** `$NAME` / `${NAME}` references to a variable with a secret name (not `$PWD` or `$SSH_AUTH_SOCK`). */
export function secretVariables(command: string): string[] {
  const names: string[] = []
  for (const match of command.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)/g)) {
    const name = match[1] ?? ""
    if (isSecretName(name)) names.push(name)
  }
  return names
}

/**
 * Keys passed to ssh/scp/sftp (`-i key`, `IdentityFile=key`): they authenticate, they are not
 * sent. One occurrence is removed per use: `scp -i k k host:` still sends the key.
 */
function identityFiles(command: string): string[] {
  const keys: string[] = []
  // Bounded search (linear cost): a key too far away still counts as sent (deny).
  for (const match of command.matchAll(/\b(?:ssh|scp|sftp)\b[^;&|]{0,500}?\s-i\s*["']?([^\s"';&|]+)/g)) keys.push(match[1] ?? "")
  for (const match of command.matchAll(/\bIdentityFile\s*[=\s]\s*["']?([^\s"';&|]+)/gi)) keys.push(match[1] ?? "")
  return keys
}

/** Credential files sent by a command (excluding ssh authentication keys). */
function sentSecretFiles(command: string, ctx: CredentialContext): string[] {
  const files = pathTokens(command).filter((token) => isCredentialFile(token, ctx))
  for (const key of identityFiles(command)) {
    const index = files.indexOf(key)
    if (index >= 0) files.splice(index, 1)
  }
  return files
}

/**
 * Device targeted by a raw write, excluding harmless pseudo-devices: `/dev/null`, terminals and
 * serial ports (`tty*`, `pts/`, `console`), shared memory (`shm/`), descriptors, and `/dev/tcp|udp/` (network,
 * handled by the exfiltration rules). Disks, `loop`, `dm-`, `/dev/mem`… remain targeted.
 */
const DEVICE = "/dev/(?!(?:null|zero|full|random|urandom|stdin|stdout|stderr|console|ptmx)\\b|tty|pts/|shm/|fd/|tcp/|udp/)"

/**
 * Fork bomb, whatever the function name (`:(){ :|:& };:`, `x(){ x|x& };x`, `function f { f|f& }`):
 * function whose body launches itself twice in a pipe; also between quotes (`bash -c ':(){ :|:& };:'`).
 */
const SELF_PIPE = "[^}]{0,200}?(?<![\\w:.+-])\\1\\s*\\|&?\\s*\\1(?![\\w:.+-])"
const FORK_BOMBS = [
  new RegExp(`(?:^|[\\s;&|(\`{'"])([\\w:.+-]+)\\s*\\(\\s*\\)\\s*\\{${SELF_PIPE}`),
  new RegExp(`(?:^|[\\s;&|(\`{'"])function\\s+([\\w:.+-]+)\\s*(?:\\(\\s*\\))?\\s*\\{${SELF_PIPE}`),
]

const DOWNLOADERS = new Set(["curl", "wget", "aria2c", "http", "https", "xh"])
const DOWNLOADER = "(?:[^\\s()`'\"]*/)?(?:curl|wget|aria2c|https?|xh)\\b"

/**
 * Interpreters that execute their standard input: `code` = options that take the code as an argument (stdin is
 * then not executed), `value` = options followed by a value, `stdin` = option that forces reading stdin,
 * `subcommand` = subcommand skipped once (`bun run -`, `deno run -`), `bare` = without a script, standard input is
 * executed (false for `bun` alone, which shows help). Versioned names included (`perl5.40.1`, `ruby3.3`, `php8.3`).
 */
const EXECUTORS: ReadonlyArray<{
  readonly name: RegExp
  readonly code: RegExp
  readonly value?: RegExp
  readonly stdin?: RegExp
  readonly subcommand?: RegExp
  readonly bare?: boolean
}> = [
  {
    name: /^(?:sh|bash|zsh|dash|ksh|mksh|ash|yash|fish)$/,
    code: /^-[a-zA-Z]*c[a-zA-Z]*$/,
    value: /^[-+][oO]$|^--(?:rcfile|init-file)$/,
    stdin: /^-[a-zA-Z]*s[a-zA-Z]*$/,
  },
  { name: /^python[0-9.]*$/, code: /^-[a-zA-Z]*[cm]/, value: /^-[WX]$/ },
  { name: /^(?:node|nodejs)$/, code: /^(?:-[ep]|--eval|--print)(?:=|$)/, value: /^(?:-r|--require|--import|--loader|--input-type)$/ },
  { name: /^perl(?:5[\w.-]*)?$/, code: /^-(?![MmIx])[a-zA-Z0-9]*[eE]/, value: /^-[IM]$/ },
  { name: /^ruby[\d.]*$/, code: /^-(?![rI])[a-zA-Z]*e/, value: /^-[rI]$/ },
  { name: /^php[\d.]*$/, code: /^-[a-zA-Z]*[rfRFBE]/, value: /^-[cdz]$/ },
  // `bun -` and `bun run -` execute standard input (verified, Bun 1.4.2); `bun` alone shows help.
  {
    name: /^bun$/,
    code: /^(?:-[ep]|--eval|--print)(?:=|$)/,
    value: /^(?:-r|--preload|--cwd|-c|--config|--env-file)$/,
    subcommand: /^run$/,
    bare: false,
  },
  // `deno run -` (documented); `deno` alone opens a REPL that reads its input (not verified: counted as executing).
  // No code option: `deno eval` is a subcommand, handled as a script.
  { name: /^deno$/, code: /(?!)/, value: /^(?:-c|--config|--import-map|--location|--cert|--lock|--env-file)$/, subcommand: /^run$/ },
]

const STDIN_PATH = /^\/(?:dev\/stdin|dev\/fd\/0|proc\/self\/fd\/0)$/

/** Code passed as an argument that evaluates standard input (explicit evaluation + reading stdin). */
const EVALUATES = /\b(?:exec|eval|compile)\s*\(|\$\(\s*cat\b/
const READS_STDIN = /stdin|readFileSync\(\s*0\b|\$\(\s*cat\b|\/dev\/fd\/0/
const evaluatesStdin = (stage: string) => EVALUATES.test(stage) && READS_STDIN.test(stage)

/** Pipeline stage that executes what it receives: shell without `-c` (or with `-s`/`-`), interpreter without code or script. */
function executesStdin(stage: string, codeRunsStdin: () => boolean): boolean {
  const { name, args } = commandOf(stage)
  const executor = EXECUTORS.find((candidate) => candidate.name.test(name))
  if (!executor) return false
  let stdin = false
  const bare = executor.bare ?? true
  const start = executor.subcommand && args[0] !== undefined && executor.subcommand.test(args[0]) ? 1 : 0
  for (let i = start; i < args.length; i++) {
    const arg = args[i]!
    // Redirection (`2>/dev/null`, `2> err.log`): neither an option nor a script.
    if (/^(?:\d*|&)[<>]/.test(arg)) {
      if (/^(?:\d*|&)[<>]+&?$/.test(arg)) i++
      continue
    }
    // `-` and standard input paths (`bash /dev/stdin`, `python3 /dev/fd/0`): stdin executed.
    if (arg === "-" || STDIN_PATH.test(arg)) return true
    if (arg === "--") return stdin || (i + 1 >= args.length ? bare : args[i + 1] === "-")
    if (arg.startsWith("-") || (executor.stdin && arg.startsWith("+"))) {
      // Code as an argument: reads data only, unless it itself evaluates its standard input.
      // (searched in the whole command: pipeline splitting cuts the code at its `;`).
      if (executor.code.test(arg)) return codeRunsStdin()
      if (executor.stdin?.test(arg)) stdin = true
      if (executor.value?.test(arg)) i++
      continue
    }
    // Script file (or arguments of `bash -s`).
    return stdin
  }
  return stdin || bare
}

/** Stage that downloads: downloader launched, or `curl`/`wget` cited in the stage (`$(curl …`, `bash -c "curl …`). */
const downloads = (stage: string) => DOWNLOADERS.has(commandOf(stage).name) || /(?<![\w.-])(?:curl|wget)(?![\w.-])/.test(stage)

/**
 * Executed download: in the same pipeline (separators `;`, `&&`, `||`, `&`, newline), a stage that
 * downloads followed by a stage that executes its input (`curl … | tee f | sudo -E sh`). `curl … | python3 -m json.tool`
 * or `| node -e "…"` only read data.
 */
function pipesDownloadToShell(command: string): boolean {
  // Computed once per command (linear cost even with thousands of `sh -c` stages).
  let memo: boolean | undefined
  const codeRunsStdin = () => (memo ??= evaluatesStdin(command))
  for (const pipeline of command.split(/\|\||&&|;|\n|(?<![|>&])&(?![>&])/)) {
    const stages = pipeline.split(/(?<!>)\|&?/)
    if (stages.length < 2) continue
    const first = stages.findIndex(downloads)
    if (first >= 0 && stages.slice(first + 1).some((stage) => executesStdin(stage, codeRunsStdin))) return true
  }
  return false
}

const PROCESS_SUBSTITUTION_EXEC = new RegExp(
  `(?:sh|bash|zsh|dash|ksh|source|\\.|python[0-9.]*|perl(?:5[\\w.-]*)?|ruby[\\d.]*|php[\\d.]*|node|bun(?:\\s+run)?|deno\\s+run(?:\\s+-\\S+)*)\\s+<\\(\\s*${DOWNLOADER}`,
)
const COMMAND_SUBSTITUTION_EXEC = new RegExp(`(?:sh|bash|zsh|dash|ksh)\\s+-[a-zA-Z]*c\\s+["']?(?:\\$\\(|\`)\\s*${DOWNLOADER}`)

/** Signature formatting and wiping launched by common recognition (same names as the `mkfs` rule). */
const FORMAT_TOOLS = "mkfs(?:\\.[a-z0-9]+)?|wipefs"
const FORMAT_COMMAND = commandRegex(FORMAT_TOOLS, undefined, true)

/**
 * `dd` launched by common recognition, call tail up to the separator included. `of=` to a device
 * is searched in the whole match: the tail, where any following call of the same segment is found (matches
 * do not overlap), but also the wrapper and the words it skips, where a call placed in a
 * substitution has no match of its own. An `of=` to a device among those skipped words therefore also counts
 * (a rare extra deny). Each character is examined only once (linear cost).
 */
const DD_CALL = new RegExp(commandRegex("dd", "\\s[^;&|]*", true).source, "g")
const DD_DEVICE_OUTPUT = new RegExp(`\\bof=["']?${DEVICE}`)
const ddCommandToDevice = (command: string) => [...command.matchAll(DD_CALL)].some((match) => DD_DEVICE_OUTPUT.test(match[0]))

/** Added recognition alone, without a switch or fallback to data (cost tests). */
export const addedRecognition = (command: string) => FORMAT_COMMAND.test(command) || ddCommandToDevice(command)

/**
 * Recognition added to the `mkfs` and `dd-device` rules (path `/usr/sbin/mkfs.ext4`, `/bin/dd`, `\mkfs`, wrappers,
 * `sh -c "…"` text, `find -exec`), evaluated after all rules (`addedShellFinding`): an existing finding at
 * least as strong keeps its identifier.
 */
const ADDED_DENY_RULES: readonly RegexRule[] = [
  { id: "mkfs", verdict: "deny", reason: "disk formatting", test: (command) => FORMAT_COMMAND.test(command) },
  { id: "dd-device", verdict: "deny", reason: "raw write to a device", test: ddCommandToDevice },
]

const DENY_RULES: readonly RegexRule[] = [
  { id: "placeholder", verdict: "deny", reason: PLACEHOLDER_REASON, test: re(PLACEHOLDER_RE) },
  { id: "placeholder", verdict: "deny", reason: PLACEHOLDER_ENCODED_REASON, test: (command) => containsEncodedPlaceholder(command) },
  { id: "mkfs", verdict: "deny", reason: "disk formatting", test: re(word("mkfs(?:\\.[a-z0-9]+)?|wipefs")) },
  {
    id: "dd-device",
    verdict: "deny",
    reason: "raw write to a device",
    test: re(new RegExp(`(?:^|[\\s;&|(\`{]|(?<![\\w])=)dd\\s[^;&|]*\\bof=["']?${DEVICE}`)),
  },
  {
    id: "redirect-device",
    verdict: "deny",
    reason: "raw write to a device",
    test: re(new RegExp(`>\\|?\\s*["']?${DEVICE}`)),
  },
  { id: "write-device", verdict: "deny", reason: "raw write to a device", test: writesDevice },
  { id: "shred-device", verdict: "deny", reason: "device wipe", test: re(new RegExp(`shred\\s[^;&|]*${DEVICE}`)) },
  { id: "fork-bomb", verdict: "deny", reason: "fork bomb", test: (command) => FORK_BOMBS.some((regex) => regex.test(command)) },
  {
    id: "pipe-to-shell",
    verdict: "deny",
    reason: "running a downloaded script (download piped to a shell or an interpreter)",
    test: (command) =>
      pipesDownloadToShell(command) || PROCESS_SUBSTITUTION_EXEC.test(command) || COMMAND_SUBSTITUTION_EXEC.test(command),
  },
  // Deny only if a network tool is launched; a mere word (`grep -i http .env`) asks (ask rules).
  {
    id: "secret-file-network",
    verdict: "deny",
    reason: "credential file and network tool in the same command (exfiltration)",
    test: (command, ctx) => runsNetwork(command) && sentSecretFiles(command, ctx).length > 0,
  },
  {
    id: "env-dump-network",
    verdict: "deny",
    reason: "environment variables sent over the network (exfiltration)",
    test: (command) => runsNetwork(command) && ENV_DUMP.test(command),
  },
  {
    id: "secret-network",
    verdict: "deny",
    reason: "secret found in a network command (exfiltration)",
    test: (command, ctx) => runsNetwork(command) && ctx.redactor.containsSecret(command),
  },
  // Output of an OpenCode subcommand that prints a secret (`opencodeKinds`), after the existing denials: same
  // identifier and same switch as the credential file sent by a launched network tool.
  {
    id: "secret-file-network",
    verdict: "deny",
    reason: "OpenCode credentials or service secrets printed and network tool in the same command (exfiltration)",
    test: (command) => opencodeKinds(command).has("printed") && runsNetwork(command),
  },
]

/**
 * Argument of a git global option: runs of ordinary characters separated by quoted pieces
 * (bounded), `$(…)` without nested parentheses or a lone `$`. An ordinary run is followed only by a piece that starts
 * with `"`, `'` or `$`: a single decomposition, and backtracking fails immediately (linear cost, even under Bun, when
 * the expected subcommand does not follow). An unclosed quote stops the argument.
 */
const GIT_WORD = String.raw`[^\s;&|"'$]+`
const GIT_QUOTED = String.raw`(?:"[^"]{0,4096}"|'[^']{0,4096}'|\$\([^()]*\)|\$(?!\())`
const GIT_ARG = String.raw`(?=[^\s;&|])(?:${GIT_WORD})?(?:${GIT_QUOTED}(?:${GIT_WORD})?)*`

/** Git global options placed before the subcommand (git.c's `handle_options`); `--` ends them. */
const GIT_GLOBAL_OPTION =
  String.raw`(?:-[Cc]\s*${GIT_ARG}|--(?:git-dir|work-tree|namespace|exec-path|config-env|attr-source)(?:=(?:${GIT_ARG})?|\s+${GIT_ARG})` +
  String.raw`|--(?:no-pager|paginate|bare|no-replace-objects|no-lazy-fetch|no-optional-locks|no-advice|literal-pathspecs|glob-pathspecs|noglob-pathspecs|icase-pathspecs)|-[pP]|--)`

/** `git`, at most 16 global options, then the subcommand (`git -C repo reset`). No capturing group. */
const GIT = String.raw`git(?:\s+${GIT_GLOBAL_OPTION}){0,16}\s+`

/** `git <subcommand>` calls: group 1 contains their arguments, up to `;`, `&` or `|` (end of line included). */
const gitCall = (subcommand: string) => new RegExp(`${GIT}${subcommand}(?=\\s|$)([^;&|]*)`, "g")

const GIT_PUSH = gitCall("push")
const GIT_CHECKOUT = gitCall("checkout")
const GIT_SWITCH = gitCall("switch")
const GIT_WORKTREE = gitCall("worktree")
const GIT_REFLOG = gitCall("reflog")
const GIT_RESTORE = gitCall("restore")

/**
 * Words of each call, without their quotes (`":$BRANCH"`, `"--force"`: git receives the word without them), stopped at the word
 * `--` (the rest are paths or names; `"--"` too).
 */
function gitArgs(command: string, call: RegExp): string[][] {
  return [...command.matchAll(call)].map((match) => {
    const words = (match[1] ?? "").split(/\s+/).map(unquote).filter(Boolean)
    const end = words.indexOf("--")
    return end >= 0 ? words.slice(0, end) : words
  })
}

/** Letter in a short-option group (`-qf`), except after an option that takes the rest as an argument (`-bfix`). */
function hasShortOption(words: readonly string[], letter: string, withArgument = ""): boolean {
  return words.some((word) => {
    if (!/^-[^-]/.test(word)) return false
    for (const char of word.slice(1)) {
      if (char === letter) return true
      if (withArgument.includes(char)) return false
    }
    return false
  })
}

const hasLongOption = (words: readonly string[], ...names: string[]) => words.some((word) => names.some((name) => isLongOption(word, name)))

const firstOperand = (words: readonly string[]) => words.find((word) => !word.startsWith("-"))

/** `git push` that deletes or replaces remote refs: `--delete`, `-d`, `--prune`, `--mirror`, `:ref`. */
function pushDeletesRefs(command: string): boolean {
  return gitArgs(command, GIT_PUSH).some(
    (words) =>
      hasLongOption(words, "delete", "prune", "mirror") ||
      hasShortOption(words, "d", "o") ||
      words.some((word) => /^\+?:[^:\s]/.test(word)),
  )
}

/** Forced push outside the regex: abbreviated `--force`, any `--force-…` option, refspec `+…` (even alone) or `…:+…`. */
function pushForcesRefs(command: string): boolean {
  return gitArgs(command, GIT_PUSH).some((words) =>
    words.some((word) => isLongOption(word, "force") || word.startsWith("--force-") || word.startsWith("+") || word.includes(":+")),
  )
}

/** Forced `checkout` or `switch`: uncommitted changes of the whole tree lost. */
function forcedCheckout(command: string): boolean {
  return (
    gitArgs(command, GIT_CHECKOUT).some((words) => hasLongOption(words, "force") || hasShortOption(words, "f", "bBU")) ||
    gitArgs(command, GIT_SWITCH).some((words) => hasLongOption(words, "force", "discard-changes") || hasShortOption(words, "f", "cC"))
  )
}

const reflogDeletion = (command: string) =>
  gitArgs(command, GIT_REFLOG).some((words) => ["expire", "delete"].includes(firstOperand(words) ?? ""))

const forcedWorktreeRemoval = (command: string) =>
  gitArgs(command, GIT_WORKTREE).some(
    (words) => firstOperand(words) === "remove" && (hasLongOption(words, "force") || hasShortOption(words, "f")),
  )

/**
 * Words of each call, without their quotes, `--` included (paths follow). Here operands are counted: a
 * piece enclosed in quotes remains a single word (`"$(git describe --tags)"`), the call stops at end of line
 * (except a line continued by `\`) and at a comment (`#` at the start of a word), and redirections are removed with their target
 * (`2>/dev/null`, `> out.txt`), otherwise `git checkout main` followed by one of them would have two operands. One pass per line.
 */
function gitCallWords(command: string, call: RegExp): string[][] {
  const calls: string[][] = []
  for (const line of command.replace(/\\\n/g, " ").split("\n")) {
    for (const match of line.matchAll(call)) {
      const tokens = (match[1] ?? "")
        .replace(/"[^"]*"|'[^']*'/g, (quoted) => quoted.replace(/\s/g, "\0"))
        .split(/\s+/)
        .filter(Boolean)
      const words: string[] = []
      for (let i = 0; i < tokens.length; i++) {
        const token = tokens[i]!
        if (token.startsWith("#")) break
        const redirect = /^\d*[<>]+/.exec(token)
        if (redirect) {
          if (redirect[0] === token) i++
          continue
        }
        const word = unquote(token)
        if (word) words.push(word)
      }
      calls.push(words)
    }
  }
  return calls
}

/**
 * Options, operands (before `--`, option values skipped) and paths (after `--`) of a call. `valueLetters` /
 * `valueOptions`: options followed by a value, attached (`-s@`, `--source=HEAD`) or in the next word (`-s HEAD`,
 * `--sou HEAD`). A word starting with `-` is never a path, even after `--` (`git checkout -- "-f"` remains without an ask).
 */
function gitOperands(words: readonly string[], valueLetters: string, valueOptions: readonly string[]) {
  const options: string[] = []
  const operands: string[] = []
  for (let i = 0; i < words.length; i++) {
    const word = words[i]!
    if (word === "--") return { options, operands, paths: words.slice(i + 1).filter((path) => !path.startsWith("-")) }
    if (!word.startsWith("-") || word === "-") {
      operands.push(word)
      continue
    }
    options.push(word)
    if (word.startsWith("--")) {
      if (!word.includes("=") && valueOptions.some((name) => isLongOption(word, name))) i++
      continue
    }
    // Short group (`-qs HEAD`, `-SW`): the first letter that takes a value takes the rest of the word, or the next word.
    const letter = [...word.slice(1)].findIndex((char) => valueLetters.includes(char))
    if (letter === word.length - 2) i++
  }
  return { options, operands, paths: [] as string[] }
}

/** Last form of a negation option (`-p`, `--patch`, `--no-patch`): the last one wins; absent = undefined. */
function lastFlag(options: readonly string[], letter: string, name: string, valueLetters: string): boolean | undefined {
  let value: boolean | undefined
  for (const option of options) {
    if (hasShortOption([option], letter, valueLetters) || isLongOption(option, name)) value = true
    else if (isLongOption(option, `no-${name}`)) value = false
  }
  return value
}

/**
 * `git restore` that replaces working tree files: at least one path, paths read from a file
 * (`--pathspec-from-file`) or hunk mode (`-p`, the whole tree without a path). The working tree is touched only if
 * the last form of `--worktree`/`-W` is positive, or there is no destination option at all, even negated (`--staged` alone:
 * the index; `--no-staged` or `--no-worktree` alone: git refuses).
 */
function restoresWorkingFiles(words: readonly string[]): boolean {
  const { options, operands, paths } = gitOperands(words, "sU", ["source", "unified", "inter-hunk-context", "conflict", "pathspec-from-file"])
  const worktree = lastFlag(options, "W", "worktree", "sU")
  const staged = lastFlag(options, "S", "staged", "sU")
  if (!(worktree ?? staged === undefined)) return false
  return operands.length + paths.length > 0 || hasLongOption(options, "pathspec-from-file") || lastFlag(options, "p", "patch", "sU") === true
}

/**
 * `git checkout` that replaces files: paths after `--` (with or without a source), a source followed by at least one path,
 * paths read from a file (`--pathspec-from-file`) or hunk mode (`-p`, even without a path). With the choice of one
 * side of the conflict (`--ours`, `--theirs`, `-2`, `-3`), git refuses to switch branches: every operand is a path.
 * Otherwise, a single operand (branch or file) is left to the decision model. Branch creation (`-b`, `-B`,
 * `--orphan`), tracking (`-t`, `--track`) or detaching (`-d`, `--detach`): git then refuses every path, and their two
 * operands are a branch and its starting point.
 */
function checkoutRestoresFiles(words: readonly string[]): boolean {
  const { options, operands, paths } = gitOperands(words, "bBU", ["unified", "inter-hunk-context", "conflict", "pathspec-from-file", "orphan"])
  if ([..."bBtd"].some((letter) => hasShortOption(options, letter, "bBU")) || hasLongOption(options, "orphan", "track", "detach")) return false
  const side = hasLongOption(options, "ours", "theirs") || hasShortOption(options, "2", "bBU") || hasShortOption(options, "3", "bBU")
  return (
    paths.length > 0 ||
    operands.length >= (side ? 1 : 2) ||
    hasLongOption(options, "pathspec-from-file") ||
    lastFlag(options, "p", "patch", "bBU") === true
  )
}

const discardsNamedFiles = (command: string) =>
  gitCallWords(command, GIT_RESTORE).some(restoresWorkingFiles) || gitCallWords(command, GIT_CHECKOUT).some(checkoutRestoresFiles)

/** Case-insensitive letters (`[aA][lL]…`): git reads section names without regard to case. */
const caseless = (text: string) => [...text].map((char) => (/[a-z]/.test(char) ? `[${char}${char.toUpperCase()}]` : `\\${char}`)).join("")

/**
 * Configuration given in the command that can define an alias (its command is not checked): `-c alias.…`,
 * `--config-env alias.…`, inclusion of a file (`include.path`, `includeIf.…`), among global options;
 * configuration through the environment (`GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`) or a designated
 * configuration file (`GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, except `/dev/null`).
 */
const GIT_ALIAS_OPTION = new RegExp(
  String.raw`git(?:\s+${GIT_GLOBAL_OPTION}){0,15}?\s+(?:-c\s*|--config-env(?:=|\s+))["']?(?:${caseless("alias")}|${caseless("include")}(?:${caseless("if")})?)\.`,
)
const GIT_CONFIG_ENV = /(?<![\w$])GIT_CONFIG_(?:PARAMETERS|COUNT|KEY_\d+)=|(?<![\w$])GIT_CONFIG_(?:GLOBAL|SYSTEM)=(?!["']?\/dev\/null(?:["']?)(?=\s|$))/

/** `git branch`: `-D`, or deletion (`-d`, abbreviated `--delete`) and force (`-f`, abbreviated `--force`), in any order. */
/**
 * Option searched in the tail of a `git <subcommand>` call. One pass per segment: the tail captured from
 * the first occurrence contains that of any following occurrence of the same segment (same end `;`, `&`, `|`), hence the
 * same result as a regex tested from each occurrence, without its quadratic cost (repeated `git push `).
 */
const gitTail = (call: RegExp, tail: RegExp) => (command: string) => [...command.matchAll(call)].some((match) => tail.test(match[1] ?? ""))

const gitCallLoose = (subcommand: string, after = "\\b") => new RegExp(`${GIT}(?:${subcommand})${after}([^;&|]*)`, "g")

const gitClean = gitTail(gitCallLoose("clean", "\\s+"), /-[a-zA-Z]*f/)
const gitResetHard = gitTail(gitCallLoose("reset", "\\s+"), new RegExp(longOptionPattern("hard")))
// `+` at the end of the tail: the old regex recognized it followed by the separator (`+;`), outside the segment.
const gitPushForceOption = gitTail(gitCallLoose("push"), /\s--force(?:-with-lease)?\b|\s-[a-zA-Z]*f\b|\s\+(?:\S|$)/)
// `.` optionally between quotes (git receives the word without them).
const gitDiscardAll = gitTail(gitCallLoose("checkout|restore"), /\s--\s+["']?\.|\s["']?\.["']?(?=\s|$)/)
const GIT_STASH_OR_FILTER = new RegExp(`${GIT}(?:stash\\s+(?:drop|clear)\\b|filter-branch\\b|filter-repo\\b)`)

const GIT_BRANCH = new RegExp(`${GIT}branch\\s+([^;&|]*)`, "g")

function forcedBranchDeletion(command: string): boolean {
  for (const match of command.matchAll(GIT_BRANCH)) {
    const tokens = (match[1] ?? "").split(/\s+/).map(unquote)
    const short = (letter: string) => tokens.some((token) => new RegExp(`^-[a-zA-Z]*${letter}`).test(token))
    if (short("D")) return true
    const remove = short("d") || tokens.some((token) => isLongOption(token, "delete"))
    const force = short("f") || tokens.some((token) => isLongOption(token, "force"))
    if (remove && force) return true
  }
  return false
}

/** `crontab -l` (read-only, optionally `-u user`): removed before looking for a modification. */
const CRONTAB_LIST = /(^|[\s;&|(`])crontab(?:\s+-u\s+\S+)?\s+-l\b(?:\s+-u\s+\S+)?(?=\s*(?:[;&|)<>]|$))/g

/**
 * Names of shells and interpreters for the dynamic rules (same sets as `EXECUTORS`,
 * plus historical variants for detection only).
 */
const DYNAMIC_SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "fish", "csh", "tcsh"])
const DYNAMIC_INTERPRETERS = new Set(["python", "node", "nodejs", "ruby", "perl", "php", "bun", "deno"])
const DYNAMIC_AWKS = new Set(["awk", "gawk", "nawk", "mawk"])

/** Bare name without path or bypass (`\cmd`, zsh's `=cmd`). */
function bareHead(token: string | undefined): string {
  if (!token) return ""
  return (commandName(token).split("/").pop() ?? "").toLowerCase().replace(/^\\/, "")
}

/** Versioned base (`python3.11` → `python`, `perl5.40` → `perl`, `ruby3.3` → `ruby`, `php8.3` → `php`), anchored like
 * the names of `EXECUTORS`: `perltidy`, `perldoc`, `phpunit`, `phpstan`… are not interpreters. */
function baseHead(head: string): string {
  if (/^python[0-9.]*$/.test(head)) return "python"
  if (/^perl(?:5[\w.-]*)?$/.test(head)) return "perl"
  if (/^ruby[\d.]*$/.test(head)) return "ruby"
  if (/^php[\d.]*$/.test(head)) return "php"
  return head
}

/** Kind of a wrapper's child (or of a program): single classification shared by both wrappers. */
type ChildKind = "shell" | "interpreter" | "awk" | "eval" | "find" | "git" | "launcher" | "rm" | "other"
function childKind(token: string): ChildKind {
  const head = baseHead(bareHead(token))
  if (DYNAMIC_SHELLS.has(head)) return "shell"
  if (DYNAMIC_INTERPRETERS.has(head)) return "interpreter"
  if (DYNAMIC_AWKS.has(head)) return "awk"
  if (head === "eval" || head === "source" || head === ".") return "eval"
  if (head === "find") return "find"
  if (head === "git") return "git"
  if (head === "xargs" || head === "parallel") return "launcher"
  if (head === "rm") return "rm"
  return "other"
}

/** Code option of a shell (`-c`, `-xc`, grouped `-c`). */
const isShellDashC = (token: string) => token === "-c" || /^-[a-zA-Z]*c[a-zA-Z]*$/.test(token)

/** Positional reference (`$1`, `$@`, `${1:-x}`…): the added input then supplies the executed source. */
const POSITIONAL_REF = /\$(?:[0-9@*#]|\{[0-9@*#][^}]*\})/

/** Template of the parallel wrapper (`{}`, `{1}`, `{//}`…: no space, no nested brace). */
const PARALLEL_PLACEHOLDER = /\{[^{}\s]*\}/
function hasParallelPlaceholder(token: string): boolean {
  return PARALLEL_PLACEHOLDER.test(token)
}

/** Options of the batch wrapper that take a value (third-party list, without execution). */
const XARGS_VALUE_OPTS = new Set([
  "-L",
  "-n",
  "-P",
  "-s",
  "-a",
  "-E",
  "-R",
  "-S",
  "-e",
  "-d",
  "-J",
  "--max-args",
  "--max-procs",
  "--max-chars",
  "--arg-file",
  "--eof",
  "--delimiter",
  "--max-lines",
  "--process-slot-var",
])

/**
 * Child of the batch wrapper and replacement token (`-I`, `-i`, `--replace`, `-J`), plus `help` (help/version
 * option specific to xargs, before the child). One pass, without nested expression.
 */
function xargsInfo(args: readonly string[]): { start: number; replacement: string | null; help: boolean } {
  let replacement: string | null = null
  let help = false
  let i = 0
  while (i < args.length) {
    const token = args[i]!
    if (token === "--") return { start: i + 1, replacement, help }
    if (!token.startsWith("-") || token === "-") return { start: i, replacement, help }
    if (token === "--help" || token === "--version") {
      help = true
      i += 1
      continue
    }
    if (token === "-I") {
      replacement = args[i + 1] ?? "{}"
      i += 2
      continue
    }
    if (token.startsWith("-I") && token.length > 2) {
      replacement = token.slice(2)
      i += 1
      continue
    }
    // `-i` (old form of `-I`, optional replacement attached).
    if (token === "-i") {
      replacement = "{}"
      i += 1
      continue
    }
    if (token.startsWith("-i") && token.length > 2) {
      replacement = token.slice(2) || "{}"
      i += 1
      continue
    }
    if (token === "--replace") {
      replacement = "{}"
      i += 1
      continue
    }
    if (token.startsWith("--replace=")) {
      const value = token.slice("--replace=".length)
      replacement = value === "" ? "{}" : value
      i += 1
      continue
    }
    if (token === "-J") {
      replacement = args[i + 1] ?? "{}"
      i += 2
      continue
    }
    i += XARGS_VALUE_OPTS.has(token) ? 2 : 1
  }
  return { start: args.length, replacement, help }
}

/** Options of the parallel wrapper that take a value (without execution). */
const PARALLEL_VALUE_OPTS = new Set([
  "-L",
  "-d",
  "-n",
  "--delay",
  "--delimiter",
  "--header",
  "--joblog",
  "--jl",
  "--max-args",
  "--max-lines",
  "--nice",
  "--results",
  "--result",
  "--res",
  "--tagstring",
  "--timeout",
  "--env",
  "--arg-file",
  "--colsep",
  "--rpl",
  "--arg-sep",
  "--arg-file-sep",
  "-S",
  "--sshlogin",
  "--slf",
  "--sshloginfile",
  "--workdir",
  "--wd",
  "-a",
])

/** Options of the parallel wrapper that redefine the replacement string: the template can then contain
 * one without a visible `{}`, so detection can no longer spot it (ask by default). */
function parallelRedefinesMarker(token: string): boolean {
  return (
    token === "-I" ||
    token === "--replace" ||
    token.startsWith("--replace=") ||
    token === "--er" ||
    token.startsWith("--er=") ||
    token === "--extensionreplace" ||
    token.startsWith("--extensionreplace=") ||
    token === "--bnr" ||
    token.startsWith("--bnr=") ||
    token === "--basenamereplace" ||
    token.startsWith("--basenamereplace=") ||
    token === "--dnr" ||
    token.startsWith("--dnr=") ||
    token === "--dirnamereplace" ||
    token.startsWith("--dirnamereplace=") ||
    token === "--bner" ||
    token.startsWith("--bner=") ||
    token === "--basenameextensionreplace" ||
    token.startsWith("--basenameextensionreplace=")
  )
}

/**
 * Simplified parsing of the parallel wrapper: its own options (help, quote, pipe), template, marker
 * (`:::`, `:::+`, `::::`, `::::+`) and its position. Help, quote and pipe are taken into account only among
 * `parallel` options, before the template. One pass, bounded windows.
 */
interface ParallelInfo {
  readonly template: readonly string[]
  readonly hasPlaceholder: boolean
  readonly hasMarker: boolean
  readonly markerToken: string | null
  readonly markerIndex: number
  readonly readsCommands: boolean
  readonly quotes: boolean
  readonly safe: boolean
}
const PARALLEL_MARKER = /^::::?\+?$/
function parallelInfo(args: readonly string[]): ParallelInfo {
  let safe = false
  let quotes = false
  let start = args.length
  let marker = -1
  let i = 0
  while (i < args.length) {
    const token = args[i]!
    if (PARALLEL_MARKER.test(token)) {
      marker = i
      start = Math.min(start, i)
      break
    }
    if (token === "--") {
      start = i + 1
      break
    }
    if (!token.startsWith("-") || token === "-") {
      start = i
      break
    }
    // Options specific to parallel (before the template).
    if (token === "--dry-run" || token === "--help" || token === "--version") safe = true
    if (token === "-q" || token === "--quote") quotes = true
    if (token === "-j" || token === "--jobs") {
      i += 2
      continue
    }
    if (PARALLEL_VALUE_OPTS.has(token) || (token.startsWith("--") && token.includes("="))) {
      i += token.includes("=") ? 1 : 2
      continue
    }
    i += 1
  }
  if (marker < 0)
    for (let j = start; j < args.length; j++)
      if (PARALLEL_MARKER.test(args[j]!)) {
        marker = j
        break
      }
  const end = marker >= 0 ? marker : args.length
  const template = start <= end ? args.slice(start, end) : []
  const hasMarker = marker >= 0
  const markerToken = marker >= 0 ? args[marker]! : null
  if (safe) return { template, hasPlaceholder: false, hasMarker, markerToken, markerIndex: marker, readsCommands: false, quotes: false, safe: true }
  const hasPlaceholder = !quotes && template.some(hasParallelPlaceholder)
  const readsCommands = template.length === 0 && !hasMarker
  return { template, hasPlaceholder, hasMarker, markerToken, markerIndex: marker, readsCommands, quotes, safe: false }
}

/**
 * Non-literal whole (`$…`, `${…}`, `$(…)`, backtick, glob): the executed content is not visible.
 * Bounded window, no backtracking.
 */
function isNonLiteralSource(text: string): boolean {
  return /[$`*?[\]]/.test(text)
}

/** Source designated by a leading variable (`$NAME`, `"${NAME}"`, `$(…)` at the start after quotes). */
function startsWithVariable(text: string): boolean {
  const trimmed = text.trim().replace(/^["']+/, "")
  return /^\$[A-Za-z_*{(@0-9#]/.test(trimmed) || /^\$\{/.test(trimmed) || trimmed.startsWith("$(") || trimmed.startsWith("`")
}

/** A single quoted string, nothing else (literal and static awk command). */
function isSingleStringLiteral(text: string): boolean {
  return /^"(?:[^"\\]|\\.)*"$/.test(text) || /^'[^']*'$/.test(text)
}

/**
 * Command text after `-c` (first argument after the code option) and script operand
 * (first argument not an option) for a shell. Bounded loops, one pass.
 */
function shellCodeAndScript(args: readonly string[]): { code: string | undefined; script: string | undefined } {
  let code: string | undefined
  let script: string | undefined
  let i = 0
  while (i < args.length) {
    const arg = args[i]!
    if (arg === "--") {
      script = args[i + 1]
      break
    }
    if (arg.startsWith("-") && arg !== "-") {
      // Grouped code option (`-c`, `-xc`): the text follows.
      if (isShellDashC(arg)) {
        code = args[i + 1]
        break
      }
      // Options with a value (`-o`, `-O`, `--rcfile`, `--init-file`): skips the next one.
      if (/^[-+][oO]$/.test(arg) || arg === "--rcfile" || arg === "--init-file") i += 2
      else i += 1
      continue
    }
    script = arg
    break
  }
  return { code, script }
}

/**
 * Decision for a wrapper's "template" mode: the replacement token (`markerIn`) appears in an
 * executed position (executable name, text after `-c`, code, script, interpreter/awk/eval argument, structural
 * position of find/git). Shared by both wrappers.
 */
function launcherTemplateExecutes(child: readonly string[], markerIn: (token: string) => boolean): boolean {
  if (child.length === 0) return false
  // Executable name itself supplied by the input (`xargs -I{} {} …`, `parallel {} ::: cmd`).
  if (markerIn(child[0]!)) return true
  const kind = childKind(child[0]!)
  if (kind === "rm" || kind === "other") return false
  const rest = child.slice(1)
  if (kind === "shell") {
    const dashC = rest.findIndex(isShellDashC)
    // Any marker after `-c` (code or positional): the input feeds the source (conservative ask).
    if (dashC >= 0) return rest.slice(dashC + 1).some(markerIn)
    const { code, script } = shellCodeAndScript(rest)
    if (code !== undefined && markerIn(code)) return true
    if (script !== undefined && markerIn(script)) return true
    // Without an explicit source, the added input becomes the source.
    return code === undefined && script === undefined
  }
  if (kind === "interpreter" || kind === "awk" || kind === "eval" || kind === "launcher") return rest.some(markerIn)
  // find / git: only before `--` (not a mere file after `--`).
  const end = child.indexOf("--")
  const structural = end >= 0 ? child.slice(1, end) : rest
  return structural.some(markerIn)
}

/**
 * Decision for a wrapper's "added input" mode: the input (lines read or marker values) becomes
 * an argument added to the command, which can then make it its executed source. Shared by both wrappers.
 */
function launcherStreamExecutes(child: readonly string[], kind: ChildKind): boolean {
  if (child.length === 0) return true
  const rest = child.slice(1)
  if (kind === "shell") {
    const { code, script } = shellCodeAndScript(rest)
    if (code === undefined && script === undefined) return true
    // Text with a positional reference (`$1`, `$@`): the input supplies the positions.
    if (code !== undefined) return POSITIONAL_REF.test(rest.join(" "))
    return false
  }
  if (kind === "interpreter" || kind === "awk") {
    // Without explicit code or script, the input becomes the program.
    return !rest.some((token) => !token.startsWith("-") && token !== "--")
  }
  if (kind === "eval" || kind === "launcher") return true
  if (kind === "git") {
    // Without a subcommand (only global options), the input can supply it.
    let j = 0
    while (j < rest.length) {
      if (rest[j] === "--" || !rest[j]!.startsWith("-")) break
      j += 1
    }
    return j >= rest.length || rest[j] === "--"
  }
  // find (paths only), other, rm: silent.
  return false
}

/**
 * Dynamic execution through the batch wrapper: child absent (reads commands), executable name
 * with a template, or executable source that the input can change. One pass per segment.
 */
function xargsDynamic(command: string): boolean {
  for (const segment of segments(command)) {
    const { name, args } = commandOf(segment)
    if (bareHead(name) !== "xargs") continue
    const { start, replacement, help } = xargsInfo(args)
    if (help) continue
    const child = args.slice(start)
    if (child.length === 0) return true
    if (replacement !== null) {
      if (launcherTemplateExecutes(child, (token) => token.includes(replacement))) return true
    } else {
      const kind = childKind(child[0]!)
      if (kind === "rm" || kind === "other") continue
      if (launcherStreamExecutes(child, kind)) return true
    }
  }
  return false
}

/**
 * Dynamic execution through the parallel wrapper: executable expression or redefined marker (ask
 * by default), commands read from the input, marker values becoming commands, template in the executable
 * source, or added input that can become the source. One pass per segment.
 */
function parallelDynamic(command: string): boolean {
  for (const segment of segments(command)) {
    const { name, args } = commandOf(segment)
    if (bareHead(name) !== "parallel") continue
    // Executable Perl expression (`{= … =}`): not checkable.
    if (/\{=/.test(segment) && /=\}/.test(segment)) return true
    // Redefined marker, column/argument separator, exported environment: not checkable.
    if (
      args.some(
        (arg) =>
          arg === "--rpl" ||
          arg.startsWith("--rpl=") ||
          arg === "--arg-sep" ||
          arg === "--arg-file-sep" ||
          arg === "--colsep" ||
          arg.startsWith("--colsep=") ||
          arg === "--env" ||
          arg.startsWith("--env="),
      )
    )
      return true
    // Options that redefine the replacement string: detection no longer sees it.
    if (args.some(parallelRedefinesMarker)) return true
    // Several value groups (`::: a ::: b`): not checkable.
    if ((segment.match(/:::/g) ?? []).length > 1) return true
    const info = parallelInfo(args)
    if (info.safe) continue
    if (info.template.length === 0) {
      // Empty template: the values (or the input) are the executed commands.
      if (info.readsCommands) return true
      if (info.hasMarker) {
        // Argument file (`::::`): invisible commands.
        if (info.markerToken === "::::" || info.markerToken === "::::+") return true
        const values = args.slice(info.markerIndex + 1).filter((value) => !PARALLEL_MARKER.test(value))
        if (values.some((value) => startsWithVariable(value) || isNonLiteralSource(value))) return true
      }
      continue
    }
    if (info.hasPlaceholder) {
      // `launcherTemplateExecutes` first spots the template in executable position, then rules out rm/other.
      if (launcherTemplateExecutes(info.template, hasParallelPlaceholder)) return true
    } else {
      // Without a `{}` template, the input (marker or pipe) is added as an argument.
      const kind = childKind(info.template[0]!)
      if (kind === "rm" || kind === "other") continue
      if (launcherStreamExecutes(info.template, kind)) return true
    }
  }
  return false
}

/**
 * Parsing of an interpreter through the `EXECUTORS` table: code option (`-c`, `-e`…) and its text, script
 * operand, reading the program from the input (`-`, stdin path, `-s`), and help/version (options of the program
 * itself, before its operand). Redirections and value options skipped. One pass.
 */
function parseExecutor(
  executor: (typeof EXECUTORS)[number],
  args: readonly string[],
): { code: string | undefined; script: string | undefined; readsStdin: boolean; help: boolean } {
  const isShell = executor === EXECUTORS[0]
  const start = executor.subcommand && args[0] !== undefined && executor.subcommand.test(args[0]) ? 1 : 0
  for (let i = start; i < args.length; i++) {
    const arg = args[i]!
    // Redirection (`2>/dev/null`, `2> err.log`): neither an option nor an operand.
    if (/^(?:\d*|&)[<>]/.test(arg)) {
      if (/^(?:\d*|&)[<>]+&?$/.test(arg)) i++
      continue
    }
    if (arg === "-" || STDIN_PATH.test(arg)) return { code: undefined, script: undefined, readsStdin: true, help: false }
    if (arg === "--") return { code: undefined, script: args[i + 1], readsStdin: false, help: false }
    if (arg.startsWith("-") || (executor.stdin && arg.startsWith("+"))) {
      if (arg === "--help" || arg === "--version" || (!isShell && arg === "-h")) return { code: undefined, script: undefined, readsStdin: false, help: true }
      if (executor.code.test(arg)) return { code: args[i + 1], script: undefined, readsStdin: false, help: false }
      if (executor.stdin?.test(arg)) return { code: undefined, script: undefined, readsStdin: true, help: false }
      if (executor.value?.test(arg)) i++
      continue
    }
    return { code: undefined, script: arg, readsStdin: false, help: false }
  }
  return { code: undefined, script: undefined, readsStdin: false, help: false }
}

/** Operand of an input redirection from a file (`< f`, `0<f`) or a here-string (`<<< v`); not a heredoc (`<<`). */
function stdinRedirectOperand(args: readonly string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!
    if (arg === "<" || arg === "0<" || arg === "<<<") {
      const operand = args[i + 1]
      if (operand !== undefined) return unquote(operand)
      continue
    }
    const match = /^(?:0?<<<|0?<)(?!<)(.+)$/.exec(arg)
    if (match) return unquote(match[1]!)
  }
  return undefined
}

/**
 * Shell or interpreter launched on a file or text designated by a variable (content not visible at
 * decision time). The program's help/version options invalidate the ask only if they
 * precede its operand. One pass per segment.
 */
function variableShellSource(command: string): boolean {
  for (const segment of segments(command)) {
    const { name, args } = commandOf(segment)
    const rawHead = bareHead(name)
    // Inclusion (`source f`, `. f`): operand looked up in PATH without `/`, content not visible if it is a variable/glob.
    if (rawHead === "source" || name === ".") {
      const op = args[0]
      if (op !== undefined && op !== "--help" && op !== "--version" && literalPath(op) === undefined && (startsWithVariable(op) || isNonLiteralSource(op))) return true
      continue
    }
    const executor = EXECUTORS.find((candidate) => candidate.name.test(name))
    if (!executor) continue
    const parsed = parseExecutor(executor, args)
    if (parsed.help) continue
    if (parsed.code !== undefined && startsWithVariable(parsed.code)) return true
    if (parsed.script !== undefined && literalPath(parsed.script) === undefined) {
      if (startsWithVariable(parsed.script)) return true
      // Node test runner mode (`node --test <glob>`): operand globs designate test
      // files, not a variable source; a variable always triggers (handled just above).
      const nodeTest = (rawHead === "node" || rawHead === "nodejs") && args.some((arg) => arg === "--test" || arg.startsWith("--test-"))
      if (!nodeTest && isNonLiteralSource(parsed.script)) return true
    }
    // Program read from input redirected from a file/string designated by a variable (without code or script).
    if (parsed.code === undefined && parsed.script === undefined) {
      const redir = stdinRedirectOperand(args)
      if (redir !== undefined && literalPath(redir) === undefined && startsWithVariable(redir)) return true
    }
  }
  return false
}

/**
 * Environment assignments at the start of a segment (wrappers `env`, `sudo`… included, like `commandOf`),
 * then the launched command and its arguments. One pass.
 */
function envAssignments(segment: string): { assigns: Map<string, string>; name: string; args: string[] } {
  const tokens = segment.split(/\s+/).filter(Boolean).map(unquote)
  const assigns = new Map<string, string>()
  let i = 0
  let wrapper: string | undefined
  while (i < tokens.length) {
    const token = tokens[i]!
    const assignment = /^([A-Za-z_][A-Za-z0-9_]*)=([\s\S]*)$/.exec(token)
    if (assignment) {
      assigns.set(assignment[1]!, assignment[2]!)
      i++
      continue
    }
    const nm = commandName(token)
    if (GROUPING_WORDS.has(token)) i++
    else if (nm in PREFIX_OPTIONS) {
      wrapper = nm
      i++
    } else if (wrapper && token.startsWith("-") && token !== "-") i += PREFIX_OPTIONS[wrapper]!.has(token) ? 2 : 1
    else if (wrapper === "timeout" && /^\d+(?:\.\d+)?[smhd]?$/.test(token)) {
      wrapper = undefined
      i++
    } else break
  }
  return { assigns, name: commandName(tokens[i] ?? ""), args: tokens.slice(i + 1) }
}

/**
 * Startup file designated by the environment (`BASH_ENV`, `ENV`, `ZDOTDIR`, wrappers included) or by
 * an option (`--rcfile`, `--init-file`: missing or non-literal value). Interactivity is read only
 * among the shell's options, before its operand. One pass per segment.
 */
function shellStartupFile(command: string): boolean {
  for (const segment of segments(command)) {
    const { assigns, name, args } = envAssignments(segment)
    const rawHead = bareHead(name)
    const head = baseHead(rawHead)
    const isBash = head === "bash"
    const isShLike = head === "sh" || head === "dash" || head === "ksh"
    const isZsh = head === "zsh"
    if (isBash || isShLike || isZsh) {
      // Interactivity: shell options, before its operand (`-i`, not `+i`, not a script option).
      let interactive = false
      for (const arg of args) {
        if (arg === "--") break
        if (!arg.startsWith("-")) break
        if (arg.startsWith("+")) continue
        if (/^-[a-zA-Z]*i/.test(arg)) interactive = true
      }
      if (isBash) {
        for (let k = 0; k < args.length; k++) {
          const arg = args[k]!
          if (arg === "--") break
          if (arg === "--rcfile" || arg === "--init-file") {
            const value = args[k + 1]
            if (value === undefined || value === "--" || isNonLiteralSource(value)) return true
          }
        }
      }
      const bashEnv = assigns.get("BASH_ENV")
      const shEnv = assigns.get("ENV")
      const zdotdir = assigns.get("ZDOTDIR")
      if (isBash && !interactive && bashEnv !== undefined && bashEnv !== "") return true
      if (isShLike && interactive && shEnv !== undefined && shEnv !== "") return true
      if (isZsh && zdotdir !== undefined && zdotdir !== "") return true
    }
    // Isolated export/declare/typeset: designates the startup of subsequent shells.
    if (rawHead === "export" || rawHead === "declare" || rawHead === "typeset") {
      if (/\bBASH_ENV=/.test(segment) || /(?:^|\s)ENV=/.test(segment) || /\bZDOTDIR=/.test(segment)) return true
    }
  }
  return false
}

/**
 * Text-processing program with execution of non-literal text (`system`, output pipe, pipe
 * to `getline`). Linear analysis with string and comment tracking. Programs with spaces or
 * pipes are quoted: split outside quotes.
 */
function awkDynamicExec(command: string): boolean {
  for (const segment of awkSegments(command)) {
    const { name, args } = commandOf(segment)
    const head = bareHead(name)
    if (!DYNAMIC_AWKS.has(head)) {
      // Child of a wrapper: checked by the wrapper rules, except a direct program with a dynamic
      // system call visible in the raw segment.
      if (bareHead(name) !== "xargs" && bareHead(name) !== "parallel") continue
      if (!/\b(?:awk|gawk|nawk|mawk)\b/.test(segment)) continue
      for (const quoted of quotedStrings(segment)) {
        if (/\bsystem\s*\(/.test(quoted) && /[$`{}]/.test(quoted) && awkProgramIsDynamic(quoted)) return true
      }
      continue
    }
    // Help/version: awk options, before its program.
    let help = false
    for (const arg of args) {
      if (arg === "--help" || arg === "--version" || arg === "-V") {
        help = true
        break
      }
      if (!arg.startsWith("-")) break
      if (arg === "--") break
      if (arg === "-e" || arg === "--source" || arg.startsWith("--source=")) break
      if (arg === "-f" || arg === "--file" || arg.startsWith("--file=") || (arg.startsWith("-f") && arg.length > 2)) break
    }
    if (help) continue
    // Program file or non-literal library (`-f`, `-i`/`--include`, `-l`/`--load`, `-E`/`--exec`,
    // long forms `--file=`…): content not visible.
    for (let k = 0; k < args.length; k++) {
      const arg = args[k]!
      if (arg === "-f" || arg === "--file" || arg === "-i" || arg === "--include" || arg === "-l" || arg === "--load" || arg === "-E" || arg === "--exec") {
        const value = args[k + 1] ?? ""
        if (value !== "" && isNonLiteralSource(value)) return true
        k++
      } else if (arg.length > 2 && (arg.startsWith("-f") || arg.startsWith("-i") || arg.startsWith("-l") || arg.startsWith("-E"))) {
        if (isNonLiteralSource(arg.slice(2))) return true
      } else if (arg.startsWith("--file=") || arg.startsWith("--include=") || arg.startsWith("--load=") || arg.startsWith("--exec=")) {
        if (isNonLiteralSource(arg.slice(arg.indexOf("=") + 1))) return true
      }
    }
    // Quoted sources in the raw segment (programs with spaces).
    const quoted = quotedStrings(segment)
    if (quoted.length > 0) {
      for (const program of quoted) {
        // Ignores data option values (`-F`, `-v`): only the program counts.
        if (!/[{}]|\bsystem\b|\|/.test(program)) continue
        if (awkProgramIsDynamic(program)) return true
      }
      continue
    }
    // Without quotes: first one not an option (case without spaces).
    let program: string | undefined
    for (let k = 0; k < args.length; k++) {
      const arg = args[k]!
      if (arg === "--") {
        program = args[k + 1]
        break
      }
      if (arg === "-e" || arg === "--source") {
        program = args[k + 1]
        break
      }
      if (arg.startsWith("-")) continue
      program = arg
      break
    }
    if (program !== undefined && awkProgramIsDynamic(program)) return true
  }
  return false
}

/** Quoted strings of a segment (single and double quotes, with escapes). */
function quotedStrings(segment: string): string[] {
  const out: string[] = []
  let i = 0
  while (i < segment.length) {
    const char = segment[i]!
    if (char !== '"' && char !== "'") {
      i += 1
      continue
    }
    const quote = char
    let j = i + 1
    let value = ""
    while (j < segment.length) {
      const inner = segment[j]!
      if (quote === '"' && inner === "\\" && j + 1 < segment.length) {
        value += inner + segment[j + 1]!
        j += 2
        continue
      }
      if (inner === quote) break
      value += inner
      j += 1
      if (value.length > 65536) break
    }
    if (j < segment.length) out.push(value)
    i = j + 1
  }
  return out
}

/** Split outside quotes (`;`, `&&`, `||`, `|`, `&`, newlines) for programs with pipes. */
function awkSegments(command: string): string[] {
  const parts: string[] = []
  let current = ""
  let quote: string | undefined
  let i = 0
  while (i < command.length) {
    const char = command[i]!
    if (quote) {
      current += char
      if (quote === '"' && char === "\\" && i + 1 < command.length) {
        current += command[i + 1]!
        i += 2
        continue
      }
      if (char === quote) quote = undefined
      i += 1
      continue
    }
    if (char === '"' || char === "'") {
      quote = char
      current += char
      i += 1
      continue
    }
    if (char === ";" || char === "&" || char === "|" || char === "\n") {
      if ((char === "&" && command[i + 1] === "&") || (char === "|" && command[i + 1] === "|")) {
        parts.push(current)
        current = ""
        i += 2
        continue
      }
      if (char === "|" || char === "&" || char === ";" || char === "\n") {
        parts.push(current)
        current = ""
        i += 1
        continue
      }
    }
    current += char
    i += 1
  }
  parts.push(current)
  for (const match of command.matchAll(/[$<>]\(([^()]*)\)|`([^`]*)`/g)) parts.push(match[1] ?? match[2] ?? "")
  return parts.map((part) => part.trim()).filter(Boolean)
}

/**
 * Linear scan of an awk program: `system(` with a non-literal argument, output pipe (`print … | cmd`)
 * to a non-literal command, input pipe (`cmd | getline`) from a non-literal command. The
 * statement start and the presence of `print` are tracked while advancing (no backward search, no
 * prefix copying: linear cost).
 */
function awkProgramIsDynamic(program: string): boolean {
  let i = 0
  let quote: string | undefined
  let stmtStart = 0
  let stmtHasPrint = false
  const reset = (pos: number) => {
    stmtStart = pos
    stmtHasPrint = false
  }
  while (i < program.length) {
    const char = program[i]!
    if (quote) {
      if (char === "\\") {
        i += 2
        continue
      }
      if (char === quote) quote = undefined
      i += 1
      continue
    }
    if (char === '"' || char === "'") {
      quote = char
      i += 1
      continue
    }
    if (char === "#") {
      const end = program.indexOf("\n", i)
      if (end < 0) break
      i = end + 1
      reset(i)
      continue
    }
    if (char === ";" || char === "\n" || char === "{" || char === "}") {
      i += 1
      reset(i)
      continue
    }
    // `print`/`printf` keyword of the current statement.
    if (char === "p" && !/[A-Za-z0-9_]/.test(program[i - 1] ?? "")) {
      if (program.startsWith("printf", i) && !/[A-Za-z0-9_]/.test(program[i + 6] ?? "")) {
        stmtHasPrint = true
        i += 6
        continue
      }
      if (program.startsWith("print", i) && !/[A-Za-z0-9_]/.test(program[i + 5] ?? "")) {
        stmtHasPrint = true
        i += 5
        continue
      }
    }
    // Isolated `system(`.
    if (program.startsWith("system", i) && !/[A-Za-z0-9_]/.test(program[i - 1] ?? "") && !/[A-Za-z0-9_]/.test(program[i + 6] ?? "")) {
      let j = i + 6
      while (j < program.length && /\s/.test(program[j]!)) j += 1
      if (program[j] !== "(") {
        i += 6
        continue
      }
      j += 1
      while (j < program.length && /\s/.test(program[j]!)) j += 1
      const next = program[j] ?? ""
      if (next !== '"' && next !== "'") return true
      const end = findAwkStringEnd(program, j, next)
      if (end < 0) return true
      let k = end
      while (k < program.length && /\s/.test(program[k]!)) k += 1
      if (program[k] !== ")") return true
      if (/[$`{}]/.test(program.slice(j + 1, end - 1))) return true
      i = k + 1
      continue
    }
    // Pipe (`|` or coprocess `|&`): excluding `||`.
    if (char === "|") {
      const coprocess = program[i + 1] === "&"
      if (!coprocess && (program[i - 1] === "|" || program[i + 1] === "|")) {
        i += program[i + 1] === "|" ? 2 : 1
        continue
      }
      let j = i + (coprocess ? 2 : 1)
      while (j < program.length && /\s/.test(program[j]!)) j += 1
      if (program.startsWith("getline", j) && !/[A-Za-z0-9_]/.test(program[j + 7] ?? "")) {
        // `command | getline`: the command is the left side of the statement. Dynamic unless it is
        // exactly a single literal string.
        if (i - stmtStart > 512) return true
        if (!isSingleStringLiteral(program.slice(stmtStart, i).trim())) return true
        i = j + 7
        continue
      }
      // `print … | cmd`: the command is to the right of the pipe.
      if (stmtHasPrint) {
        if (program[j] !== '"' && program[j] !== "'") return true
        const end = findAwkStringEnd(program, j, program[j]!)
        if (end < 0) return true
        let k = end
        while (k < program.length && /[ \t]/.test(program[k]!)) k += 1
        const after = program[k]
        if (after !== undefined && after !== ";" && after !== "\n" && after !== "#" && after !== "}") return true
        if (/[$`{}]/.test(program.slice(j + 1, end - 1))) return true
        i = k
        continue
      }
      i += coprocess ? 2 : 1
      continue
    }
    i += 1
  }
  return false
}

/** End of a quoted string (with escapes), or -1 if unclosed. */
function findAwkStringEnd(program: string, start: number, quote: string): number {
  let i = start + 1
  while (i < program.length) {
    const char = program[i]!
    if (char === "\\") {
      i += 2
      continue
    }
    if (char === quote) return i + 1
    i += 1
  }
  return -1
}

/**
 * Version-control settings whose value designates a program to launch (command, tool, editor,
 * pager, hook, driver, filter, helper, help). Alias and inclusion keys are covered by
 * the `git-config-alias` rule (same switch). List checked against the local git documentation.
 */
const GIT_PROGRAM_KEYS = [
  "core.sshcommand",
  "core.gitproxy",
  "core.fsmonitor",
  "core.askpass",
  "core.editor",
  "core.pager",
  "core.hookspath",
  "core.alternaterefscommand",
  "diff.external",
  "diff.*.command",
  "diff.*.textconv",
  "difftool.*.cmd",
  "difftool.*.path",
  "merge.tool",
  "mergetool.*.cmd",
  "mergetool.*.path",
  "merge.*.driver",
  "filter.*.clean",
  "filter.*.smudge",
  "filter.*.process",
  "credential.helper",
  "credential.*.helper",
  "gpg.program",
  "gpg.*.program",
  "gpg.ssh.defaultkeycommand",
  "guitool.*.cmd",
  "sequence.editor",
  "sendemail.sendmailcmd",
  "sendemail.tocmd",
  "sendemail.cccmd",
  "sendemail.headercmd",
  "pager.*",
  "man.viewer",
  "man.*.cmd",
  "man.*.path",
  "browser.*.cmd",
  "browser.*.path",
  "web.browser",
  "instaweb.browser",
  "instaweb.httpd",
  "imap.tunnel",
  "interactive.difffilter",
  "remote.*.receivepack",
  "remote.*.uploadpack",
  "remote.*.vcs",
  "submodule.*.update",
  "trailer.*.cmd",
  "trailer.*.command",
  "uploadpack.packobjecthook",
  "gc.recentobjectshook",
  "init.templatedir",
  "protocol.allow",
  "protocol.*.allow",
]
function gitProgramKeyPattern(key: string): string {
  // `*`: a subsection that may contain dots (credential URL, dotted driver…), bounded to the token
  // (everything except space, `=` and command separators); the literal final component follows. Case handled by `caseless`.
  const parts = key.split("*")
  return parts.map((part) => caseless(part)).join("[^\\s=;|&]+")
}
const GIT_PROGRAM_OPTION = new RegExp(
  String.raw`git(?:\s+${GIT_GLOBAL_OPTION}){0,15}?\s+(?:-c\s*|--config-env(?:=|\s+))["']?(?:${GIT_PROGRAM_KEYS.map(gitProgramKeyPattern).join("|")})\s*=`,
)
/** Environment variables that designate a program, an executables path or a protocol launching a command. */
const GIT_PROGRAM_ENV =
  /(?<![\w$])(?:GIT_SSH_COMMAND|GIT_SSH|GIT_ASKPASS|GIT_PAGER|GIT_EDITOR|GIT_SEQUENCE_EDITOR|GIT_EXTERNAL_DIFF|GIT_PROXY_COMMAND|GIT_EXEC_PATH|GIT_TEMPLATE_DIR|GIT_ALLOW_PROTOCOL)=/
/** Global option `--exec-path=<path>` (git's subprogram directory) with a value; bare, it only displays the path. */
const GIT_EXEC_PATH_OPTION = /(?:^|[\s;&|(`])git\s[^;&|]{0,200}?--exec-path(?:=\S|\s+[^\s;&|-])/
function gitProgramConfig(command: string): boolean {
  return GIT_PROGRAM_OPTION.test(command) || GIT_PROGRAM_ENV.test(command) || GIT_EXEC_PATH_OPTION.test(command)
}

/** Code option of an interpreter whose argument text launches an already-condemned command. */
const INTERPRETER_DANGEROUS_CODE =
  /(\b(?:python[0-9.]*|node|nodejs|bun|ruby[\d.]*|perl(?:5[\w.-]*)?|php[\d.]*)(?:\s+-[^\s;&|'"]+){0,6}?\s+(?:-c|-e|-p|-E|-r|--eval|--print)\s+|\bdeno\s+eval\s+)("(?:[^"\\]|\\.)*"|'[^']*')/g

/** Recursive/forced deletion in a text (an option token starting with `-` contains `r`, `R` or `f`). */
function codeHasRecursiveRm(code: string): boolean {
  for (const match of code.matchAll(/(?:^|[\s;&|(`'"])rm\b/gi)) {
    const after = code.slice(match.index + match[0].length, match.index + match[0].length + 200)
    for (const token of after.split(/[\s;|&)'"]+/).filter(Boolean).slice(0, 12)) {
      if (!token.startsWith("-")) continue
      if (token.startsWith("--")) {
        if (isLongOption(token, "recursive") || isLongOption(token, "force")) return true
      } else if (/[rRf]/.test(token.slice(1))) return true
    }
  }
  return false
}

/**
 * Code passed to an interpreter that launches an already-condemned command (deletion, raw write,
 * irreversible version control, executed download). Reuses the predicates of the existing rules
 * (a single source of truth). One pass over code blocks, bounded patterns.
 */
function interpreterDangerousCode(command: string): boolean {
  for (const match of command.matchAll(INTERPRETER_DANGEROUS_CODE)) {
    const quoted = match[2] ?? ""
    const code = quoted.length >= 2 ? quoted.slice(1, -1) : quoted
    if (code.length === 0 || code.length > 65536) continue
    const lower = code.toLowerCase()
    // Execution sink (system call, evaluation, process creation); prefixes (`exec*`, `spawn*`) included.
    const hasSink =
      /\b(?:system|popen|subprocess|child_process|open3|eval|fork|qx|shell_exec|passthru|proc_open|pcntl_exec|spawn\w*|exec\w*)\b/.test(lower) ||
      code.includes("`") ||
      /%x/.test(code)
    if (!hasSink) continue
    if (codeHasRecursiveRm(code)) return true
    if (/(?:^|[\s;&|(`'"])dd\b[^;|&]{0,200}?\bof=\/dev\//i.test(code)) return true
    if (/\bmkfs\b/i.test(code) || /\bshred\b/i.test(code)) return true
    if (/(?:^|[\s;&|(`'"])find\b[^;&|]{0,200}?(?:-delete\b|-exec\s+rm\b)/i.test(code)) return true
    if (gitClean(code) || gitResetHard(code) || gitPushForceOption(code) || pushForcesRefs(code) || gitDiscardAll(code) || GIT_STASH_OR_FILTER.test(code)) return true
    if (pipesDownloadToShell(code)) return true
  }
  return false
}

/**
 * OpenCode 2.1.1 CLI (`packages/cli/src/commands/commands.ts`), read like the `effect/cli` 4.0.1 parser: `opencode`
 * launched by common recognition, or behind assignments, then the call tail (`callTail`). Global options
 * (and, before the first word, those of the root) skipped before and between the subcommand words, with their
 * value; a boolean swallows the literal that follows it.
 */
const OPENCODE_CALL = new RegExp(commandRegex("opencode", undefined, true).source, "g")
/**
 * Binary attached to a quote, searched separately (a discarded match does not hide any `OPENCODE_CALL` call):
 * counted only if that quote closes the `-c` wrapper containing it.
 */
const OPENCODE_QUOTED_CALL = new RegExp(commandRegex("opencode", "(?=[\"'])", true).source, "g")
/** Opening quote of a `-c` wrapper, as in common recognition. */
const LAUNCHER_OPENING = /-[a-zA-Z]*c\s+(["'])/g
/**
 * Assignments (`A=1 B=2 opencode`), which common recognition does not skip, recognized by this layer alone: segment
 * or `-c` wrapper head followed by an assignment, then at most 8 assignments (quoted value, substitution
 * without nested parentheses, or a word without parenthesis, quote or separator; no head in such a word: linear
 * cost), then the same recognition at the start of the text that follows.
 */
const ASSIGNMENTS_START = /(?:^|[;&|(`\n]|-[a-zA-Z]*c\s+["'])[^\S\n]*(?=[A-Za-z_]\w*=)/g
const ASSIGNMENT = /([A-Za-z_]\w*)=('[^'\n]*'|"[^"\n]*"|\$\([^()\n]*\)|[^\s;&|()`'"]*)[^\S\n]+/y
const OPENCODE_HEAD = new RegExp(`^(?:${commandRegex("opencode", undefined, true).source})`)
const OPENCODE_QUOTED_HEAD = new RegExp(`^(?:${OPENCODE_QUOTED_CALL.source})`)
/** The operator alone (`2>`, `>`, `<<-`) has its target in the next word. */
const BARE_REDIRECTION = /^(?:\d+|&)?[<>][<>&|-]*$/
/** Word without expansion or splitting at run time: ordinary characters, or entirely quoted. */
const PLAIN_WORD = /^(?:[\w./:=@%+,-]+|'[^']*'|"[^"$`\\]*")$/
const BOOLEAN_LITERALS = new Set(["true", "yes", "on", "1", "y", "false", "no", "off", "0", "n"])
const isOptionWord = (word: string) => word.startsWith("-") && word !== "-"

/** Options (name or letter; `=` : takes a value): global of `effect/cli` and `--print-logs`, root, `api`. */
const OPENCODE_GLOBAL = "help h version v wizard print-logs completions= log-level="
const flagTable = (names: string) => new Map(names.split(" ").map((name) => [name.replace(/=$/, ""), name.endsWith("=")] as const))
const OPENCODE_GLOBAL_FLAGS = flagTable(OPENCODE_GLOBAL)
const OPENCODE_ROOT_FLAGS = flagTable(`${OPENCODE_GLOBAL} standalone server= auto yolo dangerously-skip-permissions continue c session= s= prompt=`)
const OPENCODE_API_FLAGS = flagTable(`${OPENCODE_GLOBAL} standalone server= data= d= header= H= param=`)

/** Root subcommands, with the words of those that have several levels (`debug heap-dump`: OpenCode 2.1.4). */
const OPENCODE_COMMANDS = new Map<string, readonly string[]>([
  ..."upgrade update uninstall acp api models stats mini run reload pair serve".split(" ").map((name) => [name, []] as const),
  ["debug", ["agents", "config", "heap-dump", "paths"]],
  ["auth", ["list", "login", "logout", "export", "import", "switch"]],
  ["mcp", ["list", "add", "auth", "logout"]],
  ["plugin", ["list", "add", "check", "update", "remove"]],
  ["session", ["list", "delete", "export", "import"]],
  ["service", ["start", "restart", "status", "stop", "get", "set", "unset"]],
])

/** Findings of a call (`printed`: output that prints a secret); `OPENCODE_KINDS`: without examining arguments. */
type OpencodeKind = "nested" | "service-change" | "service-secret" | "credentials" | "printed" | "heap-dump" | "api" | "config" | "unchecked" | "long"
const OPENCODE_KINDS = new Map<string, readonly OpencodeKind[]>([
  ...["run", "serve", "acp"].map((name) => [name, ["nested"]] as const),
  ...["uninstall", "service set", "service unset", "service stop", "service restart"].map((name) => [name, ["service-change"]] as const),
  ["pair", ["service-secret"]],
  ["auth export", ["credentials", "printed"]],
  ["debug heap-dump", ["heap-dump"]],
  ...["plugin add", "plugin remove", "mcp add"].map((name) => [name, ["config"]] as const),
])

/**
 * API reads: GET operations of the OpenCode 2.1.1 protocol (`packages/protocol/openapi.json`), identifier then
 * path template, except `credential.list`, `server.connect`, `config.get`, `fs.read` and the two WebSocket
 * (`pty.connect`, `persistentPty.connect`). Any other operation asks, including one from a future version.
 */
const OPENCODE_API_READS = `
  agent.list /api/agent  agent.get /api/agent/{agentID}  command.list /api/command  config.shells /api/config/shell
  debug.location.list /api/debug/location  event.subscribe /api/event  experimental.migration.v1.status /api/experimental/migration/v1
  server.experimental.persistentPty.get /api/experimental/persistent-pty/{ptyID}
  server.experimental.persistentPty.snapshot /api/experimental/persistent-pty/{ptyID}/snapshot
  experimental.session.stats /api/experimental/session/stats  experimental.session.export /api/experimental/session/{sessionID}/export
  experimental.session.instructions.entry.list /api/experimental/session/{sessionID}/instructions/entries
  session.log /api/experimental/session/{sessionID}/log
  server.experimental.persistentPty.list /api/experimental/session/{sessionID}/terminal
  server.experimental.persistentPty.read /api/experimental/session/{sessionID}/terminal/read  form.list /api/form  fs.find /api/fs/find
  fs.list /api/fs/list  server.info /api/info  integration.list /api/integration  integration.get /api/integration/{integrationID}
  integration.command.status /api/integration/{integrationID}/connect/command/{attemptID}
  integration.oauth.status /api/integration/{integrationID}/connect/oauth/{attemptID}  location.get /api/location  mcp.list /api/mcp
  mcp.resource.catalog /api/mcp/resource  model.list /api/model  model.default /api/model/default
  permission.request.list /api/permission/request  permission.saved.list /api/permission/saved  plugin.list /api/plugin
  project.list /api/project  provider.list /api/provider  provider.get /api/provider/{providerID}  pty.list /api/pty
  pty.get /api/pty/{ptyID}  reference.list /api/reference  session.list /api/session  session.active /api/session/active
  session.get /api/session/{sessionID}  session.context /api/session/{sessionID}/context  session.diff /api/session/{sessionID}/diff
  session.form.list /api/session/{sessionID}/form  session.form.get /api/session/{sessionID}/form/{formID}
  session.inbox.list /api/session/{sessionID}/inbox  session.message.list /api/session/{sessionID}/message
  session.message.get /api/session/{sessionID}/message/{messageID}  session.permission.list /api/session/{sessionID}/permission
  session.permission.get /api/session/{sessionID}/permission/{requestID}  shell.list /api/shell  shell.get /api/shell/{id}
  shell.output /api/shell/{id}/output  skill.list /api/skill  vcs.get /api/vcs  vcs.base /api/vcs/base  vcs.branch.list /api/vcs/branch
  vcs.diff /api/vcs/diff  vcs.status /api/vcs/status  websearch.providers /api/websearch/provider  worktree.list /api/worktree
`.trim().split(/\s+/)
const API_READ_IDS = new Set(OPENCODE_API_READS.filter((_, index) => index % 2 === 0))
/** Templates, and the API description document (outside the protocol, read by the CLI itself). */
const API_READ_PATHS = [...OPENCODE_API_READS.filter((_, index) => index % 2 === 1), "/openapi.json"].map((path) => path.split("/"))
/** `opencode service get` keys that display neither the password nor the environment. */
const SERVICE_PLAIN_KEYS = new Set(["disabled", "remote", "hostname", "port", "cors"])

/**
 * Words swallowed by an option read like `effect/cli` (`--name`, `--name=value`, `--no-<boolean>`, `-x`, `-x=value`, cluster
 * `-hv` where the last letter decides): its value, or the literal following a boolean; `undefined` if unknown.
 */
function optionWidth(option: string, next: string | undefined, flags: ReadonlyMap<string, boolean>): number | undefined {
  const long = option.startsWith("--")
  const body = option.slice(long ? 2 : 1)
  const equal = body.indexOf("=")
  const names = equal >= 0 ? [body.slice(0, equal)] : long ? [body] : [...body]
  const literal = next !== undefined && BOOLEAN_LITERALS.has(next) ? 1 : 0
  if (long && equal < 0 && !flags.has(body) && body.startsWith("no-") && flags.get(body.slice(3)) === false) return literal
  if (!names.every((name) => flags.has(name))) return undefined
  if (equal >= 0) return 0
  if (!flags.get(names.at(-1)!)) return literal
  return next !== undefined && !isOptionWord(next) ? 1 : 0
}

/** Character preceded by an odd number of backslashes: escaped. */
function escapedAt(text: string, index: number): boolean {
  let count = 0
  while (text[index - 1 - count] === "\\") count++
  return count % 2 === 1
}

/**
 * Spans of `-c` wrappers, per quote: from the opener to the first following quote of the same kind, unescaped
 * inside double quotes as for the shell (otherwise the end). For a given quote, sorted and disjoint (an opener
 * follows a blank, it is never escaped): each character is searched only once.
 */
function launcherSpans(command: string): ReadonlyArray<ReadonlyArray<readonly [number, number]>> {
  const spans: Record<string, Array<readonly [number, number]>> = { "'": [], '"': [] }
  for (const match of command.matchAll(LAUNCHER_OPENING)) {
    const open = match.index + match[0].length - 1
    let close = command.indexOf(match[1]!, open + 1)
    while (match[1] === '"' && close > 0 && escapedAt(command, close)) close = command.indexOf('"', close + 1)
    spans[match[1]!]!.push([open, close < 0 ? command.length : close])
  }
  return Object.values(spans)
}

/** Closest closing quote of the `-c` wrappers containing the position (binary search), otherwise the end. */
function launcherEnd(spans: ReturnType<typeof launcherSpans>, index: number, length: number): number {
  let end = length
  for (const list of spans) {
    let low = 0
    for (let high = list.length; low < high; ) {
      const middle = (low + high) >> 1
      if (list[middle]![0] < index) low = middle + 1
      else high = middle
    }
    if (low > 0 && list[low - 1]![1] >= index) end = Math.min(end, list[low - 1]![1])
  }
  return end
}

/**
 * Call tail: up to the separator outside quotes (except `>&`, `<&`, `&>`, `>|`), at the newline or at
 * `stop` (closing quote of a `-c` wrapper); bounded (linear cost; more than 1,024 characters: `long`).
 */
function callTail(command: string, start: number, stop: number): string {
  let quote: string | undefined
  let end = start
  for (; end < stop && end - start <= 1024; end++) {
    const char = command[end]
    if (char === "\n") break
    if (quote !== undefined) {
      if (char === quote) quote = undefined
    } else if (char === "'" || char === '"') quote = char
    else if (char === ";" || char === ")" || char === "`") break
    else if (char === "&" && command[end - 1] !== "<" && command[end - 1] !== ">" && command[end + 1] !== ">") break
    else if (char === "|" && command[end - 1] !== ">") break
  }
  return command.slice(start, end)
}

/** Start of a redirection inside a word, outside quotes (`2>&1`, `&>f`, attached: `word>f`; not `<(…)`), otherwise -1. */
function redirectionAt(token: string): number {
  if (!/[<>]/.test(token)) return -1
  let quote: string | undefined
  for (let i = 0; i < token.length; i++) {
    const char = token[i]!
    if (quote) quote = char === quote ? undefined : quote
    else if (char === "'" || char === '"') quote = char
    else if ((char === "<" || char === ">") && token[i + 1] !== "(") return /^(?:\d+|&)?$/.test(token.slice(0, i)) ? 0 : token[i - 1] === "&" ? i - 1 : i
  }
  return -1
}

/** Words of a call tail: redirections removed (with their detached target), final comment discarded. */
function tailWords(tail: string): string[] {
  const words: string[] = []
  const tokens = tail.split(/\s+/).filter(Boolean)
  for (let i = 0; i < tokens.length && !tokens[i]!.startsWith("#"); i++) {
    const at = redirectionAt(tokens[i]!)
    if (at !== 0) words.push(at < 0 ? tokens[i]! : tokens[i]!.slice(0, at))
    if (at >= 0 && BARE_REDIRECTION.test(tokens[i]!.slice(at))) i++
  }
  return words
}

/**
 * Subcommand path (`service get`) and the words that follow it. Unknown option or word that is not ordinary, before or
 * between the words of a subcommand, or literal word unknown where a group expects one of its subcommands (newer
 * OpenCode version): `unchecked`. First literal word that is not a subcommand (the root's directory operand), or
 * double dash at those places (`effect/cli` cuts argv at the first one and no longer chooses a subcommand after it): no
 * words.
 */
function readOpencodeCall(tokens: readonly string[]): { words: string[]; rest: readonly string[]; unchecked: boolean } {
  const words: string[] = []
  for (let i = 0; i < tokens.length; i++) {
    const raw = tokens[i]!
    const text = unquote(raw)
    if (!PLAIN_WORD.test(raw)) return { words, rest: [], unchecked: true }
    if (text === "--") return { words: [], rest: [], unchecked: false }
    if (isOptionWord(text)) {
      const next = tokens[i + 1]
      const width = optionWidth(text, next === undefined ? undefined : unquote(next), words.length ? OPENCODE_GLOBAL_FLAGS : OPENCODE_ROOT_FLAGS)
      if (width === undefined || (width === 1 && !PLAIN_WORD.test(next!))) return { words, rest: [], unchecked: true }
      i += width
      continue
    }
    const children = words.length ? OPENCODE_COMMANDS.get(words[0]!)! : undefined
    if (children && !children.includes(text)) return { words, rest: [], unchecked: true }
    if (!children && !OPENCODE_COMMANDS.has(text)) return { words: [], rest: [], unchecked: false }
    words.push(text)
    if (children || OPENCODE_COMMANDS.get(text)!.length === 0) return { words, rest: tokens.slice(i + 1), unchecked: false }
  }
  return { words, rest: [], unchecked: false }
}

/** Positional words following a subcommand, `flags` options skipped; `doubt`: unknown option, doubtful word. */
function leafWords(rest: readonly string[], flags: ReadonlyMap<string, boolean>) {
  const positionals: Array<{ readonly raw: string; readonly text: string }> = []
  let doubt = false
  for (let i = 0; i < rest.length; i++) {
    const raw = rest[i]!
    const text = unquote(raw)
    doubt ||= !PLAIN_WORD.test(raw)
    if (!isOptionWord(text)) {
      positionals.push({ raw, text })
      continue
    }
    const width = optionWidth(text, rest[i + 1] === undefined ? undefined : unquote(rest[i + 1]!), flags)
    doubt ||= width === undefined || (width === 1 && !PLAIN_WORD.test(rest[i + 1]!))
    i += width ?? 0
  }
  return { positionals, doubt }
}

/** Path of a read, query removed: exact template, `{parameter}` = a segment of letters, digits, `_` or `-`. */
function readPath(path: string): boolean {
  const parts = path.split("?")[0]!.split("/")
  return API_READ_PATHS.some(
    (template) => template.length === parts.length && template.every((part, i) => (part.startsWith("{") ? /^[\w-]+$/.test(parts[i]!) : part === parts[i])),
  )
}

/**
 * Path as the server routes it: the CLI's `new URL` (segments `.`, `..` and `%2e` resolved), then the `effect`
 * 4.0.1 router with default settings (`FindMyWay`: doubled slashes reduced, cut at `;`, escapes decoded except `%25`
 * and reserved characters, trailing slash removed, case ignored). `undefined`: path rejected by the router.
 */
function routedPath(path: string): string | undefined {
  try {
    const sent = URL.parse(path, "http://localhost")?.pathname.replace(/\/\/+/g, "/").split(";")[0]!.replaceAll("%25", "%2525")
    return sent === undefined ? undefined : decodeURI(sent).replace(/(?<=.)\/$/, "").toLowerCase()
  } catch {
    return undefined
  }
}

/**
 * `opencode api`: exact identifier of a read, or GET (any case) and path of a read; without an operation, the list
 * of operations. Everything else asks: write, sensitive GET, unknown identifier or option, doubtful word.
 */
function apiKinds(rest: readonly string[], kinds: Set<OpencodeKind>): void {
  const { positionals, doubt } = leafWords(rest, OPENCODE_API_FLAGS)
  const words = positionals.map((word) => word.text)
  const get = (word: string | undefined) => word?.toLowerCase() === "get"
  if (words.some((word, i) => word === "credential.list" || (get(word) && routedPath(words[i + 1] ?? "") === "/api/credential")))
    kinds.add("credentials").add("printed")
  const read = words.length === 0 || (words.length === 1 && API_READ_IDS.has(words[0]!)) || (words.length === 2 && get(words[0]) && readPath(words[1]!))
  if (doubt || !read) kinds.add("api")
}

/** `opencode service get`: without a key (everything except the password, environment included), `password` and `env` print a secret. */
function serviceGetKinds(rest: readonly string[], kinds: Set<OpencodeKind>): void {
  const key = leafWords(rest, OPENCODE_GLOBAL_FLAGS).positionals[0]
  const plain = key !== undefined && PLAIN_WORD.test(key.raw)
  if (!plain || !SERVICE_PLAIN_KEYS.has(key.text)) kinds.add("service-secret")
  if (key === undefined || (plain && (key.text === "password" || key.text === "env"))) kinds.add("printed")
}

let lastOpencodeCommand: string | undefined
let lastOpencodeKinds: ReadonlySet<OpencodeKind> = new Set()

/**
 * Findings of a call whose binary ends at `start`; `stop`: closing quote of a `-c` wrapper, otherwise the end.
 * Returns true if the tail goes up to `stop`. Backtick in the tail or at its cut (whether it opens a
 * substitution or closes an enclosing substitution, without distinction): `unchecked`.
 */
function callKinds(command: string, start: number, stop: number, kinds: Set<OpencodeKind>): boolean {
  const tail = callTail(command, start, stop)
  const call = readOpencodeCall(tailWords(tail))
  const name = call.words.join(" ")
  if (tail.length > 1024) kinds.add("long")
  if (call.unchecked || tail.includes("`") || command[start + tail.length] === "`") kinds.add("unchecked")
  for (const kind of OPENCODE_KINDS.get(name) ?? []) kinds.add(kind)
  if (name === "api") apiKinds(call.rest, kinds)
  if (name === "service get") serviceGetKinds(call.rest, kinds)
  return start + tail.length === stop
}

/**
 * Findings of OpenCode CLI calls in a command: a single analysis, shared by the table entries. Behind
 * the assignment that makes the program behave like Bun (`BUN_BE_BUN=1`, a value OpenCode uses itself):
 * nothing new. Tail that goes up to the closing quote of a `-c` wrapper followed (after that of an enclosing wrapper)
 * by text that the shell attaches to the last word (backtick included), neither blank, nor separator, nor redirection, nor
 * the end: `unchecked`.
 */
function opencodeKinds(command: string): ReadonlySet<OpencodeKind> {
  if (command === lastOpencodeCommand) return lastOpencodeKinds
  const kinds = new Set<OpencodeKind>()
  if (command.includes("opencode")) {
    const spans = launcherSpans(command)
    const call = (start: number) => {
      const stop = launcherEnd(spans, start, command.length)
      if ((command[start] === '"' || command[start] === "'") && start !== stop) return
      if (!callKinds(command, start, stop, kinds) || stop === command.length) return
      const next = launcherEnd(spans, stop + 1, command.length) === stop + 1 ? stop + 2 : stop + 1
      if (/[^\s;&|)<>]/.test(command.charAt(next))) kinds.add("unchecked")
    }
    for (const match of command.matchAll(OPENCODE_CALL)) call(match.index + match[0].length)
    if (/opencode["']/.test(command)) for (const match of command.matchAll(OPENCODE_QUOTED_CALL)) call(match.index + match[0].length)
    for (const match of command.matchAll(ASSIGNMENTS_START)) {
      let end = match.index + match[0].length
      let bun = false
      ASSIGNMENT.lastIndex = end
      for (let count = 0, word = ASSIGNMENT.exec(command); word && count < 8; count++, word = ASSIGNMENT.exec(command)) {
        bun ||= word[1] === "BUN_BE_BUN" && unquote(word[2]!) === "1"
        end = ASSIGNMENT.lastIndex
      }
      const head = bun || end === match.index + match[0].length ? null : (OPENCODE_HEAD.exec(command.slice(end)) ?? OPENCODE_QUOTED_HEAD.exec(command.slice(end)))
      if (head) call(end + head[0].length)
    }
  }
  lastOpencodeCommand = command
  lastOpencodeKinds = kinds
  return kinds
}

const CONFIRMED_OUTPUT_REDACTION =
  "once confirmed, its output is redacted unless output redaction is turned off (redactOutputs), which covers the service password, the remote access route, " +
  "credential values (keys, OAuth tokens) and the pairing code (links, server response, QR code); other values, such as environment variables with neutral names or credential metadata, reach the agent's model provider and the decision model (output check) as is"

/**
 * OpenCode CLI asks, at the end of `ASK_RULES`: an existing ask keeps its identifier. Forms already promised
 * (binary by its path, global option before or in the middle of the subcommand): existing reason, word for word.
 */
const OPENCODE_ASK_RULES: readonly RegexRule[] = (
  [
    ["opencode-service", "service-change", "change to the OpenCode service (environment, restart) or uninstall: can disable the guard"],
    ["opencode-service", "service-secret", `display of the OpenCode service password, environment or settings, or pairing (access to the server): ${CONFIRMED_OUTPUT_REDACTION}`],
    ["opencode-server-api", "credentials", `export of the OpenCode credentials (auth export, or the credential list of the server API): ${CONFIRMED_OUTPUT_REDACTION}`],
    ["opencode-server-api", "heap-dump", "copy of the OpenCode server memory written to a file (debug heap-dump): it can contain the OpenCode credentials, the service password and other secrets"],
    ["opencode-server-api", "api", "call to the OpenCode server API other than a known read (write, sensitive read, unknown operation): it can bypass the guard"],
    ["nested-opencode", "nested", "launches another OpenCode agent or server, or changes its configuration: it may run without the guard or approve its confirmations (--auto)"],
    ["nested-opencode", "long", "OpenCode command line longer than the plugin checks (1024 characters after the program name): it cannot be checked"],
    ["nested-opencode", "unchecked", "OpenCode command line with an unknown option or a word known only at run time in its subcommand: it cannot be checked"],
    ["self-protection", "config", "OpenCode command that adds or removes a plugin or adds an MCP server: rewrites OpenCode's configuration (self-protection)"],
  ] as const
).map(([id, kind, reason]): RegexRule => ({ id, verdict: "ask", reason, test: (command) => opencodeKinds(command).has(kind) }))

const ASK_RULES: readonly RegexRule[] = [
  {
    id: "find-delete",
    verdict: "ask",
    reason: "deletion via find",
    test: re(/(?:^|[\s;&|(`])find\s[^;&|]*(?:-delete\b|-exec\s+rm\b)/),
  },
  // Git global options (`git -C repo …`, `-c`, `--no-pager`, `--`) skipped before the subcommand: `${GIT}`.
  { id: "git-clean", verdict: "ask", reason: "git clean -f (untracked files deleted)", test: gitClean },
  {
    id: "git-reset-hard",
    verdict: "ask",
    reason: "git reset --hard (uncommitted changes lost)",
    test: gitResetHard,
  },
  {
    id: "git-push-force",
    verdict: "ask",
    reason: "forced git push (rewrites remote history)",
    test: (command) => gitPushForceOption(command) || pushForcesRefs(command),
  },
  {
    id: "git-push-delete",
    verdict: "ask",
    reason: "git push deleting or replacing remote refs (--delete, :ref, --prune, --mirror)",
    test: pushDeletesRefs,
  },
  { id: "git-branch-delete", verdict: "ask", reason: "forced branch deletion", test: forcedBranchDeletion },
  {
    id: "git-discard",
    verdict: "ask",
    reason: "discarding git changes",
    test: (command) => gitDiscardAll(command) || GIT_STASH_OR_FILTER.test(command),
  },
  { id: "git-checkout-force", verdict: "ask", reason: "forced git checkout or switch (uncommitted changes lost)", test: forcedCheckout },
  { id: "git-worktree-force", verdict: "ask", reason: "forced worktree removal (uncommitted changes lost)", test: forcedWorktreeRemoval },
  {
    id: "git-reflog",
    verdict: "ask",
    reason: "deleting reflog entries (commits lost since then can no longer be recovered)",
    test: reflogDeletion,
  },
  {
    id: "git-config-alias",
    verdict: "ask",
    reason: "git alias or configuration given in the command or the environment (the command it runs is not checked)",
    test: (command) => GIT_ALIAS_OPTION.test(command) || GIT_CONFIG_ENV.test(command),
  },
  // After `git-discard` and `git-checkout-force`: the first ask found wins, those two keep their name.
  {
    id: "git-discard-file",
    verdict: "ask",
    reason: "git restore or checkout of named files (their uncommitted changes are lost)",
    test: discardsNamedFiles,
  },
  { id: "privilege", verdict: "ask", reason: "privilege escalation", test: re(word("sudo|doas|su|pkexec")) },
  {
    id: "recursive-permissions",
    verdict: "ask",
    reason: "recursive or 777 permission change",
    test: re(
      new RegExp(
        `(?:^|[\\s;&|(\`{]|(?<!\\w)=)(?:(?:chmod|chown|chgrp)\\s+(?:[^;&|\\s]+\\s+)*?${RECURSIVE_PERMISSION_OPTION}|chmod\\s+(?:-\\S+\\s+)*0?777\\b)`,
      ),
    ),
  },
  {
    id: "kill",
    verdict: "ask",
    reason: "forced process kill",
    test: (command) => /(?:^|[\s;&|(`])kill\s+(?:-9|-KILL|-SIGKILL)\b/.test(command) || word("pkill|killall").test(command),
  },
  {
    // Signal that makes an OpenCode server write a heap snapshot (`cli/src/heap.ts`, 2.1.3 and later), by name or number
    // (Linux), in any case like bash; `pkill` and `killall` already ask. Options before it skipped, except `--`.
    id: "kill",
    verdict: "ask",
    reason: "signal USR1 sent to a process: an OpenCode server then writes a copy of its memory to a file, which can contain the OpenCode credentials, the service password and other secrets",
    test: re(/(?:^|[\s;&|(`/])kill\s+(?:-(?!-\s)\S+\s+)*?-(?:-signal[\s=]+|[sn]\s*)?(?:sig)?(?:usr1|10)(?![\w-])/i),
  },
  {
    id: "power",
    verdict: "ask",
    reason: "shutdown / reboot / system services",
    test: (command) =>
      word("shutdown|reboot|poweroff|halt").test(command) ||
      /systemctl\s+(?:--user\s+)?(?:stop|disable|mask|kill|poweroff|reboot|halt)\b/.test(command),
  },
  {
    id: "containers",
    verdict: "ask",
    reason: "removal of containers, images or volumes",
    test: re(/(?:docker|podman)\s+(?:system\s+prune|(?:container|image|volume|network)\s+(?:prune|rm)\b|rm\s+[^;&|]*-[a-zA-Z]*f|rmi\b)/),
  },
  {
    id: "infra",
    verdict: "ask",
    reason: "infrastructure change",
    // `kubectl|oc … scale … --replicas=0`: stopping a service (bounded windows, linear cost).
    test: re(
      /(?:kubectl\s+(?:delete|drain|cordon)|helm\s+(?:uninstall|delete)|terraform\s+(?:destroy|apply)|pulumi\s+(?:destroy|up))\b|\b(?:kubectl|oc)\s(?:[^;&|\n]{0,200}?\s)?scale\s[^;&|\n]{0,200}?--replicas(?:=|\s+)0(?!\d)/,
    ),
  },
  {
    id: "publish",
    verdict: "ask",
    reason: "package publishing",
    test: re(/(?:(?:npm|pnpm|yarn|bun)\s+publish|cargo\s+publish|gem\s+push|twine\s+upload)\b/),
  },
  {
    id: "install",
    verdict: "ask",
    reason: "software installation",
    test: (command) =>
      /(?:npm|pnpm|bun)\s+(?:i|install|add)\b[^;&|]*(?:\s-g\b|\s--global\b)/.test(command) ||
      /yarn\s+global\s+add\b/.test(command) ||
      /(?:^|[\s;&|(`])(?:pip3?|pipx|uv\s+pip|uv\s+tool)\s+install\b/.test(command) ||
      /(?:apt|apt-get|dnf|yum|zypper|apk)\s+(?:install|add)\b/.test(command) ||
      /pacman\s+-S/.test(command) ||
      /(?:brew\s+(?:install|reinstall)|(?:snap|flatpak)\s+install|(?:cargo|go)\s+install)\b/.test(command),
  },
  {
    id: "upload",
    verdict: "ask",
    reason: "data upload over HTTP",
    test: (command) =>
      /curl\b[^;&|]*(?:\s-d\b|\s--data(?:-\w+)?\b|\s-F\b|\s--form\b|\s-T\b|\s--upload-file\b|\s--json\b|\s-X\s*(?:POST|PUT|PATCH|DELETE)\b|\s--request\s+(?:POST|PUT|PATCH|DELETE)\b)/.test(
        command,
      ) || /wget\s[^;&|]*--(?:post-data|post-file|method|body-data|body-file)\b/.test(command),
  },
  {
    id: "remote",
    verdict: "ask",
    reason: "connection or transfer to a remote host",
    test: (command) =>
      word("scp|sftp|ssh|nc|ncat|netcat|socat|telnet|ftp|lftp").test(command) ||
      /rsync\s[^;&|]*\S+:/.test(command) ||
      NETWORK_DEVICE.test(command),
  },
  {
    id: "gh-upload",
    verdict: "ask",
    reason: "GitHub CLI upload or API call",
    test: re(/(?:^|[\s;&|(`])gh\s+(?:gist\s+(?:create|edit)|api|release\s+(?:create|upload)|secret\s+set|variable\s+set|ssh-key\s+add|gpg-key\s+add)\b/),
  },
  {
    id: "opencode-service",
    verdict: "ask",
    reason: "change to the OpenCode service (environment, restart) or uninstall: can disable the guard",
    test: re(/(?:^|[\s;&|(`])opencode\s+(?:service\s+(?:set|unset|stop|restart|uninstall)|uninstall)\b/),
  },
  {
    // With the server password, these routes bypass the guardrail (switch to the unprotected agent, prompt or
    // command in the user's name, answer to permission requests). Complement: a constructed URL escapes it.
    id: "opencode-server-api",
    verdict: "ask",
    reason: "call to the OpenCode server API that switches the agent, sends a prompt or a command, or answers a permission request: it can bypass the guard",
    // Documentation template (`/api/session/{sessionID}/prompt`) excluded: a real identifier has no brace.
    test: re(/\/api\/session\/[^\s"'\/{}]+\/(?:agent|command|prompt|permission)\b/),
  },
  {
    id: "nested-opencode",
    verdict: "ask",
    reason: "launches another OpenCode agent or server, or changes its configuration: it may run without the guard or approve its confirmations (--auto)",
    test: (command) => NESTED_OPENCODE.test(command) || OPENCODE_CONFIG_VARIABLE.test(command),
  },
  {
    id: "env-dump-network-word",
    verdict: "ask",
    reason: "environment variables in a command that mentions a network tool",
    test: (command) => NETWORK_WORD.test(command) && ENV_DUMP.test(command),
  },
  {
    id: "secret-network-word",
    verdict: "ask",
    reason: "secret in a command that mentions a network tool",
    test: (command, ctx) => NETWORK_WORD.test(command) && ctx.redactor.containsSecret(command),
  },
  {
    // No deny: `curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com` is a normal use.
    id: "secret-variable-network",
    verdict: "ask",
    reason: "variable holding a secret ($…_TOKEN, $…_KEY, $…PASSWORD…) used in a network command",
    test: (command) => mentionsNetwork(command) && secretVariables(command).length > 0,
  },
  {
    id: "crontab",
    verdict: "ask",
    reason: "scheduled task change",
    test: (command) => word("crontab").test(command.replace(CRONTAB_LIST, "$1")),
  },
  { id: "eval", verdict: "ask", reason: "dynamic execution (eval)", test: re(word("eval")) },
  {
    id: "base64-exec",
    verdict: "ask",
    reason: "running decoded content",
    test: re(
      new RegExp(
        `base64\\s+(?:[^|;&\\s]+\\s+)*?(?:-[a-zA-Z]*d[a-zA-Z]*|${longOptionPattern("decode")})(?=\\s|$)[^|]*\\|\\s*(?:sh|bash|zsh|python[0-9.]*|perl(?:5[\\w.-]*)?|ruby[\\d.]*|node|bun|deno)\\b`,
      ),
    ),
  },
  {
    id: "xargs-dynamic-exec",
    verdict: "ask",
    reason: "dynamic execution via xargs (input can supply the executed command)",
    test: xargsDynamic,
  },
  {
    id: "parallel-dynamic-exec",
    verdict: "ask",
    reason: "dynamic execution via parallel (input can supply the executed command)",
    test: parallelDynamic,
  },
  {
    id: "dynamic-shell-source",
    verdict: "ask",
    reason: "shell or interpreter launched on a variable-designated file or command text",
    test: variableShellSource,
  },
  {
    id: "shell-startup-file",
    verdict: "ask",
    reason: "shell startup file designated by environment or command-line option",
    test: shellStartupFile,
  },
  {
    id: "awk-dynamic-exec",
    verdict: "ask",
    reason: "awk program executing non-literal text as a command",
    test: awkDynamicExec,
  },
  {
    id: "git-exec-config",
    verdict: "ask",
    reason: "git configuration designates a program to run",
    test: gitProgramConfig,
  },
  {
    id: "interpreter-dangerous-code",
    verdict: "ask",
    reason: "interpreter code launching a dangerous command",
    test: interpreterDangerousCode,
  },
  {
    id: "secret-file-read",
    verdict: "ask",
    reason: "access to a credential file",
    test: (command, ctx) => pathTokens(command).some((t) => isCredentialFile(t, ctx)),
  },
  {
    id: "self-protection",
    verdict: "ask",
    reason: "write to OpenCode's configuration or to the guard plugin (self-protection)",
    test: (command, ctx) => protectedTargets(command, ctx).includes("opencode"),
  },
  {
    id: "protected-write",
    verdict: "ask",
    reason: "write to a protected location (startup file, ~/.ssh, git hook, /etc)",
    test: (command, ctx) => protectedTargets(command, ctx).includes("system"),
  },
  ...OPENCODE_ASK_RULES,
]

/** Kinds of protected locations targeted by the command's writes (`protectedWriteKind`). */
function protectedTargets(command: string, ctx: ShellRuleContext): Array<"opencode" | "system" | undefined> {
  // Without shell re-entry, an interpreter's code (`node -e "x => …"`) is not a redirection.
  const data = withoutData(command)
  return writeTargets(reentersShell(data) ? command : data).map((target) => protectedWriteKind(target, ctx.home, ctx))
}

/**
 * Shell re-entry: a heredoc or interpreter code can end up executed as shell (`bash -c`, `| sh`,
 * `eval`, `ssh host "…"`, `watch "…"`, script launched by its path or made executable). The analysis then remains complete.
 */
const SHELL_REENTRY = commandRegex("sh|bash|zsh|dash|ksh|fish|eval|source|\\.|ssh|su|watch|parallel|script|flock|tmux|screen|expect")
const PATH_EXECUTION = /(?:^|[;&|(`\n{])\s*(?:sudo\s+)?(?:\.{1,2}\/|~\/|\/)[^\s;&|()]/
const MAKE_EXECUTABLE = /\bchmod\s[^;&|\n]*\+[rw]*x/

export function reentersShell(command: string): boolean {
  return SHELL_REENTRY.test(command) || PATH_EXECUTION.test(command) || MAKE_EXECUTABLE.test(command)
}

/** Code passed to a non-shell interpreter (`node -e "…"`, `python3 -c '…'`, `perl -E`, `php -r`, `deno eval`). */
const INTERPRETER_CODE =
  /(\b(?:node|nodejs|bun|python[0-9.]*|ruby[\d.]*|perl(?:5[\w.-]*)?|php[\d.]*)(?:\s+-[^\s;&|'"]+){0,6}?\s+(?:-e|-p|-c|-E|-r|--eval|--print)\s+|\bdeno\s+eval\s+)("(?:[^"\\]|\\.)*"|'[^']*')/g

/** Heredoc start (`<<EOF`, `<<-'EOF'`); a `<` just before signals a here-string (`<<<`), left as is. */
const HEREDOC_START = /<<(-?)[ \t]*(["']?)([A-Za-z_][A-Za-z0-9_]*)\2/g

/**
 * Removes heredoc bodies, traversed in order (linear cost); a body expanded by the shell (`$(…)`) is kept.
 * `withTerminators`: also removes the closing line (view of `onlyInHeredocData`); a kept body is signaled there by
 * `undefined` (never data alone). `blank`: removed bodies replaced by blanks (positions kept).
 */
function withoutHeredocBodies(command: string): string
function withoutHeredocBodies(command: string, withTerminators: true): string | undefined
function withoutHeredocBodies(command: string, withTerminators: false, blank: true): string
function withoutHeredocBodies(command: string, withTerminators = false, blank = false): string | undefined {
  let out = ""
  let kept = 0
  const start = new RegExp(HEREDOC_START.source, "g")
  for (let match = start.exec(command); match; match = start.exec(command)) {
    if (command[match.index - 1] === "<") continue
    const [, dash, quote, delimiter] = match
    const lineEnd = command.indexOf("\n", start.lastIndex)
    if (lineEnd < 0) break
    const terminator = new RegExp(`\\n${dash ? "\\t*" : ""}${delimiter}(?=\\n|$)`, "g")
    terminator.lastIndex = lineEnd
    const end = terminator.exec(command)
    const bodyEnd = end ? end.index : command.length
    if (quote || !/\$\(|`/.test(command.slice(lineEnd + 1, bodyEnd))) {
      out += blank ? command.slice(kept, Math.min(lineEnd + 1, bodyEnd)) + " ".repeat(Math.max(0, bodyEnd - lineEnd - 1)) : command.slice(kept, lineEnd + 1)
      kept = withTerminators && end ? end.index + end[0].length : bodyEnd
    } else if (withTerminators) return undefined
    if (!end) break
    start.lastIndex = end.index + end[0].length
  }
  return out + command.slice(kept)
}

/**
 * View without data intended for another program: heredoc bodies and non-shell interpreter code.
 * Quoted arguments (`rm -rf "/"`, `curl -d "@.env"`, `>> "$HOME/.bashrc"`) remain analyzed.
 */
export function withoutData(command: string): string {
  return withoutHeredocBodies(command).replace(INTERPRETER_CODE, (match, head: string, body: string) =>
    body.startsWith('"') && /\$\(|`/.test(body) ? match : `${head}""`,
  )
}

/** Directory change: the relative paths that follow no longer resolve from the shell's directory. */
const CHANGES_DIRECTORY = new Set(["cd", "pushd", "popd"])

export const changesDirectory = (command: string) => segments(command).some((segment) => CHANGES_DIRECTORY.has(commandOf(segment).name))

/**
 * Leading `cd <path> && rest`, the only directory change: the rest runs in that directory, or not at all.
 * Absolute path, `~`, `./` or `../` only: another relative path is looked up in `CDPATH` (defined by
 * `.zshenv`, invisible to the plugin). `~` or `$` between quotes (not expanded) rejected.
 */
export function afterLeadingCd(command: string): { path: string; rest: string } | undefined {
  const match = /^\s*cd\s+("[^"]*"|'[^']*'|[^\s'"]+)\s*&&([\s\S]*)$/.exec(command)
  if (!match || /^["'][~$]/.test(match[1]!)) return undefined
  const path = literalPath(unquote(match[1]!))
  if (!path || !/^(?:\/|~|\.\.?(?:\/|$))/.test(path) || changesDirectory(match[2]!)) return undefined
  return { path, rest: match[2]! }
}

/** Word `cd`, `pushd` or `popd` anywhere (quotes, substitutions, `eval` text or a nested shell included). */
const DIRECTORY_WORD = /(?<![\w.-])(?:cd|pushd|popd)(?![\w.-])/

export const mentionsDirectoryChange = (text: string) => DIRECTORY_WORD.test(text)

/**
 * Possible directory change, seen broadly (protected write rules): a word from `mentionsDirectoryChange`, or
 * the directory option of `env` (`-C`, `--chdir`) or `sudo` (`-D`, `--chdir`) in the same segment. A false positive
 * costs only one extra candidate directory, never a lost finding.
 */
export function mayChangeDirectory(command: string): boolean {
  if (mentionsDirectoryChange(command)) return true
  if (!/(?<![\w.-])(?:env|sudo)(?![\w.-])/.test(command)) return false
  for (const segment of segments(command)) {
    let runner: string | undefined
    for (const token of segment.split(/\s+/).filter(Boolean).map(unquote)) {
      const name = commandName(token)
      if (name === "env" || name === "sudo") runner = name
      else if (runner && (token === "--chdir" || token.startsWith("--chdir=") || (runner === "env" ? /^-[a-zA-Z]*C/ : /^-[a-zA-Z]*D/).test(token)))
        return true
    }
  }
  return false
}

/**
 * Leading `cd <path> && rest` (`afterLeadingCd`) whose rest is chained only by `&&` and pipes: if the
 * `cd` fails, nothing runs. A `;`, `||`, newline or lone `&` (except redirections `>&`, `&>`, `<&`)
 * anywhere in the rest, even between quotes, or another possible directory change → nothing: that part
 * could run in the starting directory (with `&`, the chain goes into a subshell).
 */
export function leadingCdChain(command: string): { path: string; rest: string } | undefined {
  const lead = afterLeadingCd(command)
  if (!lead || mayChangeDirectory(lead.rest) || /;|\|\||\n|(?<![&<>])&(?![&>])/.test(lead.rest)) return undefined
  return lead
}

/** Literal targets of `cd` and `pushd` (also after `builtin` or `command`): first argument not an option. */
export function directoryTargets(command: string): string[] {
  const targets: string[] = []
  for (const segment of segments(command)) {
    let { name, args } = commandOf(segment)
    if ((name === "builtin" || name === "command") && args.length > 0) [name, args] = [commandName(args[0]!), args.slice(1)]
    if (name !== "cd" && name !== "pushd") continue
    const path = literalPath(args.find((arg) => !arg.startsWith("-")))
    if (path) targets.push(path)
  }
  return targets
}

/**
 * File path usable as is: without variable (except leading `$HOME`/`${HOME}`, reduced to `~`), glob,
 * substitution or `~user` (expanded by the shell, impossible to resolve here).
 */
function literalPath(token: string | undefined): string | undefined {
  if (!token || token.startsWith("-")) return undefined
  const path = token.replace(/^(?:\$HOME|\$\{HOME\})(?=\/|$)/, "~")
  if (/[$`*?[\]{}()<>|;&\\]/.test(path) || /^~[^/]/.test(path)) return undefined
  return path
}

/** Script file of an interpreter: first argument not an option; nothing if the code is an argument or read from stdin. */
function scriptArgument(executor: (typeof EXECUTORS)[number], args: readonly string[]): string | undefined {
  const start = executor.subcommand && args[0] !== undefined && executor.subcommand.test(args[0]) ? 1 : 0
  for (let i = start; i < args.length; i++) {
    const arg = args[i]!
    if (/^(?:\d*|&)[<>]/.test(arg)) {
      if (/^(?:\d*|&)[<>]+&?$/.test(arg)) i++
      continue
    }
    if (arg === "--") return args[i + 1]
    if (arg === "-" || STDIN_PATH.test(arg)) return undefined
    if (arg.startsWith("-") || (executor.stdin && arg.startsWith("+"))) {
      if (executor.code.test(arg) || executor.stdin?.test(arg)) return undefined
      if (executor.value?.test(arg)) i++
      continue
    }
    return arg
  }
  return undefined
}

export interface ScriptRun {
  /** Path as written in the command (`$HOME` reduced to `~`). */
  readonly path: string
  /** `shell`: read by a shell (`bash f`, `source f`); `interpreter`: another language; `direct`: launched by its path. */
  readonly kind: "shell" | "interpreter" | "direct"
}

/**
 * Files executed by a command (excluding data: heredoc bodies, interpreter code): `bash f.sh`,
 * `source ./f`, `. ./f`, `python3 f.py`, `node f.js`, `bun run f.ts`…, or a command launched by its path (`./f.sh`,
 * `bin/x`). A segment that quotes `~` or `$` between quotes (not expanded by the shell) is ignored. Internal error of the
 * view without leading assignments: scripts tracked as without it (the result carries no ask).
 */
export function scriptRuns(command: string, max = 4): ScriptRun[] {
  const runs: ScriptRun[] = []
  let bare = command
  try {
    bare = withoutAssignments(command)
  } catch {}
  for (const segment of segments(withoutData(bare))) {
    if (runs.length >= max) break
    if (/["'][~$]/.test(segment)) continue
    const { name, args, path } = commandOf(segment)
    const executor = EXECUTORS.find((candidate) => candidate.name.test(name))
    // `source f`/`. f` without `/`: looked up in PATH before the directory (bash, zsh's `.`) → ignored.
    const run: ScriptRun | undefined =
      name === "source" || name === "."
        ? { path: args[0]?.includes("/") ? args[0] : "", kind: "shell" }
        : executor
          ? { path: scriptArgument(executor, args) ?? "", kind: executor === EXECUTORS[0] ? "shell" : "interpreter" }
          : path.includes("/")
            ? { path, kind: "direct" }
            : undefined
    const literal = literalPath(run?.path)
    if (run && literal && !runs.some((item) => item.path === literal)) runs.push({ path: literal, kind: run.kind })
  }
  return runs
}

export interface HeredocFile {
  /** Target as written (`$HOME` reduced to `~`). */
  readonly path: string
  /** Expected content: heredoc body (tabs removed for `<<-`) and final newline. */
  readonly content: string
}

/**
 * Files that a heredoc creates entirely: a line alone `cat > f <<'D'`, `cat <<'D' > f` or `tee f <<'D'` (without `>>`,
 * option, other redirection or other command on the line), quoted delimiter or body without expansion
 * (`$`, backtick, `\`). The caller compares this content with the real file: another write in the command sets it aside.
 */
export function heredocFiles(command: string): HeredocFile[] {
  const files: HeredocFile[] = []
  const start = new RegExp(HEREDOC_START.source, "g")
  for (let match = start.exec(command); match; match = start.exec(command)) {
    if (command[match.index - 1] === "<") continue
    const [operator, dash, quote, delimiter] = match
    const lineStart = command.lastIndexOf("\n", match.index) + 1
    const lineEnd = command.indexOf("\n", start.lastIndex)
    if (lineEnd < 0) break
    const terminator = new RegExp(`\\n${dash ? "\\t*" : ""}${delimiter}(?=\\n|$)`, "g")
    terminator.lastIndex = lineEnd
    const end = terminator.exec(command)
    if (!end) break
    start.lastIndex = end.index + end[0].length
    // Continued line (`\` at the end of the previous line): incomplete command, ignored.
    if (lineStart >= 2 && command[lineStart - 2] === "\\") continue
    const offset = match.index - lineStart
    const header = command.slice(lineStart, lineEnd)
    const rest = `${header.slice(0, offset)} ${header.slice(offset + operator.length)}`
    if (/[;&|`]|\$\(|<</.test(rest)) continue
    const target = heredocTarget(rest.trim().split(/\s+/).filter(Boolean))
    const path = literalPath(target && unquote(target))
    if (!path || path.startsWith("/dev/")) continue
    let body = end.index > lineEnd ? command.slice(lineEnd + 1, end.index) : ""
    if (!quote && /[$`\\]/.test(body)) continue
    if (dash) body = body.replace(/^\t+/gm, "")
    files.push({ path, content: end.index > lineEnd ? `${body}\n` : "" })
  }
  return files
}

/** Target of `cat > f` (a single `>` redirection) or of `tee f` (without option, output possibly to `/dev/null`). */
function heredocTarget(tokens: readonly string[]): string | undefined {
  const words: string[] = []
  const redirects: string[] = []
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]!
    const redirect = /^1?>(.*)$/.exec(token)
    if (redirect) {
      const target = redirect[1] || tokens[++i]
      if (!target || /^[>|&]/.test(target)) return undefined
      redirects.push(target)
    } else if (/[<>]/.test(token)) return undefined
    else words.push(token)
  }
  if (words.length === 1 && words[0] === "cat" && redirects.length === 1) return redirects[0]
  if (words.length === 2 && words[0] === "tee" && !words[1]!.startsWith("-") && redirects.every((item) => item === "/dev/null"))
    return words[1]
  return undefined
}

/**
 * Shell finding: existing finding (`rulesAndNetworkFinding`), then, without a deny and only if a
 * user rule matches the whole command, user rules alone (`userRulesFinding`): a user
 * rule keeps its verdict whatever the findings of the built-in rules (a built-in deny reduced to an
 * ask by the data mechanism no longer masks its deny). The strongest wins (`strength`); at equal strength, the
 * existing finding is returned as is.
 */
function priorShellFinding(command: string, ctx: ShellRuleContext): Finding | undefined {
  const existing = rulesAndNetworkFinding(command, ctx)
  if (existing?.verdict === "deny") return existing
  // Cost guard: predicate of `onlyInHeredocData` copied word for word (rule for the shell or all tools whose
  // pattern matches the whole command). Asymmetric overlap: the filter of `userRulesFinding` implies the
  // guard unconditionally (its last two conditions are, rule by rule, this predicate), so without a match it
  // would discard the pass's finding anyway; the guard covers attribution only under the invariant described at
  // `userRulesFinding`. The guard for cost, the filter for attribution.
  if (!ctx.custom?.some((rule) => (rule.tools.includes("shell") || rule.tools.includes("*")) && rule.pattern.test(command))) return existing
  const user = userRulesFinding(command, ctx)
  return user && strength(user) > strength(existing) ? user : existing
}

/** Strength of a finding: deny, ask without a mark, ask that the model can decide (`dataOnly`, `modelDecides`), nothing. */
const strength = (finding: Finding | undefined) =>
  finding === undefined ? 0 : finding.verdict === "deny" ? 3 : finding.dataOnly || finding.modelDecides !== undefined ? 1 : 2

/** All switches off: only always-active rules and user rules remain. */
const ALL_FEATURES_OFF: ActiveRules = { dangerousCommands: false, sensitiveFiles: false }

/**
 * User rules alone: existing evaluation (`evaluate`) on the whole command, switches off. The
 * always-active rules remain: the placeholder exits before the user rules, but is never reduced to
 * data (the existing finding is then already a deny); self-protection asks are collected after them. The
 * finding is kept only if it carries the identifier, verdict and reason of a user rule that the `evaluate`
 * loop retains (shell or all tools, pattern that matches the whole command): a rule that copies these
 * three fields from a self-protection ask without targeting the shell or without matching does not claim it. Asymmetric
 * overlap with the guard of `shellFinding`: this filter implies the guard unconditionally (its last two
 * conditions are its predicate); the guard covers attribution only under an invariant. Invariant: no always-active
 * rule that denies before the user rules in `evaluate` (early exit, or finding collected
 * before theirs) is reduced to data; today only the placeholder denies that way, and it is exempted. Under
 * this invariant, when a rule matches, the first finding of the pass comes from a user rule (first
 * deny, otherwise first finding, and its own are collected before always-active asks), which this filter keeps.
 * Invariant guarded by the test "shell example of each always-active rule, alone in a heredoc body → user
 * deny" (test/features.test.ts). Never marked "data only".
 */
function userRulesFinding(command: string, ctx: ShellRuleContext): Finding | undefined {
  const found = evaluate(command, { ...ctx, active: ALL_FEATURES_OFF })
  // The three fields, then the condition of the user-rule loop of `evaluate`, copied word for word.
  const fromUser = ctx.custom?.some(
    (rule) =>
      rule.id === found?.rule &&
      rule.verdict === found.verdict &&
      rule.reason === found.reason &&
      (rule.tools.includes("shell") || rule.tools.includes("*")) &&
      rule.pattern.test(command),
  )
  return fromUser ? found : undefined
}

/**
 * Shell finding: existing rules and added recognition (`shellRulesFinding`), then, without a deny, network examination of
 * code passed inline to an interpreter (`networkCodeFinding`). Same strength as `shellRulesFinding`: a deny from the code
 * wins; its ask (without a mark) yields to an existing ask without a mark, but not to a marked ask
 * (`dataOnly`, `modelDecides`).
 */
function rulesAndNetworkFinding(command: string, ctx: ShellRuleContext): Finding | undefined {
  const existing = shellRulesFinding(command, ctx)
  if (existing?.verdict === "deny") return existing
  const added = networkCodeFinding(command, ctx)
  if (!added) return existing
  if (added.verdict === "deny") return added
  return existing && !existing.dataOnly && existing.modelDecides === undefined ? existing : added
}

/** JavaScript engines among the heads of `INTERPRETER_CODE`: the network function there designates only network access. */
const JAVASCRIPT_ENGINES = /^(?:node|nodejs|bun|deno)$/

/** Presence of code delimited by `INTERPRETER_CODE` (without the global flag: stateless test). */
const HAS_INTERPRETER_CODE = new RegExp(INTERPRETER_CODE.source)

/** Execution sink of `interpreterDangerousCode`, reproduced identically (the existing path remains intact). */
const hasExecutionSink = (code: string) =>
  /\b(?:system|popen|subprocess|child_process|open3|eval|fork|qx|shell_exec|passthru|proc_open|pcntl_exec|spawn\w*|exec\w*)\b/.test(code.toLowerCase()) ||
  code.includes("`") ||
  /%x/.test(code)

/**
 * Code delimited by `INTERPRETER_CODE` that reaches the network, according to two existing detectors: the network function of the
 * CodeMode rule in JavaScript engine code, escapes decoded; an execution sink with a cited
 * downloader (`downloads`), like the predicates of `interpreterDangerousCode`. Same bound as it (empty code or more than
 * 64 KiB ignored). One pass over code blocks, patterns without nested repetition.
 */
function codeReachesNetwork(text: string): boolean {
  for (const match of text.matchAll(new RegExp(INTERPRETER_CODE.source, "g"))) {
    const quoted = match[2] ?? ""
    const code = quoted.length >= 2 ? quoted.slice(1, -1) : quoted
    if (code.length === 0 || code.length > 65536) continue
    const head = /^\S+/.exec(match[1] ?? "")?.[0] ?? ""
    if (JAVASCRIPT_ENGINES.test(head) && (NETWORK_FUNCTION.test(code) || NETWORK_FUNCTION.test(decodeUnicodeEscapes(code)))) return true
    if (hasExecutionSink(code) && downloads(code)) return true
  }
  return false
}

/**
 * Examined text: the whole command, or the command without heredoc bodies (`bodies`, computed once by
 * the caller) under the guards of `onlyInHeredocData`: no substitution outside the removed bodies, all commands
 * outside the bodies are data commands, heredoc starts are real (neither quoted nor in a comment)
 * and no shell is launched outside the data (same condition as `existingShellFinding`). Checks done only if
 * a body was removed, cheapest first: the re-entry test is quadratic on a long run of newlines
 * (existing state of `SHELL_REENTRY`, already computed by `protectedTargets`).
 */
function networkCodeView(command: string, bodies: string): string {
  if (bodies === command) return command
  // Guards of `onlyInHeredocData`, reproduced identically (the existing path remains intact): substitutions, data
  // commands, real heredoc starts.
  if (/\$\(|`|[<>]\(/.test(bodies)) return command
  const commands = withoutHeredocBodies(command, true)
  if (commands === undefined || !segments(commands).every((segment) => DATA_COMMANDS.has(commandOf(segment).name))) return command
  if (!heredocsAreReal(command)) return command
  return reentersShell(withoutData(command)) ? command : bodies
}

/**
 * Code delimited in the whole command or in the command without bodies, the two possible texts of the view: removing a
 * body can close code that the body interrupted (backslash at end of line).
 */
const hasInterpreterCode = (command: string, bodies: string) =>
  HAS_INTERPRETER_CODE.test(command) || (bodies !== command && HAS_INTERPRETER_CODE.test(bodies))

/** Detection only, view included, without switch (cost tests). Without delimited code, the view is not computed. */
export function inlineCodeNetwork(command: string): boolean {
  const bodies = withoutHeredocBodies(command)
  return hasInterpreterCode(command, bodies) && codeReachesNetwork(networkCodeView(command, bodies))
}

/**
 * Findings of the network examination of inline code: credential file then secret in the view (order of the deny
 * table), denies never reduced to data (this code is executed: its network access is not data); otherwise
 * an ask.
 */
const NETWORK_CODE_RULES: readonly RegexRule[] = [
  {
    id: "secret-file-network",
    verdict: "deny",
    reason: "credential file in a command whose inline interpreter code makes network requests (exfiltration)",
    test: (view, ctx) => sentSecretFiles(view, ctx).length > 0,
  },
  {
    id: "secret-network",
    verdict: "deny",
    reason: "secret found in a command whose inline interpreter code makes network requests (exfiltration)",
    test: (view, ctx) => ctx.redactor.containsSecret(view),
  },
  // Output of an OpenCode subcommand that prints a secret: same place as in the deny table.
  {
    id: "secret-file-network",
    verdict: "deny",
    reason: "OpenCode credentials or service secrets printed in a command whose inline interpreter code makes network requests (exfiltration)",
    test: (view) => opencodeKinds(view).has("printed"),
  },
  { id: "interpreter-network", verdict: "ask", reason: "inline interpreter code making network requests", test: () => true },
]

function networkCodeFinding(command: string, ctx: ShellRuleContext): Finding | undefined {
  const bodies = withoutHeredocBodies(command)
  if (!hasInterpreterCode(command, bodies)) return undefined
  const view = networkCodeView(command, bodies)
  if (!codeReachesNetwork(view)) return undefined
  const rule = NETWORK_CODE_RULES.find((candidate) => ruleEnabled(candidate.id, ctx.active) && candidate.test(view, ctx))
  return rule && { verdict: rule.verdict, rule: rule.id, reason: rule.reason }
}

/**
 * Finding of the existing rules, then, without an existing deny, of the added recognition (`ADDED_DENY_RULES`). Strength:
 * deny, ask without a mark, ask that the model can decide (`dataOnly`, `modelDecides`), nothing. The existing finding
 * wins if it is at least as strong: an added deny reduced to an ask (only inside data) yields to an
 * existing ask without a mark, but not to a marked ask (the name alone also gives the ask without a mark).
 */
function shellRulesFinding(command: string, ctx: ShellRuleContext): Finding | undefined {
  const existing = existingShellFinding(command, ctx)
  if (existing?.verdict === "deny") return existing
  const added = addedShellFinding(command, ctx)
  if (!added) return existing
  if (added.verdict === "deny") return added
  return existing && !existing.dataOnly && existing.modelDecides === undefined ? existing : added
}

/**
 * Deny from added recognition, reduced to an ask like the other denials (`existingShellFinding`) if it is only
 * in interpreter code or a heredoc. The deny remains if the view without data contains a deny, added included.
 */
function addedShellFinding(command: string, ctx: ShellRuleContext): Finding | undefined {
  const added = (text: string) => ADDED_DENY_RULES.find((rule) => ruleEnabled(rule.id, ctx.active) && rule.test(text, ctx))
  const rule = added(command)
  if (!rule) return undefined
  const finding: Finding = { verdict: "deny", rule: rule.id, reason: rule.reason }
  if (ctx.custom?.some((custom) => custom.id === rule.id)) return finding
  const data = withoutData(command)
  if (data === command || reentersShell(data) || evaluate(data, ctx)?.verdict === "deny" || added(data)) return finding
  return { verdict: "ask", rule: rule.id, reason: `${rule.reason}, only inside code passed to an interpreter or a heredoc: confirmation required` }
}

/**
 * A deny pattern present only in code passed to an interpreter or in a heredoc (e.g. test strings
 * `node -e "…'shred /dev/sda'…"`) becomes an ask: never less. Excluded: the placeholder, user
 * rules and any shell re-entry outside that data.
 */
function existingShellFinding(command: string, ctx: ShellRuleContext): Finding | undefined {
  const finding = evaluate(command, ctx)
  if (finding?.verdict === "ask") return onlyInHeredocData(command, ctx) ? { ...finding, dataOnly: true } : finding
  if (finding?.verdict !== "deny" || finding.rule === "placeholder" || ctx.custom?.some((rule) => rule.id === finding.rule))
    return finding
  // Re-entry searched outside the data: `bash <<EOF`, `| bash`, `./x.sh` are outside the body; a body expanded
  // by the shell (`$(…)`) is kept in the view without data.
  const data = withoutData(command)
  if (data === command || reentersShell(data) || evaluate(data, ctx)?.verdict === "deny") return finding
  return {
    verdict: "ask",
    rule: finding.rule,
    reason: `${finding.reason}, only inside code passed to an interpreter or a heredoc: confirmation required`,
  }
}

/** Commands that only read, write or display data: never execute what they receive. */
const DATA_COMMANDS = new Set(["cat", "tee", "echo", "printf", "mkdir", "touch", "cd", "ls", "pwd", "true", ":"])

/**
 * Real heredoc starts: quote and comment state tracked from the start of the command (bodies skipped),
 * so that a quoted or commented `"<<EOF"` does not make the rest look like data.
 */
function heredocsAreReal(command: string): boolean {
  const start = new RegExp(HEREDOC_START.source, "g")
  let from = 0
  let quote: string | undefined
  for (let match = start.exec(command); match; match = start.exec(command)) {
    if (match.index < from) continue
    for (let i = from; i < match.index; i++) {
      const char = command[i]
      if (quote) {
        if (char === quote) quote = undefined
        else if (char === "\\" && quote === '"') i++
      } else if (char === "\\") i++
      else if (char === '"' || char === "'") quote = char
      else if (char === "#" && (i === 0 || /\s/.test(command[i - 1]!))) {
        const end = command.indexOf("\n", i)
        if (end < 0 || end > match.index) return false
        i = end
      }
    }
    if (quote) return false
    from = match.index + match[0].length
    // Here-string (`<<<`): no body.
    if (command[match.index - 1] === "<") continue
    const lineEnd = command.indexOf("\n", from)
    if (lineEnd < 0) return true
    const terminator = new RegExp(`\\n${match[1] ? "\\t*" : ""}${match[3]}(?=\\n|$)`, "g")
    terminator.lastIndex = lineEnd
    const end = terminator.exec(command)
    if (!end) return true
    from = end.index + end[0].length
    start.lastIndex = from
  }
  return true
}

/**
 * Ask coming only from heredoc bodies READ by data commands (`cat > test.ts <<'EOF'`, test
 * data): the decision model decides (decide.ts). Never for a user rule, interpreter code
 * (executed), a substitution (`$(…)`, backticks, `<(…)`, `>(…)`), a shell re-entry, nor if a command outside the
 * DATA_COMMANDS list receives the body (`docker exec -i c sh <<EOF`, `at now <<EOF`, `python3 <<EOF`…).
 */
function onlyInHeredocData(command: string, ctx: ShellRuleContext): boolean {
  if (ctx.custom?.some((rule) => (rule.tools.includes("shell") || rule.tools.includes("*")) && rule.pattern.test(command))) return false
  const view = withoutHeredocBodies(command)
  if (view === command || withoutData(command) !== view) return false
  if (/\$\(|`|[<>]\(/.test(view)) return false
  // Checks from cheapest to most expensive (full re-evaluation last). Only closing lines
  // actually spotted are removed: a segment that carries the delimiter name (`cat <<'python3' | python3`) remains
  // a command to check.
  const commands = withoutHeredocBodies(command, true)
  if (commands === undefined || !segments(commands).every((segment) => DATA_COMMANDS.has(commandOf(segment).name))) return false
  return heredocsAreReal(command) && !reentersShell(view) && !evaluate(view, ctx)
}

function evaluate(command: string, ctx: ShellRuleContext): Finding | undefined {
  // Rule disabled by a switch: discarded BEFORE choosing the most severe finding (otherwise a deny from a disabled
  // feature would mask that of an active feature).
  const on = (finding: Finding | undefined) => (finding && ruleEnabled(finding.rule, ctx.active) ? finding : undefined)
  const findings: Array<Finding | undefined> = []
  for (const rule of DENY_RULES) {
    if (ruleEnabled(rule.id, ctx.active) && rule.test(command, ctx)) return { verdict: rule.verdict, rule: rule.id, reason: rule.reason }
  }
  for (const segment of segments(command)) {
    const permissions = on(permissionFinding(segment, ctx.home))
    if (permissions) return permissions
    findings.push(on(rmFinding(segment, ctx.home)), on(deletionFinding(segment)), on(moveFinding(segment, ctx.home)))
  }
  for (const rule of ctx.custom ?? []) {
    if ((rule.tools.includes("shell") || rule.tools.includes("*")) && rule.pattern.test(command))
      findings.push({ verdict: rule.verdict, rule: rule.id, reason: rule.reason })
  }
  for (const rule of ASK_RULES) {
    if (ruleEnabled(rule.id, ctx.active) && rule.test(command, ctx)) findings.push({ verdict: rule.verdict, rule: rule.id, reason: rule.reason })
  }
  return mostSevere(findings)
}

/**
 * Segment-leading assignments (`A=1 curl`), which common recognition does not skip: its heads (without `find -exec`
 * or `${`), then name (`+=` and bash index included) and value read like the shell (`shellEnd`).
 */
const ASSIGNED_HEAD = /(?:^|[;&|(`\n]|(?<!\$)\{|-[a-zA-Z]*c\s+["'])[^\S\n]*(?=[A-Za-z_]\w*(?:\[[^\]\s;&|]*\])?\+?=)/g
const ASSIGNED_NAME = /[A-Za-z_]\w*(?:\[[^\]\s;&|]*\])?\+?=/y
/** Fallback for a value that the read does not close (first blank or separator, like `commandOf`); blanks between two words. */
const BLANK_WORD = /[^\s;&|]*/y
const WORD_GAP = /(?:[^\S\n]|\\\n)*/y
const BETWEEN_WORDS = /[\s;&|()<>]*/y
const stickyEnd = (regex: RegExp, text: string, at: number) => ((regex.lastIndex = at), regex.exec(text), regex.lastIndex)
const DOLLAR_OPENERS = new Map([["(", "("], ["{", "}"], ["'", "$"], ['"', '"']])

/**
 * End of the shell word that starts at `i` (`group`: by the `(` of a bash array), read with a stack of closers:
 * quotes, `$'…'` (noted `$`), `$"…"`, escapes, substitutions (`(` and backtick, outermost bodies in `subs`)
 * and parameters nested like the shell. -1: construction not closed before `stop` (end, or closing quote of a
 * `-c` wrapper) or step budget exhausted.
 */
function shellEnd(text: string, i: number, stop: number, budget: { left: number }, group: boolean, subs?: Array<readonly [number, number]>): number {
  const modes = group ? ["", ")"] : [""]
  let [depth, open] = [0, 0]
  for (i += group ? 1 : 0; i < stop && --budget.left >= 0; i++) {
    const mode = modes[modes.length - 1]!
    const char = text[i]!
    if (mode === "" && /[\s;&|()<>]/.test(char)) return i
    if (char === (mode === "$" ? "'" : mode === "(" ? ")" : mode)) {
      if ((mode === "(" || mode === "`") && --depth === 0) subs?.push([open, i])
      modes.pop()
    } else if (char === "\\" && mode !== "'") i++
    else if (mode !== "'" && mode !== "$" && mode !== "`") {
      const dollar = char === "$" ? DOLLAR_OPENERS.get(text[i + 1] ?? "") : undefined
      const quote = char === "`" || (mode !== '"' && (char === "'" || char === '"')) ? char : char === "(" && /[()]/.test(mode) ? ")" : undefined
      const inner = dollar && (mode !== '"' || dollar === "(" || dollar === "}") ? dollar : quote
      if ((inner === "(" || inner === "`") && depth++ === 0) open = inner === "(" ? i + 2 : i + 1
      if (inner && modes.push(inner) && inner === dollar) i++
    }
  }
  return modes.length === 1 && i === stop ? i : -1
}

/**
 * View without the leading assignments followed by a command (`A=1 curl …` → `curl …`) on the view without data except
 * shell re-entry; inside a word of the command (`shellEnd`, comments skipped), head read only in a substitution
 * or the wrapper string that opens that word. Copied at the end of the view: the bodies of erased substitutions, never the
 * values. Kept: assignment alone, `BUN_BE_BUN=1` before `opencode`. Unclosed value: fallback; head in a value
 * or after a failure: shared budget (four times the length). Linear cost.
 */
function withoutAssignments(command: string): string {
  if (!command.includes("=")) return command
  const data = withoutData(command)
  const text = data !== command && !reentersShell(data) ? data : command
  const spans = launcherSpans(text)
  const opens = new Map(spans.flat())
  const budget = { left: 4 * text.length + 1024 }
  const ranges: Array<readonly [number, number, ReadonlyArray<readonly [number, number]>]> = []
  const subs: Array<readonly [number, number]> = []
  let [frontier, from, word, sub] = [0, 0, 0, 0]
  for (const match of text.matchAll(ASSIGNED_HEAD)) {
    const start = match.index + match[0].length
    while (word <= start) {
      for (from = word; (from = stickyEnd(BETWEEN_WORDS, text, from)) < text.length && text[from] === "#"; ) from = Math.min(text.indexOf("\n", from) >>> 0, text.length)
      sub = subs.length = 0
      word = from < text.length ? shellEnd(text, from, text.length, { left: Infinity }, false, subs) : Infinity
      if (word < 0) word = Infinity
    }
    while (sub < subs.length && subs[sub]![1] <= start) sub++
    if (start !== from && !(from < start && (word === Infinity || (subs[sub]?.[0] ?? Infinity) <= start || (opens.get(from) ?? 0) > start))) continue
    let pool = start >= frontier ? { left: Infinity } : budget
    if (pool.left < 0) continue
    const stop = launcherEnd(spans, start, text.length)
    const bodies: Array<readonly [number, number]> = []
    let end = start
    let bun = false
    while (end < stop) {
      ASSIGNED_NAME.lastIndex = end
      const name = ASSIGNED_NAME.exec(text)?.[0]
      if (!name) break
      const value = end + name.length
      const read = shellEnd(text, value, stop, pool, text[value] === "(", bodies)
      if (read < 0 && pool !== budget) [frontier, pool] = [Math.max(frontier, stop), budget]
      const after = read < 0 ? Math.min(stickyEnd(BLANK_WORD, text, value), stop) : read
      bun ||= name === "BUN_BE_BUN=" && unquote(text.slice(value, after)) === "1"
      end = Math.min(stickyEnd(WORD_GAP, text, after), stop)
      if (end === after) break
    }
    const opencode = bun && (OPENCODE_HEAD.test(text.slice(end)) || OPENCODE_QUOTED_HEAD.test(text.slice(end)))
    if (end > start && end < stop && !/[;&|)\n]/.test(text[end]!) && !opencode) ranges.push([start, end, bodies])
    frontier = Math.max(frontier, end)
  }
  const lines: string[] = []
  let next = 0
  const render = (from: number, to: number): string => {
    let out = ""
    let at = from
    for (let range = ranges[next]; range && range[0] < to; range = ranges[next]) {
      next++
      if (range[0] < at) continue
      out += text.slice(at, range[0])
      for (const [start, end] of range[2]) lines.push(render(start, end))
      at = Math.min(range[1], to)
    }
    return out + text.slice(at, to)
  }
  return ranges.length ? render(0, text.length) + lines.map((line) => `\n${line}`).join("") : command
}

/** Most severe finding (verdict alone) between `found` and that of the view without leading assignments; at equal verdict, `found` (mark included). */
function assignedFinding(command: string, ctx: ShellRuleContext, found: Finding | undefined): Finding | undefined {
  try {
    const bare = found?.verdict === "deny" ? command : withoutAssignments(command)
    return bare === command ? found : mostSevere([found, layeredShellFinding(bare, ctx).finding])
  } catch {
    return mostSevere([found, ANALYSIS_FAILED])
  }
}

/** Characters that can hide the real program name (quotes, substitution, escape): elsewhere, zero cost. */
const COMMAND_WORD_SPECIAL = /["'`$\\]/
/** Letters that bash decodes in `$'…'`. */
const ANSI_C_LETTERS: Readonly<Record<string, string>> = { a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v", "\\": "\\", "'": "'", '"': '"', "?": "?" }
const ANSI_C_ESCAPE = /\\(?:([abeEfnrtv\\'"?])|([0-7]{1,3})|x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{1,4})|U([0-9A-Fa-f]{1,8}))/g
const RUNTIME_WORD_REASON = "the launched program is known only at run time (a command substitution forms part of the command word): it cannot be checked"
const UNDETERMINED_WORD_REASON = "the launched program could not be determined (command word too long or too complex for the plugin, with quotes, a substitution or an escape): it cannot be checked"
/** Prudent ask of an extra layer that throws (internal error): original finding kept, ask always active. */
const ANALYSIS_FAILED: Finding = { verdict: "ask", rule: "nested-opencode", reason: "the analysis of the command failed (internal error): it cannot be checked" }

/** Text of a `$'…'` form decoded like bash (letters, octal, hexadecimal, code points up to 0x10FFFF; without the control `\c`, noted as a limit). */
function decodeAnsiC(body: string): string {
  return body.replace(ANSI_C_ESCAPE, (escape, letter: string, octal: string, hex: string, u: string, big: string) =>
    letter ? ANSI_C_LETTERS[letter]! : octal ? String.fromCharCode(parseInt(octal, 8) & 0xff) : hex ? String.fromCharCode(parseInt(hex, 16)) : parseInt(u ?? big, 16) <= 0x10ffff ? String.fromCodePoint(parseInt(u ?? big, 16)) : escape,
  )
}

/** Literal value of a word without substitution `text[i..end]`: quotes removed like the shell (single, double, `$'…'`, `$"…"`, escapes). */
function dequoteWord(text: string, i: number, end: number): string {
  let out = ""
  for (let j = i; j < end; ) {
    const c = text[j]!
    if (c === "'") {
      const k = text.indexOf("'", j + 1)
      const close = k < 0 || k > end ? end : k
      out += text.slice(j + 1, close)
      j = close + 1
    } else if (c === "$" && text[j + 1] === "'") {
      let k = j + 2
      while (k < end && text[k] !== "'") k += text[k] === "\\" ? 2 : 1
      out += decodeAnsiC(text.slice(j + 2, Math.min(k, end)))
      j = k + 1
    } else if (c === '"' || (c === "$" && text[j + 1] === '"')) {
      const start = c === "$" ? j + 2 : j + 1
      let k = start
      while (k < end && text[k] !== '"') k += text[k] === "\\" ? 2 : 1
      out += text.slice(start, Math.min(k, end)).replace(/\\\n/g, "").replace(/\\([$`"\\])/g, "$1")
      j = k + 1
    } else if (c === "\\") {
      if (text[j + 1] !== "\n") out += text[j + 1] ?? ""
      j += 2
    } else {
      out += c
      j++
    }
  }
  return out
}

const SHELL_LAUNCHER = /^(?:sh|bash|zsh|dash|ksh|mksh|ash|yash|fish)$/

/**
 * View where the word in command position is reduced to its literal value (choice 1), so that the rules recognize the
 * program actually launched. Built on the view without data (except shell re-entry, where the heredoc read by a shell is
 * normalized, choice 3). A single word scan (`shellEnd`) touches only the first word, leading assignment (`A=1`)
 * skipped, of each top-level command: the quoted text of an argument, read as a single word, remains intact;
 * comments skipped (`#` after a blank or an operator); unclosed word: resume at the next separator or end of line.
 * Literal that would keep a separator: a single word. `flag`, reason for an ask: substitution attached to
 * other characters (program fixed at run time, choice 2; except a substitution alone or followed by a slash);
 * oversized head word (> 1024) with a special character, or exhausted budget (undetermined program), if a special character
 * remains outside heredoc data bodies (`outside`, no body attached to the shell that reads it). Zero cost without a
 * special character; not descended into a substitution or a wrapper string (limit).
 */
function commandWordView(command: string): { view: string; flag?: string } {
  if (!COMMAND_WORD_SPECIAL.test(command)) return { view: command }
  const data = withoutData(command)
  const text = data !== command && !reentersShell(data) ? data : command
  const budget = { left: 8 * text.length + 1024 }
  let [out, cursor, changed, i, head, launcher, flag, mask] = ["", 0, false, 0, true, false, undefined as string | undefined, undefined as string | undefined]
  const outside = (from: number, to?: number) => COMMAND_WORD_SPECIAL.test((mask ??= heredocsAreReal(text) ? withoutHeredocBodies(text, false, true) : text).slice(from, to))
  while (i < text.length && budget.left > 0) {
    const c = text[i]!
    if (/[;&|\n({]/.test(c)) [head, launcher, i] = [true, false, i + 1]
    else if (/[)<>]/.test(c)) [head, launcher, i] = [false, false, i + 1]
    else if (/\s/.test(c)) i++
    else if (c === "#" && (i === 0 || /[\s;&|()<>]/.test(text[i - 1]!))) i = Math.min(text.indexOf("\n", i) >>> 0, text.length)
    else {
      const subs: Array<readonly [number, number]> = []
      const end = shellEnd(text, i, text.length, budget, false, subs)
      const stop = end < 0 ? stickyEnd(/[^;&|\n]*/y, text, i) : Math.max(end, i + 1)
      const word = text.slice(i, Math.min(stop, i + 1025))
      const small = word.length <= 1024
      const assign = head && /^[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=/.test(word)
      if (head && !assign && !small && end >= 0 && outside(i, stop)) flag ??= UNDETERMINED_WORD_REASON
      if (launcher && small && word.startsWith("$'")) {
        const decoded = dequoteWord(text, i, stop).replace(/[\\"$`]/g, "\\$&")
        ;[out, cursor, changed] = [out + text.slice(cursor, i) + `"${decoded}"`, stop, true]
      } else if (head && !assign && small) {
        const literal = subs.length === 0 ? dequoteWord(text, i, stop) : word
        if (SHELL_LAUNCHER.test(literal)) launcher = true
        if (COMMAND_WORD_SPECIAL.test(word)) {
          if (subs.length === 0) {
            if (literal !== word && literal !== "" && !/[\s;&|()<>`]/.test(literal)) [out, cursor, changed] = [out + text.slice(cursor, i) + literal, stop, true]
          } else {
            const first = subs[0]!
            const before = dequoteWord(text, i, text[first[0] - 1] === "(" ? first[0] - 2 : first[0] - 1)
            const after = subs.length === 1 ? dequoteWord(text, first[1] + 1, stop) : "x"
            if (before !== "" || (after !== "" && after[0] !== "/")) flag ??= RUNTIME_WORD_REASON
          }
        }
      }
      // Budget exhausted during this word: text unread or misread, from this word to the end.
      if ((budget.left < 0 || (budget.left === 0 && stop < text.length)) && (outside(i) || mask === text)) flag ??= UNDETERMINED_WORD_REASON
      ;[head, i] = [assign, stop]
    }
  }
  return { view: changed ? out + text.slice(cursor) : command, flag }
}

/**
 * Shell finding: finding of the rules (`priorShellFinding`, kept word for word), then, without a deny and if the cost guard
 * allows it (`layerGuard`), layer of indirectly designated devices (`deviceLayer`). The strongest wins
 * (`strength`); at equal strength, the existing finding is returned as is. Then the same examination of the view without leading
 * assignments (`assignedFinding`), and of the view of the word in command position reduced to its literal value (`commandWordView`,
 * judged additionally; at equal verdict, the original finding is kept with its mark). Internal error of either of these two
 * layers: original finding kept, prudent ask added (`ANALYSIS_FAILED`).
 */
export function shellFinding(command: string, ctx: ShellRuleContext): Finding | undefined {
  const base = assignedFinding(command, ctx, layeredShellFinding(command, ctx).finding)
  if (base?.verdict === "deny") return base
  try {
    const { view, flag } = commandWordView(command)
    const normalized = view !== command ? assignedFinding(view, ctx, layeredShellFinding(view, ctx).finding) : undefined
    return mostSevere([base, normalized, flag ? { verdict: "ask", rule: "nested-opencode", reason: flag } : undefined])
  } catch {
    return mostSevere([base, ANALYSIS_FAILED])
  }
}

/** Target groups of the device family: one per rule that compares a target (`mkfs` compares none). */
type DeviceGroup = "dd" | "redirect" | "write" | "shred"

/** Rule of each group, in the order of the deny table: same identifier, same reason, same switch. */
const DEVICE_RULES: ReadonlyArray<{ readonly group: DeviceGroup; readonly rule: RegexRule }> = (
  [
    ["dd", "dd-device"],
    ["redirect", "redirect-device"],
    ["write", "write-device"],
    ["shred", "shred-device"],
  ] as const
).map(([group, id]) => ({ group, rule: DENY_RULES.find((rule) => rule.id === id)! }))

/** Common definition anchored at the start of an absolute path, as in `writesDevice`. */
const DEVICE_AT_START = new RegExp(`^${DEVICE}`)

/** Absolute path that designates a device according to the common definition (exported for the measurement tool). */
export const isDevicePath = (path: string) => DEVICE_AT_START.test(path)

/** `dd` call according to the original rule: `dd-device` pattern copied without its target, tail up to the separator. */
const DD_RULE_CALL = /(?:^|[\s;&|(`{]|(?<![\w])=)dd\s[^;&|]*/g

/** Output operand in a `dd` call: position of `\bof=` in both `dd-device` rules. */
const DD_OUTPUT = /\bof=(\S+)/g

/** `shred` call according to its rule: `shred-device` pattern copied without its target, tail up to the separator. */
const SHRED_RULE_CALL = /shred\s[^;&|]*/g

/** Reader of the redirection targets of `writeTargets`, copied word for word: same strings as those it returns. */
const REDIRECT_TARGET = /(?:^|[^<>])(?:\d|&)?>>?\|?\s*([^\s;&|<>()]+)/g

/**
 * Write targets of a group, read at the positions where its rule looks for the definition, without a new command
 * recognition: `of=` output of `dd` calls from both recognitions (`DD_CALL` and original rule); targets of the
 * redirection reader of `writeTargets`; targets of `tee` and copy destination, read as in `writesDevice`; words
 * of the `shred` call outside options. One pass per reader, patterns without nested repetition.
 */
function deviceTargets(group: DeviceGroup, text: string): string[] {
  const targets: string[] = []
  if (group === "redirect") for (const match of text.matchAll(REDIRECT_TARGET)) targets.push(unquote(match[1] ?? ""))
  else if (group === "write")
    for (const segment of segments(text)) {
      const { name, args } = commandOf(segment)
      if (name === "tee") targets.push(...args.filter((arg) => !arg.startsWith("-")))
      else if (COPY_COMMANDS.has(name)) {
        const destination = copyDestination(args, name !== "rsync")
        if (destination !== undefined) targets.push(destination)
      }
    }
  else if (group === "dd")
    for (const call of [...text.matchAll(DD_CALL), ...text.matchAll(DD_RULE_CALL)])
      for (const output of call[0].matchAll(DD_OUTPUT)) targets.push(cleanTarget(output[1] ?? ""))
  else
    for (const call of text.matchAll(SHRED_RULE_CALL))
      for (const word of call[0].split(/\s+/).slice(1)) if (!word.startsWith("-")) targets.push(cleanTarget(word))
  return [...new Set(targets)].filter(Boolean)
}

/**
 * Target whose value is known only at run time: test of the inclusion operand of `variableShellSource`, copied
 * word for word (leading variable or non-literal value, outside a literal path; leading `$HOME` remains literal).
 */
const unknownTarget = (target: string) => literalPath(target) === undefined && (startsWithVariable(target) || isNonLiteralSource(target))

/**
 * Forms of a target, copied word for word from `protectedWriteKind` (sensitive-paths.ts): expanded form (blanks,
 * leading/trailing quotes and backticks removed, leading home directory expanded), base directories (root for an
 * absolute path, otherwise the command's directories), form resolved from each (`lexical`), and the two forms passed
 * to the real-path predicate (`asked`: raw, then resolved). Same strings: the replay finds exactly the
 * answers obtained by self-protection and protected write. `relative`: expanded form is relative, therefore judged
 * from the command's possible directories; otherwise (absolute path, expanded home directory) it depends on the
 * launch directory only if it goes through the process current directory link (`deviceHit`).
 */
function deviceForms(raw: string, ctx: ShellRuleContext): { expanded: string; lexical: string[]; asked: string[]; relative: boolean } {
  const expanded = raw.trim().replace(/^["'`]+|["'`]+$/g, "").replace(/^(~|\$HOME|\$\{HOME\})(?=\/|$)/, ctx.home ?? "~")
  const bases = posix.isAbsolute(expanded) ? ["/"] : ctx.cwds?.length ? ctx.cwds : ctx.cwd ? [ctx.cwd] : []
  const lexical = bases.map((base) => posix.resolve(base, expanded))
  return { expanded, lexical, asked: bases.flatMap((base, index) => [`${base}/${expanded}`, lexical[index]!]), relative: !posix.isAbsolute(expanded) }
}

/**
 * `/proc/self` entry designated by the following components: `selfEntry` from `src/real-path.ts`, copied word for word
 * (the rules module does not import the resolver, which accesses files).
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

/**
 * Absolute path that goes through the process current directory link (`/proc/self/cwd`, `/proc/thread-self/cwd`, or through
 * `task/<n>/`): traversal of `createRealPath` (`src/real-path.ts`) copied without its file operations, each
 * component being taken as an existing directory that is not a link. The resolver resolves this link from the command's
 * possible directories and the server's: the target depends on the launch directory, even after reshaping.
 * Accepted corner: each component is taken as is, and the expanded form removes quotes only at the ends
 * (`deviceForms`). A component of this link written with a quote or a backslash is therefore not recognized,
 * whereas reshaping crosses it like an ordinary directory: deny instead of the ask, although the shell
 * removes those characters and the target depends on the launch directory. Strict side only. The raw copy reader
 * already removes all quotes (`cleanTarget`): only the backslash causes this deny there.
 */
function throughProcessDirectory(absolute: string): boolean {
  const parts = absolute.split("/").reverse()
  let current = ""
  while (parts.length > 0) {
    const part = parts.pop()!
    if (part === "" || part === ".") continue
    if (part === "..") {
      current = current.slice(0, Math.max(current.lastIndexOf("/"), 0))
      continue
    }
    if (current === "/proc" && (part === "self" || part === "thread-self")) {
      const entry = selfEntry(parts, part === "thread-self")
      if (entry === "..") continue
      if (entry === "root") {
        current = ""
        continue
      }
      return entry === "cwd"
    }
    current = `${current}/${part}`
  }
  return false
}

interface DeviceHit {
  readonly group: DeviceGroup
  readonly rule: RegexRule
  readonly axis: "A" | "B"
  /**
   * Target that depends on the launch directory: ask under the group's identifier, never a deny (those denials do
   * not resolve a relative path).
   */
  readonly relative: boolean
  /** Absolute target that goes through the process current directory link, written or reached through a link. */
  readonly process: boolean
}

/**
 * Known-value target that designates a device: by its resolved form (A, reshaping), otherwise by the real
 * paths of its forms (B, resolution; `ctx.realPaths` here is the replay). Deny level first (target that does not
 * depend on the launch directory: A then B, all groups combined), then ask level: a target that does
 * depend on it never masks the deny of another group. A target depends on it if it is relative, if it goes through the
 * process current directory link, or if one of its forms has several replayed real paths (the resolver returns
 * several only through that link). Groups in the order of the deny table; targets read once per group.
 */
function deviceHit(text: string, ctx: ShellRuleContext): DeviceHit | undefined {
  const active = DEVICE_RULES.filter(({ rule }) => ruleEnabled(rule.id, ctx.active))
  const known = active.flatMap(({ group, rule }) =>
    deviceTargets(group, text)
      .filter((target) => !unknownTarget(target))
      .map((target) => {
        const forms = deviceForms(target, ctx)
        const process = !forms.relative && (throughProcessDirectory(forms.expanded) || forms.asked.some((form) => (ctx.realPaths?.(form)?.length ?? 0) > 1))
        return { group, rule, ...forms, process, launched: forms.relative || process }
      }),
  )
  for (const relative of [false, true]) {
    const level = known.filter((target) => target.launched === relative)
    const reshaped = level.find(({ lexical }) => lexical.some(isDevicePath))
    if (reshaped) return { group: reshaped.group, rule: reshaped.rule, axis: "A", relative, process: reshaped.process }
    const linked = level.find(({ asked }) => asked.some((form) => (ctx.realPaths?.(form) ?? []).some(isDevicePath)))
    if (linked) return { group: linked.group, rule: linked.rule, axis: "B", relative, process: linked.process }
  }
  return undefined
}

/**
 * Groups of the unknown value (C): raw copy, write and copy commands. Redirection left to the decision
 * model (current unknown-value target); wiping already asked by `file-delete` at the same position, with the
 * same strength.
 */
const UNKNOWN_GROUPS: ReadonlySet<DeviceGroup> = new Set(["dd", "write"])

/**
 * Targets of a launched command, read by the segment-head reader (`segments`, `commandOf`) of `writesDevice` and
 * of file deletion: `of=` operand of `dd`, targets of `tee` and copy destination (`deviceTargets`).
 * A name merely cited in a text is not a launched command.
 */
function launchedTargets(group: DeviceGroup, text: string): string[] {
  if (group !== "dd") return deviceTargets(group, text)
  const targets: string[] = []
  for (const segment of segments(text)) {
    const { name, args } = commandOf(segment)
    if (name === "dd") for (const arg of args) if (arg.startsWith("of=")) targets.push(cleanTarget(arg.slice("of=".length)))
  }
  return targets
}

/**
 * Active unknown-value groups whose launched target has an unknown value, in the protected write view
 * (`protectedTargets`: without data, except shell re-entry). The whole text is examined first: the view
 * is computed only if it has one.
 */
function unknownGroups(command: string, ctx: ShellRuleContext): DeviceGroup[] {
  const scan = (text: string) =>
    DEVICE_RULES.filter(({ group, rule }) => UNKNOWN_GROUPS.has(group) && ruleEnabled(rule.id, ctx.active) && launchedTargets(group, text).some(unknownTarget))
  if (scan(command).length === 0) return []
  const data = withoutData(command)
  return scan(reentersShell(data) ? command : data).map(({ group }) => group)
}

interface DeviceLayer {
  readonly finding: Finding
  readonly axis: "A" | "B" | "C"
  readonly group: DeviceGroup
  readonly relative: boolean
}

/**
 * Layer of indirectly designated devices, evaluated with the replay (`replay`): no call to budgeted
 * predicates. Reshaping and resolution (A, B) of a target that does not depend on the launch directory: deny of the group's
 * rule, reduced to an ask like that of a target written out in full (handling of `addedShellFinding`,
 * copied): never for a user rule with the same identifier; the deny remains if the view without data is the
 * command, contains a shell re-entry or a deny (existing, added or from the layer). Target that depends on the launch
 * directory: unmarked ask of the group's rule, in data as elsewhere. Unknown value (C): ask
 * of the rule of the first group concerned. Each axis is examined only if its guard condition is met
 * (`layerGuard`): otherwise it would find nothing, outside the corner noted at `TARGET_BOUND`.
 */
function deviceLayer(command: string, replay: ShellRuleContext, guard: LayerGuard): DeviceLayer | undefined {
  const hit = guard.base || guard.text || guard.links ? deviceHit(command, replay) : undefined
  if (hit) {
    const { rule, axis, group, relative, process } = hit
    const through = process ? "through a path that stands for the directory where the command runs" : "through a relative path"
    if (relative) return { finding: { verdict: "ask", rule: rule.id, reason: `${rule.reason} ${through}: confirmation required` }, axis, group, relative }
    const kept = () => {
      if (replay.custom?.some((custom) => custom.id === rule.id)) return true
      const data = withoutData(command)
      if (data === command || reentersShell(data) || evaluate(data, replay)?.verdict === "deny") return true
      return ADDED_DENY_RULES.some((added) => ruleEnabled(added.id, replay.active) && added.test(data, replay)) || deviceHit(data, replay)?.relative === false
    }
    const finding: Finding = kept()
      ? { verdict: "deny", rule: rule.id, reason: rule.reason }
      : { verdict: "ask", rule: rule.id, reason: `${rule.reason}, only inside code passed to an interpreter or a heredoc: confirmation required` }
    return { finding, axis, group, relative }
  }
  if (!guard.unknown) return undefined
  const group = unknownGroups(command, replay)[0]
  const entry = DEVICE_RULES.find((candidate) => candidate.group === group)
  if (!entry) return undefined
  const reason = `write target known only when the command runs, possibly a device (${entry.rule.reason}): confirmation required`
  return { finding: { verdict: "ask", rule: entry.rule.id, reason }, axis: "C", group: entry.group, relative: false }
}

/**
 * Cost guard of the layer: one necessary condition per axis, drawn from the layer's mechanisms. Guard closed, the
 * layer would find nothing (outside the corner noted at `TARGET_BOUND`): reshaping (A) requires `base` or `text`,
 * resolution (B) requires `links`, unknown value (C) requires `unknown`.
 */
interface LayerGuard {
  readonly base: boolean
  readonly text: boolean
  readonly links: boolean
  readonly unknown: boolean
}

/** Canonical path that is the device directory or a path below it: whole components, never a substring. */
const reachesDeviceDirectory = (path: string) => path === "/dev" || path.startsWith("/dev/")

/**
 * `posix.resolve` form of an absolute path: the path itself if it has no repeated slashes, no `.` or `..` component,
 * and no trailing slash (nothing to reshape); otherwise `posix.resolve`.
 */
const canonical = (path: string) =>
  path.startsWith("/") && !path.includes("//") && !path.includes("/.") && (path.length === 1 || !path.endsWith("/")) ? path : posix.resolve(path)

/**
 * Base directories of a relative target in `deviceForms` (possible directories of the command, otherwise current directory),
 * in the form of `posix.resolve` (a relative directory is completed by the process one).
 */
const canonicalBases = (ctx: ShellRuleContext) => (ctx.cwds?.length ? ctx.cwds : ctx.cwd ? [ctx.cwd] : []).map(canonical)

/**
 * Guard, A, base: a base directory or the home directory that replaces `~` in `deviceForms` reaches the device
 * directory. A resolved form whose first component comes from the base (or the home directory) has that component
 * only if the canonical base starts with it: the target's `..` remove components from the end.
 */
const baseReachesDevices = (bases: readonly string[], home: string | undefined) =>
  bases.some(reachesDeviceDirectory) || (home !== undefined && reachesDeviceDirectory(canonical(home.startsWith("/") ? home : `/${home}`)))

/**
 * Characters that no target reader removes or takes as a target boundary, and that reshaping leaves
 * in their component: such a character attached to the directory name makes a longer component.
 */
/** Escaped hyphen: the class remains without a range when the backslash is added to it. */
const COMPONENT_CHARS = "\\w.+,:@%^#\\-"
const COMPONENT_CHAR = new RegExp(`[${COMPONENT_CHARS}]`)
const PATH_CHAR = new RegExp(`[${COMPONENT_CHARS}/]`)
/** Same classes, by character code (fast test; outside ASCII: neither one). */
const COMPONENT_CODES = Array.from({ length: 128 }, (_, code) => COMPONENT_CHAR.test(String.fromCharCode(code)))
const PATH_CODES = Array.from({ length: 128 }, (_, code) => PATH_CHAR.test(String.fromCharCode(code)))
/**
 * Common boundary to all target readers (`REDIRECT_TARGET`, `dd` and `shred` calls, `segments`, words).
 * Accepted corner: the write and copy reader also reads the content of a substitution (`$(…)`, `<(…)`,
 * `>(…)`) or backticks, which `segments` keeps whole, `;`, `&` and `|` included, and which `commandOf` splits at
 * blanks only. A target read there can contain one of these three characters: the guard nevertheless treats it as bounded by
 * it (`mentionMayLead`, `mentionMayName`) and can close reshaping (A) where, without it, the layer would deny:
 * never less strict than the existing rules. Unquoted, this character cuts the real target for the shell: the guard
 * avoids a false deny. Quoted, the deny is missed, for a target whose component contains this character (absurd names).
 */
const TARGET_BOUND = /[\s;&|]/
/** Name of the device directory, embedded quotes included (`cleanTarget` removes quotes everywhere). */
const DEVICE_DIRECTORY_NAME = /d["']*e["']*v/g
/** Leading home directory, which `deviceForms` expands. */
const HOME_WORD = /(?:~|\$HOME|\$\{HOME\})$/
/**
 * Tail of a mention up to the common boundary: path characters, then characters that a reader removes, keeps or
 * takes as a target end (quotes, backtick, closing parenthesis and brace).
 */
const MENTION_TAIL = new RegExp(`([${COMPONENT_CHARS}/]*)([)}"'\`]*)(?=[\\s;&|]|$)`, "y")
/** Mentions examined at most; beyond that, the guard lets it through (bounded cost). */
const MENTION_LIMIT = 64

/**
 * Can the mention that starts at `start` be the first component of a target's resolved form? The path
 * characters that precede it belong to any target that contains it. Each whole component they
 * contain after the first must be removed by a `..` placed after it. Preceded by a common boundary (quotes or
 * leading backticks, which readers remove, and home directory included), they are moreover the exact
 * start of the target (outside the corner noted at `TARGET_BOUND`): the resolved form of that start (`deviceForms`) must be the
 * directory itself. Without a dot or home directory, that start is made of slashes (absolute path: that is the case), empty
 * (relative target: only from a base that is the root, `rootBase`) or starts with an ordinary component
 * that no `..` removes (never).
 */
function mentionMayLead(text: string, start: number, ctx: ShellRuleContext, rootBase: boolean): boolean {
  let first = start
  while (first > 0 && PATH_CODES[text.charCodeAt(first - 1)] === true) first--
  const path = text.slice(first, start)
  let kept = 0
  for (const part of path.split("/").slice(1, -1)) kept = part === ".." ? Math.max(kept - 1, 0) : part === "" || part === "." ? kept : kept + 1
  if (kept > 0) return false
  const home = HOME_WORD.exec(text.slice(Math.max(0, first - 7), first))?.[0] ?? ""
  let edge = first - home.length
  while (edge > 0 && /["'`]/.test(text[edge - 1]!)) edge--
  if (edge > 0 && !TARGET_BOUND.test(text[edge - 1]!)) return true
  if (home === "" && !path.includes(".")) return path === "" ? rootBase : path.startsWith("/")
  return deviceForms(`${home}${path}dev`, ctx).lexical.includes("/dev")
}

/**
 * Can the mention tail that ends at `end` give a resolved form that designates a device according to the common
 * definition? Any target that contains the mention stops at the common boundary (outside the corner noted at
 * `TARGET_BOUND`); the path characters that follow are part of it as is, then any part of the end
 * characters. These are neither slashes nor dots nor word characters: for the definition, any
 * non-empty part is equivalent to a closing parenthesis.
 */
function mentionMayName(text: string, end: number): boolean {
  MENTION_TAIL.lastIndex = end
  const tail = MENTION_TAIL.exec(text)
  if (!tail) return true
  return isDevicePath(canonical(`/dev${tail[1]}`)) || (tail[2] !== "" && isDevicePath(canonical(`/dev${tail[1]})`)))
}

/**
 * Guard, A, text: a mention of the device directory name as a whole component, which can be the first
 * component of a resolved form (otherwise this component comes from the base) and whose tail can designate a device.
 */
function textMayReachDevices(text: string, ctx: ShellRuleContext, rootBase: boolean): boolean {
  let examined = 0
  DEVICE_DIRECTORY_NAME.lastIndex = 0
  for (let match = DEVICE_DIRECTORY_NAME.exec(text); match; match = DEVICE_DIRECTORY_NAME.exec(text)) {
    const start = match.index
    const end = start + match[0].length
    if (COMPONENT_CODES[text.charCodeAt(start - 1)] === true || COMPONENT_CODES[text.charCodeAt(end)] === true) continue
    if (++examined > MENTION_LIMIT) return true
    if (mentionMayName(text, end) && mentionMayLead(text, start, ctx, rootBase)) return true
  }
  return false
}

/** Names of the write and copy group commands (`deviceTargets`), bounded like a word (`commandName`). */
const LAUNCHED_WRITE = new RegExp(`\\b(?:tee|${[...COPY_COMMANDS].join("|")})\\b`)

/**
 * Guard, C: `unknownTarget` assumes a character with an unknown value (`isNonLiteralSource`, which also covers
 * `startsWithVariable`), which the target gets from the text of its segment (`segments`); and the reader of a retained group
 * assumes, earlier in that segment, `of=` and the raw copy as a command (`commandOf`), or the name of a write or copy
 * command (which `commandToken` and `commandName` bound with non-word characters) that is the segment's
 * command. The whole text is examined first; `commandOf` reads only the segments that remain.
 */
function unknownMayApply(command: string): boolean {
  const after = (text: string, index: number) => index >= 0 && isNonLiteralSource(text.slice(index))
  if (!isNonLiteralSource(command) || (!after(command, command.indexOf("of=")) && !after(command, command.search(LAUNCHED_WRITE)))) return false
  return segments(command).some((segment) => {
    const raw = after(segment, segment.indexOf("of="))
    const write = after(segment, segment.search(LAUNCHED_WRITE))
    if (!raw && !write) return false
    const { name } = commandOf(segment)
    return (raw && name === "dd") || (write && (name === "tee" || COPY_COMMANDS.has(name)))
  })
}

/**
 * Guard conditions; `linked`: a recorded answer from the real-path predicate designates a device. An
 * exception (process directory unreadable for a relative base) opens the guard: the layer then behaves as
 * without it.
 */
function layerGuard(command: string, ctx: ShellRuleContext, linked: boolean): LayerGuard {
  try {
    const bases = canonicalBases(ctx)
    return { base: baseReachesDevices(bases, ctx.home), text: textMayReachDevices(command, ctx, bases.includes("/")), links: linked, unknown: unknownMayApply(command) }
  } catch {
    return { base: true, text: true, links: true, unknown: true }
  }
}

/**
 * Context budget predicates (`realPaths`, `credentialContent`), recorded during the existing finding (`record`)
 * and only replayed by the layer (`replay`): answer already obtained for the same question, otherwise unknown (real paths
 * `undefined`: lexical comparison only; content: not recognized). The replay never queries the instance: its
 * consultation ceiling remains whole for existing consumers, in this call as in the following ones that
 * share the instance (subcommands during permission examination, scripts of a call without directory). `linked`: a
 * recorded real-path answer designates a device (the only possible trace of a neutrally named link). Without
 * either predicate, nothing to record: the context serves both.
 */
function budgetedPredicates(ctx: ShellRuleContext): { record: ShellRuleContext; replay: ShellRuleContext; linked: () => boolean } {
  const { realPaths, credentialContent } = ctx
  if (!realPaths && !credentialContent) return { record: ctx, replay: ctx, linked: () => false }
  const paths = new Map<string, readonly string[] | undefined>()
  const contents = new Map<string, boolean>()
  const recordPaths = realPaths
    ? (absolute: string) => {
        const found = realPaths(absolute)
        paths.set(absolute, found)
        return found
      }
    : undefined
  const recordContent = credentialContent
    ? (path: string) => {
        const found = credentialContent(path)
        contents.set(path, found)
        return found
      }
    : undefined
  return {
    record: { ...ctx, ...(recordPaths ? { realPaths: recordPaths } : {}), ...(recordContent ? { credentialContent: recordContent } : {}) },
    replay: {
      ...ctx,
      ...(realPaths ? { realPaths: (absolute: string) => paths.get(absolute) } : {}),
      ...(credentialContent ? { credentialContent: (path: string) => contents.get(path) === true } : {}),
    },
    linked: () => [...paths.values()].some((found) => found?.some(isDevicePath) === true),
  }
}

/** Existing finding with the recorded predicates; without a deny, layer with their replay, if the guard allows it. */
function layeredShellFinding(
  command: string,
  ctx: ShellRuleContext,
): { finding: Finding | undefined; layer?: DeviceLayer; guard?: LayerGuard; replay: ShellRuleContext } {
  const { record, replay, linked } = budgetedPredicates(ctx)
  const existing = priorShellFinding(command, record)
  if (existing?.verdict === "deny") return { finding: existing, replay }
  const guard = layerGuard(command, replay, linked())
  const layer = guard.base || guard.text || guard.links || guard.unknown ? deviceLayer(command, replay, guard) : undefined
  if (!layer) return { finding: existing, guard, replay }
  return { finding: strength(layer.finding) > strength(existing) ? layer.finding : existing, layer, guard, replay }
}

/**
 * Detail for the measurement tool only, outside the returned finding: `assignedFinding` finding (without `commandWordView`); layer (axis,
 * group, relative target and finding); guard conditions (absent after an existing deny); groups that write
 * to a target, in the protected write view; groups
 * of the unknown value whose launched target has an unknown value; known-value targets whose replayed real paths
 * designate a device; requested forms, target by target, of the `dd` and `shred` targets that reshaping
 * does not recognize (existing consumers never ask for them).
 */
export function deviceLayerDetail(command: string, ctx: ShellRuleContext) {
  const { finding, layer, guard, replay } = layeredShellFinding(command, ctx)
  const data = withoutData(command)
  const view = reentersShell(data) ? command : data
  const writes = DEVICE_RULES.filter(({ group }) => deviceTargets(group, view).length > 0).map(({ group }) => group)
  const unknown = unknownGroups(command, replay)
  let resolved = 0
  const unasked: string[][] = []
  for (const { group } of DEVICE_RULES)
    for (const target of deviceTargets(group, command).filter((candidate) => !unknownTarget(candidate))) {
      const { lexical, asked } = deviceForms(target, replay)
      if (asked.some((form) => (replay.realPaths?.(form) ?? []).some(isDevicePath))) resolved++
      if ((group === "dd" || group === "shred") && !lexical.some(isDevicePath)) unasked.push(asked)
    }
  return { finding: assignedFinding(command, ctx, finding), layer, guard, writes, unknown, resolved, unasked }
}
