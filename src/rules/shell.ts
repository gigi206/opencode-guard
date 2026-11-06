import { posix } from "node:path"
import { containsEncodedPlaceholder, PLACEHOLDER_RE, PLACEHOLDER_SHOWN, type Redactor } from "../secrets/redact.ts"
import { decodeUnicodeEscapes, NETWORK_FUNCTION, OWN_HTTP_CALLS, PYTHON_HTTP_CALL, UNPARSED_QUOTING } from "./code-network.ts"
import { entrusted, hardened, overrideOf, ruleEnabled, waivable, waiverOf, withoutLowered, type ActiveRules } from "./features.ts"
import { OPAQUE_RULES } from "./opaque.ts"
import {
  completesProtectedPath,
  credentialFile,
  hasParentComponent,
  isCredentialFile,
  isStartupName,
  lexicalPath,
  namedCredentialFile,
  pathTokens,
  protectedWriteClass,
  realFile,
  strictestKind,
  systemWrite,
  targetable,
  uncheckedCredentialReason,
  uncheckedWriteReason,
  type CredentialContext,
  type WriteClass,
  type WritePathContext,
} from "./sensitive-paths.ts"
import { LIMIT_REACHED, mostSevere, type CustomRule, type Finding, type Waiver, type WaiverContext } from "./types.ts"

export interface ShellRuleContext extends WritePathContext, CredentialContext, WaiverContext {
  readonly redactor: Redactor
  /** The command as written, whichever view of it a rule is given (`shellFinding`). */
  readonly written?: string
  readonly home?: string
  readonly custom?: readonly CustomRule[]
  /**
   * Rule policy (`dangerousCommands` / `sensitiveFiles` switches, `ruleOverrides`): a disabled rule is not evaluated, an ask
   * of a rule set to `deny` is a deny where it is built; a deny of a rule set to `ask` is lowered at the end of
   * `shellFinding`; absent = all, unchanged.
   */
  readonly active?: ActiveRules
  /** Content of an executed script (`scriptFinding`): the placeholder rule (write) does not apply to an execution. */
  readonly executedScript?: boolean
  /**
   * The other sub-commands of the same `permission.evaluate`: a target is retained only if each of them only reads
   * (`partsOnlyRead`), like the other parts of a command.
   */
  readonly others?: readonly string[]
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

/** `command -v`/`-V` only prints how a name resolves: not a launch. */
const WRAPPERS = "sudo|doas|env|command(?![^\\S\\n]+-[a-zA-Z]*[vV])|exec|nohup|time|timeout|nice|ionice|stdbuf|xargs|watch|setsid|torsocks|proxychains4?|unbuffer"

/** Path before a command name; does not cross separators (linear cost). */
const COMMAND_PATH = "(?:[^\\s;&|()`{}]*/)?"

/**
 * Launched command (not a mere argument): start, after a separator, `(`, `$(`, a backtick,
 * `sh -c "…"` or `find -exec`; possibly behind a wrapper (sudo, timeout, xargs…) and at most
 * 8 arguments (bound: otherwise quadratic cost on a booby-trapped command; beyond it, a plain ask), with a
 * path (`/usr/bin/curl`), a bypassed alias (`\curl`) or zsh's `=curl` (command path); never
 * after an identifier (`PAGER=less` is not run). `after`: tail required after the name. The blanks after the
 * opener do not absorb the newline, which is itself an opener (same result; otherwise each newline in a long tail
 * rescans it, quadratic cost); those of `find -exec`, a single repetition (two in a row try every split of a long
 * run of spaces, quadratic cost; same result).
 */
const commandRegex = (names: string, after = "(?=\\s|$|[;&|)])") =>
  new RegExp(
    `(?:(?:^|[;&|(\`\\n{]|-[a-zA-Z]*c\\s+["'])[^\\S\\n]*|-(?:exec|execdir|ok|okdir)\\s+)` +
      `(?:[\\\\=]?${COMMAND_PATH}(?:${WRAPPERS})(?:\\s+[^\\s;&|]+){0,8}?\\s+)?` +
      `[\\\\=]?${COMMAND_PATH}(?:${names})${after}`,
  )

const NETWORK_COMMAND = commandRegex(NETWORK_TOOLS)
const REMOTE_TOOLS = "scp|sftp|ssh|nc|ncat|netcat|socat|telnet|ftp|lftp"
const REMOTE_COMMAND = commandRegex(REMOTE_TOOLS)
/** A remote tool's path looked up and run in the same word (`$(which ssh) host`, `` `command -v nc` ``). */
const REMOTE_LOOKED_UP = new RegExp(`(?:\\$\\(|\`)\\s*(?:which|command\\s+-v|type\\s+-[pP])\\s+(?:${REMOTE_TOOLS})\\s*(?:\\)|\`)`)

/** bash network redirection (`> /dev/tcp/host/port`): equivalent to a launched network tool. */
const NETWORK_DEVICE = /\/dev\/(?:tcp|udp)\//

const runsNetwork = (command: string) => NETWORK_COMMAND.test(command) || NETWORK_DEVICE.test(command)

const mentionsNetwork = (command: string) => runsNetwork(command) || NETWORK_WORD.test(command)

/**
 * Another OpenCode agent or server launched by the agent: a nested `opencode run --auto` would approve all
 * requests (also without a subcommand, and with the hidden aliases of `--auto`, OpenCode 2.2.0), and OPENCODE_CONFIG / OPENCODE_CONFIG_CONTENT / OPENCODE_CONFIG_DIR can remove the plugin from it.
 */
const NESTED_OPENCODE = commandRegex("opencode", "(?:\\s+(?:run|serve|web|acp|attach)\\b|(?=[^;&|\\n]{0,500}?\\s--(?:auto|yolo|dangerously-skip-permissions)\\b))")
const OPENCODE_CONFIG_VARIABLE = /\bOPENCODE_CONFIG(?:_DIR|_CONTENT)?=/
/**
 * With a nested OpenCode launch (OpenCode 2.2.0): the other variables that change the configuration or the plugins it
 * loads (TUI settings and plugins, project configuration skipped, the directories its global configuration and the code
 * of its npm plugins are found from), and the options that approve its confirmations.
 */
const NESTED_CONFIG_VARIABLE = /(?:^|[^\w$])(?:OPENCODE_CLI_CONFIG_CONTENT|OPENCODE_CONFIG_PROJECT_DISABLE|OPENCODE_DISABLE_PROJECT_CONFIG|XDG_CONFIG_HOME|XDG_CACHE_HOME|HOME)=/
const AUTO_APPROVE = /\s--(?:auto|yolo|dangerously-skip-permissions)(?![\w-])/

const PLACEHOLDER_REASON =
  `the command contains a redacted secret (${PLACEHOLDER_SHOWN}): writing it would destroy the real secret. Make a targeted edit that does not include the placeholder`
const PLACEHOLDER_ENCODED_REASON =
  `the command contains a redacted secret encoded in base64 (a ${PLACEHOLDER_SHOWN} placeholder once decoded): writing it would destroy the real secret. Make a targeted edit that does not include it`

/** Shell separators; `SHELL_SEPARATORS`: not inside a redirection operator (`2>&1`, `&>`, `<&`, `>|`), like the shell. */
const SEPARATORS = /\|\||&&|;|\||&|\n/
const SHELL_SEPARATORS = /\|\||&&|;|(?<!>)\||(?<![<>])&(?!>)|\n/

/** Simple segments: shell separators + contents of `$(…)` and backticks. */
export function segments(command: string, separators = SEPARATORS): string[] {
  const parts = command.split(separators)
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

/** `critical`: `rm-critical` active; otherwise a recursive or forced deletion of a critical target is still an `rm` ask. */
function rmFinding(segment: string, home?: string, critical = true): Finding | undefined {
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
  if (critical && (noPreserve || (recursive && targets.some((target) => isCriticalTarget(target, home)))))
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
  const { name, args: tokens } = commandOf(segment)
  if (name !== "mv") return undefined
  const args = withoutRedirections(tokens)
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
    else if (!arg.startsWith("-")) positional.push(arg)
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
  /** Ask born from a check stopped by a limit or a form the plugin does not read: never left to the decision model by a setting. */
  readonly unfinished?: true
  /**
   * Ask about a change of the plugin's settings: never left to the decision model (user's decision), `selfProtectionByModel`
   * included. A function decides by the finding, for an ask that covers both a settings location and another one.
   */
  readonly userOnly?: true | ((command: string, ctx: ShellRuleContext) => boolean)
  /** Reason and targets of the finding read with the test (`secret-file-read`: the files named). */
  readonly detail?: (command: string, ctx: ShellRuleContext) => Pick<Finding, "reason" | "targets">
}

const re = (regex: RegExp) => (command: string) => regex.test(command)

/**
 * Server API routes that bypass the guard with the server password (rule `opencode-server-api`), also looked for in the
 * code of an artifact's pages (`artifacts.ts`). Documentation template (`/api/session/{sessionID}/prompt`) excluded: a
 * real identifier has no brace. OpenCode 2.1.3 voice route: replaces the instructions of a voice call of the session.
 */
export const SERVER_API_ROUTE = /\/api\/(?:session\/[^\s"'\/{}]+\/(?:agent|command|prompt|permission)|experimental\/voice\/session\/[^\s"'\/{}]+\/instructions|plugin\/update)\b/

const WRITE_COMMANDS = new Set(["cp", "mv", "ln", "install", "rm", "unlink", "truncate", "tee", "touch", "rsync"])
const unquote = (token: string) => token.replace(/^["']+|["']+$/g, "")

/** Wrappers that launch the next command, with their options followed by a value (`sudo -u bob`, `timeout -s KILL`). */
const PREFIX_OPTIONS: Readonly<Record<string, ReadonlySet<string>>> = {
  sudo: new Set(["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-T", "-U"]),
  doas: new Set(["-u", "-C"]),
  env: new Set(["-u", "-C", "-a", "--unset", "--chdir", "--argv0"]),
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
  busybox: new Set(),
  toybox: new Set(),
  watch: new Set(["-n", "--interval"]),
}
/** Structural words before a command (`{ cmd; }`, `if cmd`, `! cmd`). */
const GROUPING_WORDS = new Set(["{", "(", "!", "if", "then", "elif", "else", "do", "while", "until"])

/**
 * String of `env -S<text>` or `--split-string=<text>` attached to its option: put back as a word of its own, read like the
 * rest of the command (a detached string needs nothing: the option takes no value here, its words follow it).
 */
function attachedSplitString(tokens: string[], i: number, wrapper: string | undefined): void {
  if (wrapper !== "env") return
  const attached = /^(?:-[iv0]*S|--split-string=)(.+)$/.exec(tokens[i]!)?.[1]
  if (attached !== undefined) tokens[i] = unquote(attached)
}

/** Command as launched (path included), without attached `{`/`(`/`$(`/quotes, `=` (zsh), `\` or closing characters. */
const commandToken = (token: string) => token.replace(/^(?:\$?\(|[{=\\"'`])+/, "").replace(/[)}"'`]+$/, "")

/** Bare name: without attached `{`/`(`/`$(`/quotes, `=` (zsh), `\`, path, or trailing `)`/`}`/quotes (`sh')"`). */
const commandName = (token: string) => commandToken(token).split("/").pop() ?? ""

/**
 * Command of a segment and its arguments, after structural words, assignments (`A=1 cmd`) and
 * wrappers with their options (`sudo -E -u bob cmd`, `timeout -s KILL 5 cmd`). `path`: the command as
 * launched (`./build.sh`, `/usr/bin/python3`).
 */
function commandOf(segment: string): { name: string; args: string[]; path: string } {
  return commandOfWords(segment.split(/\s+/).filter(Boolean).map(unquote))
}

/** `commandOf` on words already cut (changes `tokens`). */
function commandOfWords(tokens: string[]): { name: string; args: string[]; path: string } {
  let i = 0
  let wrapper: string | undefined
  while (i < tokens.length) {
    attachedSplitString(tokens, i, wrapper)
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

/** A word that opens a redirection (`<`, `2>x`, `&>x`, `{fd}>x`). */
const REDIRECTION_WORD = /^(?:\d*|&|\{[A-Za-z_]\w*\})[<>]/
/** A redirection operator alone, its target in the next word (`2>`, `>|`, `<<-`, `2>&`). `2>&-` closes: it has no target. */
const LONE_REDIRECTION = /^(?:\d*|&|\{[A-Za-z_]\w*\})(?:<<-|[<>]+[&|]?)$/

/** The words of a command without its redirections and their targets. A process substitution (`<(x)`) stays a word: it is an operand. */
function withoutRedirections(args: readonly string[]): string[] {
  const words: string[] = []
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!
    if (!REDIRECTION_WORD.test(arg) || /^[<>]\(/.test(arg)) words.push(arg)
    else if (LONE_REDIRECTION.test(arg)) i++
  }
  return words
}

const CLOSING_GROUP = /\)*/y

/** Segments for the readers of a launcher: cut as the shell cuts, where `2>&1` stays in its command, and at every `&`, which also cuts a quoted word. */
const launcherSegments = (command: string) => new Set([...segments(command, SHELL_SEPARATORS), ...segments(command)])

/**
 * The segment without the redirections written in it and their targets, read by the words of the shell (`shellEnd`):
 * unlike `withoutRedirections`, on text that still has its quotes, so a quoted `'>'` stays a word. A target known at run
 * time goes as well (`>$X`, `2>"$LOG"`). An operator without a target (a segment cut at `2>&1`) stays a word, and a word
 * that the read does not close keeps the rest of the segment. Linear cost.
 */
function withoutWrittenRedirections(segment: string): string {
  const budget = { left: 8 * segment.length + 1024 }
  const wordEnd = (at: number) => {
    const substitution = /[<>]/.test(segment[at] ?? "") && segment[at + 1] === "("
    const end = substitution ? shellEnd(segment, at + 1, segment.length, budget, true) : shellEnd(segment, at, segment.length, budget, false)
    return end < 0 ? segment.length : Math.max(end, at + 1)
  }
  let [out, i] = ["", 0]
  while (i < segment.length) {
    const start = stickyEnd(BLANKS, segment, i)
    out += segment.slice(i, start)
    if (start === segment.length) break
    const substitution = /[<>]/.test(segment[start]!) && segment[start + 1] === "("
    const operator = substitution ? start : stickyEnd(REDIRECTION_OPERATOR, segment, start)
    const target = stickyEnd(WORD_GAP, segment, operator)
    const end = operator > start && target < segment.length ? wordEnd(target) : 0
    // A `)` glued to the target closes a group, it is no word (`(cmd >x)`).
    if (end > 0) i = stickyEnd(CLOSING_GROUP, segment, end)
    else {
      i = wordEnd(start)
      out += segment.slice(start, i)
    }
  }
  return out
}

/** One short option of a word, with its value when it takes one (attached to the letter, otherwise the next word). */
interface ShortOption {
  readonly letter: string
  readonly value?: string
}

/**
 * Words of a command after its options: the options that take a value are given by their short letters (`values`, a
 * value ends the group as in `tar -xzfa.tar`) and by their long names (`long`, also abbreviated, `--name value`); the
 * short options read go to `seen`, a long one and its value (`--name=value`, or `value` when the next word is taken) to
 * `seenLong`. Stops at the first redirection (`patch a < b`) and treats everything after `--` as an operand.
 */
function operands(
  tokens: readonly string[],
  values: string,
  long: readonly string[],
  seen: (option: ShortOption) => void,
  seenLong: (name: string, value: string | undefined) => void = () => {},
): string[] {
  const words: string[] = []
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]!
    if (REDIRECTION_WORD.test(token)) {
      if (/^(?:\d*|&)[<>]+$/.test(token)) i++
    } else if (token === "--") return [...words, ...tokens.slice(i + 1).filter((word) => !REDIRECTION_WORD.test(word))]
    else if (token.startsWith("--")) {
      const takes = !token.includes("=") && long.some((name) => isLongOption(token, name))
      const value = takes ? tokens[++i] : token.includes("=") ? token.slice(token.indexOf("=") + 1) : undefined
      seenLong(token, value)
    } else if (token.startsWith("-") && token !== "-")
      for (let j = 1; j < token.length; j++) {
        const letter = token[j]!
        if (!values.includes(letter)) {
          seen({ letter })
          continue
        }
        seen({ letter, value: j + 1 < token.length ? token.slice(j + 1) : tokens[++i] })
        break
      }
    else words.push(token)
  }
  return words
}

/** Files `patch` changes: the original file (first operand; the second is the patch, read), `-o`, the directory of `-d`. */
function patchTargets(tokens: readonly string[]): string[] {
  const targets: string[] = []
  const files = operands(
    tokens,
    "BDFVYgdiopryz",
    ["prefix", "ifdef", "fuzz", "version-control", "basename-prefix", "get", "directory", "input", "output", "strip", "reject-file", "suffix", "quoting-style", "reject-format", "merge"],
    ({ letter, value }) => {
      if ((letter === "o" || letter === "d") && value !== undefined) targets.push(value)
    },
    (name, value) => {
      if (value !== undefined && (isLongOption(name, "output") || isLongOption(name, "directory"))) targets.push(value)
    },
  )
  return files[0] === undefined ? targets : [files[0], ...targets]
}

/** Short options of `tar` that take a value. */
const TAR_VALUES = "CFHIKLNTVXbfg"

/** Extraction directories of `tar` (`-C`, `--directory`), new syntax and old syntax without a dash; none without extraction. */
function tarTargets(tokens: readonly string[]): string[] {
  const directories: string[] = []
  let extract = false
  let rest = tokens
  const first = tokens[0] ?? ""
  if (/^[A-Za-z]+$/.test(first)) {
    // Old syntax: the values of the group's letters follow it, in order.
    let next = 1
    for (const letter of first) {
      if (letter === "x") extract = true
      if (!TAR_VALUES.includes(letter)) continue
      const value = tokens[next++]
      if (letter === "C" && value !== undefined) directories.push(value)
    }
    rest = tokens.slice(next)
  }
  operands(
    rest,
    TAR_VALUES,
    ["directory", "file", "files-from", "exclude-from", "blocking-factor", "format", "group", "owner", "mode", "mtime", "suffix", "use-compress-program", "volno-file", "info-script", "new-volume-script"],
    ({ letter, value }) => {
      if (letter === "x") extract = true
      if (letter === "C" && value !== undefined) directories.push(value)
    },
    (name, value) => {
      if (isLongOption(name, "extract") || isLongOption(name, "get")) extract = true
      if (value !== undefined && isLongOption(name, "directory")) directories.push(value)
    },
  )
  return extract ? directories : []
}

/** Extraction directory of `unzip` (`-d`, attached or not, last of a group: `-od dir`). */
function unzipTargets(tokens: readonly string[]): string[] {
  const directories: string[] = []
  operands(tokens, "dIOP", [], ({ letter, value }) => {
    if (letter === "d" && value !== undefined) directories.push(value)
  })
  return directories
}

/** Directory of `cpio` (`-D`, `--directory`) outside its create mode, which only reads there. */
function cpioTargets(tokens: readonly string[]): string[] {
  const directories: string[] = []
  let create = false
  operands(
    tokens,
    "CDEFHIMOR",
    ["directory", "block-size", "pattern-file", "file", "format", "message", "owner", "rsh-command"],
    ({ letter, value }) => {
      if (letter === "o") create = true
      if (letter === "D" && value !== undefined) directories.push(value)
    },
    (name, value) => {
      if (isLongOption(name, "create")) create = true
      if (value !== undefined && isLongOption(name, "directory")) directories.push(value)
    },
  )
  return create ? [] : directories
}

/** Directory of `git apply --directory` (git's own options before the subcommand skipped). */
function gitApplyTargets(tokens: readonly string[]): string[] {
  let i = 0
  while (i < tokens.length && tokens[i]!.startsWith("-")) i += /^(?:-C|-c|--git-dir|--work-tree|--namespace)$/.test(tokens[i]!) ? 2 : 1
  if (tokens[i] !== "apply") return []
  const directories: string[] = []
  operands(tokens.slice(i + 1), "p", ["directory"], () => {}, (name, value) => {
    if (value !== undefined && isLongOption(name, "directory")) directories.push(value)
  })
  return directories
}

/** Output files and directories that a program writes by its own operand or option. */
function ownOutputs(name: string, tokens: readonly string[]): string[] {
  switch (name) {
    case "dd":
      return tokens.filter((token) => token.startsWith("of=")).map((token) => unquote(token.slice(3)))
    case "sponge":
      return operands(tokens, "", [], () => {})
    case "patch":
      return patchTargets(tokens)
    case "tar":
      return tarTargets(tokens)
    case "unzip":
      return unzipTargets(tokens)
    case "cpio":
      return cpioTargets(tokens)
    case "git":
      return gitApplyTargets(tokens)
    default:
      return []
  }
}

/** Levels of `bash -c` read inside each other (`shellCodeFinding`); deeper, `UNSTABLE_SHELL_CODE`. */
const MAX_SHELL_LEVELS = 3

/** Index of the code of a shell's `-c` among its arguments (`-lc 'x'`, `-e -c -- 'x'`), -1 without one: an operand ends the options. */
function shellCodeWord(args: readonly string[]): number {
  let code = false
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!
    if (arg === "--") return code ? i + 1 : -1
    if (!/^[-+]./.test(arg)) return code ? i : -1
    if (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(arg)) code = true
    if (/^[-+][a-zA-Z]*[oO]$/.test(arg) || arg === "--rcfile" || arg === "--init-file") i++
  }
  return -1
}

/**
 * Actually written targets: redirections to a file (not `2>&1` or `/dev/null`), arguments of
 * write commands, files modified in place (`sed -i`, `perl -i`) and the outputs of `ownOutputs`. The code of a shell's
 * `-c` is read as a command of its own by every rule (`shellCodeFinding`).
 */
export function writeTargets(command: string): string[] {
  const targets: string[] = []
  for (const match of command.matchAll(/(?:^|[^<>])(?:\d|&)?>>?\|?\s*([^\s;&|<>()]+)/g)) targets.push(unquote(match[1] ?? ""))
  for (const segment of segments(command)) {
    const { name, args: tokens } = commandOf(segment)
    const args = tokens.filter((token) => !token.startsWith("-") && !/^\d*>/.test(token))
    const inPlace = (name === "sed" || name === "perl") && tokens.some((t) => /^-[a-zA-Z]*i/.test(t) || t.startsWith("--in-place"))
    if (WRITE_COMMANDS.has(name) || inPlace) targets.push(...args)
    targets.push(...ownOutputs(name, tokens))
  }
  return targets.filter((target) => target && !target.startsWith("/dev/"))
}

/** `-t` with its value attached (`-t/etc`, `-rt.git`), after letters that take no value (`install -m`, `-g`, `-o`, `-S`). */
const ATTACHED_TARGET = /^-[^-gmoSt]*t(.+)$/

/**
 * Write target of a copy command: `-t`/`--target-directory`, abbreviated or with an attached value (cp, mv, install; for
 * rsync, `-t` preserves the dates), otherwise the last argument (if there is a source). Redirections are no arguments.
 */
function copyDestination(words: readonly string[], targetOption: boolean): string | undefined {
  const args = withoutRedirections(words)
  const positional: string[] = []
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!
    if (targetOption) {
      if (isLongOption(arg, "target-directory")) return arg.includes("=") ? arg.slice(arg.indexOf("=") + 1) : args[i + 1]
      if (arg === "-t" || /^-[a-zA-Z]+t$/.test(arg)) return args[i + 1]
      const attached = ATTACHED_TARGET.exec(arg)
      if (attached) return attached[1]
    }
    if (!arg.startsWith("-")) positional.push(arg)
  }
  return positional.length >= 2 ? positional[positional.length - 1] : undefined
}

const COPY_COMMANDS = new Set(["cp", "mv", "install", "rsync"])

/** Write to a device by a command: `tee` (all its targets), cp/mv/install/rsync (destination). */
function writesDevice(command: string): boolean {
  const device = new RegExp(`^${DEVICE}`)
  return segments(command, SHELL_SEPARATORS).some((segment) => {
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
function secretVariables(command: string): string[] {
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

/** Credential files of a command (`secret-file-read`). */
interface CredentialReading {
  /** A file the rule asks about, a word not checked (`LIMIT_REACHED`, no file found), or neither. */
  readonly found: boolean | typeof LIMIT_REACHED
  /** Files named by the reason: absolute when computed without reading, otherwise as written. */
  readonly shown: readonly string[]
  /** Real paths of all the files (`Finding.targets`): only when the rule is `waivable` and every one is known. */
  readonly targets?: readonly string[]
}

/** Paths named in a reason, then how many more. */
const SHOWN_FILES = 3

/**
 * Credential files among the command's words (`credentialFile`). Default settings: after the first one, names only (same
 * content lookups as before, none after it), for the reason. Exception or memory active (`waivable`): every word,
 * content included, and the targets; a word not checked leaves the finding unfinished (no exception, no memory); all its
 * targets excepted, or this exact set confirmed earlier in the session: no finding (the other rules are unchanged).
 */
function credentialTokens(command: string, ctx: ShellRuleContext): CredentialReading {
  const waiving = waivable("secret-file-read", ctx.active)
  const { files, unchecked } = credentialWords(command, waiving, ctx)
  if (files.size === 0) return { found: unchecked ? LIMIT_REACHED : false, shown: [] }
  // Relative or with a `..` component: as written (the file the shell opens is not known without reading).
  const shown = [...files].map((file) => (hasParentComponent(file) ? undefined : lexicalPath(file, ctx.home, undefined)) ?? file)
  const targets = waiving && !unchecked ? (credentialTargets(command, [...files], ctx) ?? reducedTargets(command, files, ctx)) : undefined
  if (targets && waiverOf("secret-file-read", targets, ctx.active, ctx)) return { found: false, shown: [] }
  return { found: true, shown, ...(targets ? { targets } : {}) }
}

/** Credential files among the words of a command; `every`: each word in full, otherwise names only after the first file. */
function credentialWords(command: string, every: boolean, ctx: ShellRuleContext): { files: Set<string>; unchecked: boolean } {
  let unchecked = false
  const files = new Set<string>()
  for (const token of pathTokens(command)) {
    const found = files.size > 0 && !every ? namedCredentialFile(token, ctx) : credentialFile(token, ctx)
    if (found === true) files.add(token)
    else if (found === LIMIT_REACHED) unchecked = true
  }
  return { files, unchecked }
}

/**
 * Targets of a command whose files are pieces of words (`.env""`, `''.env`, `"<dir>"/.env`, which `pathTokens` cuts at the
 * quotes): those of the words reduced to their value, provided every file read here is part of one of them.
 */
function reducedTargets(command: string, files: ReadonlySet<string>, ctx: ShellRuleContext): string[] | undefined {
  let view = command
  try {
    view = commandWordView(command, MAX_SHELL_LEVELS).view
  } catch {}
  if (view === command) return undefined
  const words = credentialWords(view, true, ctx)
  const covered = [...files].every((file) => [...words.files].some((word) => word.includes(file)))
  return covered && !words.unchecked ? credentialTargets(view, [...words.files], ctx) : undefined
}

/** Blank or operator around a whole word, outside quotes. */
const WORD_BEFORE = /[\s;&|(<>]/
const WORD_AFTER = /[\s;&|)<>]/
/** Separators of `pathTokens`: the edges of the words it cuts. */
const TOKEN_EDGE = /[\s'"`;|&<>()=,@]/

/**
 * Quote state of each character: 0 unquoted, 1 quoted or escaped, 2 opening quote, 3 closing quote. `undefined` where this
 * simple reading could differ from the shell's (heredoc, comment, `$'…'`, backtick, substitution or parameter inside
 * double quotes, quote not closed): no word is then taken as whole.
 */
function quoteStates(command: string): Uint8Array | undefined {
  const states = new Uint8Array(command.length)
  let quote: string | undefined
  for (let i = 0; i < command.length; i++) {
    const char = command[i]!
    if (quote) {
      if (char === quote) {
        states[i] = 3
        quote = undefined
        continue
      }
      if (quote === '"' && (char === "`" || (char === "$" && (command[i + 1] === "(" || command[i + 1] === "{")))) return undefined
      states[i] = 1
      if (quote === '"' && char === "\\" && i + 1 < command.length) states[++i] = 1
    } else if (char === "\\") {
      states[i] = 1
      if (i + 1 < command.length) states[++i] = 1
    } else if (char === "'" || char === '"') {
      if (char === "'" && command[i - 1] === "$") return undefined
      states[i] = 2
      quote = char
    } else if (char === "`" || (char === "<" && command[i + 1] === "<") || (char === "#" && (i === 0 || /[\s;&|(]/.test(command[i - 1]!)))) return undefined
  }
  return quote ? undefined : states
}

/**
 * Every place `pathTokens` cut this word is a whole shell word: unquoted between blanks or operators, or the whole content
 * of a quoted string. A piece of a longer word (quoted blank, escape, `=`, `,`, `@`) names another file.
 */
function wholeWord(command: string, word: string, states: Uint8Array): boolean {
  const before = (at: number) => at < 0 || (states[at] === 0 && WORD_BEFORE.test(command[at]!))
  const after = (at: number) => at >= command.length || (states[at] === 0 && WORD_AFTER.test(command[at]!))
  const spans = wordSpans(command, word)
  for (const [at, end] of spans) {
    const inside = states.subarray(at, end)
    if (inside.every((state) => state === 0) && before(at - 1) && after(end)) continue
    if (inside.every((state) => state === 1) && states[at - 1] === 2 && states[end] === 3 && before(at - 2) && after(end + 1)) continue
    return false
  }
  return spans.length > 0
}

type Span = readonly [number, number]

/** Every place `pathTokens` cut this word (its edges), as [start, end). */
function wordSpans(command: string, word: string): Span[] {
  const edge = (at: number) => at < 0 || at >= command.length || TOKEN_EDGE.test(command[at]!)
  const spans: Span[] = []
  for (let at = command.indexOf(word); at >= 0; at = command.indexOf(word, at + 1)) if (edge(at - 1) && edge(at + word.length)) spans.push([at, at + word.length])
  return spans
}

/** The command with these spans blanked (what lies outside the target words), in one pass. */
function blanked(command: string, spans: readonly Span[]): string {
  const chars = command.split("")
  for (const [at, end] of spans) chars.fill(" ", at, end)
  return chars.join("")
}

/** Beyond these, the targets are unfinished (linear cost): target words, substitutions, other sub-commands. */
const MAX_TARGET_WORDS = 64
const MAX_SUBSTITUTIONS = 32
const MAX_OTHERS = 64

/**
 * Programs that, whatever their options, modify no file, launch no other program and run no code (GNU coreutils, grep,
 * diffutils `cmp`, util-linux `rev`, shell built-ins `echo`, `pwd`, `true`, `false`): print or compare what they read.
 * The only programs of a command an exception or the memory lifts, the one that names the target included. `sort`
 * (output file, compression program), `uniq` (output operand), `diff` (an option pipes its output through `pr`), `sed`,
 * `awk`, `tee`, `less`, `xxd`, `file`, `date`, `printf` (`-v` assigns), `jq` (runs its filter language) and `cd` (zsh
 * hooks) are left out, as is any other program (a database client, a tool that runs commands).
 */
const READ_ONLY_COMMANDS = new Set([
  ...["cat", "head", "tail", "wc", "grep", "cut", "tr", "nl", "tac", "rev", "fold", "paste", "base64", "od"],
  ...["basename", "dirname", "realpath", "readlink", "pwd", "ls", "stat", "echo", "true", "false", "sleep"],
  ...["sha1sum", "sha256sum", "sha512sum", "md5sum", "cksum", "cmp", "uname", "whoami", "id"],
])

/** Expansion that assigns a variable (`${x:=…}`, `${x=…}`, `$[…]`); arithmetic in parentheses is cut into parts. */
const ASSIGNING_EXPANSION = /\$\{[^}]*=|\$\[/
/** A plain name: unquoted, unescaped, without a path or an expansion. */
const PLAIN_NAME = /^[\w.+-]+$/

/**
 * Parts of the command, each read in `text` (the command with the substitutions already masked): every substitution
 * (`$(…)`, `<(…)`, `>(…)`, innermost first) is a part of its own, seen in its enclosing part as one word that is not a
 * plain name; then cut at unquoted separators (sequence, pipeline, background, line) and parentheses (subshell,
 * arithmetic, nesting the masking does not reach); `>&`, `&>`, `<&` and `>|` are redirections. More than
 * `MAX_SUBSTITUTIONS`: `undefined`.
 */
function commandParts(command: string, states: Uint8Array): Array<{ readonly text: string; readonly span: Span }> | undefined {
  const cut = (text: string, from: number, to: number) => {
    const parts: Span[] = []
    let start = from
    for (let i = from; i < to; i++) {
      const c = text[i]!
      if (states[i] !== 0 || !/[;&|\n()]/.test(c)) continue
      if (c === "&" && (text[i - 1] === ">" || text[i - 1] === "<" || text[i + 1] === ">")) continue
      if (c === "|" && text[i - 1] === ">") continue
      parts.push([start, i])
      start = i + 1
    }
    parts.push([start, to])
    return parts.filter(([at, end]) => text.slice(at, end).trim() !== "").map((span) => ({ text, span }))
  }
  let text = command
  const parts: Array<{ readonly text: string; readonly span: Span }> = []
  for (let masked = true; masked; ) {
    masked = false
    for (let i = 1; i < text.length; i++) {
      if (states[i] !== 0 || states[i - 1] !== 0 || text[i] !== "(" || !/[$<>]/.test(text[i - 1]!)) continue
      let j = i + 1
      while (j < text.length && !(states[j] === 0 && (text[j] === "(" || text[j] === ")"))) j++
      if (text[j] !== ")") continue
      if (parts.length >= MAX_SUBSTITUTIONS) return undefined
      parts.push(...cut(text, i + 1, j))
      text = `${text.slice(0, i - 1)}$${"_".repeat(j - i + 1)}${text.slice(j + 1)}`
      masked = true
    }
  }
  return [...parts, ...cut(text, 0, text.length)]
}

/** Words of a part: cut at unquoted blanks. */
function partWords(command: string, states: Uint8Array, [at, end]: Span): Span[] {
  const words: Span[] = []
  let start = -1
  for (let i = at; i <= end; i++) {
    const blank = i === end || (states[i] === 0 && /\s/.test(command[i]!))
    if (blank && start >= 0) words.push([start, i])
    if (blank) start = -1
    else if (start < 0) start = i
  }
  return words
}

/**
 * A redirection of the part to a file: output, append, read-write (it creates the file), `>&file`; never `/dev/null` nor a
 * duplication of a descriptor (`2>&1`, `>&-`). A `>` before a parenthesis is a process substitution (its own part).
 */
function redirectsToFile(command: string, states: Uint8Array, [at, end]: Span): boolean {
  const unquotedWord = (from: number) => {
    let to = from
    while (to < end && !(states[to] === 0 && /[\s;&|()<>]/.test(command[to]!))) to++
    return { word: command.slice(from, to), plain: states.subarray(from, to).every((state) => state === 0) }
  }
  for (let i = at; i < end; i++) {
    if (states[i] !== 0 || (command[i] !== ">" && !(command[i] === "<" && command[i + 1] === ">"))) continue
    let j = i + (command[i] === "<" ? 2 : command[i + 1] === ">" ? 2 : 1)
    if (command[j] === "|" || command[j] === "!") j++
    const duplicated = command[j] === "&"
    if (duplicated) j++
    while (j < end && states[j] === 0 && /[^\S\n]/.test(command[j]!)) j++
    const { word, plain } = unquotedWord(j)
    if (word === "" && j >= end) continue
    if (!(plain && (word === "/dev/null" || (duplicated && /^(?:\d+|-)$/.test(word))))) return true
    i = j + word.length - 1
  }
  return false
}

/**
 * Every part only reads: the one that names a target as every other one, substitutions included, a program of
 * `READ_ONLY_COMMANDS` named alone (a plain name: neither an assignment, nor a path, nor a structural word), without a
 * redirection to a file (set up before the program reads). Nowhere an expansion that assigns.
 */
function partsOnlyRead(command: string, states: Uint8Array, spans: readonly Span[]): boolean {
  if (ASSIGNING_EXPANSION.test(blanked(command, spans))) return false
  const parts = commandParts(command, states)
  return parts !== undefined && parts.every(({ text, span: part }) => {
    const [first] = partWords(text, states, part)
    if (!first || redirectsToFile(text, states, part)) return false
    const name = text.slice(first[0], first[1])
    const plain = states.subarray(first[0], first[1]).every((state) => state === 0) && PLAIN_NAME.test(name)
    return plain && READ_ONLY_COMMANDS.has(name)
  })
}

/**
 * Another sub-command of the same evaluation only reads (`ShellRuleContext.others`): judged like a part of the command,
 * the words of the same target files set aside as there.
 */
function onlyReading(command: string, files: readonly string[]): boolean {
  const states = quoteStates(command)
  if (!states) return false
  const spans = files.flatMap((file) => (wholeWord(command, file, states) ? wordSpans(command, file) : []))
  return spans.length <= MAX_TARGET_WORDS && partsOnlyRead(command, states, spans)
}

/**
 * Real paths of the files (existing regular files, `realFile`), sorted; `undefined` as soon as one is unknown: not
 * absolute, or with a `..` component (`targetable`), not a whole word, expansion or pattern, a part of the command that
 * does not only read (`partsOnlyRead`, other sub-commands included), more words, substitutions or sub-commands than the
 * plugin examines, missing, or a limit of the resolver.
 */
function credentialTargets(command: string, files: readonly string[], ctx: ShellRuleContext): string[] | undefined {
  const states = quoteStates(command)
  if (!states || !files.every(targetable)) return undefined
  if (!files.every((file) => wholeWord(command, file, states))) return undefined
  const spans = files.flatMap((file) => wordSpans(command, file))
  if (spans.length > MAX_TARGET_WORDS || (ctx.others?.length ?? 0) > MAX_OTHERS) return undefined
  if (!partsOnlyRead(command, states, spans) || ctx.others?.some((other) => !onlyReading(other, files))) return undefined
  const targets = new Set<string>()
  for (const file of files) {
    const absolute = lexicalPath(file, undefined, undefined)
    const real = absolute === undefined ? undefined : realFile(absolute, ctx)
    if (real === undefined) return undefined
    targets.add(real)
  }
  return [...targets].sort()
}

/** Reason of `secret-file-read` naming the files (at most `SHOWN_FILES`, then how many more), and its targets. */
function credentialDetail(reading: CredentialReading): Pick<Finding, "reason" | "targets"> {
  const named = reading.shown.slice(0, SHOWN_FILES).join(", ")
  const more = reading.shown.length > SHOWN_FILES ? ` and ${reading.shown.length - SHOWN_FILES} more` : ""
  return { reason: `access to a credential file (${named}${more})`, ...(reading.targets ? { targets: reading.targets } : {}) }
}

/**
 * Reading shared by two `ASK_RULES` rules evaluated in this order during the same evaluation: the first does it and
 * notes it (`note`), the second rereads it once for the same command and the same context, otherwise redoes it
 * (`reread`). The ask for a check interrupted by a limit thus costs neither an extra call of the budgeted predicates
 * nor a second walk of the command. A rule between them reads the noted value without taking it (`peek`).
 */
function sharedReading<T>(read: (command: string, ctx: ShellRuleContext) => T) {
  let last: { readonly command: string; readonly ctx: ShellRuleContext; readonly value: T } | undefined
  return {
    note(command: string, ctx: ShellRuleContext): T {
      const value = read(command, ctx)
      last = { command, ctx, value }
      return value
    },
    peek(command: string, ctx: ShellRuleContext): T {
      return last?.command === command && last.ctx === ctx ? last.value : read(command, ctx)
    },
    reread(command: string, ctx: ShellRuleContext): T {
      const noted = last
      last = undefined
      return noted?.command === command && noted.ctx === ctx ? noted.value : read(command, ctx)
    },
  }
}

/** Credential files: noted by `secret-file-read`, reread by the ask for content not checked that follows it. */
const CREDENTIAL_TOKENS = sharedReading(credentialTokens)
/** Kinds of the targets: noted by `self-protection` (settings), peeked by `self-protection`, reread by the ask for an unchecked real path. */
const PROTECTED_TARGETS = sharedReading(protectedTargets)
/** awk programs: noted by `awk-dynamic-exec`, reread by the ask for a quoted string not read that follows it. */
const AWK_PROGRAMS = sharedReading(awkDynamicExec)

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

/**
 * Words taken as values by an option of `executor`: one for its value options (`value`); read like the shell
 * (`grouped`), one per `o` or `O` of a group of a shell's short options (`-eo pipefail`, `-oo a b`: bash and dash).
 */
function optionValues(executor: (typeof EXECUTORS)[number], arg: string, grouped: boolean): number {
  if (grouped && executor === EXECUTORS[0] && /^[-+][a-zA-Z]+$/.test(arg)) return arg.replace(/[^oO]/g, "").length
  return executor.value?.test(arg) ? 1 : 0
}

/** A shell's group of short options that takes a value (`-eo pipefail`): its options are also read like the shell. */
const groupedValue = (executor: (typeof EXECUTORS)[number], args: readonly string[]) =>
  executor === EXECUTORS[0] && args.some((arg) => arg.length > 2 && /^[-+][a-zA-Z]*[oO][a-zA-Z]*$/.test(arg))

/** Code passed as an argument that evaluates standard input (explicit evaluation + reading stdin). */
const EVALUATES = /\b(?:exec|eval|compile)\s*\(|\$\(\s*cat\b/
const READS_STDIN = /stdin|readFileSync\(\s*0\b|\$\(\s*cat\b|\/dev\/fd\/0/
const evaluatesStdin = (stage: string) => EVALUATES.test(stage) && READS_STDIN.test(stage)

/**
 * Pipeline stage that executes what it receives: shell without `-c` (or with `-s`/`-`), interpreter without code or script.
 * Read by `commandOf`, then with the redirections set aside (`launchedCommand`, if `readsLaunched`): either reading
 * counts (strict side).
 */
function executesStdin(stage: string, codeRunsStdin: () => boolean): boolean {
  const previous = commandOf(stage)
  return (
    executesInput(previous, codeRunsStdin) ||
    (readsLaunched(stage, previous, readsOperands(previous.name)) && executesInput(launchedCommand(stage), codeRunsStdin))
  )
}

/**
 * `executesStdin` for one reading of the stage. A shell's options are also read like the shell (`groupedValue`,
 * `grouped`): either reading counts (strict side). `grouped` given: that reading only, as written (false) or like the
 * shell (true).
 */
function executesInput({ name, args }: { name: string; args: readonly string[] }, codeRunsStdin: () => boolean, grouped?: boolean): boolean {
  const executor = EXECUTORS.find((candidate) => candidate.name.test(name))
  if (!executor) return false
  if (grouped === undefined)
    return executesInput({ name, args }, codeRunsStdin, false) || (groupedValue(executor, args) && executesInput({ name, args }, codeRunsStdin, true))
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
      i += optionValues(executor, arg, grouped)
      continue
    }
    // Script file (or arguments of `bash -s`).
    return stdin
  }
  return stdin || bare
}

/**
 * Stage that downloads: downloader launched (read by `commandOf`, or with the redirections set aside if `readsLaunched`),
 * or `curl`/`wget` cited in the stage (`$(curl …`, `bash -c "curl …`).
 */
function downloads(stage: string): boolean {
  const previous = commandOf(stage)
  return (
    DOWNLOADERS.has(previous.name) ||
    (readsLaunched(stage, previous, false) && DOWNLOADERS.has(launchedCommand(stage).name)) ||
    /(?<![\w.-])(?:curl|wget)(?![\w.-])/.test(stage)
  )
}

/**
 * Pipe (not `>|`) followed by blanks, a newline and the empty lines that follow: the shell continues the pipeline on
 * the next line (the stage before was only blanks). Each blank is examined only once (linear cost).
 */
const PIPE_LINE_BREAK = /(?<!>)(\|&?)[^\S\n]*\n\s*/g
/**
 * Second reading: the same, a comment after the pipe and the comment lines that follow skipped too (quotes not
 * followed: added to the first reading, never in its place). Matches at each pipe, the replacement keeps it without a
 * newline: each character is examined only once (linear cost).
 */
const PIPE_COMMENT_BREAK = /(?<!>)(\|&?)[^\S\n]*(?:#[^\n]*)?(?:\n[^\S\n]*(?:#[^\n]*)?)*/g
const pipeCommentBreak = (match: string, pipe: string) => (match.includes("\n") ? `${pipe} ` : match)

/**
 * Executed download: in the same pipeline (separators `;`, `&&`, `||`, `&`, newline except after a pipe), a stage
 * that downloads followed by a stage that executes its input (`curl … | tee f | sudo -E sh`).
 * `curl … | python3 -m json.tool` or `| node -e "…"` only read data. Pipelines read with `PIPE_LINE_BREAK`, then, with
 * a `#`, with `PIPE_COMMENT_BREAK` (the same text without a comment): either reading counts.
 */
function pipesDownloadToShell(command: string): boolean {
  // Computed once per command (linear cost even with thousands of `sh -c` stages).
  let memo: boolean | undefined
  const codeRunsStdin = () => (memo ??= evaluatesStdin(command))
  const executed = (text: string) => {
    for (const pipeline of text.split(/\|\||&&|;|\n|(?<![|>&])&(?![>&])/)) {
      const stages = pipeline.split(/(?<!>)\|&?/)
      if (stages.length < 2) continue
      const first = stages.findIndex(downloads)
      if (first >= 0 && stages.slice(first + 1).some((stage) => executesStdin(stage, codeRunsStdin))) return true
    }
    return false
  }
  const joined = command.replace(PIPE_LINE_BREAK, "$1 ")
  if (executed(joined)) return true
  // Without a `#`, the second reading is the first one.
  const skipped = command.includes("#") ? command.replace(PIPE_COMMENT_BREAK, pipeCommentBreak) : joined
  return skipped !== joined && executed(skipped)
}

const PROCESS_SUBSTITUTION_EXEC = new RegExp(
  `(?:sh|bash|zsh|dash|ksh|source|\\.|python[0-9.]*|perl(?:5[\\w.-]*)?|ruby[\\d.]*|php[\\d.]*|node|bun(?:\\s+run)?|deno\\s+run(?:\\s+-\\S+)*)\\s+<\\(\\s*${DOWNLOADER}`,
)
const COMMAND_SUBSTITUTION_EXEC = new RegExp(`(?:sh|bash|zsh|dash|ksh)\\s+-[a-zA-Z]*c\\s+["']?(?:\\$\\(|\`)\\s*${DOWNLOADER}`)

/** Signature formatting and wiping launched by common recognition (same names as the `mkfs` rule). */
const FORMAT_TOOLS = "mkfs(?:\\.[a-z0-9]+)?|wipefs"
const FORMAT_COMMAND = commandRegex(FORMAT_TOOLS)

/**
 * `dd` launched by common recognition, call tail up to the separator included. `of=` to a device
 * is searched in the whole match: the tail, where any following call of the same segment is found (matches
 * do not overlap), but also the wrapper and the words it skips, where a call placed in a
 * substitution has no match of its own. An `of=` to a device among those skipped words therefore also counts
 * (a rare extra deny). Each character is examined only once (linear cost).
 */
const DD_CALL = new RegExp(commandRegex("dd", "\\s[^;&|]*").source, "g")
const DD_DEVICE_OUTPUT = new RegExp(`\\bof=["']?${DEVICE}`)
const ddCommandToDevice = (command: string) => [...command.matchAll(DD_CALL)].some((match) => DD_DEVICE_OUTPUT.test(match[0]))

/**
 * Recognition added to the `mkfs` and `dd-device` rules (path `/usr/sbin/mkfs.ext4`, `/bin/dd`, `\mkfs`, wrappers,
 * `sh -c "…"` text, `find -exec`), evaluated after all rules (`addedShellFinding`): an existing finding at
 * least as strong keeps its identifier. Tests without context.
 */
const ADDED_DENY_RULES: ReadonlyArray<Omit<RegexRule, "test"> & { readonly test: (command: string) => boolean }> = [
  { id: "mkfs", verdict: "deny", reason: "disk formatting", test: (command) => FORMAT_COMMAND.test(command) },
  { id: "dd-device", verdict: "deny", reason: "raw write to a device", test: ddCommandToDevice },
]

/**
 * First rule of the added recognition, active according to the switches (all without them), that recognizes the text,
 * without fallback to data: read by `addedShellFinding` and by the device layer, alone in cost tests.
 */
export const addedRecognition = (text: string, active?: ActiveRules) => ADDED_DENY_RULES.find((rule) => ruleEnabled(rule.id, active) && rule.test(text))

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
      replacement = token.slice(2)
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

/** One reading of `xargsDynamic`. `alone`: `xargs` without a child counts. */
function xargsWordsDynamic(args: readonly string[], alone: boolean): boolean {
  const { start, replacement, help } = xargsInfo(args)
  if (help) return false
  const child = args.slice(start)
  if (child.length === 0) return alone
  if (replacement !== null) return launcherTemplateExecutes(child, (token) => token.includes(replacement))
  const kind = childKind(child[0]!)
  return kind !== "rm" && kind !== "other" && launcherStreamExecutes(child, kind)
}

/**
 * Dynamic execution through the batch wrapper: `xargs` alone (no child, no redirection either), executable name
 * with a template, or executable source that the input can change. Two readings whose asks add up: the words as written,
 * and without the redirections (`xargs >x sh`, as `xargs sh`), where no child does not count: without one, `xargs` runs
 * `echo`, so `ls | xargs 2>/dev/null` does not ask. One pass per segment.
 */
function xargsDynamic(command: string): boolean {
  const launches = (segment: string) => bareHead(commandOf(segment).name) === "xargs"
  for (const segment of segments(command)) if (launches(segment) && xargsWordsDynamic(commandOf(segment).args, true)) return true
  for (const segment of launcherSegments(command)) if (launches(segment) && xargsWordsDynamic(commandOf(withoutWrittenRedirections(segment)).args, false)) return true
  return false
}

/** One reading of `parallelDynamic`. */
function parallelWordsDynamic(segment: string, args: readonly string[]): boolean {
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
  if (info.safe) return false
  if (info.template.length === 0) {
    // Empty template: the values (or the input) are the executed commands.
    if (info.readsCommands) return true
    if (info.hasMarker) {
      // Argument file (`::::`): invisible commands.
      if (info.markerToken === "::::" || info.markerToken === "::::+") return true
      const values = args.slice(info.markerIndex + 1).filter((value) => !PARALLEL_MARKER.test(value))
      if (values.some((value) => startsWithVariable(value) || isNonLiteralSource(value))) return true
    }
    return false
  }
  if (info.hasPlaceholder) {
    // `launcherTemplateExecutes` first spots the template in executable position, then rules out rm/other.
    if (launcherTemplateExecutes(info.template, hasParallelPlaceholder)) return true
  } else {
    // Without a `{}` template, the input (marker or pipe) is added as an argument.
    const kind = childKind(info.template[0]!)
    if (kind === "rm" || kind === "other") return false
    if (launcherStreamExecutes(info.template, kind)) return true
  }
  return false
}

/**
 * Dynamic execution through the parallel wrapper: executable expression or redefined marker (ask
 * by default), commands read from the input, marker values becoming commands, template in the executable
 * source, or added input that can become the source. Two readings whose asks add up: the words as written, and without
 * the redirections (`parallel -a f sh >x`, as `parallel -a f sh`). One pass per segment.
 */
function parallelDynamic(command: string): boolean {
  const launches = (segment: string) => bareHead(commandOf(segment).name) === "parallel"
  for (const segment of segments(command)) if (launches(segment) && parallelWordsDynamic(segment, commandOf(segment).args)) return true
  for (const segment of launcherSegments(command)) if (launches(segment) && parallelWordsDynamic(segment, commandOf(withoutWrittenRedirections(segment)).args)) return true
  return false
}

/**
 * Parsing of an interpreter through the `EXECUTORS` table: code option (`-c`, `-e`…) and its text, script
 * operand, reading the program from the input (`-`, stdin path, `-s`), and help/version (options of the program
 * itself, before its operand). Redirections and value options skipped (`optionValues`; `grouped`: a shell's options
 * read like the shell, the code after the values of its group). One pass.
 */
function parseExecutor(
  executor: (typeof EXECUTORS)[number],
  args: readonly string[],
  grouped = false,
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
      const values = optionValues(executor, arg, grouped)
      if (executor.code.test(arg)) return { code: args[i + 1 + values], script: undefined, readsStdin: false, help: false }
      if (executor.stdin?.test(arg)) return { code: undefined, script: undefined, readsStdin: true, help: false }
      i += values
      continue
    }
    return { code: undefined, script: arg, readsStdin: false, help: false }
  }
  return { code: undefined, script: undefined, readsStdin: false, help: false }
}

/**
 * Operands of input redirections from a file (`< f`, `0<f`; `readWrite`: also `<> f`, `0<>f`, input opened for reading
 * and writing) or a here-string (`<<< v`, `string` true), in order; not a heredoc (`<<`). A single pass.
 */
function stdinRedirects(args: readonly string[], readWrite = false): Array<{ operand: string; string: boolean }> {
  const found: Array<{ operand: string; string: boolean }> = []
  const attached = readWrite ? /^(0?<<<|0?<>?)(?![<>])(.+)$/ : /^(0?<<<|0?<)(?!<)(.+)$/
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!
    if (arg === "<" || arg === "0<" || arg === "<<<" || (readWrite && (arg === "<>" || arg === "0<>"))) {
      const operand = args[i + 1]
      if (operand !== undefined) found.push({ operand: unquote(operand), string: arg === "<<<" })
      i++
      continue
    }
    const match = attached.exec(arg)
    if (match) found.push({ operand: unquote(match[2]!), string: match[1]!.endsWith("<<<") })
  }
  return found
}

/**
 * Shell or interpreter launched on a file or text designated by a variable (content not visible at
 * decision time). The program's help/version options invalidate the ask only if they
 * precede its operand. Each segment read by `commandOf` (first input redirection), then with the redirections set
 * aside (`launchedCommand`, if `readsLaunched`; input read like the shell: the last redirection, read-write included):
 * either reading counts (strict side). One pass per segment.
 */
function variableShellSource(command: string): boolean {
  return segments(command).some((segment) => {
    const previous = commandOf(segment)
    const found = variableSource(previous, () => stdinRedirects(previous.args)[0]?.operand)
    if (found) return true
    if (!readsLaunched(segment, previous, found === false)) return false
    const launched = launchedCommand(segment)
    return variableSource(launched, () => stdinRedirects(launched.redirects, true).at(-1)?.operand) === true
  })
}

/**
 * `variableShellSource` for one reading of a segment; `input`: operand of the input redirection read by the program
 * (looked up only without code or script). Undefined: neither an inclusion nor a program of `EXECUTORS` (nothing read).
 * A shell's options are also read like the shell (`groupedValue`, `grouped`): either reading counts (strict side).
 */
function variableSource(
  { name, args }: { name: string; args: readonly string[] },
  input: () => string | undefined,
  grouped = false,
): boolean | undefined {
  const rawHead = bareHead(name)
  // Inclusion (`source f`, `. f`): operand looked up in PATH without `/`, content not visible if it is a variable/glob.
  if (rawHead === "source" || name === ".") {
    const op = args[0]
    return op !== undefined && op !== "--help" && op !== "--version" && literalPath(op) === undefined && (startsWithVariable(op) || isNonLiteralSource(op))
  }
  const executor = EXECUTORS.find((candidate) => candidate.name.test(name))
  if (!executor) return undefined
  if (!grouped && groupedValue(executor, args) && variableSource({ name, args }, input, true)) return true
  const parsed = parseExecutor(executor, args, grouped)
  if (parsed.help) return false
  if (parsed.code !== undefined && startsWithVariable(parsed.code)) return true
  if (parsed.script !== undefined && literalPath(parsed.script) === undefined) {
    if (startsWithVariable(parsed.script)) return true
    // Node test runner mode (`node --test <glob>`): operand globs designate test
    // files, not a variable source; a variable always triggers (handled just above).
    const nodeTest = (rawHead === "node" || rawHead === "nodejs") && args.some((arg) => arg === "--test" || arg.startsWith("--test-"))
    if (!nodeTest && isNonLiteralSource(parsed.script)) return true
  }
  // Program read from input redirected from a file/string designated by a variable (without code or script).
  if (parsed.code !== undefined || parsed.script !== undefined) return false
  const redirected = input()
  return redirected !== undefined && literalPath(redirected) === undefined && startsWithVariable(redirected)
}

/** Marks of a value read only in part, which leave it neither empty nor a plain program: added to by `+=`, or cut in a quote. */
const APPENDED_VALUE = "\0"
const CUT_VALUE = "\x01"

/**
 * Environment assignments at the start of a segment (wrappers `env`, `sudo`… included, like `commandOf`, a subshell's
 * parenthesis set aside on each word), then the launched command and its arguments. `+=` adds to a value it cannot know
 * (`APPENDED_VALUE`) and keeps what was read before it. One pass.
 */
function envAssignments(segment: string): { assigns: Map<string, string>; name: string; args: string[] } {
  const tokens = segment.split(/\s+/).filter(Boolean).map(unquote)
  const assigns = new Map<string, string>()
  let i = 0
  let wrapper: string | undefined
  while (i < tokens.length) {
    attachedSplitString(tokens, i, wrapper)
    const token = tokens[i]!.replace(/^\(+/, "")
    if (token === "") {
      i++
      continue
    }
    const assignment = /^([A-Za-z_][A-Za-z0-9_]*)(\+?)=([\s\S]*)$/.exec(token)
    if (assignment) {
      const [, variable, adds, value] = assignment as unknown as [string, string, string, string]
      assigns.set(variable, adds ? `${APPENDED_VALUE}${assigns.get(variable) ?? ""}${value}` : value)
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
 * Interactivity and POSIX mode as the shell reads them among its options, up to its operand, `--` or a lone dash: `-` and
 * `+` options, alone or grouped (the last one wins), value options with their value (`-o`, `-O`, grouped included,
 * `--rcfile`, `--init-file`), `-o posix`, `--posix`. One pass.
 */
function shellModes(args: readonly string[]): { interactive: boolean; posix: boolean } {
  let [interactive, posix] = [false, false]
  for (let k = 0; k < args.length; k++) {
    const arg = args[k]!
    if (arg === "--" || !/^[-+]./.test(arg)) break
    if (arg.startsWith("--")) {
      if (arg === "--posix") posix = true
      else if (arg === "--rcfile" || arg === "--init-file") k++
      continue
    }
    for (const letter of arg.slice(1)) {
      if (letter === "i") interactive = arg[0] === "-"
      else if (letter === "o" || letter === "O") {
        const value = args[++k]
        if (letter === "o" && value === "posix") posix = arg[0] === "-"
      }
    }
  }
  return { interactive, posix }
}

/**
 * Previous reading of interactivity, kept (strict side): `-i` among the shell's options before its operand, `+i`
 * excluded. `+` option: skipped for sh, dash and ksh (the read continues); for bash, the read stops.
 */
function previousInteractive({ name, args }: { name: string; args: readonly string[] }): boolean {
  const bash = baseHead(bareHead(name)) === "bash"
  let interactive = false
  for (const arg of args) {
    if (arg === "--") break
    if (arg.startsWith("+")) {
      if (bash) break
      continue
    }
    if (!arg.startsWith("-")) break
    if (/^-[a-zA-Z]*i/.test(arg)) interactive = true
  }
  return interactive
}

/** Shells whose startup file `startupFileAsk` knows. */
const STARTUP_SHELLS = new Set(["bash", "sh", "dash", "ksh", "zsh"])

/**
 * Startup file of one reading of a segment (launched shell, assignments, options), interactivity and POSIX mode given:
 * bash reads `BASH_ENV` when not interactive outside POSIX mode, `ENV` when interactive in POSIX mode, and its option
 * file (`--rcfile`, `--init-file`: missing or non-literal value); sh, dash and ksh read `ENV` when interactive; zsh
 * `ZDOTDIR`.
 */
function startupFileAsk({ assigns, name, args }: ReturnType<typeof envAssignments>, interactive: boolean, posix: boolean): boolean {
  const head = baseHead(bareHead(name))
  const set = (variable: string) => (assigns.get(variable) ?? "") !== ""
  if (head === "bash") {
    for (let k = 0; k < args.length && args[k] !== "--"; k++) {
      if (args[k] !== "--rcfile" && args[k] !== "--init-file") continue
      const value = args[k + 1]
      if (value === undefined || value === "--" || isNonLiteralSource(value)) return true
    }
    return interactive ? posix && set("ENV") : !posix && set("BASH_ENV")
  }
  if (head === "sh" || head === "dash" || head === "ksh") return interactive && set("ENV")
  return head === "zsh" && set("ZDOTDIR")
}

/**
 * Startup file designated by the environment (`BASH_ENV`, `ENV`, `ZDOTDIR`, wrappers included) or by
 * an option (`--rcfile`, `--init-file`: missing or non-literal value). Interactivity is read only
 * among the shell's options, before its operand. Two readings whose asks add up: the previous one, kept (strict side,
 * outside POSIX mode), and the shell's, redirections set aside (`tailWords`, if `readsLaunched`), options read by
 * `shellModes`, POSIX mode also given by the environment (`POSIXLY_CORRECT`, `SHELLOPTS`). Read only for a shell whose
 * startup file is known. One pass per segment.
 */
function shellStartupFile(command: string): boolean {
  for (const segment of segments(command)) {
    const previous = envAssignments(segment)
    const rawHead = bareHead(previous.name)
    const startup = STARTUP_SHELLS.has(baseHead(rawHead))
    const shell = readsLaunched(segment, previous, startup) ? envAssignments(tailWords(segment).join(" ")) : previous
    if (startup || (shell !== previous && STARTUP_SHELLS.has(baseHead(bareHead(shell.name))))) {
      const modes = shellModes(shell.args)
      const stated = modes.posix || shell.assigns.has("POSIXLY_CORRECT")
      const options = shell.assigns.get("SHELLOPTS") ?? ""
      const named = /(?:^|:)posix(?::|$)/.test(options.replace(/^\0+/, ""))
      // An append to a value it cannot know leaves the mode open: either reading that asks counts.
      if (named && options.startsWith(APPENDED_VALUE) && startupFileAsk(shell, modes.interactive, stated)) return true
      if (startupFileAsk(previous, previousInteractive(previous), false) || startupFileAsk(shell, modes.interactive, stated || named)) return true
    }
    // Isolated export/declare/typeset: designates the startup of subsequent shells.
    if (rawHead === "export" || rawHead === "declare" || rawHead === "typeset") {
      if (/\bBASH_ENV\+?=/.test(segment) || /(?:^|\s)ENV\+?=/.test(segment) || /\bZDOTDIR\+?=/.test(segment)) return true
    }
  }
  return false
}

/** Variables that have the dynamic loader or a runtime load code, whatever their value. */
const CODE_LOADING_ENV = new Set([
  "LD_PRELOAD",
  "LD_AUDIT",
  "LD_LIBRARY_PATH",
  "DYLD_INSERT_LIBRARIES",
  "NODE_OPTIONS",
  "NODE_PATH",
  "PERL5OPT",
  "PERL5LIB",
  "RUBYOPT",
  "RUBYLIB",
  "PYTHONSTARTUP",
  "PYTHONPATH",
  "PYTHONHOME",
])
/** Variables that name a program another one launches; the values of `PLAIN_PROGRAMS` choose nothing to check. */
const PROGRAM_ENV = new Set(["EDITOR", "VISUAL", "PAGER", "BROWSER"])
const PLAIN_PROGRAMS = new Set(["", "cat", "true", ":", "less", "more", "vi", "vim", "nano"])
const EXPORTING_WORDS = new Set(["export", "declare", "typeset"])

const CODE_LOADING_REASON = "environment variable makes the program load or run other code"

/** An empty value loads nothing; a marked value (`APPENDED_VALUE`, `CUT_VALUE`) is not whole, so neither empty nor plain. */
function loadsCode(variable: string, value: string): boolean {
  const plain = unquote(value)
  return CODE_LOADING_ENV.has(variable) ? plain !== "" : PROGRAM_ENV.has(variable) && !PLAIN_PROGRAMS.has(plain)
}

/** The command with its quoted blanks and separators replaced, so that quoted text starts no word or segment; unchanged where `quoteStates` does not hold. */
function quotedAsOneWord(command: string): string {
  const states = quoteStates(command)
  return states ? command.replace(/[\s;&|]/g, (char, i: number) => (states[i] ? "_" : char)) : command
}

/** Quote still open at the end of this word, from the one open at its start. */
function quoteAfter(word: string, open = ""): string {
  let quote = open
  for (let i = 0; i < word.length; i++) {
    const char = word[i]!
    if (char === "\\" && quote !== "'") i++
    else if (quote) quote = char === quote ? "" : quote
    else if (char === "'" || char === '"') quote = char
  }
  return quote
}

/** Marks a word that assigns and ends inside a quote: what follows it is not read. */
function markedCut(word: string): string {
  return word.includes("=") && quoteAfter(word) !== "" ? word + CUT_VALUE : word
}

/** A word that assigns a `loadsCode` variable. */
function assignsCodeLoading(word: string): boolean {
  const variable = /^\(*([A-Za-z_][A-Za-z0-9_]*)\+?=/.exec(word)?.[1] ?? ""
  return CODE_LOADING_ENV.has(variable) || PROGRAM_ENV.has(variable)
}

/**
 * The segment with each value that blanks cut in a quote put back as one word, as `quotedAsOneWord` would, so that the
 * assignments behind it stay read. A quote not closed in the segment, or one that would swallow such an assignment (this
 * reading of the quotes may be wrong there: `$'it\'s'`): the words from there on are only marked. Each word is read at
 * most twice, so one pass.
 */
function valuesKeptWhole(segment: string): string {
  const words = segment.split(/\s+/)
  const kept: string[] = []
  for (let i = 0; i < words.length; ) {
    let end = i + 1
    let quote = words[i]!.includes("=") ? quoteAfter(words[i]!) : ""
    while (quote !== "" && end < words.length) quote = quoteAfter(words[end++]!, quote)
    if (quote !== "" || words.slice(i + 1, end).some(assignsCodeLoading)) return [...kept, ...words.slice(i).map(markedCut)].join(" ")
    kept.push(words.slice(i, end).join("_"))
    i = end
  }
  return kept.join(" ")
}

/**
 * Assignment of a `loadsCode` variable for the launched program: in front of it (launchers and redirections included, as
 * read by `envAssignments`), or in an `export`, `declare` or `typeset` for the programs to come. Where `quotedAsOneWord`
 * could not keep a value whole, `valuesKeptWhole` does, or marks the piece read. A segment that launches nothing assigns a
 * shell variable only, unless its value was cut there: the rest may reach a program. One pass per segment.
 */
function codeLoadingEnv(command: string): boolean {
  for (const text of segments(quotedAsOneWord(command))) {
    const segment = valuesKeptWhole(text)
    const previous = envAssignments(segment)
    const { assigns, name, args } = readsLaunched(segment, previous, false) ? envAssignments(tailWords(segment).join(" ")) : previous
    const exporting = EXPORTING_WORDS.has(bareHead(name))
    const chosen = exporting ? args.flatMap((arg) => [...envAssignments(arg).assigns]) : name === "" ? [...assigns].filter(([, value]) => value.endsWith(CUT_VALUE)) : assigns
    for (const [variable, value] of chosen) if (loadsCode(variable, value)) return true
  }
  return false
}

/**
 * Text-processing program with execution of non-literal text (`system`, output pipe, pipe
 * to `getline`). Linear analysis with string and comment tracking. Programs with spaces or
 * pipes are quoted: split outside quotes. `LIMIT_REACHED`: quoted string too long to read (`quotedStrings`).
 */
function awkDynamicExec(command: string): boolean | typeof LIMIT_REACHED {
  for (const segment of awkSegments(command)) {
    const { name, args } = commandOf(segment)
    const head = bareHead(name)
    if (!DYNAMIC_AWKS.has(head)) {
      // Child of a wrapper: checked by the wrapper rules, except a direct program with a dynamic
      // system call visible in the raw segment.
      if (bareHead(name) !== "xargs" && bareHead(name) !== "parallel") continue
      if (!/\b(?:awk|gawk|nawk|mawk)\b/.test(segment)) continue
      const strings = quotedStrings(segment)
      if (strings === undefined) return LIMIT_REACHED
      for (const quoted of strings) {
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
    if (quoted === undefined) return LIMIT_REACHED
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

/** Longest quoted string read in an awk segment (`quotedStrings`). */
const AWK_STRING_LIMIT = 65536

/**
 * Quoted strings of a segment (single and double quotes, with escapes). String longer than 64 KiB
 * (`AWK_STRING_LIMIT`): `undefined`, incomplete read that the caller asks for (`LIMIT_REACHED`).
 */
function quotedStrings(segment: string): string[] | undefined {
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
      if (value.length > AWK_STRING_LIMIT) return undefined
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

/** Length beyond which inline code is not examined: an ask replaces it (64 KiB). */
const INLINE_CODE_LIMIT = 65536

const DANGEROUS_CODE_REASON = "interpreter code launching a dangerous command"

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
    if (code.length === 0 || code.length > INLINE_CODE_LIMIT) continue
    if (codeLaunchesDangerous(code)) return true
  }
  return false
}

/** One piece of code with an execution sink that cites an already-condemned command (`interpreterDangerousCode`). */
function codeLaunchesDangerous(code: string): boolean {
  return codeHasDangerSink(code) && citesDangerousCommand(code)
}

/** Execution sink (system call, evaluation, process creation); prefixes (`exec*`, `spawn*`) included. */
function codeHasDangerSink(code: string): boolean {
  return (
    /\b(?:system|popen|subprocess|child_process|open3|eval|fork|qx|shell_exec|passthru|proc_open|pcntl_exec|spawn\w*|exec\w*)\b/.test(code.toLowerCase()) ||
    code.includes("`") ||
    /%x/.test(code)
  )
}

function citesDangerousCommand(code: string): boolean {
  if (codeHasRecursiveRm(code)) return true
  if (/(?:^|[\s;&|(`'"])dd\b[^;|&]{0,200}?\bof=\/dev\//i.test(code)) return true
  if (/\bmkfs\b/i.test(code) || /\bshred\b/i.test(code)) return true
  if (/(?:^|[\s;&|(`'"])find\b[^;&|]{0,200}?(?:-delete\b|-exec\s+rm\b)/i.test(code)) return true
  if (gitClean(code) || gitResetHard(code) || gitPushForceOption(code) || pushForcesRefs(code) || gitDiscardAll(code) || GIT_STASH_OR_FILTER.test(code)) return true
  return pipesDownloadToShell(code)
}

/** String literal of inline code: single, double or backtick quotes, with escapes. */
const CODE_LITERAL = /'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)"|`((?:[^`\\]|\\.)*)`/g

/**
 * Quotes of `code` that open a `CODE_LITERAL` literal (it is closed), in one pass from the end per quote: the body of a
 * literal, from a position, reaches its closing quote or not whatever comes before (an escape takes any character but a
 * line terminator, as `.`; a line break ends a single or double quoted literal).
 */
function closingQuotes(code: string): Uint8Array {
  const closes = new Uint8Array(code.length)
  for (const quote of ["'", '"', "`"]) {
    const reaches = new Uint8Array(code.length + 2)
    for (let i = code.length - 1; i >= 0; i--) {
      const char = code[i]!
      if (char === quote) closes[i] = reaches[i + 1]!
      reaches[i] =
        char === quote ? 1
        : char === "\\" ? (i + 1 < code.length && !"\n\r  ".includes(code[i + 1]!) ? reaches[i + 2]! : 0)
        : char === "\n" && quote !== "`" ? 0
        : reaches[i + 1]!
    }
  }
  return closes
}

const STICKY = new Map<RegExp, RegExp>()

/**
 * Matches of a global `pattern` of inline code whose alternatives start with a quote, `#` or `/` (`CODE_LITERAL`, alone or
 * with comments and triple quotes), the same as `matchAll` gives, in linear time: a quote that opens no literal is passed
 * without an attempt (nothing matches there: no closed literal, and no triple quote, whose first two quotes would close
 * one), where each attempt would scan up to the end of the literal (quadratic cost with many unclosed quotes).
 */
function codeMatches(code: string, pattern: RegExp): RegExpExecArray[] {
  const closes = closingQuotes(code)
  let sticky = STICKY.get(pattern)
  if (!sticky) STICKY.set(pattern, (sticky = new RegExp(pattern.source, "y")))
  const found: RegExpExecArray[] = []
  for (let i = 0; i < code.length; ) {
    const char = code[i]!
    sticky.lastIndex = i
    const match = "#/".includes(char) || ("'\"`".includes(char) && closes[i]) ? sticky.exec(code) : null
    if (match) found.push(match)
    // Every alternative matches at least one character.
    i += match ? match[0].length : 1
  }
  return found
}

/** `code` with the matches of `codeMatches` that `blank` selects blanked, line breaks and positions kept. */
function blankedCode(code: string, pattern: RegExp, blank: (match: RegExpExecArray) => boolean = () => true): string {
  let blanked = ""
  let end = 0
  for (const match of codeMatches(code, pattern)) {
    if (!blank(match)) continue
    blanked += code.slice(end, match.index) + match[0].replace(/[^\n]/g, " ")
    end = match.index + match[0].length
  }
  return blanked + code.slice(end)
}
/** A literal that may launch the plugin's command line or another OpenCode. */
const NAMES_LAUNCH = /\b(?:guard|opencode)\b/
/** A call that writes the path it is given (Python, Node, Bun, Ruby, Perl, PHP), just before its opening parenthesis. */
const WRITE_CALL =
  /(?:\b(?:write\w*|append\w*|createWriteStream|copy\w*|cp(?:Sync)?|rename\w*|move\w*|unlink\w*|remove|rm(?:Sync|tree|dir\w*)?|symlink\w*|link(?:Sync)?|truncate\w*|file_put_contents|touch|mkdir\w*|makedirs|chmod\w*|install)|\bos\.replace)\s*$/
/** Between that parenthesis and the literal: nothing, or one argument without parentheses (destination of a copy, move or link). */
const FIRST_ARGUMENTS = /^\s*(?:[^()\n;]*,\s*)?$/
/** An open call just before a literal path, then its write mode after it (`open(p, 'w')`, `fopen(p, "a+")`, `{ flag: 'w' }`). */
const OPEN_BEFORE = /\b(?:open\w*|fopen)\s*\(\s*$/
const WRITE_MODE_AFTER = /^\s*,\s*(?:\{\s*)?(?:(?:mode|flags?)\s*[=:]\s*)?['"`][rbt]*[wax+][rwxabt+]*['"`]/
/** Perl: an `open` with a write mode as a separate literal, just before a literal path (`open(my $f, ">", "x")`, `open F, "+<", "x"`). */
const PERL_OPEN_BEFORE = /\bopen\s*\(?\s*[^,;()]*,\s*["'](?:\+<|\+?>>?)(?::[^"']*)?["']\s*,\s*$/
/** Perl: `sysopen` just before a literal path, then flags that are not a plain read-only open. */
const SYSOPEN_BEFORE = /\bsysopen\s*\(?\s*[^,;()]*,\s*$/
const SYSOPEN_WRITE_AFTER = /^\s*,(?!\s*(?:0|O_RDONLY)\s*[,);])/
/** A path object of the literal, then a method that writes it (`Path(p).write_text(…)`). */
const PATH_BEFORE = /\bPath\s*\(\s*$/
const PATH_WRITE_AFTER = /^\s*\)\s*\.\s*(?:write_\w+|touch|unlink|rename|replace|symlink_to|hardlink_to|mkdir|rmdir|chmod|open\s*\(\s*(?:mode\s*=\s*)?['"][rbt]*[wax+])/
/** A literal that may be a path to a protected location: a slash, or a JSON name (`guard.json`, `service.json`…); or `isStartupName`. */
const PATH_CANDIDATE = /^[^\s;&|<>()'"`]*(?:\/[^\s;&|<>()'"`]*|\.jsonc?)$/
const pathCandidate = (literal: string) => PATH_CANDIDATE.test(literal) || isStartupName(literal)
/** A word that may be an awk program's name. */
const AWK_WORD = /\b[gnm]?awk\b/
/** Output of an awk program to a literal file (`print "x" > "f"`, `>> "f"`, `> ("f")`); its quotes are escaped in a double-quoted program. */
const AWK_OUTPUT = />>?\s*(?:\(\s*)?\\?"([^"\\\n]*)\\?"/g

/** Literal files the awk programs of a text write to. */
function awkOutputs(text: string): string[] {
  const outputs: string[] = []
  for (const segment of awkSegments(text)) {
    if (!DYNAMIC_AWKS.has(bareHead(commandOf(segment).name))) continue
    for (const program of quotedStrings(segment) ?? []) for (const match of program.matchAll(AWK_OUTPUT)) outputs.push(match[1]!)
  }
  return outputs
}

/** A method of a value that takes content (`f.write(…)`, `sys.path.append(…)`, `w.writerow(…)`). */
const CONTENT_METHOD = /(?:\.|->)\s*(?:write(?:_text|_bytes|lines|rows?)?|append)\s*$/
/** The `write` of a file API, whose first argument is a path. */
const FILE_API_WRITE = /\b(?:File|IO|Bun)\s*\.\s*write\s*$/
/** A call whose first argument is the file written and the others its content. */
const WRITES_FIRST = /\b(?:write\w*|append\w*|file_put_contents)\s*$/
/** A call whose first argument is the source when a second one follows (`Path.copy` takes the destination alone). */
const COPIES_FIRST = /\b(?:copy\w*|cp(?:Sync)?|install)\s*$/
const SECOND_POSITIONAL = /^\s*,(?!\s*(?:\w+\s*=[^=]|\*|[)\]]))/

/** A literal of a call of `WRITE_CALL` that the call does not write: content, or the source of a copy. */
function notWritten(callee: string, between: string, after: string): boolean {
  if (CONTENT_METHOD.test(callee) && !FILE_API_WRITE.test(callee)) return true
  const first = between.trim() === ""
  return WRITES_FIRST.test(callee) ? !first : first && COPIES_FIRST.test(callee) && SECOND_POSITIONAL.test(after)
}

/**
 * Equivalent shell form of what inline interpreter code launches or writes, for the rules that protect the plugin's
 * settings and the protected locations (`guard-cli`, `nested-opencode`, `self-protection`, `opencode-service`, `opencode-server-api`,
 * `protected-write`): with an execution sink, each literal (or list of literals separated by commas, one command) that
 * names `guard` or `opencode`, as a command; a redirection to each literal path of a protected location that a call
 * writes (argument of a write, copy, move or removal call, opened for writing, Perl's `>` target, its `open` with a
 * separate mode, `sysopen`) or an awk program sends its output to, never one only read. The `system` class leaves out what
 * `notWritten` tells apart: a text that names `/etc` is frequent, a text that names the plugin's settings is not. A path
 * past the limit on links counts, as for the command. Literal paths only (a path built by the code or known once the
 * shell runs is not followed); `undefined` without either. Judged in addition to the command, for those rules only
 * (`CODE_VIEW_RULES`).
 */
function interpreterCodeView(command: string, ctx: ShellRuleContext): string | undefined {
  const awk = AWK_WORD.test(command)
  if (!awk && !HAS_INTERPRETER_CODE.test(command)) return undefined
  const text = reentersShell(withoutData(command)) ? command : withoutHeredocBodies(command)
  const lines: string[] = []
  for (const match of text.matchAll(INTERPRETER_DANGEROUS_CODE)) {
    const code = inlineCode(match[2] ?? "")
    if (code !== undefined) lines.push(...codeViewLines(code, ctx))
  }
  if (awk) for (const path of awkOutputs(text)) if (pathCandidate(path)) lines.push(...protectedRedirect(path, ctx))
  return lines.length ? lines.join("\n") : undefined
}

/** Redirection to a protected `path`, if any; `content`: the code may only hold the path as text (`notWritten`). */
function protectedRedirect(path: string, ctx: ShellRuleContext, content = false): string[] {
  const kind = protectedWriteClass(path, ctx.home, ctx)
  return kind !== undefined && !(content && kind === "system") ? [`: >${path}`] : []
}

/** Lines of `interpreterCodeView` for one piece of code: its protected writes, then its launches. */
function codeViewLines(code: string, ctx: ShellRuleContext): string[] {
  const lines: string[] = []
  for (const literal of codeMatches(code, CODE_LITERAL)) {
    const value = literal[1] ?? literal[2] ?? literal[3] ?? ""
    const end = literal.index + literal[0].length
    const perl = /^(?:\+[<>]|>)>?\s*/.exec(value)?.[0]
    const path = perl ? value.slice(perl.length) : value
    if (!pathCandidate(path)) continue
    const before = code.slice(Math.max(0, literal.index - 240), literal.index)
    const after = code.slice(end, end + 80)
    const call = before.lastIndexOf("(")
    const byCall = call >= 0 && WRITE_CALL.test(before.slice(Math.max(0, call - 40), call)) && FIRST_ARGUMENTS.test(before.slice(call + 1))
    const written =
      perl !== undefined ||
      byCall ||
      (OPEN_BEFORE.test(before) && WRITE_MODE_AFTER.test(after)) ||
      PERL_OPEN_BEFORE.test(before) ||
      (SYSOPEN_BEFORE.test(before) && SYSOPEN_WRITE_AFTER.test(after)) ||
      (PATH_BEFORE.test(before) && PATH_WRITE_AFTER.test(after))
    if (written) lines.push(...protectedRedirect(path, ctx, byCall && notWritten(before.slice(Math.max(0, call - 40), call), before.slice(call + 1), after)))
  }
  if (hasExecutionSink(code)) lines.push(...literalGroups(code).map((group) => group.text).filter((group) => NAMES_LAUNCH.test(group)))
  return lines
}

/** Code of a quoted block of `INTERPRETER_DANGEROUS_CODE`, double-quote escapes removed; `undefined` if empty or too long. */
function inlineCode(quoted: string): string | undefined {
  const code = quoted.length >= 2 ? quoted.slice(1, -1) : quoted
  if (code.length === 0 || code.length > INLINE_CODE_LIMIT) return undefined
  return quoted.startsWith('"') ? code.replace(/\\([\\"$`])/g, "$1") : code
}

/** Literals of inline code, a list of literals separated by commas as one command: text, start, backtick literal. */
function literalGroups(code: string): Array<{ text: string; start: number; backtick: boolean }> {
  const groups: Array<{ text: string; start: number; backtick: boolean }> = []
  let end = -1
  for (const literal of codeMatches(code, CODE_LITERAL)) {
    const value = literal[1] ?? literal[2] ?? literal[3] ?? ""
    if (end >= 0 && /^\s*,\s*$/.test(code.slice(end, literal.index))) groups[groups.length - 1]!.text += ` ${value}`
    else groups.push({ text: value, start: literal.index, backtick: literal[3] !== undefined })
    end = literal.index + literal[0].length
  }
  return groups
}

/** Just before a literal: the opening of a call that launches a process (`subprocess.run(`, `os.system(`, `execSync(`, `system `…), a list included. */
const LAUNCH_BEFORE =
  /\b(?:system|popen\w*|run|call|check_call|check_output|Popen|getoutput|getstatusoutput|exec\w*|spawn\w*|shell_exec|passthru|proc_open|capture\w*)(?:\s*\(\s*\[?|\s+)\s*$/

/** Literals of inline code, then its comments by language (a comment marker inside a literal stays in the literal). */
const commentsOf = (comment: string) => new RegExp(`${CODE_LITERAL.source}|(${comment})`, "g")
const JAVASCRIPT_COMMENTS = commentsOf(String.raw`\/\/[^\n]*|\/\*[\s\S]*?(?:\*\/|$)`)
const PHP_COMMENTS = commentsOf(String.raw`#[^\n]*|\/\/[^\n]*|\/\*[\s\S]*?(?:\*\/|$)`)
const HASH_COMMENTS = commentsOf(String.raw`#[^\n]*`)

/**
 * Inline code with its comments outside literals blanked (line breaks and positions kept): `//` and `/* *\/` in a
 * JavaScript engine, `#` in Python, Ruby and Perl, all three in PHP. Other comment forms (Ruby's `=begin`, Perl's POD) stay.
 */
function withoutComments(code: string, interpreter: string): string {
  const comments = JAVASCRIPT_ENGINES.test(interpreter) ? JAVASCRIPT_COMMENTS : /^php/.test(interpreter) ? PHP_COMMENTS : HASH_COMMENTS
  return blankedCode(code, comments, (match) => match[4] !== undefined)
}

/**
 * Inline code delimited in `text` that launches an OpenCode subcommand that prints a secret (`opencodeKinds`): a literal
 * (or list) that names `opencode`, given directly to a call that launches a process, or a backtick literal outside a
 * JavaScript engine, comments of the code left out (`withoutComments`). A literal only printed or kept in a variable
 * does not count (the ask of the code stays).
 */
function codeLaunchesPrinted(text: string): boolean {
  for (const match of text.matchAll(INTERPRETER_DANGEROUS_CODE)) {
    const interpreter = /^\S+/.exec(match[1] ?? "")?.[0] ?? ""
    const inline = inlineCode(match[2] ?? "")
    const code = inline === undefined ? undefined : withoutComments(inline, interpreter)
    if (code === undefined || !hasExecutionSink(code)) continue
    for (const group of literalGroups(code)) {
      if (NAMES_LAUNCH.test(group.text) && launchedLiteral(code, group, interpreter) && opencodeKinds(group.text).has("printed")) return true
    }
  }
  return false
}

/** A literal group of comment-free code given directly to a call that launches a process, or a backtick literal outside a JavaScript engine. */
const launchedLiteral = (code: string, group: { start: number; backtick: boolean }, interpreter: string) =>
  (group.backtick && !JAVASCRIPT_ENGINES.test(interpreter)) || LAUNCH_BEFORE.test(code.slice(Math.max(0, group.start - 80), group.start))

/** Python literals, triple-quoted ones first (over several lines; an unclosed one runs to the end), then `#` comments. */
const PYTHON_LITERALS_AND_COMMENTS = new RegExp(String.raw`'''(?:[^\\]|\\[\s\S])*?(?:'''|$)|"""(?:[^\\]|\\[\s\S])*?(?:"""|$)|${CODE_LITERAL.source}|#[^\n]*`, "g")

/**
 * Literals of Ruby and Perl (single, double and backtick quotes, over several lines; an unclosed one runs to the end), then
 * `#` comments; for PHP, its `//` and `/* *\/` comments too; then the other literals of `quoted` (`RUBY_LITERALS`,
 * `PERL_LITERALS`). Each attempt matches up to where it stops: linear cost.
 */
const scriptLiterals = (comment: string, quoted?: string) =>
  new RegExp(String.raw`'((?:[^'\\]|\\[\s\S]?)*)(?:'|$)|"((?:[^"\\]|\\[\s\S]?)*)(?:"|$)|\x60((?:[^\x60\\]|\\[\s\S]?)*)(?:\x60|$)|(${comment})${quoted === undefined ? "" : `|(${quoted})`}`, "g")
/**
 * A word list after `lead`: between paired brackets (nesting not followed: the list ends at the first closing one) or
 * between two `other` characters; an unclosed one runs to the end. Its delimiter is group 6 of `scriptLiterals`.
 */
const wordList = (lead: string, other: string) =>
  String.raw`${lead}(?:\((?:[^)\\]|\\[\s\S]?)*(?:\)|$)|\[(?:[^\]\\]|\\[\s\S]?)*(?:\]|$)|\{(?:[^}\\]|\\[\s\S]?)*(?:\}|$)|<(?:[^>\\]|\\[\s\S]?)*(?:>|$)|(${other})(?:(?!\6)[^\\]|\\[\s\S]?)*(?:\6|$))`
/** Keywords after which a slash opens a Ruby regular expression. */
const RUBY_REGEXP_KEYWORDS = "when|if|elsif|unless|while|until|and|or|not|return|then"
/**
 * Ruby literals of the view of `OWN_HTTP_CALLS` beyond quotes: word lists (`%w`, `%W`, `%i`, `%I`, not right after a name,
 * `)` or `]`), and a regular expression closed on its line, after a keyword of `RUBY_REGEXP_KEYWORDS`, or after a method
 * name written after a dot and followed by a space when no space or `=` follows the slash (a bare name: a division).
 */
const RUBY_LITERALS = scriptLiterals(
  String.raw`#[^\n]*`,
  String.raw`${wordList(String.raw`(?<![\w)\]])%[wWiI]`, String.raw`[^\w\s([{<]`)}|(?<=(?<![\w.:$@])(?:${RUBY_REGEXP_KEYWORDS})[ \t]*)\/(?:[^/\\\n]|\\[^\n])*\/|(?<=\.[ \t]*\w+[?!]?[ \t]+)\/(?![\s=])(?:[^/\\\n]|\\[^\n])*\/`,
)
/** Perl literals of the view of `OWN_HTTP_CALLS` beyond quotes: `qw` word lists (after the same characters as `UNPARSED_QUOTING`, `#` not taken as delimiter). */
const PERL_LITERALS = scriptLiterals(String.raw`#[^\n]*`, wordList(String.raw`(?<![\w$@%&:>])qw\s*`, String.raw`[^\w\s#,;=)>}\]([{<]`))
const PHP_LITERALS = scriptLiterals(String.raw`#[^\n]*|\/\/[^\n]*|\/\*[\s\S]*?(?:\*\/|$)`)
/** A literal kept by the view of `OWN_HTTP_CALLS`: an `http(s)://` URL, or the name of the `http` or `https` module. */
const HTTP_URL = /^https?:\/\//i
const HTTP_MODULE = /^(?:node:)?https?$/

/**
 * Request call of the code's own HTTP functions: in Python, a call of `PYTHON_HTTP_CALL` with literals (triple-quoted ones
 * included) and comments blanked; in Ruby, Perl, PHP and a JavaScript engine, a call of `OWN_HTTP_CALLS` in its view
 * (literals of `RUBY_LITERALS`, `PERL_LITERALS`, `PHP_LITERALS` or `JAVASCRIPT_COMMENTS`), never with quoting that view
 * leaves out (`UNPARSED_QUOTING`).
 */
function callsOwnHttp(code: string, interpreter: string): boolean {
  if (/^python/.test(interpreter)) return PYTHON_HTTP_CALL.test(blankedCode(code, PYTHON_LITERALS_AND_COMMENTS))
  const language = JAVASCRIPT_ENGINES.test(interpreter) ? "javascript" : /^ruby/.test(interpreter) ? "ruby" : /^perl/.test(interpreter) ? "perl" : /^php/.test(interpreter) ? "php" : undefined
  if (language === undefined) return false
  const literals = language === "javascript" ? codeMatches(code, JAVASCRIPT_COMMENTS) : code.matchAll(language === "php" ? PHP_LITERALS : language === "ruby" ? RUBY_LITERALS : PERL_LITERALS)
  let view = ""
  let end = 0
  for (const match of literals) {
    // A word list or a regular expression (group 5): no URL kept.
    const value = match[1] ?? match[2] ?? match[3] ?? (match[5] === undefined ? undefined : "")
    view += code.slice(end, match.index) + (value === undefined ? " " : HTTP_URL.test(value) ? '"http:"' : HTTP_MODULE.test(value) ? '"https"' : '""')
    end = match.index + match[0].length
  }
  view += code.slice(end)
  return OWN_HTTP_CALLS[language].test(view) && !UNPARSED_QUOTING[language].test(view)
}

/**
 * Inline code delimited in `text` that sends a credential file without reaching the network as `codeReachesNetwork`
 * sees it, the deny rule of the network examination it gives: a literal (or list) launched as in `codeLaunchesPrinted`
 * that runs a network tool with the file (the deny table's test, on that literal: an ssh key given to `-i` does not
 * count) or with an OpenCode subcommand that prints a secret, or a request call of the code's own HTTP functions
 * (`callsOwnHttp`) with the file anywhere in `text`, as for `fetch`.
 */
function codeSendsCredentialFile(text: string, ctx: CredentialContext): RegexRule | undefined {
  // Files of the whole text, computed at most once (linear cost with many code blocks).
  let inText: boolean | undefined
  for (const match of text.matchAll(INTERPRETER_DANGEROUS_CODE)) {
    const interpreter = /^\S+/.exec(match[1] ?? "")?.[0] ?? ""
    const inline = inlineCode(match[2] ?? "")
    if (inline === undefined) continue
    if (callsOwnHttp(inline, interpreter) && (inText ??= sentSecretFiles(text, ctx).length > 0)) return NETWORK_CODE_RULES[0]
    const code = withoutComments(inline, interpreter)
    if (!hasExecutionSink(code)) continue
    for (const group of literalGroups(code)) {
      if (!launchedLiteral(code, group, interpreter) || !runsNetwork(group.text)) continue
      if (sentSecretFiles(group.text, ctx).length > 0) return NETWORK_CODE_RULES[0]
      if (NAMES_LAUNCH.test(group.text) && opencodeKinds(group.text).has("printed")) return NETWORK_CODE_RULES[2]
    }
  }
  return undefined
}

/**
 * Inline code outside heredoc bodies that names a network tool and holds a literal (or list) naming an OpenCode
 * subcommand that prints a secret (`opencodeKinds`), launched or not: the place where a credential path gives the
 * deny of the table reduced to an ask (`existingShellFinding`).
 */
function codeCitesPrinted(command: string): boolean {
  if (!command.includes("opencode")) return false
  for (const match of withoutHeredocBodies(command).matchAll(INTERPRETER_DANGEROUS_CODE)) {
    const code = inlineCode(match[2] ?? "")
    if (code === undefined || !runsNetwork(code)) continue
    for (const group of literalGroups(code)) if (NAMES_LAUNCH.test(group.text) && opencodeKinds(group.text).has("printed")) return true
  }
  return false
}

/** Code passed to an interpreter too long for `interpreterDangerousCode` (not examined); no cost on a shorter command. */
function interpreterCodeTooLong(command: string): boolean {
  if (command.length <= INLINE_CODE_LIMIT) return false
  for (const match of command.matchAll(INTERPRETER_DANGEROUS_CODE)) if ((match[2] ?? "").length - 2 > INLINE_CODE_LIMIT) return true
  return false
}

/**
 * OpenCode 2.1.1 CLI (`packages/cli/src/commands/commands.ts`), read like the `effect/cli` 4.0.1 parser: `opencode`
 * launched by common recognition, or behind assignments, then the call tail (`callTail`). Global options
 * (and, before the first word, those of the root) skipped before and between the subcommand words, with their
 * value; a boolean swallows the literal that follows it.
 */
const OPENCODE_CALL = new RegExp(commandRegex("opencode").source, "g")
/**
 * Binary attached to a quote, searched separately (a discarded match does not hide any `OPENCODE_CALL` call):
 * counted only if that quote closes the `-c` wrapper containing it.
 */
const OPENCODE_QUOTED_CALL = new RegExp(commandRegex("opencode", "(?=[\"'])").source, "g")
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
const OPENCODE_HEAD = new RegExp(`^(?:${commandRegex("opencode").source})`)
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
type OpencodeKind = "nested" | "service-config" | "service-change" | "service-secret" | "credentials" | "printed" | "heap-dump" | "api" | "config" | "plugin-update" | "unchecked" | "long"
const OPENCODE_KINDS = new Map<string, readonly OpencodeKind[]>([
  ...["run", "serve", "acp"].map((name) => [name, ["nested"]] as const),
  // `service set` and `unset` write the service's settings and environment (`service.json`); the others leave them as they are.
  ...["service set", "service unset"].map((name) => [name, ["service-config"]] as const),
  ...["uninstall", "service stop", "service restart"].map((name) => [name, ["service-change"]] as const),
  ["pair", ["service-secret"]],
  ["auth export", ["credentials", "printed"]],
  ["debug heap-dump", ["heap-dump"]],
  ...["plugin add", "plugin remove", "mcp add"].map((name) => [name, ["config"]] as const),
  ["plugin update", ["plugin-update"]],
])

/**
 * API reads: GET operations of the OpenCode 2.1.1 protocol (`packages/protocol/openapi.json`, with the five renamed in 2.2.5), identifier then
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
  experimental.session.log /api/experimental/session/{sessionID}/log
  experimental.persistentPty.get /api/experimental/persistent-pty/{ptyID}
  experimental.persistentPty.snapshot /api/experimental/persistent-pty/{ptyID}/snapshot
  experimental.persistentPty.list /api/experimental/session/{sessionID}/terminal
  experimental.persistentPty.read /api/experimental/session/{sessionID}/terminal/read
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

/**
 * Words of a call tail: redirections removed (with their detached target; both collected in order in `redirects` if
 * given), final comment discarded.
 */
function tailWords(tail: string, redirects?: string[]): string[] {
  const words: string[] = []
  const tokens = tail.split(/\s+/).filter(Boolean)
  for (let i = 0; i < tokens.length && !tokens[i]!.startsWith("#"); i++) {
    const at = redirectionAt(tokens[i]!)
    if (at !== 0) words.push(at < 0 ? tokens[i]! : tokens[i]!.slice(0, at))
    if (at >= 0) redirects?.push(tokens[i]!.slice(at))
    if (at >= 0 && BARE_REDIRECTION.test(tokens[i]!.slice(at)) && ++i < tokens.length) redirects?.push(tokens[i]!)
  }
  return words
}

/**
 * Command of a segment as the shell launches it: redirections set aside first, wherever they are (before the name,
 * among the options, after `--`, attached to a word), with their target (`tailWords`); `redirects`: those set aside, in
 * order. Added to the reading of `commandOf` by the readers of the launched program and its operand (input executed,
 * scripts examined, variable source, startup file).
 */
function launchedCommand(segment: string): { name: string; args: string[]; path: string; redirects: string[] } {
  const redirects: string[] = []
  return { ...commandOf(tailWords(segment, redirects).join(" ")), redirects }
}

/** Redirection or comment word: `tailWords` sets it aside (and the words after a comment). */
const SETS_ASIDE = /[<>]|(?:^|\s)#/

/**
 * Whether a reader also reads `launchedCommand(segment)`, besides `previous` (`commandOf` or `envAssignments` of the same
 * segment): a redirection or a comment word (`SETS_ASIDE`), and either the reader reads the arguments of the program
 * named by `previous` (`concerned`), or such a word comes at or before that name (another program may be launched).
 * Otherwise both readings launch the same program after the same words: the second one adds nothing.
 */
function readsLaunched(segment: string, previous: { args: readonly string[] }, concerned: boolean): boolean {
  const at = segment.search(SETS_ASIDE)
  return at >= 0 && (concerned || (segment.slice(at).match(/\S+/g)?.length ?? 0) > previous.args.length)
}

/** Inclusion (`source`, `.`) or program of `EXECUTORS`: its operands are read (`executesStdin`, `scriptRuns`). */
const readsOperands = (name: string) => name === "source" || name === "." || EXECUTORS.some((candidate) => candidate.name.test(name))

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
    ["opencode-service", "service-config", "change to the OpenCode service (environment, restart) or uninstall: can disable the guard"],
    ["opencode-service", "service-change", "change to the OpenCode service (environment, restart) or uninstall: can disable the guard"],
    ["opencode-service", "service-secret", `display of the OpenCode service password, environment or settings, or pairing (access to the server): ${CONFIRMED_OUTPUT_REDACTION}`],
    ["opencode-server-api", "credentials", `export of the OpenCode credentials (auth export, or the credential list of the server API): ${CONFIRMED_OUTPUT_REDACTION}`],
    ["opencode-server-api", "heap-dump", "copy of the OpenCode server memory written to a file (debug heap-dump): it can contain the OpenCode credentials, the service password and other secrets"],
    ["opencode-server-api", "api", "call to the OpenCode server API other than a known read (write, sensitive read, unknown operation): it can bypass the guard"],
    ["nested-opencode", "nested", "launches another OpenCode agent or server, or changes its configuration: it may run without the guard or approve its confirmations (--auto)"],
    ["nested-opencode", "long", "OpenCode command line longer than the plugin checks (1024 characters after the program name): it cannot be checked"],
    ["nested-opencode", "unchecked", "OpenCode command line with an unknown option or a word known only at run time in its subcommand: it cannot be checked"],
    ["self-protection", "config", "OpenCode command that adds or removes a plugin or adds an MCP server: rewrites OpenCode's configuration (self-protection)"],
    ["self-protection", "plugin-update", "OpenCode command that updates package plugins: it can replace the guard's code (self-protection)"],
  ] as const
).map(([id, kind, reason]): RegexRule => ({
  id,
  verdict: "ask",
  reason,
  test: (command) => opencodeKinds(command).has(kind),
  ...(kind === "long" || kind === "unchecked" ? { unfinished: true } : {}),
  // Rewrites opencode.json, or the service's environment (`{env:…}` of the plugin's settings, OpenCode's configuration
  // directory or content): a change of the plugin's settings.
  ...(kind === "config" || kind === "plugin-update" || kind === "service-config" ? { userOnly: true } : {}),
}))

const NAMED_LOCATION_REASON = "command that names OpenCode's configuration or the guard plugin and does more than read: it may write there in a form the plugin does not recognize (self-protection)"
const NAMED_WORDS_LIMIT_REASON = "command with too many paths to compare with OpenCode's configuration and the guard plugin: the plugin's limit on named paths was reached, so it could not be checked: confirmation required (self-protection)"

const ASK_RULES: readonly RegexRule[] = [
  // First: on equal terms, a command of the plugin's command line shows this rule.
  {
    id: "guard-cli",
    verdict: "ask",
    reason: "the guard command line, which changes the plugin's settings, run or named by the command (self-protection; another program named guard asks too)",
    test: (command, ctx) => namesGuardCli(command, ctx),
    userOnly: true,
  },
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
    // Launched, like the network tools: a name only printed or searched (`command -v ssh`, `which ssh`, `grep ssh f`)
    // is not a connection.
    test: (command) =>
      REMOTE_COMMAND.test(command) ||
      REMOTE_LOOKED_UP.test(command) ||
      /rsync\s[^;&|]*\S+:/.test(command) ||
      NETWORK_DEVICE.test(command),
  },
  {
    id: "gh-upload",
    verdict: "ask",
    reason: "GitHub CLI upload or API call",
    test: re(/(?:^|[\s;&|(`])gh\s+(?:gist\s+(?:create|edit)|api|release\s+(?:create|upload)|secret\s+set|variable\s+set|ssh-key\s+add|gpg-key\s+add)\b/),
  },
  // `service set` and `unset` change the service's environment or settings: never left to the decision model.
  {
    id: "opencode-service",
    verdict: "ask",
    reason: "change to the OpenCode service (environment, restart) or uninstall: can disable the guard",
    test: re(/(?:^|[\s;&|(`])opencode\s+service\s+(?:set|unset)\b/),
    userOnly: true,
  },
  {
    id: "opencode-service",
    verdict: "ask",
    reason: "change to the OpenCode service (environment, restart) or uninstall: can disable the guard",
    test: re(/(?:^|[\s;&|(`])opencode\s+(?:service\s+(?:stop|restart|uninstall)|uninstall)\b/),
  },
  {
    // With the server password, these routes bypass the guardrail (switch to the unprotected agent, prompt or
    // command in the user's name, answer to permission requests). Complement: a constructed URL escapes it.
    id: "opencode-server-api",
    verdict: "ask",
    reason: "call to the OpenCode server API that switches the agent, sends a prompt or a command, replaces the instructions of a voice call, or answers a permission request: it can bypass the guard",
    test: re(SERVER_API_ROUTE),
  },
  // Its configuration or plugins changed by its environment, or its confirmations approved: never left to the decision
  // model (user's decision); another launch can be.
  {
    id: "nested-opencode",
    verdict: "ask",
    reason: "launches another OpenCode agent or server, or changes its configuration: it may run without the guard or approve its confirmations (--auto)",
    test: (command) =>
      OPENCODE_CONFIG_VARIABLE.test(command) ||
      ((AUTO_APPROVE.test(command) || NESTED_CONFIG_VARIABLE.test(command)) && (NESTED_OPENCODE.test(command) || opencodeKinds(command).has("nested"))),
    userOnly: true,
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
    test: (command, ctx) => AWK_PROGRAMS.note(command, ctx) === true,
  },
  // Quoted string not read (limit): same rule, exact reason.
  {
    id: "awk-dynamic-exec",
    verdict: "ask",
    reason: `awk program with a quoted string longer than the plugin checks (${AWK_STRING_LIMIT} characters): it cannot be checked for execution of non-literal text`,
    test: (command, ctx) => AWK_PROGRAMS.reread(command, ctx) === LIMIT_REACHED,
    unfinished: true,
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
    reason: DANGEROUS_CODE_REASON,
    test: interpreterDangerousCode,
  },
  {
    id: "interpreter-dangerous-code",
    verdict: "ask",
    reason: `interpreter code longer than the plugin checks (${INLINE_CODE_LIMIT} characters): it cannot be checked for a dangerous command`,
    test: interpreterCodeTooLong,
    unfinished: true,
  },
  {
    id: "secret-file-read",
    verdict: "ask",
    reason: "access to a credential file",
    test: (command, ctx) => CREDENTIAL_TOKENS.note(command, ctx).found === true,
    detail: (command, ctx) => credentialDetail(CREDENTIAL_TOKENS.peek(command, ctx)),
  },
  // Content not checked (limit): ask, never the network send deny (`sentSecretFiles` does not count it).
  {
    id: "secret-file-read",
    verdict: "ask",
    reason: uncheckedCredentialReason(),
    test: (command, ctx) => CREDENTIAL_TOKENS.reread(command, ctx).found === LIMIT_REACHED,
    unfinished: true,
  },
  // Its settings (opencode.json, guard.json, the plugin directory): never left to the decision model; then the rest.
  {
    id: "self-protection",
    verdict: "ask",
    reason: "write to OpenCode's configuration or to the guard plugin (self-protection)",
    test: (command, ctx) => PROTECTED_TARGETS.note(command, ctx).includes("settings"),
    userOnly: true,
  },
  {
    id: "self-protection",
    verdict: "ask",
    reason: "write to OpenCode's configuration or to the guard plugin (self-protection)",
    test: (command, ctx) => PROTECTED_TARGETS.peek(command, ctx).includes("opencode"),
  },
  {
    id: "protected-write",
    verdict: "ask",
    reason: "write to a protected location (startup file, ~/.ssh, git hook, /etc)",
    test: (command, ctx) => protectedTargets(command, ctx).includes("system"),
  },
  // Unchecked real path (limit): it could lead to self-protection, always active.
  {
    id: "self-protection",
    verdict: "ask",
    reason: uncheckedWriteReason("write to a location"),
    test: (command, ctx) => PROTECTED_TARGETS.reread(command, ctx).includes("unchecked"),
    unfinished: true,
  },
  ...OPENCODE_ASK_RULES,
  // A protected location in another form of a target that self-protection holds, when this rule is stronger.
  {
    id: "protected-write",
    verdict: "ask",
    reason: "write to a protected location (startup file, ~/.ssh, git hook, /etc)",
    test: (command, ctx) => outranksSelfProtection(ctx.active) && writtenTargets(command, ctx).some((target) => systemWrite(target, ctx.home, ctx)),
  },
  // Net: a protected location named by a command that does more than read, in a form of write no rule above reads. After
  // them: an ask above keeps its place. Limit reached or settings named: never left to the decision model, as the entries above.
  {
    id: "self-protection",
    verdict: "ask",
    reason: NAMED_LOCATION_REASON,
    test: (command, ctx) => NAMED_LOCATION.note(command, ctx) !== undefined,
    detail: (command, ctx) => ({ reason: NAMED_LOCATION.peek(command, ctx) === "limit" ? NAMED_WORDS_LIMIT_REASON : NAMED_LOCATION_REASON }),
    userOnly: (command, ctx) => NAMED_LOCATION.peek(command, ctx) !== "opencode",
  },
  // Last: any other ask names the cause better than the variable does.
  {
    id: "shell-startup-file",
    verdict: "ask",
    reason: CODE_LOADING_REASON,
    test: codeLoadingEnv,
  },
  ...OPAQUE_RULES.map(({ id, reason, hint, names }): RegexRule => ({ id, verdict: "ask", reason, test: (command) => hint.test(command) && printsRawFile(command, names) })),
]

/**
 * `protected-write` stronger than the weakest self-protection ask (rule set to `deny`, or an ask the user confirms against
 * one left to the model): only then are the other forms of the targets looked up (`systemWrite`), never with the default
 * settings. Otherwise the self-protection ask, earlier, stays shown.
 */
function outranksSelfProtection(active: ActiveRules | undefined): boolean {
  const ask = (rule: string) => entrusted(hardened({ verdict: "ask", rule, reason: "" }, active), active)
  const stronger = ask("protected-write")
  return mostSevere([ask("self-protection"), stronger]) === stronger
}

/**
 * The plugin's command line (`bin/guard`, which writes its settings): `guard` as the launched program, or a path to its
 * launcher (`…/bin/guard`, in any directory: a link installed elsewhere) or to a module of the plugin's `src/cli/`
 * anywhere in the command (run directly or by an interpreter, or only named), unless the command only reads files
 * (`onlyReads`). Lexical forms from the command's directories; only words that can name them are resolved.
 */
const GUARD_COMMAND = commandRegex("guard")

/** Constructions not modelled by `readOnlyWords`: substitutions, expansions, process substitution, heredocs, groups. */
const UNMODELLED = /\$|`|<\(|>\(|<<|[(){}]/
/** Programs that run code or another program, anywhere in the raw command (even quoted): never a plain reading then. */
const RUNS_SOMETHING =
  /(?:^|[^\w.-])(?:sh|bash|zsh|dash|ksh|mksh|ash|yash|fish|csh|tcsh|python[\d.]*|node|nodejs|bun|bunx|deno|tsx|ts-node|npx|npm|pnpm|yarn|ruby[\d.]*|perl[\d.]*|php[\d.]*|eval|source|exec|xargs|parallel|watch|ssh|su|sudo|doas|env|nohup|setsid|script|awk|gawk|nawk|mawk|find)(?![\w.-])/

/**
 * Words of each simple command, as the shell reads them (quotes removed, `\` escapes), when the command holds only
 * plain words, quotes and separators; `undefined` otherwise (a construction above, an unbalanced quote, a comment).
 */
function readOnlyWords(command: string): string[][] | undefined {
  if (UNMODELLED.test(command.replace(/'[^']*'/g, "''"))) return undefined
  const segments: string[][] = [[]]
  let word: string | undefined
  const end = () => {
    if (word !== undefined) segments.at(-1)!.push(word)
    word = undefined
  }
  for (let i = 0; i < command.length; i++) {
    const c = command[i]!
    if (c === "\\") {
      if (i + 1 >= command.length) return undefined
      word = (word ?? "") + command[++i]
    } else if (c === "'") {
      const close = command.indexOf("'", i + 1)
      if (close < 0) return undefined
      word = (word ?? "") + command.slice(i + 1, close)
      i = close
    } else if (c === '"') {
      let j = i + 1
      let value = ""
      for (; j < command.length && command[j] !== '"'; j++) value += command[j] === "\\" && j + 1 < command.length ? command[++j] : command[j]
      if (j >= command.length) return undefined
      word = (word ?? "") + value
      i = j
    } else if (c === "#" && word === undefined) return undefined
    else if (/\s/.test(c) && c !== "\n") end()
    else if (c === ";" || c === "|" || c === "\n" || (c === "&" && !/[<>]$/.test(command.slice(0, i)))) {
      end()
      if (segments.at(-1)!.length) segments.push([])
    } else word = (word ?? "") + c
  }
  end()
  return segments.filter((words) => words.length)
}

/** Options of `git` that run a program or a pager, before or after its subcommand. */
const GIT_RUNS = new Set(["-c", "-p", "--paginate", "--exec-path", "--config-env", "--ext-diff", "--textconv", "--output"])

/** Options of `file` that only change its report. */
const FILE_READS = new Set(["-b", "--brief", "-i", "--mime", "--mime-type", "--mime-encoding", "-L", "--dereference", "-h", "--no-dereference", "-k", "--keep-going", "-E", "--extension", "-N", "--no-pad", "-0", "--print0"])

/** Script of `sed` that only prints: addresses with `p`, with `-n`, or one substitution without the `e` and `w` flags. */
const SED_ADDRESS = /^(?:\d+|\$)(?:,(?:\d+|\$))?p$/
const SED_SUBSTITUTION = /^s([^\w\s\\])(?:\\.|(?!\1)[^\\\n])*\1(?:\\.|(?!\1)[^\\\n])*\1[gpiI\d]*$/

/** One simple command that only reads files: a reader of a closed list, without an option that runs something. */
function readsOnly(words: readonly string[]): boolean {
  const [name, ...args] = words
  switch (name) {
    case "cat":
    case "head":
    case "tail":
    case "wc":
    case "ls":
    case "stat":
    case "nl":
    case "diff":
    case "grep":
    case "egrep":
    case "fgrep":
      return true
    case "rg":
      return !args.some((arg) => arg.startsWith("--pre"))
    case "file":
      // Options that only change the report; `-z`, `-C`, `-m`, `-S`, `-f`… (decompressors, compiled or chosen magic
      // files, no sandbox, a list of names) keep the ask.
      return args.every((arg) => !arg.startsWith("-") || FILE_READS.has(arg))
    case "git": {
      if (args.some((arg) => GIT_RUNS.has(arg.split("=")[0]!))) return false
      let i = 0
      while (i < args.length && args[i]!.startsWith("-")) i += args[i] === "-C" || args[i] === "--git-dir" || args[i] === "--work-tree" ? 2 : 1
      return ["show", "log", "diff", "blame", "status"].includes(args[i] ?? "")
    }
    case "sed": {
      // `sed -n '1,80p' file`, `sed 's/a/b/g' file` (GNU sed's `e` and `w` run or write).
      const prints = (word: string) => SED_SUBSTITUTION.test(word) || (args.includes("-n") && SED_ADDRESS.test(word))
      let script = false
      for (let i = 0; i < args.length; i++) {
        const arg = args[i]!
        if (arg === "-n" || arg === "--quiet" || arg === "--silent" || arg === "-E" || arg === "-r") continue
        if (arg === "-e") {
          if (!prints(args[++i] ?? "")) return false
          script = true
        } else if (arg.startsWith("-")) return false
        else if (!script) {
          if (!prints(arg)) return false
          script = true
        }
      }
      return script
    }
    default:
      return false
  }
}

/**
 * A command that only reads files: plain words (no substitution, expansion, heredoc or group), no program that runs code
 * named anywhere, and each simple command a reader of a closed list (`readsOnly`). Then the word `guard` in a quoted
 * string (`grep 'a\|guard off'`) or a path of the command line only named (`git show HEAD -- src/cli/main.ts`) is not a
 * launch of it. Anything else keeps the lexical reading below. A reader made to run a program by configuration planted
 * beforehand (a repository's git config or attributes, `RIPGREP_CONFIG_PATH`, an alias of a startup file) does so
 * whether or not the command names the command line: that never depended on this rule.
 */
export function onlyReads(command: string): boolean {
  if (RUNS_SOMETHING.test(command)) return false
  const segments = readOnlyWords(command)
  return segments !== undefined && segments.length > 0 && segments.every(readsOnly)
}

/**
 * `guard update --check`, which changes nothing, and nothing else: judged on the command as written, since a view of it
 * loses what changes the program run (`PATH=x guard update --check`).
 */
function isGuardCheck(written: string | undefined): boolean {
  const segments = written === undefined ? undefined : readOnlyWords(written)
  return segments?.length === 1 && segments[0]!.join("\0") === "guard\0update\0--check"
}

function namesGuardCli(command: string, ctx: ShellRuleContext): boolean {
  if (onlyReads(command) || isGuardCheck(ctx.written)) return false
  if (GUARD_COMMAND.test(command)) return true
  const plugins = ctx.pluginDirs ?? ctx.protectedDirs ?? []
  const bases = ctx.cwds?.length ? ctx.cwds : ctx.cwd ? [ctx.cwd] : []
  const named = (path: string) => path.endsWith("/bin/guard") || plugins.some((dir) => path.startsWith(`${dir}/src/cli/`))
  // A directory of the command among the plugin's `bin` and `src/cli`: any word may name one of their files.
  const inside = bases.some((base) => plugins.some((dir) => base === `${dir}/bin` || base === `${dir}/src/cli` || base.startsWith(`${dir}/src/cli/`)))
  if (!inside && !command.includes("guard") && !command.includes("cli")) return false
  return pathTokens(command).some((token) => {
    if (!inside && !token.includes("guard") && !token.includes("cli")) return false
    const expanded = token.replace(/^(~|\$HOME|\$\{HOME\})(?=\/|$)/, ctx.home ?? "~")
    return (posix.isAbsolute(expanded) ? [posix.resolve(expanded)] : bases.map((base) => posix.resolve(base, expanded))).some(named)
  })
}

/** Kinds of protected locations targeted by the command's writes (`protectedWriteClass`). */
function protectedTargets(command: string, ctx: ShellRuleContext): Array<WriteClass | undefined> {
  // A directory known once the shell runs a substitution whose text ends with it (`"$(echo <dir>)/plugin/x.ts"`): the
  // joined form too, for self-protection only (a substitution that names no OpenCode location changes nothing).
  const selfProtection = (joined: string) => {
    const kind = protectedWriteClass(joined, ctx.home, ctx)
    return kind === "settings" || kind === "opencode" ? kind : undefined
  }
  const kinds = writtenTargets(command, ctx).map((target) => {
    const kind = protectedWriteClass(target, ctx.home, ctx)
    const joined = target.replace(SUBSTITUTION_END, "")
    return joined === target ? kind : strictestKind(kind, selfProtection(joined))
  })
  if (/\$\(|`/.test(command)) for (const match of command.matchAll(SUBSTITUTION_REDIRECT)) kinds.push(selfProtection(`${match[1]}${match[2]}`))
  return kinds
}

/** Distinct path-like words of a command compared by the net (`namedLocation`): beyond them, its ask of the limit. */
const MAX_NAMED_WORDS = 1024
const NAMED_WORD_SEPARATORS = /[\s;&|()<>`'"]+/
/**
 * Value of a `name=value` word and attached directory option, each also read as a word (`of=x`, `--output=x`, `DESTDIR=x`,
 * `D+=x`, `D[0]=x`, `-Cx`, `-dx`, `-Dx`), and what follows the last `=` of that value (`a=b=x`). The assigned value is not
 * followed to the `$D` that uses it.
 */
const OPTION_VALUE = /^-{0,2}[A-Za-z_][\w-]*(?:\[[^\]]*\])?\+?=(.+)$/
const ATTACHED_DIRECTORY = /^-[CdD](.+)$/
const HOME_PREFIX = /^(?:\$HOME|\$\{HOME\}|~)(?:\/|$)/
const PROTECTED_NAMES = new Set(["opencode.json", "opencode.jsonc", "guard.json", ".opencode"])
/** Programs that write nothing by their arguments, unless a redirection does. `find` too, without these actions. */
const NAMING_COMMANDS = new Set(["echo", "printf", "jq", "test", "[", "[["])
const FIND_ACTIONS = /\s\$?-(?:exec|execdir|ok|okdir|delete|fprint\w*|fls)\b/
/** Redirections without effect on a file: to `/dev/null`, or to another descriptor (`2>&1`, `2>&-`). */
const HARMLESS_REDIRECTION = /&?>>?\s*\/dev\/null(?![^\s)])|>&(?:\d+|-)(?![^\s)])/g

/** Launchers in front of a naming command, each with its options, durations and assignments. */
const NAMING_LAUNCHERS = new Set(["sudo", "doas", "nice", "ionice", "time", "timeout", "stdbuf", "nohup", "setsid", "env", "command", "exec", "unbuffer"])

/** The word after this launcher option is its value: the option itself, or a group of letters ending with it (`-Eu bob`). */
function valueFollows(word: string, values: ReadonlySet<string>): boolean {
  if (word.startsWith("--")) return values.has(word)
  for (let i = 1; i < word.length; i++) if (values.has(`-${word[i]}`)) return i === word.length - 1
  return false
}

/**
 * Words of a segment cut at its program: the launchers and structural words with what they take, then the program and its
 * arguments. Word by word: a linear walk. A long option not known here may take a value: the walk stops on it, so the
 * segment names no benign program.
 */
function behindLaunchers(segment: string): [string[], string[]] {
  const words = segment.trim().replace(/^\(+\s*/, "").split(/\s+/)
  let start = 0
  for (let head = words[0]!; GROUPING_WORDS.has(head) || NAMING_LAUNCHERS.has(head); head = words[start]!) {
    start++
    const values = PREFIX_OPTIONS[head]
    if (!values) continue
    for (let word = words[start]; word !== undefined; word = words[start]) {
      if (/^--[^=]+$/.test(word) && !values.has(word)) return [words.slice(0, start), words.slice(start)]
      if (word.startsWith("-") && word.length > 1) start += valueFollows(word, values) || /^\d+$/.test(words[start + 1] ?? "") ? 2 : 1
      else if (/^(?:\d+[smhd]?|[A-Za-z_]\w*=\S*)$/.test(word)) start++
      else break
    }
  }
  return [words.slice(0, start), words.slice(start)]
}

/** Text outside quotes and escapes, in place (`quoteStates`), or the whole text where that reading does not hold. */
function outsideQuotes(text: string): string {
  const states = quoteStates(text)
  return states ? text.replace(/[\s\S]/g, (char, i: number) => (states[i] ? " " : char)) : text
}

function namingOnly(words: readonly string[]): boolean {
  const rest = words.join(" ")
  if (/[<>]/.test(outsideQuotes(rest).replace(HARMLESS_REDIRECTION, " "))) return false
  // `segments` reads only the innermost substitution: the outer one runs a command nothing else reads.
  if (quoteStates(rest) && /\$\([^)]*\$\(/.test(outsideQuotes(rest))) return false
  const name = words[0]?.split("/").pop() ?? ""
  return NAMING_COMMANDS.has(name) || (name === "find" && !FIND_ACTIONS.test(rest.replace(/["'\\]/g, "")))
}

/** A program under these directories, in command position: the system's, not one relaunched by its path (`| /usr/bin/sort`). */
const SYSTEM_PROGRAM = /((?:^|[;&|(`\n{])[^\S\n]*(?:sudo\s+)?)(?:\/usr(?:\/local)?)?\/bin\/(?=[\w+-][^\s;&|()/]*(?:[\s;&|()]|$))/g
const APPLIES_ITS_INPUT = /\b(?:xargs|parallel)\b/
/** A pipe, or `>(…)`, into an interpreter that reads its standard input, behind the launchers. */
const PIPED_INTERPRETER = new RegExp(
  `(?:\\|&?|>\\()\\s*(?:${COMMAND_PATH}(?:${WRAPPERS})(?:\\s+[^\\s;&|]+){0,8}?\\s+)?${COMMAND_PATH}(?:perl|python|ruby|node|bun|deno|php|awk|gawk)[\\d.]*(?=\\s|$|[;&|)])`,
)
/** Escapes of `printf` and `echo -e`, each a blank for the net: a word ends there (`opencode.json\\0`, `rm\\040x`). */
const TEXT_ESCAPE = /\\(?:[0-7]{1,3}|x[\da-fA-F]{1,2}|[abcefnrtv])/g

/** A stage behind a pipe, without `||` and `>|`, its quoted text blanked by the search; a `(` stays in it, `)` and a backtick end it. */
const PIPE_STAGE = /(?<![|>])\|(?!\|)&?(\s*[^;&|)`\n]*)/g

/** Options of `sort` and `uniq` that only change what they print; `-o`, `-T`, a long option… are not among them. */
const SORT_PRINTS = /^-[bcCdfghiMnrRsuVz]*(?:[kSt]\S*)?$/
const UNIQ_PRINTS = /^-[cdDiuz]*(?:[fsw]\d*)?$/

/** `sort` or `uniq` that prints what it receives: not readers of `onlyReads`, an option or a second operand writes a file. */
function sortsItsInput(words: readonly string[]): boolean {
  const [name, ...rest] = words.map((word) => word.replace(/["'\\]/g, ""))
  const prints = name === "sort" ? SORT_PRINTS : name === "uniq" ? UNIQ_PRINTS : undefined
  if (!prints || !rest.every((arg) => !arg.startsWith("-") || prints.test(arg))) return false
  return name === "sort" || rest.filter((arg) => arg === "-" || !arg.startsWith("-")).length < 2
}

/**
 * This stage only reads what it receives, by its bare name or under the system's directories, without a group, a local
 * path or a redirection to a file: a reader of `onlyReads` or `READ_ONLY_COMMANDS`, a left-out command, `sort`, `uniq`.
 */
function knownReceiver(stage: string): boolean {
  const plain = stage.replace(HARMLESS_REDIRECTION, " ").trim().replace(SYSTEM_PROGRAM, "$1")
  const [launchers, program] = behindLaunchers(plain)
  if (plain.startsWith("(") || launchers.some((word) => GROUPING_WORDS.has(word)) || /[<>]/.test(outsideQuotes(plain))) return false
  const name = program[0] ?? ""
  return onlyReads(program.join(" ")) || READ_ONLY_COMMANDS.has(name) || sortsItsInput(program) || (!name.includes("/") && namingOnly(program))
}

/** A `.` behind a word is an argument (`timeout 5 jq . x`): a program cannot run this builtin, `command` can. */
const DOT_ARGUMENT = /(?<=[^\s;&|(`{]\s+)(?<!\bcommand\s+)\.(?=\s|$)/g
/** Output of a group to a file: its segments do not show it (`{ jq . x; } >/tmp/y`, `done > y`). */
const GROUP_OUTPUT = /(?:\)|(?:^|[\s;&|])(?:\}|fi|done|esac))\s*\d*&?>/

/**
 * What a command prints may be run or applied: it relaunches a shell (a program of the system by its path does not
 * count, nor a path inside quotes), holds `xargs` or `parallel`, pipes into an interpreter or into anything else than a
 * known reader (`knownReceiver`), or sends a group to a file. Linear, on the whole text: no stage is followed.
 */
function readsEveryWord(data: string): boolean {
  const plain = data.replace(/["'\\]/g, "")
  const outside = outsideQuotes(data)
  const effective = outside.replace(HARMLESS_REDIRECTION, (found) => " ".repeat(found.length))
  return (
    reentersShell(data.replace(DOT_ARGUMENT, " "), outside.replace(SYSTEM_PROGRAM, "$1")) ||
    APPLIES_ITS_INPUT.test(plain) ||
    PIPED_INTERPRETER.test(plain) ||
    GROUP_OUTPUT.test(effective) ||
    Array.from(effective.matchAll(PIPE_STAGE)).some((match) => {
      const end = match.index + match[0].length
      return !knownReceiver(data.slice(end - match[1]!.length, end))
    })
  )
}

/** An assignment alone (`D=x`, `export D=x`, `readonly D=x`), its name captured; a use of a variable, written as such. */
const LONE_ASSIGNMENT = /^\s*(?:(?:export|readonly)\s+)?([A-Za-z_]\w*)(?:\[[^\]\s]*\])?\+?=\S*\s*$/
const VARIABLE_USE = /\$\{?[#!]?([A-Za-z_]\w*)/g

const SEPARATOR_CHARS = ";&|\n"

/** The text with each separator between quotes as a control character, so that it cuts nothing; unchanged where `quoteStates` does not hold. */
function hideQuotedSeparators(text: string): string {
  const states = quoteStates(text)
  // A `#` right behind `)` starts a comment `quoteStates` does not see: a quote in it hides nothing from the shell. A `$(`
  // that `segments` does not read keeps the whole text: cut at a separator, it does not hide behind a naming command.
  if (!states || /[\x02-\x05]|\)#/.test(text) || text.replace(/\$\([^()]*\)/g, " ").includes("$(")) return text
  let open = false
  return text.replace(/['";&|\n]/g, (char, i: number) => {
    if (states[i]! >= 2) open = states[i] === 2
    const at = SEPARATOR_CHARS.indexOf(char)
    return open && at >= 0 ? String.fromCharCode(2 + at) : char
  })
}

const showQuotedSeparators = (text: string) => text.replace(/[\x02-\x05]/g, (char) => SEPARATOR_CHARS[char.charCodeAt(0) - 2]!)

/**
 * Parts of the data the net reads when no word has to be: each segment, except one that only reads or only names, of which
 * only the words of its launchers stay (`time -o x`), and an assignment no `$D` of the command uses. `dd if=` only reads.
 * A separator between quotes cuts no segment; an escaped one still does.
 */
function segmentsToRead(data: string, command: string): string[] {
  const reads = onlyReads(command)
  const used = new Set(Array.from(command.matchAll(VARIABLE_USE), (match) => match[1]))
  return segments(hideQuotedSeparators(data), SHELL_SEPARATORS).flatMap((hidden) => {
    const segment = showQuotedSeparators(hidden)
    const [launchers, program] = behindLaunchers(segment)
    if (reads || onlyReads(segment) || namingOnly(program)) return [launchers.join(" ")]
    const assigned = LONE_ASSIGNMENT.exec(segment)?.[1]
    if (assigned !== undefined && !used.has(assigned)) return []
    return [commandOf(segment).name === "dd" ? segment.replace(/(?<![^\s])if=\S*/g, " ") : segment]
  })
}

const namedWords = (segment: string) =>
  segment
    .split(NAMED_WORD_SEPARATORS)
    .filter(Boolean)
    .flatMap((word) => {
      const value = OPTION_VALUE.exec(word)?.[1]
      return [word, value, value?.slice(value.lastIndexOf("=") + 1), ATTACHED_DIRECTORY.exec(word)?.[1]].filter((part) => part !== undefined)
    })

/**
 * Word that can name a protected location as written: no glob or expansion (`$HOME`, `${HOME}` and `~` in front
 * excepted), no URL, and a path or a protected name (in a protected directory, a bare word such as `npm`
 * would resolve into it).
 */
function pathWord(word: string): boolean {
  if (/^(?:[^/]*=)?https?:/.test(word) || !(word.includes("/") || PROTECTED_NAMES.has(word))) return false
  return HOME_PREFIX.test(word) ? !/[*?[\]{}\\]/.test(word.replace(/^\$\{HOME\}/, "")) : !/[$*?[\]{}\\]/.test(word)
}

/**
 * Net of `self-protection`: class of the protected locations named by a command that does not only read, whatever the form
 * of its write, or `limit` past `MAX_NAMED_WORDS`. Words of the whole command, its data too, when what it prints may be run
 * or applied (`readsEveryWord`), otherwise `segmentsToRead`. Lexical only: it takes nothing from the budget of real paths
 * shared with the write targets, so a word reached through a link stays with the decision model.
 */
function namedLocation(command: string, ctx: ShellRuleContext): "settings" | "opencode" | "limit" | undefined {
  const { realPaths: _shared, ...lexical } = ctx
  const seen = new Set<string>()
  let named: "opencode" | undefined
  const data = withoutData(command)
  for (const part of readsEveryWord(data) ? [command.replace(TEXT_ESCAPE, " ")] : segmentsToRead(data, command)) {
    for (const word of namedWords(part)) {
      if (seen.has(word) || !pathWord(word)) continue
      seen.add(word)
      if (seen.size > MAX_NAMED_WORDS) return "limit"
      const kind = protectedWriteClass(word, ctx.home, lexical)
      if (kind === "settings") return kind
      if (kind === "opencode") named = kind
    }
  }
  return named
}

/** Class named by the command: noted by the net's test, peeked by its reason and its `userOnly`. */
const NAMED_LOCATION = sharedReading(namedLocation)

/** End of a command substitution (and a quote closed just before it) followed by the rest of a path. */
const SUBSTITUTION_END = /["']?[)`](?=\/)/g
/**
 * Redirection to a target that starts with a command substitution followed by a path, which `writeTargets` does not read
 * past the parenthesis: the last word of the substitution and the path.
 */
const SUBSTITUTION_REDIRECT = /(?:^|[^<>])(?:\d|&)?>>?\|?\s*["']?(?:\$\(|`)(?:[^()`;&|\n]*\s)?([^\s()`;&|'"]+)["']?[)`]["']?(\/[^\s;&|<>()'"]*)/g

/**
 * Paths of a copy that its words do not give: the destination joined with the name of each source that can complete a
 * protected location (`completesProtectedPath`: `cp -r /tmp/hooks .git`), and a destination attached to its option
 * (`cp -t/etc x`). The file system is not asked whether the destination is a directory, and any other name costs no
 * lookup: `cp x y` does not ask about `y/x`.
 */
function joinedCopyTargets(command: string, ctx: ShellRuleContext): string[] {
  const joined: string[] = []
  for (const segment of segments(command, SHELL_SEPARATORS)) {
    const { name, args: tokens } = commandOf(segment)
    if (!COPY_COMMANDS.has(name)) continue
    const args = withoutRedirections(tokens)
    const destination = copyDestination(args, name !== "rsync")
    if (destination === undefined) continue
    const directory = destination.replace(/["']/g, "")
    const sources = args.filter((arg) => !arg.startsWith("-"))
    const own = sources.lastIndexOf(destination)
    if (own >= 0) sources.splice(own, 1)
    else joined.push(directory)
    for (const source of sources) {
      const base = posix.basename(source.replace(/["']/g, ""))
      // A remote source of `rsync` (`host:.bashrc`).
      const file = name === "rsync" ? base.slice(base.lastIndexOf(":") + 1) : base
      if (completesProtectedPath(file, ctx)) joined.push(`${directory}/${file}`)
    }
  }
  return joined
}

/** Targets of the command's writes, the files of `joinedCopyTargets` included. */
function writtenTargets(command: string, ctx: ShellRuleContext): string[] {
  // Without shell re-entry, an interpreter's code (`node -e "x => …"`) is not a redirection.
  const data = withoutData(command)
  const text = reentersShell(data) ? command : data
  return [...writeTargets(text), ...joinedCopyTargets(text, ctx)]
}

/**
 * Shell re-entry: a heredoc or interpreter code can end up executed as shell (`bash -c`, `| sh`,
 * `eval`, `ssh host "…"`, `watch "…"`, script launched by its path or made executable). The analysis then remains complete.
 * Blanks after the path opener read as in `commandRegex` (without newline: linear cost).
 */
const SHELL_REENTRY = commandRegex("sh|bash|zsh|dash|ksh|fish|eval|source|\\.|ssh|su|watch|parallel|script|flock|tmux|screen|expect|(?:busybox|toybox)[^\\S\\n]+\\w*sh")
const PATH_EXECUTION = /(?:^|[;&|(`\n{])[^\S\n]*(?:sudo\s+)?(?:\.{1,2}\/|~\/|\/)[^\s;&|()]/
const MAKE_EXECUTABLE = /\bchmod\s[^;&|\n]*\+[rw]*x/

/** `launched`: the text read for a program launched by its path, the command itself except for the net (`readsEveryWord`). */
function reentersShell(command: string, launched = command): boolean {
  // A launcher name in quotes (`"bash" <<EOF`) is read without them: only a quoted piece without a blank or a separator,
  // so that no separator comes out of quoted text.
  const unquoted = /["']/.test(command) && SHELL_REENTRY.test(command.replace(/'([^'\s;&|()<>`]*)'|"([^"\s;&|()<>`$\\]*)"/g, "$1$2"))
  return SHELL_REENTRY.test(command) || unquoted || PATH_EXECUTION.test(launched) || MAKE_EXECUTABLE.test(command)
}

/** Code passed to a non-shell interpreter (`node -e "…"`, `python3 -c '…'`, `perl -E`, `php -r`, `deno eval`). */
const INTERPRETER_CODE =
  /(\b(?:node|nodejs|bun|python[0-9.]*|ruby[\d.]*|perl(?:5[\w.-]*)?|php[\d.]*)(?:\s+-[^\s;&|'"]+){0,6}?\s+(?:-e|-p|-c|-E|-r|--eval|--print)\s+|\bdeno\s+eval\s+)("(?:[^"\\]|\\.)*"|'[^']*')/g

/** Heredoc start (`<<EOF`, `<<-'EOF'`); a `<` just before signals a here-string (`<<<`), left as is. */
const HEREDOC_START = /<<(-?)[ \t]*(["']?)([A-Za-z_][A-Za-z0-9_]*)\2/g

/**
 * Removes heredoc bodies, traversed in order (linear cost); a body expanded by the shell (`$(…)`) is kept.
 * `withTerminators`: also removes the closing line (view of `onlyInHeredocData`); a kept body is signaled there by
 * `undefined` (never data alone). `blank`: removed bodies replaced by blanks (positions kept). `removed`: for each of
 * them, where its `<<` stands, where it starts and where it ends.
 */
function withoutHeredocBodies(command: string): string
function withoutHeredocBodies(command: string, withTerminators: true): string | undefined
function withoutHeredocBodies(command: string, withTerminators: false, blank: true, removed?: Array<readonly [number, number, number]>): string
function withoutHeredocBodies(command: string, withTerminators = false, blank = false, removed?: Array<readonly [number, number, number]>): string | undefined {
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
      removed?.push([match.index, lineEnd + 1, bodyEnd])
      out += blank ? command.slice(kept, Math.min(lineEnd + 1, bodyEnd)) + " ".repeat(Math.max(0, bodyEnd - lineEnd - 1)) : command.slice(kept, lineEnd + 1)
      kept = withTerminators && end ? end.index + end[0].length : bodyEnd
    } else if (withTerminators) return undefined
    if (!end) break
    start.lastIndex = end.index + end[0].length
  }
  return out + command.slice(kept)
}

/**
 * Command as the shell reads it, lines it continues joined: backslash-newline removed outside single quotes, `$'…'`,
 * comments and heredoc bodies (`withoutHeredocBodies`), after an odd number of backslashes. The command itself
 * without a backslash before a newline (zero cost). One pass.
 */
function joinedLines(command: string): string {
  if (!command.includes("\\\n")) return command
  const text = withoutHeredocBodies(command, false, true)
  let [out, kept, quote, previous] = ["", 0, "", " "]
  for (let i = 0; i < text.length; i++) {
    const char = text[i]!
    if (quote === "'" || quote === "$") {
      if (char === "'") quote = ""
      else if (char === "\\" && quote === "$") i++
    } else if (char === "\\") {
      if (text[i + 1] === "\n") [out, kept] = [out + command.slice(kept, i), i + 2]
      else previous = char
      i++
      continue
    } else if (quote === '"') {
      if (char === '"') quote = ""
    } else if (char === "'" || char === '"') quote = char
    else if (char === "$" && text[i + 1] === "'") [quote, i] = ["$", i + 1]
    else if (char === "#" && /[\s;&|()<>]/.test(previous)) {
      const end = text.indexOf("\n", i)
      i = (end < 0 ? text.length : end) - 1
    }
    previous = char
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

/**
 * Script file of an interpreter: first argument not an option; nothing if the code is an argument or read from stdin.
 * `grouped`: a shell's options read like the shell (`optionValues`).
 */
function scriptArgument(executor: (typeof EXECUTORS)[number], args: readonly string[], grouped = false): string | undefined {
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
      i += optionValues(executor, arg, grouped)
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
 * `source ./f`, `. ./f`, `python3 f.py`, `node f.js`, `bun run f.ts`…, a file redirected to the input of a shell or
 * interpreter that executes it (`bash < f.sh`), or a command launched by its path (`./f.sh`, `bin/x`). At most `max`
 * files. A segment that quotes `~` or `$` between quotes (not expanded by the shell) is ignored. Internal error of the
 * view without leading assignments: scripts tracked as without it (the result carries no ask). Segments read by
 * `commandOf`, then, files added after, with the redirections set aside (`SHELL_SEPARATORS`, `launchedCommand`, input
 * opened for reading and writing included; only the segments where `readsLaunched`), then both on the command with its
 * continued lines joined (`joinedLines`): none takes the place of a file of a previous reading, and the files of the
 * first reading (operands, then redirected input read as written) come before any other. The command is read with its
 * words reduced to their value (`commandWordView`).
 */
export function scriptRuns(command: string, max = 4): ScriptRun[] {
  const runs: ScriptRun[] = []
  const add = (run: ScriptRun | undefined) => {
    const literal = literalPath(run?.path)
    if (run && literal && runs.length < max && !runs.some((item) => item.path === literal)) runs.push({ path: literal, kind: run.kind })
  }
  // The words as the shell reads them (`bash s""cript.sh`), in place of the command: a piece must not take one of the places.
  let read = command
  try {
    read = commandWordView(command, MAX_SHELL_LEVELS).view
  } catch {}
  const joined = joinedLines(read)
  for (const view of joined === read ? [read] : [read, joined]) {
    let bare = view
    try {
      bare = withoutAssignments(view).view
    } catch {}
    const text = withoutData(bare)
    // Without `<`, `>` or `#`, the shell separators are the simple ones and no segment sets anything aside.
    for (const launched of /[<>#]/.test(text) ? [false, true] : [false]) {
      // Files added after the others (read from the redirected input, or by a shell's options read like the shell): none
      // takes the place of a script operand. First reading (the command, read by `commandOf`): files of its redirected
      // input read as written (`stdin`) before those of the other readings (`later`), none of which takes their place.
      const firstReading = view === read && !launched
      const [stdin, later]: Array<Array<ScriptRun | undefined>> = [[], []]
      for (const segment of launched ? segments(text, SHELL_SEPARATORS) : segments(text)) {
        if (runs.length >= max) break
        if (/["'][~$]/.test(segment) || (launched && !SETS_ASIDE.test(segment))) continue
        const first = launched ? commandOf(segment) : undefined
        if (first && !readsLaunched(segment, first, readsOperands(first.name))) continue
        const read: { name: string; args: string[]; path: string; redirects?: string[] } = launched ? launchedCommand(segment) : commandOf(segment)
        const { name, args, path, redirects = args } = read
        const executor = EXECUTORS.find((candidate) => candidate.name.test(name))
        // A shell's options read as written, then also like the shell (`groupedValue`): files of that reading added after.
        for (const grouped of executor && groupedValue(executor, args) ? [false, true] : [false]) {
          // `source f`/`. f` without `/`: looked up in PATH before the directory (bash, zsh's `.`) → ignored.
          const run: ScriptRun | undefined =
            name === "source" || name === "."
              ? { path: args[0]?.includes("/") ? args[0] : "", kind: "shell" }
              : executor
                ? { path: scriptArgument(executor, args, grouped) ?? "", kind: executor === EXECUTORS[0] ? "shell" : "interpreter" }
                : path.includes("/")
                  ? { path, kind: "direct" }
                  : undefined
          if (grouped) later.push(run)
          else add(run)
          // Without a script operand, a program that executes its input (`bash < f.sh`, `python3 - < f.py`; read of the
          // `pipe-to-shell` rule, code as an argument excluded): each file redirected to its input (the shell reads the last one).
          if (executor && run?.path === "") {
            const written = !grouped && executesInput({ name, args }, () => false, false)
            if (written || (groupedValue(executor, args) && executesInput({ name, args }, () => false, true)))
              for (const redirect of stdinRedirects(redirects, launched)) if (!redirect.string) (written && firstReading ? stdin : later).push({ path: redirect.operand, kind: run.kind })
          }
        }
      }
      for (const run of [...stdin, ...later]) add(run)
    }
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
 * 64 KiB ignored; the latter, not examined, noted in `skipped`). One pass over code blocks, patterns without nested
 * repetition.
 */
function codeReachesNetwork(text: string, skipped?: { long: boolean }): boolean {
  for (const match of text.matchAll(new RegExp(INTERPRETER_CODE.source, "g"))) {
    const quoted = match[2] ?? ""
    const code = quoted.length >= 2 ? quoted.slice(1, -1) : quoted
    if (code.length > INLINE_CODE_LIMIT && skipped) skipped.long = true
    if (code.length === 0 || code.length > INLINE_CODE_LIMIT) continue
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
 * a body was removed, the re-entry test last (already computed by `protectedTargets`).
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

/**
 * Detection, view included, without switch: called by the rule (`networkCodeFinding`) and by cost tests. Without
 * delimited code, the view is not computed. `seen` receives the examined view and the note of a block too long, not examined.
 */
export function inlineCodeNetwork(command: string, seen?: { view: string; long: boolean }): boolean {
  const bodies = withoutHeredocBodies(command)
  if (!hasInterpreterCode(command, bodies)) return false
  const view = networkCodeView(command, bodies)
  if (seen) seen.view = view
  return codeReachesNetwork(view, seen)
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
  // Output of an OpenCode subcommand that prints a secret, run by the shell or by the inline code: same place as in the
  // deny table.
  {
    id: "secret-file-network",
    verdict: "deny",
    reason: "OpenCode credentials or service secrets printed in a command whose inline interpreter code makes network requests (exfiltration)",
    test: (view) => opencodeKinds(view).has("printed") || codeLaunchesPrinted(view),
  },
  { id: "interpreter-network", verdict: "ask", reason: "inline interpreter code making network requests", test: () => true },
]

/** Code too long for the network examination, without other code that reaches the network: ask, never deny (nothing was examined). */
const LONG_NETWORK_CODE: Finding = {
  verdict: "ask",
  rule: "interpreter-network",
  reason: `inline interpreter code longer than the plugin checks (${INLINE_CODE_LIMIT} characters): its network requests cannot be checked`,
}

function networkCodeFinding(command: string, ctx: ShellRuleContext): Finding | undefined {
  const seen = { view: command, long: false }
  if (!inlineCodeNetwork(command, seen)) {
    // Sent by the code without other network access recognized: only the deny of a credential file or of a printed
    // OpenCode secret, never an ask.
    const sent = ruleEnabled(NETWORK_CODE_RULES[0]!.id, ctx.active) ? codeSendsCredentialFile(seen.view, ctx) : undefined
    if (sent) return { verdict: "deny", rule: sent.id, reason: sent.reason }
    return seen.long && ruleEnabled(LONG_NETWORK_CODE.rule, ctx.active) ? hardened(LONG_NETWORK_CODE, ctx.active) : undefined
  }
  const rule = NETWORK_CODE_RULES.find((candidate) => ruleEnabled(candidate.id, ctx.active) && candidate.test(seen.view, ctx))
  return rule && entrusted(hardened({ verdict: rule.verdict, rule: rule.id, reason: rule.reason }, ctx.active), ctx.active)
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
  const rule = addedRecognition(command, ctx.active)
  if (!rule) return undefined
  const finding: Finding = { verdict: "deny", rule: rule.id, reason: rule.reason }
  if (ctx.custom?.some((custom) => custom.id === rule.id) || overrideOf(rule.id, ctx.active) === "deny") return finding
  const data = withoutData(command)
  if (data === command || reentersShell(data) || evaluate(data, ctx)?.verdict === "deny" || addedRecognition(data, ctx.active)) return finding
  return { verdict: "ask", rule: rule.id, reason: `${rule.reason}, only inside code passed to an interpreter or a heredoc: confirmation required` }
}

/**
 * A deny pattern present only in code passed to an interpreter or in a heredoc (e.g. test strings
 * `node -e "…'shred /dev/sda'…"`) becomes an ask: never less. Excluded: the placeholder, user
 * rules and any shell re-entry outside that data. An ask becomes that of a printed OpenCode secret cited in the code
 * (`printedInCodeFinding`), and so does nothing found only because the settings turn rules off (`silencedPrintedFinding`).
 */
function existingShellFinding(command: string, ctx: ShellRuleContext): Finding | undefined {
  const finding = evaluate(command, ctx)
  if (finding?.verdict === "ask") return printedInCodeFinding(command, ctx) ?? (onlyInHeredocData(command, ctx) ? inHeredocData(command, finding, ctx) : finding)
  if (finding === undefined) return silencedPrintedFinding(command, ctx)
  // Rule set to `deny` (`ruleOverrides`): final, never reduced to an ask.
  if (finding?.verdict !== "deny" || finding.rule === "placeholder" || ctx.custom?.some((rule) => rule.id === finding.rule) || overrideOf(finding.rule, ctx.active) === "deny")
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

/** Last entry of the deny table: the output of an OpenCode subcommand that prints a secret. */
const PRINTED_NETWORK = DENY_RULES.findLast((rule) => rule.id === "secret-file-network")!

/**
 * Ask of a command that already asks, when its inline code cites a printed OpenCode secret with a network tool
 * (`codeCitesPrinted`): what a credential path at the same place gets, by the settings only: a deny if the rule is set
 * to `deny` or a user rule has its identifier (as in `existingShellFinding`), otherwise an ask without a mark (never
 * `entrusted`), even where that path's deny is not reduced.
 */
function printedInCodeFinding(command: string, ctx: ShellRuleContext): Finding | undefined {
  if (!ruleEnabled(PRINTED_NETWORK.id, ctx.active) || !codeCitesPrinted(command)) return undefined
  if (ctx.custom?.some((rule) => rule.id === PRINTED_NETWORK.id) || overrideOf(PRINTED_NETWORK.id, ctx.active) === "deny")
    return { verdict: "deny", rule: PRINTED_NETWORK.id, reason: PRINTED_NETWORK.reason }
  return { verdict: "ask", rule: PRINTED_NETWORK.id, reason: `${PRINTED_NETWORK.reason}, only inside code passed to an interpreter or a heredoc: confirmation required` }
}

/**
 * Nothing found under settings that turn rules off (`dangerousCommands`, a rule set to `off`), where the same command with
 * those rules on gets a finding: the finding of a printed OpenCode secret cited in the code (`printedInCodeFinding`), as a
 * credential path at the same place gets. With the default settings nothing changes (the evaluation is the same).
 */
function silencedPrintedFinding(command: string, ctx: ShellRuleContext): Finding | undefined {
  const active = ctx.active
  if (!active || (active.dangerousCommands && ![...(active.overrides?.values() ?? [])].includes("off"))) return undefined
  const printed = printedInCodeFinding(command, ctx)
  if (!printed) return undefined
  const overrides = active.overrides && new Map([...active.overrides].filter(([, override]) => override !== "off"))
  return evaluate(command, { ...ctx, active: { ...active, dangerousCommands: true, overrides } }) ? printed : undefined
}

/**
 * Ask found only inside heredoc data: marked `dataOnly` (the decision model decides), unless a rule set to `ask`
 * (`ruleOverrides`: the user confirms) asks there too, whichever ask won the combination: with such a setting only,
 * the command is evaluated again with each ask marked before the combination, and an ask left without a mark wins.
 */
function inHeredocData(command: string, finding: Finding, ctx: ShellRuleContext): Finding {
  const confirmed = [...(ctx.active?.overrides?.values() ?? [])].includes("ask") ? evaluate(command, ctx, true) : undefined
  return confirmed && !confirmed.dataOnly ? confirmed : { ...finding, dataOnly: true }
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

function evaluate(command: string, ctx: ShellRuleContext, inData = false): Finding | undefined {
  // Rule disabled by a switch or set to `off`: discarded BEFORE choosing the most severe finding (otherwise a deny from a
  // disabled rule would mask that of an active rule); ask of a rule set to `deny`: a deny, before it too; ask left to
  // the decision model by a setting: marked, before it too (an ask without a mark then wins the combination).
  const on = (finding: Finding | undefined) => (finding && ruleEnabled(finding.rule, ctx.active) ? entrusted(hardened(finding, ctx.active), ctx.active) : undefined)
  const findings: Array<Finding | undefined> = []
  for (const rule of DENY_RULES) {
    // Executed script: the placeholder rule is discarded here, before any combination, in every view (otherwise its deny
    // would take the place of another rule's finding, then be dropped as not applicable).
    if (ctx.executedScript && rule.id === "placeholder") continue
    if (ruleEnabled(rule.id, ctx.active) && rule.test(command, ctx)) return { verdict: rule.verdict, rule: rule.id, reason: rule.reason }
  }
  for (const segment of segments(command)) {
    const permissions = on(permissionFinding(segment, ctx.home))
    if (permissions) return permissions
    findings.push(on(rmFinding(segment, ctx.home, ruleEnabled("rm-critical", ctx.active))), on(deletionFinding(segment)), on(moveFinding(segment, ctx.home)))
  }
  for (const rule of ctx.custom ?? []) {
    if ((rule.tools.includes("shell") || rule.tools.includes("*")) && rule.pattern.test(command))
      findings.push({ verdict: rule.verdict, rule: rule.id, reason: rule.reason })
  }
  for (const rule of ASK_RULES) {
    if (ruleEnabled(rule.id, ctx.active) && rule.test(command, ctx)) {
      const finding = hardened({ verdict: rule.verdict, rule: rule.id, reason: rule.reason, ...rule.detail?.(command, ctx) }, ctx.active)
      const userOnly = typeof rule.userOnly === "function" ? rule.userOnly(command, ctx) : rule.userOnly
      findings.push(rule.unfinished || userOnly ? finding : entrusted(finding, ctx.active))
    }
  }
  // Asks found only inside heredoc data (`inHeredocData`): each marked, except those of a rule set to `ask`.
  const marked = (finding: Finding | undefined) => (finding?.verdict === "ask" && overrideOf(finding.rule, ctx.active) !== "ask" ? { ...finding, dataOnly: true } : finding)
  return mostSevere(inData ? findings.map(marked) : findings)
}

/**
 * Segment-leading assignments (`A=1 curl`), which common recognition does not skip: its heads (without `find -exec`
 * or `${`), then name (`+=` and bash index included) and value read like the shell (`shellEnd`). Candidate heads, kept
 * only if `assignedName` reads a name.
 */
const ASSIGNED_HEAD = /(?:^|[;&|(`\n]|(?<!\$)\{|-[a-zA-Z]*c\s+["'])[^\S\n]*(?=[A-Za-z_]\w*(?:\[|\+?=))/g
const ASSIGNED_WORD = /[A-Za-z_]\w*/y
/** End of a bracketed index: first `]`, blank or separator. */
const INDEX_STOP = /[\]\s;&|]/g
/** Fallback for a value that the read does not close (first blank or separator, like `commandOf`); blanks between two words. */
const BLANK_WORD = /[^\s;&|]*/y
const WORD_GAP = /(?:[^\S\n]|\\\n)*/y
const BETWEEN_WORDS = /[\s;&|()<>]*/y
const stickyEnd = (regex: RegExp, text: string, at: number) => ((regex.lastIndex = at), regex.exec(text), regex.lastIndex)
const DOLLAR_OPENERS = new Map([["(", "("], ["{", "}"], ["'", "$"], ['"', '"']])

/** End of the index of each `[` of the text (the following `INDEX_STOP`, or the end): a single scan for all brackets. */
function indexEnds(text: string): Map<number, number> {
  const ends = new Map<number, number>()
  let stop = -1
  for (const { index } of text.matchAll(/\[/g)) {
    if (stop < index) {
      INDEX_STOP.lastIndex = index + 1
      stop = INDEX_STOP.exec(text)?.index ?? text.length
    }
    ends.set(index, stop)
  }
  return ends
}

/**
 * Length of the assigned name that starts at `at` (`A=`, `A+=`, `A[i]=`), 0 otherwise. Index ends computed at the first
 * bracket and shared (`ends`): each head does not reread the rest of the text (linear cost).
 */
function assignedName(text: string, at: number, ends: { map?: Map<number, number> }): number {
  ASSIGNED_WORD.lastIndex = at
  if (!ASSIGNED_WORD.test(text)) return 0
  let i = ASSIGNED_WORD.lastIndex
  if (text[i] === "[") {
    i = (ends.map ??= indexEnds(text)).get(i)!
    if (text[i++] !== "]") return 0
  }
  if (text[i] === "+") i++
  return text[i] === "=" ? i + 1 - at : 0
}

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
      if (inner) {
        modes.push(inner)
        if (inner === dollar) i++
      }
    }
  }
  return modes.length === 1 && i === stop ? i : -1
}

/**
 * View without the leading assignments followed by a command (`A=1 curl …` → `curl …`) on the view without data except
 * shell re-entry; inside a word of the command (`shellEnd`, comments skipped), head read only in a substitution
 * or the wrapper string that opens that word. Copied at the end of the view: the bodies of erased substitutions, never the
 * values. Kept: assignment alone, `BUN_BE_BUN=1` before `opencode`. Unclosed value: fallback; head in a value
 * or after a failure: shared budget (four times the length), whose exhaustion (partial view) gives `flag`, reason
 * for an ask (undetermined program, like `commandWordView`). Linear cost.
 */
function withoutAssignments(command: string): { view: string; flag?: string } {
  if (!command.includes("=")) return { view: command }
  const data = withoutData(command)
  const text = data !== command && !reentersShell(data) ? data : command
  const spans = launcherSpans(text)
  const opens = new Map(spans.flat())
  const budget = { left: 4 * text.length + 1024 }
  const ranges: Array<readonly [number, number, ReadonlyArray<readonly [number, number]>]> = []
  const subs: Array<readonly [number, number]> = []
  const ends: { map?: Map<number, number> } = {}
  let [frontier, from, word, sub] = [0, 0, 0, 0]
  for (const match of text.matchAll(ASSIGNED_HEAD)) {
    const start = match.index + match[0].length
    if (!assignedName(text, start, ends)) continue
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
      const length = assignedName(text, end, ends)
      if (!length) break
      const value = end + length
      const name = text.slice(end, value)
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
  // Negative budget: a cut-off read or a skipped head (an unclosed value falls under the fallback, without draining it).
  const flag = budget.left < 0 ? UNDETERMINED_WORD_REASON : undefined
  return { view: ranges.length ? render(0, text.length) + lines.map((line) => `\n${line}`).join("") : command, flag }
}

/**
 * Most severe finding (verdict alone) between `found`, that of the view without leading assignments and the ask of its
 * exhausted budget; at equal verdict, `found` (mark included), unless it only names a variable that loads code (`ssh` is
 * seen behind the assignment only here).
 */
function assignedFinding(command: string, ctx: ShellRuleContext, found: Finding | undefined): Finding | undefined {
  try {
    const { view: bare, flag } = found?.verdict === "deny" ? { view: command } : withoutAssignments(command)
    const undetermined = flag ? hardened({ verdict: "ask", rule: "nested-opencode", reason: flag }, ctx.active) : undefined
    const without = bare === command ? undefined : layeredShellFinding(bare, ctx).finding
    return mostSevere(found?.reason === CODE_LOADING_REASON ? [without, found, undetermined] : [found, without, undetermined])
  } catch {
    return mostSevere([found, hardened(ANALYSIS_FAILED, ctx.active)])
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
/** Ask of a string of `env -S` not read to its end (`splitStrings`), always active. */
const UNSTABLE_SPLIT: Finding = {
  verdict: "ask",
  rule: "nested-opencode",
  reason: "a string of `env -S` is nested too deep or written in a form the plugin cannot read: the launched program cannot be checked",
}
const UNSTABLE_JOIN: Finding = {
  verdict: "ask",
  rule: "nested-opencode",
  reason: "the command could not be read with the lines the shell continues joined (command too complex for the plugin): it cannot be checked",
}

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
/** A wrapper of `commandRegex`, as a whole word (`command -v` is told apart by its next word). */
const WRAPPER_WORD = new RegExp(`^(?:${WRAPPERS})$`)
/** The options of `find` that launch the next word, as in `commandRegex`. */
const FIND_EXEC = /^-(?:exec|execdir|ok|okdir)$/
/** A string written as a single quoted piece with a literal value: single quotes, or double quotes without expansion or escape. */
const LITERAL_STRING = /^(?:'[^']*'|"[^"\\$`]*")$/

/**
 * View where the word in command position is reduced to its literal value (choice 1), so that the rules recognize the
 * program actually launched. Built on the view without data (except shell re-entry, where the heredoc read by a shell is
 * normalized, choice 3). A single word scan (`shellEnd`) touches only the first word, leading assignment (`A=1`)
 * skipped, of each top-level command: the quoted text of an argument, read as a single word, remains intact;
 * comments skipped (`#` after a blank or an operator); unclosed word: resume at the next separator or end of line.
 * Literal that would keep a separator: a single word. `flag`, reason for an ask: substitution attached to
 * other characters (program fixed at run time, choice 2; except a substitution alone or followed by a slash);
 * oversized head word (> 1024) with a special character, or exhausted budget (undetermined program), if a special character
 * remains outside heredoc data bodies (`outside`, no body attached to the shell that reads it). Behind a wrapper of
 * `commandRegex` or a `find -exec`, the words it may launch (`reach`: the wrapper's nine, its own bound) are reduced the
 * same way, a nested wrapper renewing the reach (the view is judged additionally: reducing an argument is never less
 * strict). The string after a `-c` option (any program, as `commandRegex` opens there) written as a single literal
 * quoted piece, and bash's `$'…'` after a shell launcher, is replaced by its own view, quoted again (single quotes unless
 * it holds one). Zero cost without a
 * special character; not descended into a substitution (limit). With `levels` above 0 (`viewFindings`), every other word in
 * pieces is reduced too, by the same scan and in the same view (`bareWord`), and the substitutions of a word are read the same
 * way, one level fewer each; the delimiter of a heredoc stays as written (its quotes decide whether the body expands).
 */
function commandWordView(command: string, levels = 0): { view: string; flag?: string } {
  if (!COMMAND_WORD_SPECIAL.test(command)) return { view: command }
  const data = withoutData(command)
  const text = data !== command && !reentersShell(data) ? data : command
  const budget = { left: 8 * text.length + 1024 }
  let [out, cursor, changed, i, head, launcher, flag, mask] = ["", 0, false, 0, true, false, undefined as string | undefined, undefined as string | undefined]
  let [reach, wrapper, string, delimiter] = [0, "", false, false]
  const outside = (from: number, to?: number) => COMMAND_WORD_SPECIAL.test((mask ??= heredocsAreReal(text) ? withoutHeredocBodies(text, false, true) : text).slice(from, to))
  while (i < text.length && budget.left > 0) {
    const c = text[i]!
    if (/[;&|\n({]/.test(c)) [head, launcher, reach, string, i] = [true, false, 0, false, i + 1]
    else if (c === ")") [head, launcher, reach, string, i] = [false, false, 0, false, i + 1]
    else if (/[<>]/.test(c)) {
      delimiter ||= c === "<" && text[i - 1] === "<" && text[i - 2] !== "<" && text[i + 1] !== "<"
      ;[head, launcher, i] = [false, false, i + 1]
    } else if (/\s/.test(c)) i++
    else if (c === "#" && (i === 0 || /[\s;&|()<>]/.test(text[i - 1]!))) i = Math.min(text.indexOf("\n", i) >>> 0, text.length)
    else {
      const subs: Array<readonly [number, number]> = []
      const end = shellEnd(text, i, text.length, budget, false, subs)
      const stop = end < 0 ? stickyEnd(/[^;&|\n]*/y, text, i) : Math.max(end, i + 1)
      const word = text.slice(i, Math.min(stop, i + 1025))
      const small = word.length <= 1024
      const assign = head && /^[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=/.test(word)
      if (head && !assign && !small && end >= 0 && outside(i, stop)) flag ??= UNDETERMINED_WORD_REASON
      const candidate = (head && !assign) || reach > 0
      let rewritten = false
      if (small && ((launcher && word.startsWith("$'")) || (string && LITERAL_STRING.test(word)))) {
        const decoded = dequoteWord(text, i, stop)
        const view = commandWordView(decoded).view
        const quoted = view.includes("'") ? `"${view.replace(/[\\"$`]/g, "\\$&")}"` : `'${view}'`
        if (word.startsWith("$'") || view !== decoded) [out, cursor, changed, rewritten] = [out + text.slice(cursor, i) + quoted, stop, true, true]
      }
      if (!rewritten && candidate && small) {
        const literal = subs.length === 0 ? dequoteWord(text, i, stop) : word
        if (SHELL_LAUNCHER.test(literal)) launcher = true
        if (COMMAND_WORD_SPECIAL.test(word)) {
          if (subs.length === 0) {
            if (literal !== word && literal !== "" && !/[\s;&|()<>`]/.test(literal)) [out, cursor, changed, rewritten] = [out + text.slice(cursor, i) + literal, stop, true, true]
          } else if (head && !assign) {
            const first = subs[0]!
            const before = dequoteWord(text, i, text[first[0] - 1] === "(" ? first[0] - 2 : first[0] - 1)
            const after = subs.length === 1 ? dequoteWord(text, first[1] + 1, stop) : "x"
            if (before !== "" || (after !== "" && after[0] !== "/")) flag ??= RUNTIME_WORD_REASON
          }
        }
      }
      if (levels > 0 && !rewritten && !delimiter && end >= 0 && (subs.length > 0 || /["'\\]/.test(text.slice(i, stop)))) {
        const bare = bareWord(text, i, stop, subs, levels)
        if (bare !== text.slice(i, stop)) [out, cursor, changed] = [out + text.slice(cursor, i) + bare, stop, true]
      }
      delimiter = false
      // Budget exhausted during this word: text unread or misread, from this word to the end.
      if ((budget.left < 0 || (budget.left === 0 && stop < text.length)) && (outside(i) || mask === text)) flag ??= UNDETERMINED_WORD_REASON
      const literal = small && subs.length === 0 ? dequoteWord(text, i, stop) : word
      const name = literal.replace(/^[\\=]/, "").split("/").pop()!
      if (candidate && WRAPPER_WORD.test(name)) [reach, wrapper] = [9, name]
      else if (FIND_EXEC.test(literal)) [reach, wrapper] = [1, ""]
      else if (wrapper === "command" && /^-[a-zA-Z]*[vV]$/.test(literal)) reach = 0
      else if (reach > 0) reach--
      string = /^-[a-zA-Z]*c$/.test(literal)
      ;[head, i] = [assign, stop]
    }
  }
  return { view: changed ? out + text.slice(cursor) : command, flag }
}

const UNCLOSED_WORD = /[^;&|\n]*/y
const COMPUTED_TARGET = /[\s(`]/
/** A program whose own program comes behind its words, written anywhere among them (`find . -exec cmd`, `xargs -n1 cmd`). */
const LATER_PROGRAM = new RegExp(`^(?:find|${WRAPPERS})$`)
/** Substitutions inside each other read by `movedRedirections`; deeper, only `redirectionAtHead` looks at them. */
const MAX_MOVED_LEVELS = 16
/** What ends a simple command for `redirectionAtHead`, `&` of a redirection and `(` of a process substitution apart. */
const COMMAND_END = /(?<![<>])&(?!>)|[;|()`\n]/
const PROCESS_SUBSTITUTION = /[<>]\(/g
const CONTINUED_LINE = /\\\n/g
const LOOSE_QUOTES = /["'\\]/g
/** An escape or a quoted string, for `redirectionAtHead`. */
const QUOTED_TEXT = /\\[^]|"[^"\\]*(?:\\[^][^"\\]*)*"|'[^']*'/g
/** A redirection glued to the word before it (`sudo>x`), for `redirectionAtHead`. */
const GLUED_REDIRECTION = /(?<=[^\s<>&\d])(?=&?[<>])/g
const SHELL_SYNTAX = /[;&|()<>`\n]/
const EXPANDED_TEXT = /^".*[$`]/s

/**
 * Does a redirection stand before the program of a simple command of this text? For text past the reading of
 * `movedRedirections`: a single linear pass over the bare words, with a word in pieces read joined. Quoted syntax is text,
 * except in double quotes with an expansion, which may hold commands (`"$(>x cmd)"`). `flag` of that reading only if this
 * holds: text without such a redirection stays as it is.
 */
function redirectionAtHead(text: string): boolean {
  return text
    .replace(CONTINUED_LINE, " ")
    .replace(QUOTED_TEXT, (quoted) => (SHELL_SYNTAX.test(quoted) && !EXPANDED_TEXT.test(quoted) ? "''" : quoted))
    .replace(PROCESS_SUBSTITUTION, "(")
    .split(COMMAND_END)
    .some((piece) => {
      const state = {}
      let skip = 0
      for (const [word] of piece.replace(GLUED_REDIRECTION, " ").matchAll(/\S+/g)) {
        if (stickyEnd(REDIRECTION_OPERATOR, word, 0) > 0) return true
        if (skip > 0) skip--
        else {
          const step = headStep(word.replace(LOOSE_QUOTES, ""), state)
          if (step <= 0) return false
          skip = step - 1
        }
      }
      return false
    })
}

/**
 * View where the redirections written before the program of a simple command (`>f tee /dev/sda`, `sudo 2>&1 -u bob ls`,
 * `A=1 <<<x sh`), with their targets, stand at the end of that command instead, where the shell reads them the same way:
 * a rule never has to look for the program behind them. On the view without data except shell re-entry, which the move
 * itself may show (`<<E sh`): then read again with the heredoc bodies. Two views if an input has a target with blanks or a
 * substitution: behind the program, for the rules on what a shell reads, and on a line of its own, for the rules on the
 * words of the program. No view if nothing moves. `flag`: a redirection before a program stayed unread, past the budget
 * or the levels of that reading.
 */
function redirectionsBehind(command: string): { views: string[]; flag?: string } {
  if (!/[<>]/.test(command)) return { views: [] }
  const data = withoutData(command)
  const text = data !== command && !reentersShell(data) ? data : command
  const reading = (inputsApart: boolean) => {
    const read = movedRedirections(text, inputsApart)
    return text !== command && read.moved && reentersShell(read.view) ? movedRedirections(command, inputsApart) : read
  }
  const read = reading(false)
  const views = !read.moved ? [] : read.computedInput ? [read.view, reading(true).view] : [read.view]
  return { views, ...(read.unread ? { flag: UNDETERMINED_WORD_REASON } : {}) }
}

/**
 * The reading of `redirectionsBehind`: every simple command by words (`shellEnd`, comments skipped), inside substitutions
 * too, so quoted text stays as it is; a redirection with no word after it does not count as `moved`. `unread`: what the
 * budget or `MAX_MOVED_LEVELS` left unread holds a redirection before a program (`redirectionAtHead`). Linear cost: each
 * level of substitution rereads its text, a `(` left open is tried once, and the budget pays for all the levels. Behind
 * `find`, `xargs` and the other launchers of `WRAPPER_WORD`, every redirection moves, since their program comes later.
 * `computedInput`: an input with blanks or a substitution in its target stands behind the program, or on a line of its
 * own with `inputsApart`.
 */
function movedRedirections(text: string, inputsApart: boolean): { view: string; moved: boolean; unread: boolean; computedInput: boolean } {
  const budget = { left: (MAX_MOVED_LEVELS + 8) * text.length + 1024 }
  const lines: string[] = []
  let [moved, deep, unclosed, computedInput] = [false, false, -1, false]
  let spentAt: number | undefined
  /** The word at `i`, as `shellEnd` reads it, or a process substitution; `written`: with the view of its substitutions. */
  const wordAt = (i: number, to: number, level: number) => {
    const subs: Array<readonly [number, number]> = []
    const substitution = /[<>]/.test(text[i] ?? "") && text[i + 1] === "("
    const end = substitution ? shellEnd(text, i + 1, to, budget, true) : shellEnd(text, i, to, budget, false, subs)
    // Glued to a word, a `(` stays in it (`A=(a b)`, `f()`, `awk {print($1)}`).
    let glued = -1
    if (end > i && text[end] === "(" && to !== unclosed) {
      glued = shellEnd(text, end, to, budget, true)
      if (glued < 0) unclosed = to
    }
    if (budget.left <= 0) spentAt ??= i
    const stop = Math.min(glued >= 0 ? glued : end < 0 ? stickyEnd(UNCLOSED_WORD, text, i) : end, to)
    if (substitution && stop > i + 2) subs.push([i + 2, Math.max(text.lastIndexOf(")", stop - 1), i + 2)])
    let [written, at] = ["", i]
    for (const [start, close] of subs) {
      const body = text.slice(start, close)
      const read = /[<>]/.test(body) && level < MAX_MOVED_LEVELS
      deep ||= !read && redirectionAtHead(body)
      ;[written, at] = [written + text.slice(at, start) + (read ? scan(start, close, level + 1) : body), close]
    }
    return { stop, literal: subs.length ? undefined : dequoteWord(text, i, stop), written: written + text.slice(at, stop) }
  }
  const scan = (from: number, to: number, level: number): string => {
    let [out, cursor, inputs, held, pending, words, head, launcher, skip, i] = ["", from, "", "", false, false, true, false, 0, from]
    let [xargsWords, firstLine, state] = [undefined as string[] | undefined, lines.length, {}]
    const copy = (start: number, stop: number, written: string) => {
      ;[out, cursor] = [out + text.slice(cursor, start) + written, stop]
    }
    const endCommand = (at: number) => {
      moved ||= words
      // Behind `xargs` alone a target goes back on its line: on a line of its own it would make the form that asks (`xargsDynamic`).
      if (xargsWords && xargsInfo(xargsWords).start >= xargsWords.length) held += lines.splice(firstLine).join("")
      copy(at, at, `${inputs}${held}${text[at] === "#" ? " " : ""}`)
      ;[inputs, held, pending, words, head, launcher, skip, state] = ["", "", false, false, true, false, 0, {}]
      ;[xargsWords, firstLine] = [undefined, lines.length]
    }
    while (i < to && budget.left > 0) {
      const c = text[i]!
      const substitution = (c === "<" || c === ">") && text[i + 1] === "("
      const operator = /[\d{&<>]/.test(c) && !substitution ? stickyEnd(REDIRECTION_OPERATOR, text, i) : i
      if (operator > i) {
        const start = stickyEnd(WORD_GAP, text, operator)
        const { stop, written } = wordAt(start, to, level)
        if (head || launcher) {
          // Glued to the word before it (`sudo>x ls`), which must not join the next one.
          copy(i, stickyEnd(WORD_GAP, text, stop), i > 0 && /\S/.test(text[i - 1]!) ? " " : "")
          pending = true
          const redirection = ` ${text.slice(i, start)}${written}`
          const computed = COMPUTED_TARGET.test(written)
          const input = text.slice(i, operator).includes("<")
          computedInput ||= computed && input
          // Input first: a reader may end at a descriptor (`bash 2>&1 < $F`). A target with blanks or a substitution would
          // stop the readers of the last word: an output goes to a line of its own, an input behind the program or there.
          if (computed && (!input || inputsApart)) lines.push(redirection)
          else if (!input) held += redirection
          else if (computed) inputs += redirection
          else held = `${redirection}${held}`
        } else copy(start, stop, written)
        i = Math.max(stop, operator)
      } else if (/[;&|\n()]/.test(c)) {
        // Before a group the shell refuses a redirection, but it may stand for what the group runs.
        if (c !== "(" || !head || !pending) endCommand(i)
        i++
      } else if (/\s/.test(c)) i++
      else if (c === "\\" && text[i + 1] === "\n") i += 2
      else if (c === "#" && (i === 0 || COMMENT_BEFORE.test(text[i - 1]!))) {
        endCommand(i)
        i = Math.min(text.indexOf("\n", i) >>> 0, to)
      } else {
        const { stop, literal, written } = wordAt(i, to, level)
        words ||= pending
        if (literal === "{") head = true
        else if (head && skip > 0) skip--
        else if (head) {
          const step = substitution || literal === undefined ? 0 : headStep(literal, state)
          ;[head, skip] = [step > 0, Math.max(step - 1, 0)]
          const program = step === 0 && literal !== undefined ? commandName(literal) : ""
          launcher = LATER_PROGRAM.test(program)
          if (program === "xargs") xargsWords = []
        } else xargsWords?.push(literal ?? written)
        copy(i, stop, head ? written : `${written}${inputs}`)
        if (!head) inputs = ""
        i = Math.max(stop, i + 1)
      }
    }
    endCommand(to)
    return out
  }
  const view = scan(0, text.length, 0)
  return { view: [view, ...lines].join("\n"), moved, computedInput, unread: deep || (spentAt !== undefined && redirectionAtHead(text.slice(spentAt))) }
}

/** In the value of a piece of a word: the word is not a word once read bare, so it stays as it is. */
const NOT_BARE_WORD = /[\s;&|()<>]/
/** In the value of a piece of a word: bare, it would mean something else (expansion, joker, `~`, comment), so that piece stays written. */
const KEPT_PIECE = /["'`$\\*?[\]{}~#!]/

/**
 * The word `text[i..stop)` as the rules should read it: a word in pieces (`.e""nv`, `/e'tc'/y`, `--f\orce`, `$'/'`) becomes
 * its value, so that one reading serves every rule. A word that is one `"…"` or `'…'` keeps its quotes and what it counts today,
 * and a piece of value with a blank or an operator leaves the whole word as it is: quoted text never turns into commands.
 * What the shell expands stays where it is, written, so a word with `$HOME` or a joker still loses its other pieces; a piece
 * glued to a `$NAME` stays written too (it would change the name). The bodies of substitutions are read by `commandWordView`.
 */
function bareWord(text: string, i: number, stop: number, subs: ReadonlyArray<readonly [number, number]>, levels: number): string {
  const bodies = new Map(subs.map(([start, end], index) => [start, { end, index }]))
  const views = subs.map(([start, end]) => (levels > 1 ? commandWordView(text.slice(start, end), levels - 1).view : text.slice(start, end)))
  let next = 0
  const written = (from: number, to: number) => {
    let [copied, at] = ["", from]
    for (; next < subs.length && subs[next]![1] <= to; next++) [copied, at] = [copied + text.slice(at, subs[next]![0]) + views[next], subs[next]![1]]
    return copied + text.slice(at, to)
  }
  const unchanged = () => {
    next = 0
    return written(i, stop)
  }
  let [out, j, pieces, others, parameter] = ["", i, 0, false, false]
  while (j < stop) {
    const c = text[j]!
    const prefixed = c === "$" && (text[j + 1] === "'" || text[j + 1] === '"')
    const sub = c === "`" ? bodies.get(j + 1) : c === "$" && text[j + 1] === "(" ? bodies.get(j + 2) : undefined
    if (c === "\\" || c === "'" || c === '"' || prefixed) {
      const from = j
      let held = false
      if (c === "\\") j += 2
      else {
        const close = prefixed ? text[j + 1]! : c
        for (j += prefixed ? 2 : 1; j < stop && text[j] !== close; ) {
          const inner = close !== '"' ? undefined : text[j] === "`" ? bodies.get(j + 1) : text[j] === "$" && text[j + 1] === "(" ? bodies.get(j + 2) : undefined
          if (inner) [held, j] = [true, inner.end + 1]
          else j += close === "'" && !prefixed ? 1 : text[j] === "\\" ? 2 : 1
        }
        j++
      }
      const value = dequoteWord(text, from, Math.min(j, stop))
      if (!held && NOT_BARE_WORD.test(value)) return unchanged()
      pieces += c === "\\" || prefixed ? 2 : 1
      out += KEPT_PIECE.test(value) || (parameter && !/^\W/.test(value)) ? written(from, Math.min(j, stop)) : value
      parameter = false
    } else if (sub) {
      out += written(j, sub.end + 1)
      ;[others, parameter, j] = [true, false, sub.end + 1]
    } else {
      parameter = c === "$" ? /\w/.test(text[j + 1] ?? "") : parameter && /\w/.test(c)
      out += c
      others = true
      j++
    }
  }
  return out === "" || pieces === 0 || (pieces === 1 && !others) ? unchanged() : out
}

const ENV_WORD = /(?<![\w.$-])env["']?(?=\s)/g
/** `-S`, in a group of letters that take no value, or `--split-string` possibly abbreviated; a string attached to it follows. */
const SPLIT_OPTION = /^(?:-[iv0]*S|--s[a-z-]*(?:=|$))/
/**
 * Text that may hold such an option, in any writing of the shell: quotes, a `\` or a `$` between its characters (`-""Srm`,
 * `--""split-string=`, `-i\S`), or a `$'…'` with an escape, which can spell any of them (`$'\x2dSrm'`).
 */
const SPLIT_HINT = /-[iv0"'\\$]*S|-["'\\$]*-["'\\$]*s|\$'[^']*\\/
const BLANKS = /\s*/y
/** Redirection between `env` and its options: the shell takes it away (`env 2>/dev/null -S…`). */
const REDIRECTION_OPERATOR = /(?:\d*|\{[A-Za-z_]\w*\})(?:&>>?|<<-|[<>]{1,3}[&|]?)/y
const OPTION_START = /["'\\]*-/y
/** Strings of `env -S` inside each other read at most this many times; deeper, `UNSTABLE_SPLIT`. */
const MAX_SPLIT_PASSES = 3

/** The command with the strings read as words; `unread`: a string may remain that could not be read. */
interface SplitView {
  readonly view: string
  readonly unread: boolean
}

/**
 * The command with the option of each `env -S <string>` replaced by the string, as words: every form the shell gives to
 * that word (`-Srm -rf /`, `"-Srm -rf /"`, `-S"a b"`, `--split-string=…`, abbreviated too) reads as the program it runs,
 * for the rules that read the text as well. `\_`, a line break or a carriage return is a blank in such a string. One scan:
 * each word is read once, and a word that cannot be read, in a `-c` string or past the budget, stays marked `unread`.
 */
function splitStringPass(command: string): SplitView {
  const budget = { left: 8 * command.length + 1024 }
  const wordEnd = (start: number) => shellEnd(command, start, command.length, budget, false)
  let [out, cursor, read, unread] = ["", 0, 0, false]
  scan: for (const { index, 0: name } of command.matchAll(ENV_WORD)) {
    if (index < read) continue
    read = index + name.length
    for (;;) {
      const start = stickyEnd(BLANKS, command, read)
      const operator = stickyEnd(REDIRECTION_OPERATOR, command, start)
      if (operator > start) {
        read = Math.max(wordEnd(stickyEnd(BLANKS, command, operator)), operator)
        continue
      }
      const end = wordEnd(start)
      if (budget.left <= 0) {
        unread ||= SPLIT_HINT.test(command.slice(start))
        break scan
      }
      if (end < 0) unread ||= stickyEnd(OPTION_START, command, start) > 0
      if (end <= start) break
      const word = dequoteWord(command, start, end)
      const option = SPLIT_OPTION.exec(word)?.[0]
      if (option !== undefined && (!option.startsWith("--") || "--split-string".startsWith(option.replace("=", "")))) {
        const attached = word.slice(option.length)
        const from = stickyEnd(BLANKS, command, end)
        const closed = attached ? end : wordEnd(from)
        const to = Math.max(closed, end)
        const string = attached || (to > from ? dequoteWord(command, from, to) : "")
        unread ||= closed < 0 || /\\["']/.test(command.slice(start, to))
        ;[out, cursor, read] = [out + command.slice(cursor, start) + string.replace(/\\_|[\n\r]/g, " "), to, to]
        break
      }
      if (!word.startsWith("-")) break
      read = end
      if (valueFollows(word, PREFIX_OPTIONS.env!)) {
        const value = stickyEnd(BLANKS, command, end)
        read = Math.max(wordEnd(value), end)
      }
    }
  }
  return { view: cursor === 0 ? command : out + command.slice(cursor), unread }
}

/** The command with the strings of `env -S` read as words (`splitStringPass`), the command itself without any. */
function splitStrings(command: string): SplitView {
  if (!SPLIT_HINT.test(command)) return { view: command, unread: false }
  let { view, unread } = splitStringPass(command)
  const next = (text: string) => {
    const pass = splitStringPass(text)
    unread ||= pass.unread
    return pass.view
  }
  if (view === command) {
    // A program word in pieces (`e"n"v`): only then the reduced view, which takes one level of quotes off the string too.
    const reduced = commandWordView(command).view
    view = next(reduced)
    if (view === reduced) return { view: command, unread }
  }
  for (let pass = 1; pass < MAX_SPLIT_PASSES; pass++) view = next(view)
  return { view, unread }
}

/** Ask of a `-c` code that is not read: nested too deep, or past the reading budget. Always active. */
const UNSTABLE_SHELL_CODE: Finding = {
  verdict: "ask",
  rule: "nested-opencode",
  reason: `the code given to a shell by \`-c\` is nested more than ${MAX_SHELL_LEVELS} levels deep, or too complex for the plugin to read: what it runs cannot be checked`,
}

/**
 * Views of `-c` codes read for one command, all levels together (levels multiply): each costs a full examination even
 * for a few words, the text of all of them staying within three times the command. A command with this many codes that
 * cannot be joined (mostly heredocs) is written to be hard to read; past it, an ask.
 */
const MAX_SHELL_READS = 32
/** Text that may hold a shell's `-c`: elsewhere, zero cost. */
const SHELL_CODE_HINT = /-[a-zA-Z"'\\]*c/
/** A character after which `#` opens a comment. */
const COMMENT_BEFORE = /[\s;&|()<>]/
/** A wrapper's duration, as in `commandOf`. */
const TIMEOUT_DURATION = /^\d+(?:\.\d+)?[smhd]?$/
/** How many words behind a wrapper without known options the shell is looked for, the reach of `commandRegex`. */
const WRAPPER_REACH = 9

/** A word of a simple command, as written: `subs`, the bodies of its outermost substitutions. */
interface ShellWord {
  readonly start: number
  readonly stop: number
  readonly subs: ReadonlyArray<readonly [number, number]>
}

/** A word that assigns (`A=1`, `A+=1`, `A[0]=1`), read as `withoutAssignments` reads it. */
const assignmentWord = (token: string) => assignedName(token, 0, {}) > 0

/** Option of `env` whose value is the next word, grouped behind flags (`-iu V`) or abbreviated (`--un V`). */
const envTakesValue = (token: string) => /^-[iv0]*[uCa]$/.test(token) || (!token.includes("=") && ["unset", "chdir", "argv0"].some((name) => isLongOption(token, name)))

/**
 * One word before the program of a simple command, read as `commandOf` reads it: how many words it takes (the value of a
 * wrapper's option counts), 0 if it is the program, -1 for `command -v`. `state`: the wrapper being read.
 */
function headStep(token: string, state: { wrapper?: string | undefined }): number {
  if (GROUPING_WORDS.has(token) || assignmentWord(token)) return 1
  if (Object.hasOwn(PREFIX_OPTIONS, commandName(token))) {
    state.wrapper = commandName(token)
    return 1
  }
  const { wrapper } = state
  if (wrapper === "command" && /^-[a-zA-Z]*[vV]$/.test(token)) return -1
  if (wrapper && token.startsWith("-") && (token !== "-" || wrapper === "env")) return PREFIX_OPTIONS[wrapper]!.has(token) || (wrapper === "env" && envTakesValue(token)) ? 2 : 1
  if (wrapper === "timeout" && TIMEOUT_DURATION.test(token)) {
    state.wrapper = undefined
    return 1
  }
  return 0
}

/** Indexes of the program a simple command launches behind its structural words, assignments and wrappers (`commandOf`), -1 for `command -v`. */
function launchedWord(literal: (index: number) => string | undefined, from: number): number {
  const state = {}
  for (let i = from; ; ) {
    const token = literal(i)
    if (token === undefined) return i
    const step = headStep(token, state)
    if (step <= 0) return step < 0 ? -1 : i
    i += step
  }
}

/**
 * Codes of the shells a simple command launches, each with the positional words that follow it, written as they are (its
 * command may name them, `"$1"`): at its program, behind a wrapper of `commandRegex`, after each `-exec` of `find`. A
 * word used as a code leaves `used`: its substitutions are read with it, on the next level.
 */
function simpleCommandCodes(text: string, words: readonly ShellWord[], used: Set<ShellWord>): string[] {
  const literals = new Map<number, string>()
  const literal = (index: number) => {
    const word = words[index]
    if (!word) return undefined
    let value = literals.get(index)
    if (value === undefined) literals.set(index, (value = dequoteWord(text, word.start, word.stop)))
    return value
  }
  const codes: string[] = []
  const shellAt = (program: number, end: number) => {
    const args: string[] = []
    for (let i = program + 1; i < end; i++) args.push(literal(i)!)
    const offset = shellCodeWord(args)
    if (offset < 0) return false
    const code = program + 1 + offset
    used.add(words[code]!)
    codes.push([literal(code)!, ...words.slice(code + 1, end).map((word) => text.slice(word.start, word.stop))].join(" "))
    return true
  }
  const launched = (from: number, end: number) => {
    const program = launchedWord(literal, from)
    const name = program >= 0 && program < end ? commandName(literal(program)!) : ""
    if (DYNAMIC_SHELLS.has(name)) shellAt(program, end)
    else if (WRAPPER_WORD.test(name))
      for (let i = program + 1; i < Math.min(end, program + 1 + WRAPPER_REACH); i++) {
        if (DYNAMIC_SHELLS.has(commandName(literal(i)!))) {
          shellAt(i, end)
          break
        }
      }
    return name
  }
  if (launched(0, words.length) === "find")
    for (let i = 1; i < words.length; i++) {
      if (!FIND_EXEC.test(literal(i)!)) continue
      let end = i + 1
      while (end < words.length && !/^[;+]$/.test(literal(end)!)) end++
      launched(i + 1, end)
      i = end
    }
  return codes
}

/** A heredoc or here-string operator, split by a continued line or not: such a code is never joined. */
const HEREDOC_OPERATOR = /<(?:\\\n)*</

/** Whether the scan of a code stops cleanly at its end: no open quote or substitution, no final `\`, no heredoc (`HEREDOC_OPERATOR`). Comments skipped. */
function codeIsClosed(code: string): boolean {
  if (HEREDOC_OPERATOR.test(code)) return false
  for (let i = 0; i < code.length; ) {
    if (code[i] === "#" && (i === 0 || COMMENT_BEFORE.test(code[i - 1]!))) i = Math.min(code.indexOf("\n", i) >>> 0, code.length)
    else {
      const end = shellEnd(code, i, code.length, { left: Infinity }, false)
      if (end < 0) return false
      i = Math.max(end, i + 1)
    }
  }
  return true
}

/**
 * The codes of the shells a command launches (`sh -c`, `bash -lc`, `-e -c --`…), one level. The shell runs each code
 * apart, so only codes that stop cleanly (`codeIsClosed`, `closed`) can be joined by lines, one view; any other (`open`)
 * would swallow what follows it and is a view of its own. A scan by words (`shellEnd`) over the command without
 * heredoc bodies: the quoted text of an argument, read as a single word, stays an argument (`echo 'bash -c "x"'`), and the
 * substitutions of a word are read as commands, bounded by `MAX_SHELL_LEVELS`. `unread`: a substitution deeper than that
 * holds a `-c`, or the reading budget ran out.
 */
function shellCodeViews(command: string): { closed: string[]; open: string[]; unread: boolean } {
  const text = command.includes("<<") && heredocsAreReal(command) ? withoutHeredocBodies(command, false, true) : command
  const budget = { left: 8 * text.length + 1024 }
  const codes: string[] = []
  const pending: Array<readonly [number, number, number]> = [[0, text.length, 0]]
  let unread = false
  for (let range = pending.pop(); range; range = pending.pop()) {
    const [from, to, depth] = range
    let words: ShellWord[] = []
    let target = false
    const flush = () => {
      const used = new Set<ShellWord>()
      if (words.length) codes.push(...simpleCommandCodes(text, words, used))
      for (const word of words)
        if (!used.has(word))
          for (const [start, end] of word.subs) {
            if (depth < MAX_SHELL_LEVELS) pending.push([start, end, depth + 1])
            else unread ||= SHELL_CODE_HINT.test(text.slice(start, end))
          }
      ;[words, target] = [[], false]
    }
    for (let i = from; i < to && budget.left > 0; ) {
      const c = text[i]!
      const operator = c === "&" || c === "<" || c === ">" || c === "{" ? stickyEnd(REDIRECTION_OPERATOR, text, i) : i
      if (operator > i) [target, i] = [true, operator]
      else if (/[;&|\n(){]/.test(c)) {
        flush()
        i++
      } else if (/\s/.test(c)) i++
      else if (c === "#" && (i === 0 || COMMENT_BEFORE.test(text[i - 1]!))) i = Math.min(text.indexOf("\n", i) >>> 0, to)
      else {
        const subs: Array<readonly [number, number]> = []
        const end = shellEnd(text, i, to, budget, false, subs)
        const stop = Math.min(end < 0 ? stickyEnd(/[^;&|\n]*/y, text, i) : Math.max(end, i + 1), to)
        const descriptor = /[<>]/.test(text[stop] ?? "") && /^\d+$/.test(text.slice(i, stop))
        if (!target && !descriptor) words.push({ start: i, stop, subs })
        else if (subs.length) words.push({ start: stop, stop, subs })
        ;[target, i] = [false, stop]
      }
    }
    if (budget.left <= 0) unread = true
    flush()
  }
  const [closed, open]: string[][] = [[], []]
  for (const code of codes) (codeIsClosed(code) ? closed : open).push(code)
  return { closed, open, unread }
}

/** Programs that print a file as it is, the bytes of a document or an image included. */
const RAW_READERS = new Set(["cat", "base64", "xxd", "hexdump", "od", "strings", "head", "tail"])

/** Options of a reader that take a value: a number or a format, never a file it prints (`base64 -o`: the file it writes). */
const READER_VALUES: ReadonlyMap<string, RegExp> = new Map([
  ["head", /^-[cn]$|^--(?:bytes|lines)$/],
  ["tail", /^-[cn]$|^--(?:bytes|lines)$/],
  ["base64", /^-o$|^--output$/],
  ["xxd", /^-(?:c|cols|g|groupsize|l|len|n|name|o|s|seek|R)$/],
  ["od", /^-[AjNSt]$/],
  ["hexdump", /^-[ens]$/],
  ["strings", /^-[nt]$/],
])

/** Value of a word as written: without its quotes and escapes (the words in pieces are also read in `commandWordView`). */
const wordValue = (word: string) => cleanTarget(word.replace(/\\(.)/gs, "$1").replace(/\$(?=['"])/g, "")).replace(/`$/, "")

/** Operands of a reader: any word that is neither an option nor its value, every word after `--`; `xxd infile outfile` writes the second. */
function readerOperands(name: string, args: readonly string[]): string[] {
  const end = args.indexOf("--")
  const operands = args.filter((word, index) => (end >= 0 && index > end) || (!word.startsWith("-") && !READER_VALUES.get(name)?.test(args[index - 1] ?? "")))
  return name === "xxd" ? operands.slice(0, 1) : operands
}

/**
 * Is a file `names` accepts printed by a program of `RAW_READERS`, as an operand or on its input (`<`, `<>`), or by the shell
 * itself (`$(<file)`)? A scan by words (`shellEnd`) over the command without heredoc bodies, like `shellCodeViews`: quoted text
 * stays an argument, the output of a redirection is not read, substitutions are read as commands. A statement (up to `;`,
 * `&`, `&&`, `||` or a line end, outside a group; a pipeline stays whole) that launches a shell (`bash <<E`, `echo '…' | sh`,
 * `watch '…'`) runs what it is given: its heredoc bodies, each of its quoted strings and what `echo` pipes are read as
 * commands too, each statement again by itself. Budget run out: yes, nothing was read to its end.
 */
function printsRawFile(command: string, names: (file: string) => boolean): boolean {
  const bodies: Array<readonly [number, number, number]> = []
  const text = command.includes("<<") && heredocsAreReal(command) ? withoutHeredocBodies(command, false, true, bodies) : command
  const budget = { left: 8 * command.length + 1024 }
  let body = 0
  const pending: Array<readonly [string, number, number, boolean]> = [[text, 0, text.length, false]]
  for (let range = pending.pop(); range; range = pending.pop()) {
    const [source, from, to, fedOutside] = range
    let [words, inputs]: string[][] = [[], []]
    let target: "input" | "other" | undefined
    // Where the statement starts, its groups still open, the last separator a pipe, the first operand of the current command.
    let [start, depth, afterPipe] = [from, 0, false]
    let operand: number | undefined
    // What the statement holds: substitutions, read in any case; what only a shell it launches would run.
    let [subs, fedText]: Array<readonly [number, number]>[] = [[], []]
    const prints = (piped?: number) => {
      const { name, args } = commandOfWords(words)
      const read = (RAW_READERS.has(name) && [...readerOperands(name, args), ...inputs].some(names)) || (from > 0 && !name && inputs.some(names))
      if (piped !== undefined && operand !== undefined && (name === "echo" || name === "printf")) fedText.push([operand, piped])
      ;[words, inputs, target, operand] = [[], [], undefined, undefined]
      return read
    }
    const endStatement = (end: number) => {
      let next = body
      while (next < bodies.length && bodies[next]![0] < end) next++
      if (subs.length || fedText.length || next > body) {
        budget.left -= end - start
        const fed = fedOutside || reentersShell(withoutData(source.slice(start, end).replace(/(^|[;&|(\n])[^\S\n]*(?:then|do|else)\s+/g, "$1").replace(/<+/g, " $&")))
        for (const [a, b] of subs) pending.push([source, a, b, fed])
        if (fed) {
          for (const [a, b] of fedText) pending.push([source, a, b, false])
          for (const [, a, b] of bodies.slice(body, next)) pending.push([command, a, b, false])
        }
      }
      ;[subs, fedText, body, start] = [[], [], next, end + 1]
    }
    for (let i = from; i < to && budget.left > 0; ) {
      const c = source[i]!
      const operator = c === "&" || c === "<" || c === ">" ? stickyEnd(REDIRECTION_OPERATOR, source, i) : i
      // `<(…)`: read as a command; the words around it stay those of its command.
      if ((c === "<" || c === ">") && source[i + 1] === "(") {
        const end = shellEnd(source, i + 1, to, budget, true)
        if (end < 0) return true
        subs.push([i + 2, end])
        i = end
      } else if (operator > i) {
        target = /^\d*<>?$/.test(source.slice(i, operator)) ? "input" : "other"
        i = operator
      } else if (/[;&|\n()]/.test(c)) {
        const pipe = c === "|" && source[i + 1] !== "|" && source[i - 1] !== "|"
        if (prints(pipe ? i : undefined)) return true
        depth = c === "(" ? depth + 1 : c === ")" ? Math.max(0, depth - 1) : depth
        const ends = c === ";" || (c === "\n" && !afterPipe) || (c === "&" && source[i - 1] !== "|") || (c === "|" && !pipe)
        if (ends && !depth) endStatement(i)
        if (c !== "\n") afterPipe = pipe
        i++
      } else if (/\s/.test(c)) i++
      else if (c === "#" && (i === 0 || COMMENT_BEFORE.test(source[i - 1]!))) i = Math.min(source.indexOf("\n", i) >>> 0, to)
      else {
        const found: Array<readonly [number, number]> = []
        const end = shellEnd(source, i, to, budget, false, found)
        const stop = Math.min(end < 0 ? stickyEnd(/[^;&|\n]*/y, source, i) : Math.max(end, i + 1), to)
        subs.push(...found)
        if (stop - i > 2 && /['"]/.test(source[i]!) && source[stop - 1] === source[i]) fedText.push([i + 1, stop - 1])
        const written = source.slice(i, stop)
        const word = wordValue(written)
        // A group opens and closes where a command starts; `done` as an argument is a word.
        if (!words.length && !target) depth = /^(?:\{|do|then)$/.test(written) ? depth + 1 : /^(?:\}|done|fi)$/.test(written) ? Math.max(0, depth - 1) : depth
        if (target === "input") inputs.push(word)
        else if (!target && !(/[<>]/.test(source[stop] ?? "") && /^\d+$/.test(word))) {
          if (words.length && !word.startsWith("-")) operand ??= i
          words.push(word)
        }
        target = undefined
        afterPipe = false
        i = stop
      }
    }
    if (budget.left <= 0 || prints()) return true
    endStatement(to)
  }
  return false
}

/** One examination of a command across the levels of its `-c` codes: `reads` left; `held`, what the rules lifted inside a code. */
interface CodeReading {
  reads: number
  readonly held: Waiver[]
  /** The reading of a code that only a view of the command shows: its own `MAX_SHELL_READS`, also for what that code holds. */
  readonly behind?: CodeReading
}

function newReading(): CodeReading {
  const held: Waiver[] = []
  return { reads: MAX_SHELL_READS, held, behind: { reads: MAX_SHELL_READS, held } }
}

/**
 * Finding of the code of the `-c` of the shells a command launches (`shellCodeViews`), from each of its `commands`, the
 * texts of `viewsFinding`, the first being the command as written: each view read as a command by the
 * whole composition of the views, under the same context, to `MAX_SHELL_LEVELS`, the strongest kept (`strength`). Deeper,
 * past `MAX_SHELL_READS` for the whole command, or not read to its end: an ask never left to the decision model
 * (`UNSTABLE_SHELL_CODE`). A finding lifted inside a code is only held: another view may still ask for it (`shellFinding`).
 */
function shellCodeFinding(commands: ReadonlySet<string>, ctx: ShellRuleContext, level: number, reading: CodeReading): Finding | undefined {
  const [first, ...others] = [...commands].map((command) => (SHELL_CODE_HINT.test(command) ? shellCodeViews(command) : { closed: [], open: [], unread: false }))
  if (!first) return undefined
  // The first text is read as if alone, on the bound of `reading`, so what the others show never takes a reading from it.
  const seen = new Set([...first.closed, ...first.open])
  const added = (codes: readonly string[]) => codes.filter((code) => !seen.has(code))
  const [closed, open]: string[][] = [[], []]
  for (const text of others) {
    closed.push(...added(text.closed))
    open.push(...added(text.open))
    for (const code of [...text.closed, ...text.open]) seen.add(code)
  }
  const viewsOf = (codes: { closed: readonly string[]; open: readonly string[] }) => [...(codes.closed.length ? [codes.closed.join("\n")] : []), ...codes.open]
  let unfinished = first.unread || others.some((text) => text.unread)
  let found: Finding | undefined
  const inner: ShellRuleContext = { ...ctx, waived: (waiver) => reading.held.push(waiver) }
  for (const [views, bound] of [[viewsOf(first), reading], [viewsOf({ closed, open }), reading.behind ?? reading]] as const)
    for (const view of views) {
      if (level >= MAX_SHELL_LEVELS || bound.reads <= 0) {
        unfinished = true
        break
      }
      bound.reads--
      const read = viewsFinding(view, inner, level + 1, bound)
      if (strength(read) > strength(found)) found = read
      if (found?.verdict === "deny") return found
    }
  const unstable = unfinished ? hardened(UNSTABLE_SHELL_CODE, ctx.active) : undefined
  return strength(unstable) > strength(found) ? unstable : found
}

/**
 * Shell finding: finding of the rules (`priorShellFinding`, kept word for word), then, without a deny and if the cost guard
 * allows it (`layerGuard`), layer of indirectly designated devices (`deviceLayer`). The strongest wins
 * (`strength`); at equal strength, the existing finding is returned as is. Then the same examination of the view without leading
 * assignments (`assignedFinding`), of the view of the word in command position reduced to its literal value (`commandWordView`,
 * judged additionally; at equal verdict, the original finding is kept with its mark), and of the view with the redirections
 * written before a program behind it (`redirectionsBehind`), then the same examination, once
 * and without a new joining, of the command with the lines the shell continues joined (`joinedLines`) and the strings of
 * `env -S` read as words (`splitStrings`), judged additionally (linear cost). A view that a new reading would still change
 * (reading not stable), or a string of `env -S` not read to its end: ask (`UNSTABLE_JOIN`, `UNSTABLE_SPLIT`). Internal error of these layers: findings already obtained kept, prudent ask added
 * (`ANALYSIS_FAILED`), in its own place for the joined view. The findings of the joined view, of its unstable reading
 * and of its error come after those of the original view, by `strength` (deny, ask without a mark, ask that the model
 * can decide): at equal strength, the finding of the original view is kept. The code of a shell's `-c`, read on the
 * joined view and on the joined text of each of these redirection views (`shellCodeFinding`), comes last in the same way; `level`: how many such codes this text is inside.
 */
function viewsFinding(command: string, ctx: ShellRuleContext, level: number, reading: CodeReading): Finding | undefined {
  const { found: findings, moved = [] } = viewFindings(command, ctx)
  const severe = mostSevere(findings)
  if (severe?.verdict === "deny") return severe
  let [continued, unstable, failed]: Array<Finding | undefined> = []
  const texts = new Set<string>()
  try {
    const first = joinedFinding(command, ctx)
    ;({ continued, unstable } = first)
    texts.add(first.lines)
    // A redirection before the program hides the word of `env -S` and the `-c` of a shell from these readings: once more
    // with it behind, as read by `viewFindings`. An input behind the program may hide them in turn, so every text is read.
    for (const view of moved) {
      const behind = joinedFinding(view, ctx)
      texts.add(behind.lines)
      continued = strength(behind.continued) > strength(continued) ? behind.continued : continued
      unstable ??= behind.unstable
    }
  } catch {
    failed = hardened(ANALYSIS_FAILED, ctx.active)
    texts.add(command)
  }
  // Findings of the original view first, in their order; an added finding takes the place only if it is stronger.
  const found = [continued, unstable, failed].reduce((kept, added) => (strength(added) > strength(kept) ? added : kept), severe)
  if (found?.verdict === "deny") return found
  try {
    const inner = shellCodeFinding(texts, ctx, level, reading)
    return strength(inner) > strength(found) ? inner : found
  } catch {
    return strength(found) >= 2 ? found : hardened(ANALYSIS_FAILED, ctx.active)
  }
}

/**
 * Shell finding (`viewsFinding`), then the deny of a rule set to `ask` (`ruleOverrides`) lowered, once, here: inside, it
 * stays a deny, which early exits and first matches can return in place of another rule's. The command is then
 * examined again with the rules set to `ask` turned off (same call predicates, memoized: no new read of an already
 * read path); a deny found then holds, otherwise the lowered ask, without a mark (the user is asked). What the rules
 * lifted inside a `-c` code is reported only if the command gets no finding at all, what a reading lifted unless the
 * command gets a finding of that same rule from another one.
 */
export function shellFinding(command: string, ctx: ShellRuleContext): Finding | undefined {
  const lifted: Waiver[] = []
  const found = heldShellFinding(command, ctx.waived ? { ...ctx, waived: (waiver) => lifted.push(waiver) } : ctx)
  for (const waiver of lifted) if (waiver.rule !== found?.rule) ctx.waived?.(waiver)
  return found
}

/** `shellFinding`, what the rules lift reported to `ctx.waived` as it happens. */
function heldShellFinding(command: string, ctx: ShellRuleContext): Finding | undefined {
  ctx = { ...ctx, written: command }
  const reading = newReading()
  const found = viewsFinding(command, ctx, 0, reading)
  if (!found) for (const waiver of reading.held) ctx.waived?.(waiver)
  if (found?.verdict !== "deny" || overrideOf(found.rule, ctx.active) !== "ask") return found
  const other = viewsFinding(command, { ...ctx, active: ctx.active && withoutLowered(ctx.active) }, 0, newReading())
  return other?.verdict === "deny" ? other : { verdict: "ask", rule: found.rule, reason: found.reason }
}

/** Rules the equivalent shell form of inline interpreter code is judged for (`interpreterCodeView`): the others judge the command alone. */
const CODE_VIEW_RULES: ReadonlySet<string> = new Set(["guard-cli", "nested-opencode", "self-protection", "opencode-service", "opencode-server-api", "protected-write"])

/** The rule of a group among `CODE_VIEW_RULES`: on in that view as it is on for the command. */
const CODE_VIEW_GROUP_RULE: ReadonlySet<string> = new Set(["protected-write"])

/**
 * Context of that view: groups turned off, settings of `CODE_VIEW_RULES` only (a setting turns a rule on in a disabled
 * group), no user rule. Only the always-active rules remain, and `protected-write` when it is enabled for the command
 * (`keptOn`), so a deny of another rule never hides their ask.
 */
function codeViewContext(ctx: ShellRuleContext): ShellRuleContext {
  const overrides = new Map([...(ctx.active?.overrides ?? [])].filter(([rule]) => CODE_VIEW_RULES.has(rule)))
  const byModel = { ...(ctx.active?.localAsksByModel ? { localAsksByModel: true } : {}), ...(ctx.active?.selfProtectionByModel ? { selfProtectionByModel: true } : {}) }
  const keptOn = ruleEnabled("protected-write", ctx.active) ? { keptOn: CODE_VIEW_GROUP_RULE } : {}
  return { ...ctx, custom: [], active: { dangerousCommands: false, sensitiveFiles: false, ...(overrides.size ? { overrides } : {}), ...byModel, ...keptOn } }
}

/** Finding of the equivalent shell form of code (`interpreterCodeView`), `CODE_VIEW_RULES` only. */
function codeViewFinding(view: string, ctx: ShellRuleContext): Finding | undefined {
  const only = codeViewContext(ctx)
  const found = assignedFinding(view, only, layeredShellFinding(view, only).finding)
  return found && CODE_VIEW_RULES.has(found.rule) ? found : undefined
}

/** A file's text around a command hides its end (`", shell=True)`): each literal and each list of literals is read alone too. */
function fileLaunchesDangerous(code: string): boolean {
  if (!codeHasDangerSink(code)) return false
  if (citesDangerousCommand(code)) return true
  const literals = codeMatches(code, CODE_LITERAL).map((literal) => literal[1] ?? literal[2] ?? literal[3] ?? "")
  return [...literals, ...literalGroups(code).map((group) => group.text)].some(citesDangerousCommand)
}

/**
 * Whole content of a file run by an interpreter, read as inline code: the protected writes and launches of
 * `interpreterCodeView`, then the commands of `interpreter-dangerous-code`, each under its own settings. `undefined` if
 * neither is found; `LIMIT_REACHED` past the budget of inline code, which is not read then. The language is not known:
 * nothing is left out as a comment, since a misread multi-line string would hide real code.
 */
export function scriptCodeFinding(code: string, ctx: ShellRuleContext): Finding | undefined | typeof LIMIT_REACHED {
  if (code.length > INLINE_CODE_LIMIT) return LIMIT_REACHED
  const lines = codeViewLines(code, ctx)
  const dangerous: Finding | undefined =
    ruleEnabled("interpreter-dangerous-code", ctx.active) && fileLaunchesDangerous(code) ? { verdict: "ask", rule: "interpreter-dangerous-code", reason: DANGEROUS_CODE_REASON } : undefined
  return mostSevere([lines.length ? codeViewFinding(lines.join("\n"), ctx) : undefined, hardened(dangerous, ctx.active)])
}

/**
 * Findings of a view, in order: finding of the rules and of the view without leading assignments (`assignedFinding`);
 * without a deny, that of the view of the words reduced to their literal value (`commandWordView`: the word in command
 * position, and every word in pieces, down to two levels of substitution), that of the word in command position alone, when
 * it is another view (the stronger of the two; reducing an argument may hide what a rule reads in its quotes), the ask of its flag, and that of
 * the equivalent shell form of inline interpreter code (`interpreterCodeView`), for `CODE_VIEW_RULES` only. Internal error of one of the latter two:
 * prudent ask in its place (`ANALYSIS_FAILED`), the other's finding kept.
 */
function writtenViewFindings(command: string, ctx: ShellRuleContext): Array<Finding | undefined> {
  const base = assignedFinding(command, ctx, layeredShellFinding(command, ctx).finding)
  if (base?.verdict === "deny") return [base]
  let coded: Finding | undefined
  try {
    const code = interpreterCodeView(command, ctx)
    if (code !== undefined) {
      coded = codeViewFinding(code, ctx)
      // The only ask, from this view: that of a printed OpenCode secret cited in the code, as for an ask of the command.
      if (coded?.verdict === "ask" && base === undefined) coded = printedInCodeFinding(command, ctx) ?? coded
    }
  } catch {
    coded = hardened(ANALYSIS_FAILED, ctx.active)
  }
  try {
    const { view, flag } = commandWordView(command, MAX_SHELL_LEVELS)
    // The word in command position alone: a rule may read a piece the reduced word no longer shows (`"c"url -d "@.env"*`).
    const head = commandWordView(command).view
    const reduced = reducedFinding(command, view, ctx)
    const alone = head !== view ? reducedFinding(command, head, ctx) : undefined
    return [base, strength(alone) > strength(reduced) ? alone : reduced, flag ? hardened({ verdict: "ask", rule: "nested-opencode", reason: flag }, ctx.active) : undefined, coded]
  } catch {
    // An error on a word in pieces never costs the deny of the word in command position.
    try {
      const head = reducedFinding(command, commandWordView(command).view, ctx)
      if (head?.verdict === "deny") return [base, head, undefined, coded]
    } catch {}
    return [base, hardened(ANALYSIS_FAILED, ctx.active), undefined, coded]
  }
}

/**
 * The command with the lines the shell continues joined and the strings of `env -S` read as words (`lines`), the findings
 * of that view if it differs (`continued`), and an ask if a new reading would still change it (`unstable`).
 */
function joinedFinding(command: string, ctx: ShellRuleContext): { lines: string; continued?: Finding | undefined; unstable?: Finding | undefined } {
  const { view: lines, unread } = splitStrings(joinedLines(command))
  if (lines === command) return { lines, ...(unread ? { unstable: hardened(UNSTABLE_SPLIT, ctx.active) } : {}) }
  const continued = mostSevere(viewFindings(lines, ctx).found)
  const again = joinedLines(lines)
  if (again !== lines) return { lines, continued, unstable: hardened(UNSTABLE_JOIN, ctx.active) }
  const reread = splitStrings(again)
  return { lines, continued, ...(unread || reread.unread || reread.view !== lines ? { unstable: hardened(UNSTABLE_SPLIT, ctx.active) } : {}) }
}

/**
 * Findings of the command as written (`writtenViewFindings`), then, without a deny, those of the view with the redirections
 * written before a program behind it (`redirectionsBehind`), and the ask of its flag. Internal error of that view: prudent
 * ask in its place (`ANALYSIS_FAILED`), the findings of the command kept. `moved`: these views, for the next readings.
 */
function viewFindings(command: string, ctx: ShellRuleContext): { found: Array<Finding | undefined>; moved?: string[] | undefined } {
  const found = writtenViewFindings(command, ctx)
  if (mostSevere(found)?.verdict === "deny") return { found }
  try {
    const { views, flag } = redirectionsBehind(command)
    const moved = views.filter((view) => view !== command)
    for (const view of moved) found.push(mostSevere(writtenViewFindings(view, ctx)))
    if (flag) found.push(hardened({ verdict: "ask", rule: "nested-opencode", reason: flag }, ctx.active))
    return { found, moved }
  } catch {
    found.push(hardened(ANALYSIS_FAILED, ctx.active))
    return { found }
  }
}

/** Finding of a view of the command with its words reduced (`commandWordView`), nothing more if it is the command. */
const reducedFinding = (command: string, view: string, ctx: ShellRuleContext) => (view !== command ? assignedFinding(view, ctx, layeredShellFinding(view, ctx).finding) : undefined)

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

/** Absolute path that designates a device according to the common definition. */
const isDevicePath = (path: string) => DEVICE_AT_START.test(path)

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
    for (const segment of segments(text, SHELL_SEPARATORS)) {
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
 * Forms of a target, copied word for word from `protectedWriteClass` (sensitive-paths.ts): expanded form (blanks,
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
  // Replayed limit (`LIMIT_REACHED`): no real path; the same target already gave the `self-protection` ask (the
  // replay only returns answers obtained through `protectedWriteClass`).
  const reals = (form: string) => {
    const found = ctx.realPaths?.(form)
    return found === LIMIT_REACHED ? undefined : found
  }
  const active = DEVICE_RULES.filter(({ rule }) => ruleEnabled(rule.id, ctx.active))
  const known = active.flatMap(({ group, rule }) =>
    deviceTargets(group, text)
      .filter((target) => !unknownTarget(target))
      .map((target) => {
        const forms = deviceForms(target, ctx)
        const process = !forms.relative && (throughProcessDirectory(forms.expanded) || forms.asked.some((form) => (reals(form)?.length ?? 0) > 1))
        return { group, rule, ...forms, process, launched: forms.relative || process }
      }),
  )
  // Rule set to `deny` (`ruleOverrides`): its ask is a deny, so its targets that depend on the launch directory come
  // before the others' at the ask level.
  const hardens = (target: (typeof known)[number]) => overrideOf(target.rule.id, ctx.active) === "deny"
  const levels = [known.filter((target) => !target.launched), known.filter((target) => target.launched && hardens(target)), known.filter((target) => target.launched && !hardens(target))]
  for (const [index, level] of levels.entries()) {
    const relative = index > 0
    const reshaped = level.find(({ lexical }) => lexical.some(isDevicePath))
    if (reshaped) return { group: reshaped.group, rule: reshaped.rule, axis: "A", relative, process: reshaped.process }
    const linked = level.find(({ asked }) => asked.some((form) => (reals(form) ?? []).some(isDevicePath)))
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
    if (relative) return { finding: hardened({ verdict: "ask", rule: rule.id, reason: `${rule.reason} ${through}: confirmation required` }, replay.active), axis, group, relative }
    const kept = () => {
      if (replay.custom?.some((custom) => custom.id === rule.id) || overrideOf(rule.id, replay.active) === "deny") return true
      const data = withoutData(command)
      if (data === command || reentersShell(data) || evaluate(data, replay)?.verdict === "deny") return true
      return addedRecognition(data, replay.active) !== undefined || deviceHit(data, replay)?.relative === false
    }
    const finding: Finding = kept()
      ? { verdict: "deny", rule: rule.id, reason: rule.reason }
      : { verdict: "ask", rule: rule.id, reason: `${rule.reason}, only inside code passed to an interpreter or a heredoc: confirmation required` }
    return { finding, axis, group, relative }
  }
  if (!guard.unknown) return undefined
  // First group concerned, a group set to `deny` (`ruleOverrides`) first: its ask is a deny.
  const groups = unknownGroups(command, replay).map((group) => DEVICE_RULES.find((candidate) => candidate.group === group)!)
  const entry = groups.find(({ rule }) => overrideOf(rule.id, replay.active) === "deny") ?? groups[0]
  if (!entry) return undefined
  const reason = `write target known only when the command runs, possibly a device (${entry.rule.reason}): confirmation required`
  return { finding: hardened({ verdict: "ask", rule: entry.rule.id, reason }, replay.active), axis: "C", group: entry.group, relative: false }
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
  return segments(command, SHELL_SEPARATORS).some((segment) => {
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
 * and only replayed by the layer (`replay`): answer already obtained for the same question (limit included), otherwise
 * unknown (real paths `undefined`: lexical comparison only; content: not recognized). The replay never queries the instance: its
 * consultation ceiling remains whole for existing consumers, in this call as in the following ones that
 * share the instance (subcommands during permission examination, scripts of a call without directory). `linked`: a
 * recorded real-path answer designates a device (the only possible trace of a neutrally named link). Without
 * either predicate, nothing to record: the context serves both.
 */
function budgetedPredicates(ctx: ShellRuleContext): { record: ShellRuleContext; replay: ShellRuleContext; linked: () => boolean } {
  const { realPaths, credentialContent } = ctx
  if (!realPaths && !credentialContent) return { record: ctx, replay: ctx, linked: () => false }
  const paths = new Map<string, readonly string[] | undefined | typeof LIMIT_REACHED>()
  // Existing files only (targets of an exception or the memory): answers kept apart, never seen by `linked`.
  const existingPaths = new Map<string, readonly string[] | undefined | typeof LIMIT_REACHED>()
  const contents = new Map<string, boolean | typeof LIMIT_REACHED>()
  const recordPaths = realPaths
    ? (absolute: string, existing = false) => {
        const found = realPaths(absolute, existing)
        ;(existing ? existingPaths : paths).set(absolute, found)
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
      ...(realPaths ? { realPaths: (absolute: string, existing = false) => (existing ? existingPaths : paths).get(absolute) } : {}),
      ...(credentialContent ? { credentialContent: (path: string) => contents.get(path) ?? false } : {}),
    },
    linked: () => [...paths.values()].some((found) => found !== LIMIT_REACHED && found?.some(isDevicePath) === true),
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

/** Layer finding as `shellFinding` computes it, guard conditions included (guard tests). */
export const deviceLayerDetail = layeredShellFinding
