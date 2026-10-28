import { isAbsolute } from "node:path"
import { fileURLToPath } from "node:url"
import { patchTargets } from "../patch.ts"
import { resolveLike } from "../scripts.ts"
import { containsEncodedPlaceholder, PLACEHOLDER_RE, type Redactor } from "../secrets/redact.ts"
import { decodeUnicodeEscapes } from "./code-network.ts"
import { entrusted, overridden, ruleEnabled, type ActiveRules } from "./features.ts"
import { credentialFile, exactSystemWrite, exactWriteClass, protectedWriteClass, strictestKind, systemWrite, uncheckedCredentialReason, uncheckedWriteReason, type CredentialContext, type WritePathContext } from "./sensitive-paths.ts"
import { shellFinding } from "./shell.ts"
import { decidable, INTERNAL_ERROR_RULE, LIMIT_REACHED, mostSevere, type CustomRule, type Finding } from "./types.ts"

export interface ToolRuleContext extends WritePathContext, CredentialContext {
  readonly redactor: Redactor
  readonly home?: string
  readonly custom?: readonly CustomRule[]
  /**
   * Rule policy (`dangerousCommands` / `sensitiveFiles` switches, `ruleOverrides`, `localAsks`): a disabled rule is not
   * evaluated, the verdict of the others is set on each finding where it is built (an ask left to the decision model is
   * marked there, only when the check was carried out to the end); absent = all, unchanged.
   */
  readonly active?: ActiveRules
  /** Cause of a check that threw (log); absent: nothing is logged, the ask remains. */
  readonly report?: (message: string, error: unknown) => void
}

/**
 * A check that throws (pattern on an oversized input, impossible serialization) gives an ask for itself alone: the
 * other findings of the same call, denial included, hold (`mostSevere`), instead of being lost with the whole function.
 */
function checked(what: string, ctx: ToolRuleContext, check: () => Finding | undefined): Finding | undefined {
  try {
    return check()
  } catch (error) {
    try {
      ctx.report?.(`internal error while checking ${what}`, error)
    } catch {}
    return { verdict: "ask", rule: INTERNAL_ERROR_RULE, reason: `internal guard plugin error, ${what} could not be checked: confirmation required` }
  }
}

/** OpenCode CodeMode tool: its internal calls carry the same call identifier as it. */
export const CODEMODE_TOOL = "execute"

/**
 * OpenCode v2.1.1 built-in tools (`packages/core/src/tool/plugin/*.ts`, `name` constant; `todowrite` only if
 * `experimental.todo` is true). Used by the `dev/tools/` measurements; the rules treat a missing tool as an MCP tool.
 */
export const BUILTIN_TOOLS = new Set([
  "shell",
  "read",
  "edit",
  "write",
  "patch",
  "glob",
  "grep",
  "webfetch",
  "websearch",
  "subagent",
  "skill",
  "question",
  "execute",
  "todowrite",
])

const PLACEHOLDER_REASON =
  "the content to write contains a redacted secret ([[GUARD_REDACTED:…]]): writing it would destroy the real secret. Make a targeted edit that does not include the placeholder"

const PLACEHOLDER_ENCODED_REASON =
  "the content to write contains a redacted secret encoded in base64 (a [[GUARD_REDACTED:…]] placeholder once decoded): writing it would destroy the real secret. Make a targeted edit that does not include it"

const str = (value: unknown): string => (typeof value === "string" ? value : "")

export { decodeUnicodeEscapes }

function record(input: unknown): Record<string, unknown> {
  return input !== null && typeof input === "object" ? (input as Record<string, unknown>) : {}
}

/** Credential file; content not checked (limit): ask from the same rule, with its own reason, never left to the model. */
function secretRead(path: string, ctx: ToolRuleContext): Finding | undefined {
  if (!path || !ruleEnabled("secret-file-read", ctx.active)) return undefined
  const found = credentialFile(path, ctx)
  if (found === true) return entrusted(overridden({ verdict: "ask", rule: "secret-file-read", reason: `access to a credential file (${path})` }, ctx.active), ctx.active)
  return found === LIMIT_REACHED ? overridden({ verdict: "ask", rule: "secret-file-read", reason: uncheckedCredentialReason(path) }, ctx.active) : undefined
}

/**
 * Path as written by OpenCode 2.0.31's `edit`, `write`, and `patch` tools (`resolvePath` from
 * `core/src/file-access.ts`): received as is, without trimming whitespace or quotes (for `patch`, path returned by the
 * patch read), only `~` and `~/` expanded, resolved lexically from the session directory. No exact
 * form for a relative path without a known directory, or for `~` without a home directory: the written form remains classified.
 */
function openCodeWritePath(path: string, ctx: ToolRuleContext): string | undefined {
  if (ctx.cwd === undefined && !isAbsolute(path) && path !== "~" && !path.startsWith("~/")) return undefined
  return resolveLike(ctx.cwd ?? "/", path, ctx.home)
}

/**
 * OpenCode configuration and plugin directory: self-protection (always active), like an unchecked real path (limit);
 * other protected locations. `edit`, `write`, and `patch` tools: written form (`protectedWriteClass`) and OpenCode exact
 * form, which keeps whitespace and leading/trailing quotes (`exactWriteClass`); the strictest wins. A location that
 * holds the plugin's settings is never left to the decision model (user's decision).
 */
function protectedWrite(path: string, ctx: ToolRuleContext): Finding | undefined {
  if (!path) return undefined
  const exact = openCodeWritePath(path, ctx)
  const kind = strictestKind(protectedWriteClass(path, ctx.home, ctx), exact === undefined ? undefined : exactWriteClass(exact, ctx))
  const system = () => entrusted(overridden({ verdict: "ask", rule: "protected-write", reason: `write to a protected location (${path})` }, ctx.active), ctx.active)
  const anySystem = () => systemWrite(path, ctx.home, ctx) || (exact !== undefined && exactSystemWrite(exact, ctx))
  if (kind === "settings" || kind === "opencode") {
    const finding = overridden({ verdict: "ask", rule: "self-protection", reason: `write to OpenCode's configuration or to the guard plugin (${path})` }, ctx.active)
    return withSystemForm(kind === "settings" ? finding : entrusted(finding, ctx.active), system, anySystem, ctx)
  }
  if (kind === "unchecked")
    return withSystemForm(overridden({ verdict: "ask", rule: "self-protection", reason: uncheckedWriteReason("write to a location", path) }, ctx.active), system, anySystem, ctx)
  if (kind === "system" && ruleEnabled("protected-write", ctx.active)) return system()
  return undefined
}

/**
 * Self-protection finding `own`, or the `protected-write` one when it is stronger (rule set to `deny`, or an ask the user
 * confirms against one left to the model) and some form of the target is in such a location (`systemWrite`), looked up
 * only then: the strictest class hides it.
 */
function withSystemForm(own: Finding, system: () => Finding | undefined, anySystem: () => boolean, ctx: ToolRuleContext): Finding {
  if (!ruleEnabled("protected-write", ctx.active)) return own
  const stronger = system()
  return stronger && mostSevere([own, stronger]) === stronger && anySystem() ? stronger : own
}

/**
 * Variant of `protectedWrite` for an MCP or plugin tool argument: the tool may read or write this path. No
 * exact form: each server resolves its paths in its own way (written form and resolved form of `protectedWriteKind`).
 */
function protectedArgument(path: string, ctx: ToolRuleContext): Finding | undefined {
  const kind = protectedWriteClass(path, ctx.home, ctx)
  const system = () => entrusted(overridden({ verdict: "ask", rule: "protected-write", reason: `a tool argument designates a protected location (${path})` }, ctx.active), ctx.active)
  const anySystem = () => systemWrite(path, ctx.home, ctx)
  if (kind === "settings" || kind === "opencode") {
    const finding = overridden({ verdict: "ask", rule: "self-protection", reason: `a tool argument designates OpenCode's configuration or the guard plugin (${path})` }, ctx.active)
    return withSystemForm(kind === "settings" ? finding : entrusted(finding, ctx.active), system, anySystem, ctx)
  }
  if (kind === "unchecked")
    return withSystemForm(overridden({ verdict: "ask", rule: "self-protection", reason: uncheckedWriteReason("a tool argument designates a location", path) }, ctx.active), system, anySystem, ctx)
  if (kind === "system" && ruleEnabled("protected-write", ctx.active)) return system()
  return undefined
}

/**
 * Protected-location findings from several paths of the same call (patch targets, MCP arguments): each ask is
 * replaced by the strictest of them, an ask the user confirms before one left to the decision model, then
 * self-protection before a simple protected location, in the same place. Only the displayed rule changes, never the
 * verdict: a deny (rule set to `deny`) stays in its place.
 */
function strictestProtected(findings: ReadonlyArray<Finding | undefined>): Array<Finding | undefined> {
  const confirmed = findings.filter((finding) => finding !== undefined && !decidable(finding))
  const pool = confirmed.length ? confirmed : findings
  const strictest = pool.find((finding) => finding?.rule === "self-protection") ?? pool.find((finding) => finding !== undefined)
  return findings.map((finding) => (finding?.verdict === "ask" ? strictest : finding))
}

/** Last word of a key name that designates a path: `filePath`, `outputDirPath`, `file_paths` yes, `fileType` no. */
const PATH_KEY_WORDS = new Set([
  "path",
  "paths",
  "pathname",
  "filepath",
  "filepaths",
  "file",
  "files",
  "filename",
  "filenames",
  "dir",
  "dirs",
  "dirname",
  "directory",
  "directories",
  "folder",
  "folders",
  "cwd",
  "dest",
  "destination",
])
const PATH_MAX = 4096
/** Shape of a path whatever the key: absolute, explicit relative, or in the home directory. */
const PATH_SHAPE = /^(?:\/|\.{1,2}\/|(?:~|\$HOME|\$\{HOME\})(?:\/|$))/
const FILE_URI = /^file:/i
/** Addresses (other than `file:`) that do not designate a local file: never candidates. */
const OTHER_URL = /^(?:[a-z][a-z0-9+.-]*:\/\/|data:)/i

function isPathKey(key: string): boolean {
  const words = key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z])([A-Z][a-z])/g, "$1 $2")
    .split(/[\s_.-]+/)
    .filter(Boolean)
  return PATH_KEY_WORDS.has(words[words.length - 1]?.toLowerCase() ?? "")
}

/** `file:` URI → path (`%2E` decoded); invalid (host, shape): kept as is. */
function fromFileURI(value: string): string {
  try {
    return fileURLToPath(value)
  } catch {
    return value
  }
}

/**
 * Paths designated by the arguments of an MCP or plugin tool (argument names specific to each server): single-line
 * strings under a path key, then strings shaped like a path under another key (free text is not
 * taken). This order first gives the most likely paths the call's disk lookup budget.
 * Iterative traversal (no recursion), without modifying the input.
 */
export function argumentPaths(input: unknown): string[] {
  const byKey = new Set<string>()
  const byShape = new Set<string>()
  const seen = new Set<object>()
  const stack: Array<readonly [unknown, boolean]> = [[input, false]]
  while (stack.length > 0) {
    const [value, underPathKey] = stack.pop()!
    if (typeof value === "string") {
      const text = value.trim().replace(/^["'`]+/, "")
      const uri = FILE_URI.test(text)
      if (text === "" || value.length > PATH_MAX || /[\r\n]/.test(value) || (!uri && OTHER_URL.test(text))) continue
      if (underPathKey) byKey.add(uri ? fromFileURI(text) : value)
      else if (uri || PATH_SHAPE.test(text)) byShape.add(uri ? fromFileURI(text) : value)
      continue
    }
    if (value === null || typeof value !== "object" || seen.has(value)) continue
    seen.add(value)
    // Array value: key of the array (`filePaths: [...]`).
    if (Array.isArray(value)) for (const item of value) stack.push([item, underPathKey])
    else for (const [key, item] of Object.entries(value)) stack.push([item, isPathKey(key)])
  }
  return [...byKey, ...[...byShape].filter((path) => !byKey.has(path))]
}

/**
 * Local or private addresses written as is (IPv4, IPv6 in brackets, `localhost` and its subdomains, URL
 * host name in `.local` or `.internal`). Linear cost: bounded repetitions, except the host part of a URL, whose
 * class excludes the slash (each scan stops at the next URL start).
 */
const LOCAL_IPV4 =
  /(?<![\w.])(?:127\.\d{1,3}|10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01])|169\.254)\.\d{1,3}\.\d{1,3}(?![\w.])|(?<![\w.])0\.0\.0\.0(?![\w.])/
const LOCAL_IPV6 = /\[(?:::1?|::ffff:[0-9a-f:.]{1,40}|fe[89ab][0-9a-f]:[0-9a-f:.]{0,40}|f[cd][0-9a-f]{2}:[0-9a-f:.]{0,40})(?:%[\w.-]{1,20})?\]/i
const LOCALHOST = /(?<![\w-])localhost(?![\w-])/i
const LOCAL_URL_HOST = /\/\/[^\s/"'`?#\\]*\.(?:local|internal)(?![\w.-])/i

function localAddress(text: string): boolean {
  return LOCAL_IPV4.test(text) || LOCAL_IPV6.test(text) || LOCALHOST.test(text) || LOCAL_URL_HOST.test(text)
}

const placeholder = (text: string): Finding | undefined =>
  PLACEHOLDER_RE.test(text)
    ? { verdict: "deny", rule: "placeholder", reason: PLACEHOLDER_REASON }
    : containsEncodedPlaceholder(text)
      ? { verdict: "deny", rule: "placeholder", reason: PLACEHOLDER_ENCODED_REASON }
      : undefined

const exfiltration = (value: unknown, ctx: ToolRuleContext, what: string): Finding | undefined =>
  ruleEnabled("secret-network", ctx.active) && ctx.redactor.containsSecret(value)
    ? overridden({ verdict: "deny", rule: "secret-network", reason: `secret found in ${what} (exfiltration)` }, ctx.active)
    : undefined

function customFindings(tool: string, input: unknown, ctx: ToolRuleContext): Finding[] {
  if (tool === "shell") return [] // already tested by shellFinding
  const rules = (ctx.custom ?? []).filter((rule) => rule.tools.includes(tool) || rule.tools.includes("*"))
  if (!rules.length) return []
  let serialized: string
  try {
    serialized = JSON.stringify(input) ?? ""
  } catch (error) {
    // Input that cannot be serialized: the rules cannot be judged, ask for them alone.
    const found = checked("your rules", ctx, () => {
      throw error
    })
    return found ? [found] : []
  }
  // A rule that throws (pattern on an oversized input) asks for itself alone: the tool's other findings, including
  // the placeholder denial, hold.
  return rules.flatMap((rule): Finding[] => {
    const found = checked(`your rule ${rule.id}`, ctx, () =>
      rule.pattern.test(serialized) ? { verdict: rule.verdict, rule: rule.id, reason: rule.reason } : undefined,
    )
    return found ? [found] : []
  })
}

/**
 * Placeholder rule alone, kept for the unprotected agent: writing a placeholder would destroy the real secret (a history
 * started protected contains some). Same fields as in `toolFinding`.
 */
export function placeholderFinding(tool: string, input: unknown): Finding | undefined {
  const args = record(input)
  switch (tool) {
    case "shell":
      return placeholder(str(args.command))
    case "execute":
      return placeholder(str(args.code))
    case "read":
    case "glob":
    case "grep":
    case "webfetch":
    case "websearch":
    case "subagent":
    case "skill":
    case "question":
      return undefined
    default:
      return placeholder(JSON.stringify(input) ?? "")
  }
}

export function toolFinding(tool: string, input: unknown, ctx: ToolRuleContext): Finding | undefined {
  const args = record(input)
  const custom = customFindings(tool, input, ctx)
  // Each check separate (`checked`): a check that throws never loses another's denial.
  const placeholderOf = () => checked("the placeholder check", ctx, () => placeholder(JSON.stringify(input) ?? ""))
  const read = (path: string) => checked("the credential file check", ctx, () => secretRead(path, ctx))
  const write = (path: string) => checked("the protected location check", ctx, () => protectedWrite(path, ctx))
  switch (tool) {
    case "shell":
      return shellFinding(str(args.command), ctx)
    case "read":
      return mostSevere([read(str(args.path)), ...custom])
    case "glob":
    case "grep":
      return mostSevere([read(str(args.path)), read(str(args.pattern)), read(str(args.include)), ...custom])
    // Placeholder searched in the whole input: robust to a renaming of fields by OpenCode.
    case "edit":
    case "write":
      return mostSevere([placeholderOf(), write(str(args.path)), ...custom])
    // Each file a header can designate (broad read and its pieces): an excess costs only one confirmation.
    case "patch": {
      const patch = str(args.patchText)
      const targets = checked("the protected location check", ctx, () =>
        mostSevere(strictestProtected(patchTargets(patch, { pieces: true }).map((target) => protectedWrite(target, ctx)))),
      )
      return mostSevere([placeholderOf(), targets, ...custom])
    }
    // The whole input (v2.0.29: url, format, timeout / query…): robust to added headers or a body.
    case "webfetch":
      return mostSevere([checked("the secret check", ctx, () => exfiltration(input, ctx, "the web request")), ...custom])
    case "websearch":
      return mostSevere([checked("the secret check", ctx, () => exfiltration(input, ctx, "the search request")), ...custom])
    case "execute": {
      const raw = str(args.code)
      // Raw text placeholder first and separately: it holds even if the decoded code check throws.
      const kept = checked("the placeholder check", ctx, () => placeholder(raw))
      const examined = checked("the CodeMode code", ctx, () => executeFinding(raw, ctx, custom))
      // With no other finding, the check's as is (it may leave the decision to the model, `modelDecides`).
      return kept ? mostSevere([kept, examined]) : examined
    }
    case "subagent":
    case "skill":
    case "question":
      return mostSevere(custom)
    default: {
      // MCP / plugin tools: arguments invisible to permission evaluation,
      // so checked here (a secret can leave through any MCP server; a path can designate a credential
      // file or a protected location, whether the tool reads or writes it).
      const located = checked("the tool arguments", ctx, () => {
        const paths = argumentPaths(input)
        const locations = strictestProtected(paths.map((path) => protectedArgument(path, ctx)))
        return mostSevere(paths.flatMap((path, index) => [secretRead(path, ctx), locations[index]]))
      })
      return mostSevere([
        placeholderOf(),
        checked("the secret check", ctx, () => exfiltration(input, ctx, "the tool arguments")),
        located,
        ...custom,
      ])
    }
  }
}

/** CodeMode code (`execute`): decoded text placeholder, secret, `fetch` with tools or a local address, rules. */
function executeFinding(raw: string, ctx: ToolRuleContext, custom: readonly Finding[]): Finding | undefined {
  const code = decodeUnicodeEscapes(raw)
  // Only network access of the CodeMode interpreter (v2.0.31): `fetch`, designated by its identifier (no global object,
  // no dynamic evaluation, no modules); `globalThis` does not exist there, kept for safety.
  const network = /\bfetch\b|\bglobalThis\b/.test(code) || /\bfetch\b|\bglobalThis\b/.test(raw)
  // Secret denied even without detected network access: a script's only other outputs are its tool calls (each
  // already denies a secret in its arguments), and a denial on input precedes all the script's calls.
  const what = network ? "code that makes network requests" : "CodeMode code"
  const fetchRule = network && ruleEnabled("codemode-fetch", ctx.active)
  // A tool call is possible only via the `tools` identifier (v2.0.32): any occurrence counts, strings and
  // comments included. With it, machine data can leave through `fetch` unseen: ask.
  const tools = /\btools\b/.test(code) || /\btools\b/.test(raw)
  const local = localAddress(code) || localAddress(raw)
  const found = mostSevere([
    placeholder(code),
    // Raw AND decoded text: a known secret may itself contain a literal `\u…` sequence.
    checked("the secret check", ctx, () => exfiltration(raw, ctx, what) ?? exfiltration(code, ctx, what)),
    fetchRule && tools
      ? entrusted(overridden({ verdict: "ask", rule: "codemode-fetch", reason: "CodeMode code making network requests (fetch) and calling tools" }, ctx.active), ctx.active)
      : undefined,
    fetchRule && local
      ? entrusted(overridden({ verdict: "ask", rule: "codemode-fetch", reason: "CodeMode code making network requests (fetch) to a local or private address" }, ctx.active), ctx.active)
      : undefined,
    ...custom,
  ])
  // With no tool or written local address: the decision model decides, as for `webfetch`, if it judged all the code;
  // otherwise (truncated, unreachable, disabled), the ask remains. Last: never masks another finding.
  return (
    found ??
    (fetchRule
      ? overridden({ verdict: "ask", rule: "codemode-fetch", reason: "CodeMode code making network requests (fetch)", modelDecides: "without tool calls or local addresses" }, ctx.active)
      : undefined)
  )
}
