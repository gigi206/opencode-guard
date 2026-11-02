import { UNAVAILABLE_INPUT, type Decider, type Decision, type ExecutedScript, type ReasonParts } from "../decide.ts"
import { afterLeadingCd, changesDirectory, heredocFiles, scriptRuns, shellFinding } from "../rules/shell.ts"
import { createCredentialContent } from "../credential-content.ts"
import { createRealPath } from "../real-path.ts"
import { CODEMODE_TOOL, placeholderFinding } from "../rules/tools.ts"
import { hiddenHeaders, patchTargets, readPatch, type PatchSection } from "../patch.ts"
import { createScriptTracker, isShellScript, resolveLike, shellDirectories, type ScriptTracker } from "../scripts.ts"
import type { UnprotectedGate } from "./unprotected.ts"
import type { Scope } from "../config.ts"
import type { ScopeResolver } from "../scopes.ts"
import { RULE_DETAILS } from "../rules/details.ts"
import { bySetting, TARGETED_RULES, withoutWaivers, type ActiveRules } from "../rules/features.ts"
import { INTERNAL_ERROR_RULE, mostSevere, type CustomRule, type Waiver } from "../rules/types.ts"
import type { Redactor } from "../secrets/redact.ts"
import type { GuardContext, Logger, PermissionEvaluation } from "../types.ts"

/** Plugin-specific permission action ("ask" requests via `ctx.permission.assert`). */
export const GUARD_ACTION = "guard"
/**
 * Between `GUARD_ACTION` and the detail of a request's action: OpenCode's interface shows only the action of a plugin's
 * request, neither `message`, `metadata` nor `resources`, and shows it twice, as `Call tool <action>` then
 * `Tool: <action>` (packages/tui/src/util/permission.ts, v2.2.4). The detail therefore stays compact, the full reason
 * left to the log.
 */
export const GUARD_SEPARATOR = " · "
/** Length of the detail after `GUARD_ACTION` and the separator (rule, reason, model opinion, tool call), cut mark included. */
export const MAX_ACTION_DETAIL = 120
/** Length kept for the reason, after the rule's name, when even the shortest reason does not fit with the whole tool call. */
const MIN_ACTION_REASON = 32
/** Length the tool call keeps in any case (a rule's name never takes all the room). */
const MIN_ACTION_CALL = 24

export interface GateDeps {
  readonly decider: Decider
  readonly redactor: Redactor
  readonly home?: string
  /** The user's rules when `scopes` is absent (otherwise those of the version in force). */
  readonly rules?: readonly CustomRule[]
  readonly protectedDirs?: readonly string[]
  /** The plugin's own directories among them (its settings: never left to the decision model). */
  readonly pluginDirs?: readonly string[]
  /** Directories of the OpenCode service files resolved from the environment (`service.json` recognized under them). */
  readonly serviceDirs?: readonly string[]
  /** "deny": unattended mode, every confirmation request becomes a rejection. */
  readonly askAs?: "ask" | "deny"
  readonly log: Logger
  /** Unprotected agent (`unprotectedAgent` option); absent = everything is protected. */
  readonly unprotected?: UnprotectedGate
  /** Clock (injectable for tests). */
  readonly now?: () => number
  /** Tracking of scripts created by the agent (injectable for tests). */
  readonly scripts?: ScriptTracker
  /** Directories of a shell command (injectable for tests; default: `shellDirectories`). */
  readonly directoriesOf?: typeof shellDirectories
  /** Rule policy, switches and `ruleOverrides` (`evaluate` sub-commands); absent = all active. */
  readonly active?: ActiveRules
  /** `scripts` switch: `false` = no tracking or reading of scripts written then executed. */
  readonly trackScripts?: boolean
  /** Settings of each call (agent and project sections); absent: `active` and `trackScripts` for every call. */
  readonly scopes?: ScopeResolver
  /** Private keys recognized by their content in the `evaluate` sub-commands (like the decider). */
  readonly readContent?: boolean
  /** Protected locations recognized through a symbolic link in the `evaluate` sub-commands (like the decider). */
  readonly resolveLinks?: boolean
  /** Tests only: receives the reading of internal table sizes. */
  readonly inspect?: (sizes: () => GateTableSizes) => void
}

export interface GateTableSizes {
  readonly approved: number
  readonly pending: number
  readonly directories: number
}

/**
 * Instruction attached to denials: observed in session, after two denials the model hid the reasons
 * (String.fromCharCode) then went through a script written to a file.
 */
export const NO_EVASION = "Do not try to evade this check (obfuscation, rewording, a script file…): explain the block to the user, who can run the command themselves if needed."

/** Rule named in messages; nothing for a decision without a rule (decision model). */
const ruleNote = (rule?: string) => (rule ? ` (rule ${rule})` : "")
/** Source and rule of a log line: `local, rule rm-critical`. */
const sourceNote = (source: string, rule?: string) => (rule ? `${source}, rule ${rule}` : source)
/** Log line of a finding lifted by an exception or the memory: its rule, how, and its targets (redacted by the log). */
const liftedLine = (subject: string, waiver: Waiver) => `${subject} → lifted (${sourceNote(waiver.kind, waiver.rule)}): ${waiver.targets.join(", ")}`

/** Rejection message. The `placeholder` rule specifically asks for another change: no instruction. */
export function blockedMessage(reason: string, rule?: string): string {
  const message = `[guard] Blocked${ruleNote(rule)}: ${reason}`
  return rule === "placeholder" ? message : `${message}. ${NO_EVASION}`
}

/** Explicit denial in unattended mode: the model knows why and does not retry in a loop. */
export function unattendedMessage(reason: string, rule?: string): string {
  return `[guard] Blocked${ruleNote(rule)}: confirmation required, but unattended mode (askAs: deny) denies it: ${reason}. ${NO_EVASION}`
}

/** Ask set in `permission.evaluate`; without a rule (decision model), the reason alone. */
export function askMessage(reason: string, rule?: string): string {
  return rule ? `[guard] Confirmation required${ruleNote(rule)}: ${reason}` : `[guard] ${reason}`
}

/** `value` cut to `limit` code points, at a word boundary when possible, with `…`; a cut never leaves half a character. */
function fit(value: string, limit: number): string {
  const chars = [...value]
  if (chars.length <= limit) return value
  if (limit <= 1) return "…"
  const slice = chars.slice(0, limit - 1).join("")
  const space = slice.lastIndexOf(" ")
  const kept = space > Math.floor(limit * 0.6) ? slice.slice(0, space) : slice
  return `${kept.trimEnd()}…`
}

/**
 * Action of a request: `GUARD_ACTION`, the separator, then `<rule>: <reason> — <model opinion> · <tool call>`, redacted,
 * on one line (invisible characters written out), the detail at most `MAX_ACTION_DETAIL` code points. OpenCode shows
 * the action twice, so the detail keeps the most that fits whole: the full opinion, then the model's verdict alone,
 * then no opinion, each first with the finding's reason, then with the rule's short reason (only when the reason is
 * exactly the rule's usual one, never another rule under the same name); last, the tool call kept whole if it can,
 * the reason cut at a word (the rule's name and at least `MIN_ACTION_REASON` code points of it), then the call cut too. A reason that names the call's target in parentheses (`write to a protected location (<path>)`) leaves it to the
 * tool call, shown once; when the call holds it deeper (an MCP tool's JSON, never a command or code), the call may
 * be reduced to the tool's name instead. For a shell command, a rule whose usual reason is followed by its files
 * (`TARGETED_RULES`) leaves each file the command shows whole to it, and its reason without the list comes before a cut
 * (a file is never shown cut there). The full reason is in the log. An error gives `GUARD_ACTION` alone (still asked).
 */
export function guardAction(redactor: Redactor, reason: string, rule?: string, resource?: string, parts?: ReasonParts): string {
  try {
    const clean = (value: string) => visible(redactor.redactString(value).value.replace(/\s+/g, " ").trim())
    const length = (value: string) => [...value].length
    const name = rule ? clean(rule) : ""
    const own = parts?.local ?? reason
    const usual = rule ? RULE_DETAILS.get(rule) : undefined
    const call = resource ? clean(resource) : ""
    const split = call.indexOf(": ")
    const [tool, target] = split > 0 ? [call.slice(0, split), call.slice(split + 2)] : [call, ""]
    // The call's target (`write: <path>` → `<path>`) named once: by the call, not again by the reason.
    const first = target ? clean(own).replace(` (${target})`, "") : clean(own)
    // A shell command's files after the rule's own reason (never another reason under the same name, never a tool's path).
    const listed = tool === "shell" && rule !== undefined && TARGETED_RULES.has(rule) && usual !== undefined && own.startsWith(`${usual.reason} (`)
    const reasons = [...(listed ? filesOnce(first, target) : [first]), ...(usual?.prompt && own === usual.reason ? [clean(usual.prompt)] : [])]
    // A target the reason names in parentheses and the call holds deeper, in the JSON of an input without a command,
    // path, URL, query or code (an MCP tool's): the call may then be reduced to its tool, the finding's reason naming
    // the target whole. Never a command or code, whose rest would no longer be seen.
    const json = /^[{[]/.test(target)
    const named = json && [...reasons[0]!.matchAll(/ \(([^()]{4,})\)/g)].some((match) => target.includes(match[1]!))
    const opinions = parts ? [clean(parts.opinion), clean(parts.verdict), ""] : [""]
    const why = (text: string) => [name, text].filter(Boolean).join(": ")
    const compose = (text: string, opinion: string, shown: string) =>
      [[why(text), opinion].filter(Boolean).join(" — "), shown].filter(Boolean).join(GUARD_SEPARATOR)
    const whole = [
      ...opinions.flatMap((opinion) => reasons.map((text) => compose(text, opinion, call))),
      ...(named ? opinions.map((opinion) => compose(reasons[0]!, opinion, tool)) : []),
    ]
    let detail = whole.find((candidate) => length(candidate) <= MAX_ACTION_DETAIL)
    if (detail === undefined) {
      // Nothing fits whole: the tool call first (what is approved), then the shortest reason, each cut at a word.
      const text = why(reasons.at(-1)!)
      const reserved = Math.min(length(text), (name ? length(name) + 2 : 0) + MIN_ACTION_REASON)
      const shown = call ? fit(call, Math.max(MAX_ACTION_DETAIL - length(GUARD_SEPARATOR) - reserved, Math.min(length(call), MIN_ACTION_CALL))) : ""
      detail = [fit(text, MAX_ACTION_DETAIL - (shown ? length(GUARD_SEPARATOR) + length(shown) : 0)), shown].filter(Boolean).join(GUARD_SEPARATOR)
    }
    return detail ? `${GUARD_ACTION}${GUARD_SEPARATOR}${detail}` : GUARD_ACTION
  } catch {
    return GUARD_ACTION
  }
}

/** A path of a reason's list shown whole by the call: between blanks, quotes or shell operators. */
const shownWhole = (path: string, call: string) => new RegExp(`(?:^|[\\s'"=(<>|;&,])${path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?=$|[\\s'"|;&)<>,])`).test(call)

/**
 * A reason's list of files (`access to a credential file (<a>, <b> and 2 more)`, its first parentheses): the files the
 * call shows whole left out, the list removed when none is left (the files not named are words of the call too), then,
 * when a list remains, the reason without it.
 */
function filesOnce(reason: string, call: string): string[] {
  const match = / \(([^()]+)\)/.exec(reason)
  if (!match) return [reason]
  const [, list, more = ""] = /^(.*?)( and \d+ more)?$/.exec(match[1]!)!
  const kept = list!.split(", ").filter((path) => !shownWhole(path, call))
  const bare = reason.replace(match[0], "")
  return kept.length ? [reason.replace(match[0], () => ` (${kept.join(", ")}${more})`), bare] : [bare]
}

/**
 * Request made by this plugin: `GUARD_ACTION`, alone or followed by the separator, or `metadata.guard`. Broad on purpose:
 * recognizing a request only forces an ask, while missing ours would let it pass without a question (default agents
 * allow `*`).
 */
export function isGuardRequest(event: Pick<PermissionEvaluation, "action" | "metadata">): boolean {
  const { action } = event
  return action === GUARD_ACTION || (typeof action === "string" && action.startsWith(`${GUARD_ACTION}${GUARD_SEPARATOR}`)) || event.metadata?.guard === true
}

/** Reason (redacted) and rule of an ask set by `review()`, for unattended mode. */
interface Posed {
  readonly reason: string
  readonly rule?: string
}

const MAX_SUMMARY = 200
export const APPROVAL_TTL_MS = 60 * 60 * 1000
/**
 * Entries per table, never reached in practice (calls in progress within the hour): bounds memory and the cost of
 * purging. Eviction remains safe for approvals (second ask), less so for directories (`evaluate` falls back
 * to the session directory) and pending calls (file tracking stopped): each entry is removed as soon as
 * the call ends or is not executed.
 */
export const GATE_TABLE_MAX = 10_000
/** Sets of targets confirmed by the user and remembered (`rememberConfirmations`): at most this many, the oldest forgotten. */
export const MAX_REMEMBERED = 1000
/** Tools whose files created in full (write, patch, heredoc) or modified (edit, patch) are tracked. */
const TRACKED_TOOLS = new Set(["write", "patch", "shell", "edit"])

const args = (input: unknown) => (input !== null && typeof input === "object" ? (input as Record<string, unknown>) : {})

/** Values timestamped by key (session + call id): purged on add, expiry checked on read, bounded size. */
export function timedMap<V>(clock: () => number, max = GATE_TABLE_MAX) {
  const entries = new Map<string, { at: number; value: V }>()
  const fresh = (key: string) => {
    const entry = entries.get(key)
    if (entry === undefined) return undefined
    if (clock() - entry.at <= APPROVAL_TTL_MS) return entry
    entries.delete(key)
    return undefined
  }
  return {
    add(key: string, value: V) {
      const now = clock()
      // Purge: a call whose `execute.after` never arrived (interrupted session) does not stay forever.
      for (const [item, entry] of entries) if (now - entry.at > APPROVAL_TTL_MS) entries.delete(item)
      entries.delete(key)
      while (entries.size >= max) entries.delete(entries.keys().next().value!)
      entries.set(key, { at: now, value })
    },
    get size() {
      return entries.size
    },
    has: (key: string) => fresh(key) !== undefined,
    get: (key: string) => fresh(key)?.value,
    /** Reads then removes. */
    take(key: string) {
      const entry = fresh(key)
      entries.delete(key)
      return entry?.value
    },
  }
}

/** Call to track: judged in full by the model, and files tracked just before (edit, patch) → their `judged`. */
interface PendingCall {
  readonly judged: boolean
  readonly previous: ReadonlyMap<string, boolean>
}

/** Control and formatting characters, separators, and whitespace other than space: invisible or misleading. */
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]|[^\S ]/gu
const ESCAPES: Record<string, string> = { "\t": "\\t", "\n": "\\n", "\r": "\\r" }

/** Path shown as is, its invisible characters written as in JavaScript (`\r`, `\u2028`, `\u{e0001}`). */
function visible(path: string): string {
  return path.replace(INVISIBLE, (char) => {
    const point = char.codePointAt(0)!
    return ESCAPES[char] ?? (point > 0xffff ? `\\u{${point.toString(16)}}` : `\\u${point.toString(16).padStart(4, "0")}`)
  })
}

const count = (number: number, word: string) => `${number} ${word}${number === 1 ? "" : "s"}`

/**
 * Patch summary: each file from the broad read (without hunks), once, full path made visible. At the
 * start, separately, hidden headers that are not already files (`hiddenHeaders`): unusual element, kept
 * visible when the list is cut. Cut list: counts of hidden headers and files at the start.
 */
function patchSummary(patchText: string): string {
  const paths = patchTargets(patchText)
  const listed = new Set(paths)
  const files = paths.map(visible)
  const hidden = hiddenHeaders(patchText)
    .filter((path) => !listed.has(path))
    .map(visible)
  const body = hidden.length
    ? `${hidden.length === 1 ? "hidden header" : "hidden headers"}: ${hidden.join(", ")}${files.length ? `; files: ${files.join(", ")}` : ""}`
    : files.join(", ")
  const line = `patch: ${body}`
  if (line.length <= MAX_SUMMARY) return line
  const counts = hidden.length ? `${count(hidden.length, "hidden header")}, ${count(files.length, "file")}` : count(files.length, "file")
  return `${`patch (${counts}): ${body}`.slice(0, MAX_SUMMARY - 1)}…`
}

/** Summary shown in the permission request, built from the **redacted** input. */
export function summarize(tool: string, redactedInput: unknown): string {
  const args = (redactedInput !== null && typeof redactedInput === "object" ? redactedInput : {}) as Record<string, unknown>
  const pick = (...keys: string[]) => keys.map((key) => args[key]).find((value) => typeof value === "string") as string | undefined
  if (tool === "patch" && typeof args.patchText === "string") return patchSummary(args.patchText)
  const text = pick("command", "path", "url", "query", "code") ?? (JSON.stringify(redactedInput) ?? "")
  const line = `${tool}: ${text.replace(/\s+/g, " ").trim()}`
  return line.length > MAX_SUMMARY ? `${line.slice(0, MAX_SUMMARY - 1)}…` : line
}

export async function registerGate(ctx: GuardContext, deps: GateDeps): Promise<void> {
  const { log } = deps
  /**
   * Calls already approved (session + id → date): `user`, confirmed via "guard", avoids a second ask in `evaluate`;
   * `model`, a local ask left to the decision model by a setting and allowed by it on the whole input, exempts only the
   * sub-command asks left to the model in the same way. The id comes from the provider: without the session, a local
   * server reusing its ids would exempt a call from another session.
   */
  const approvalKey = (sessionID: string, id: string) => `${sessionID}\u0000${id}`
  const clock = deps.now ?? Date.now
  // Check on read: an expired approval no longer exempts from hardening.
  const approved = timedMap<"user" | "model">(clock)
  /** Executable write/patch/shell/edit calls: the files they create or modify are tracked when they finish. */
  const pending = timedMap<PendingCall>(clock)
  /** Directories of a shell command (`shellDirectories`), re-read by `evaluate` for its sub-commands. */
  const directories = timedMap<readonly string[]>(clock)
  /**
   * Memory of confirmations (`rememberConfirmations`): session + rule + exact set of targets → time the user confirmed it.
   * Its entries expire with the table (1 h, the longest delay); the delay in force is read at each use.
   */
  const confirmed = timedMap<number>(clock, MAX_REMEMBERED)
  const confirmedKey = (sessionID: string, rule: string, targets: readonly string[]) => JSON.stringify([sessionID, rule, [...targets].sort()])
  const remembered = (sessionID: string) => (rule: string, targets: readonly string[], minutes: number) => {
    const at = confirmed.get(confirmedKey(sessionID, rule, targets))
    return at !== undefined && clock() - at < minutes * 60_000
  }
  /** Sets lifted by the memory in `execute.before`, per call: its sub-commands in `evaluate` name some of these files. */
  const liftedSets = timedMap<ReadonlyArray<{ readonly rule: string; readonly targets: readonly string[] }>>(clock)
  /** CodeMode calls in progress: their internal calls carry the same identifier, and nothing lifts their findings. */
  const codeCalls = timedMap<true>(clock)
  deps.inspect?.(() => ({ approved: approved.size, pending: pending.size, directories: directories.size }))
  const scripts = deps.scripts ?? createScriptTracker({ home: deps.home })
  const directory = ctx.location.directory
  /**
   * Command and directory where it runs: `workdir` resolved as OpenCode does (relative to the session directory), then
   * leading `cd <path> &&`; any other directory change → nothing (relative paths cannot be resolved).
   */
  function shellCommand(input: unknown): { command: string; cwd: string } | undefined {
    const { command, workdir } = args(input)
    if (typeof command !== "string") return undefined
    const cwd = typeof workdir === "string" && workdir ? resolveLike(directory, workdir, deps.home) : directory
    if (!cwd) return undefined
    const lead = afterLeadingCd(command)
    if (lead) {
      const target = resolveLike(cwd, lead.path, deps.home)
      return target ? { command: lead.rest, cwd: target } : undefined
    }
    return changesDirectory(command) ? undefined : { command, cwd }
  }

  /** Scripts tracked by the session and run by the command (content, or cause if they can no longer be read). */
  function executedScripts(sessionID: string, tool: string, input: unknown, scope: Scope | undefined): ExecutedScript[] | undefined {
    if ((scope ? !scope.scripts : deps.trackScripts === false) || tool !== "shell" || !scripts.has(sessionID)) return undefined
    const shell = shellCommand(input)
    if (!shell) return undefined
    const { command, cwd } = shell
    const found: ExecutedScript[] = []
    for (const run of scriptRuns(command)) {
      const path = resolveLike(cwd, run.path, deps.home)
      const file = path === undefined ? undefined : scripts.read(sessionID, path)
      if (file === undefined) continue
      if ("unverifiable" in file) {
        found.push({ path: run.path, content: "", shell: false, forModel: false, unverifiable: file.unverifiable })
        continue
      }
      const shell = run.kind === "shell" || (run.kind === "direct" && isShellScript(file.content))
      found.push({ path: run.path, content: file.content, shell, forModel: file.judged })
    }
    return found.length ? found : undefined
  }

  /**
   * Patch section that moves its file to another resolved path. `*** Move to:` the same resolved path is a modification:
   * OpenCode 2.2.0 updates the file in place, 2.1.4 writes then deletes it (the modification then finds it missing).
   */
  const movesAway = (section: PatchSection) =>
    section.type === "update" && section.moveTo !== undefined && resolveLike(directory, section.moveTo, deps.home) !== resolveLike(directory, section.path, deps.home)

  /**
   * Tracked files the call will modify (edit, patch Update File, moved to itself included) → their `judged` (false if
   * they changed since or can no longer be read: the modification registers them again, tracked or unverifiable).
   */
  function trackedBefore(sessionID: string, tool: string, input: unknown): Map<string, boolean> {
    const previous = new Map<string, boolean>()
    if (!scripts.has(sessionID)) return previous
    const { path, patchText } = args(input)
    const reading = tool === "patch" && typeof patchText === "string" ? readPatch(patchText) : undefined
    const paths =
      tool === "edit" && typeof path === "string"
        ? [path]
        : reading?.accepted
          ? reading.sections.flatMap((section) => (section.type === "update" && !movesAway(section) ? [section.path] : []))
          : []
    for (const raw of paths) {
      const absolute = resolveLike(directory, raw, deps.home)
      const file = absolute === undefined ? undefined : scripts.read(sessionID, absolute)
      if (absolute !== undefined && file) previous.set(absolute, "unverifiable" in file ? false : file.judged)
    }
    return previous
  }

  /**
   * Files created in full or modified by the completed call, rebuilt from the input (never rewritten by
   * redaction). Modification of a file that was not tracked (neither readable nor unverifiable), deletion or move:
   * tracking stopped. Patch: sections from the exact read, in order; a file added by an earlier section is tracked for
   * the following ones; text it rejects although OpenCode applied it (another version): files from the broad read that
   * exist are marked unverifiable.
   */
  function recordAfter(sessionID: string, tool: string, input: unknown, call: PendingCall) {
    const { path, content, newString, patchText } = args(input)
    const at = (raw: string) => resolveLike(directory, raw, deps.home)
    const record = (absolute: string | undefined, check: Parameters<ScriptTracker["record"]>[2]) => {
      if (absolute && scripts.record(sessionID, absolute, check)) log.debug(`${tool}: file tracked (${absolute}${check.judged ? "" : ", local rules only"})`)
    }
    /** `added`: files added by an earlier section of the same patch, modified without `judged` (see below). */
    const modified = (absolute: string | undefined, contains: readonly string[], added?: ReadonlySet<string>) => {
      if (absolute === undefined) return
      const before = call.previous.get(absolute) ?? (added?.has(absolute) ? false : undefined)
      if (before === undefined) scripts.forget(sessionID, absolute)
      else record(absolute, { judged: before && call.judged, contains })
    }
    if (tool === "write" && typeof path === "string")
      record(at(path), { judged: call.judged, ...(typeof content === "string" ? { equals: content } : {}) })
    if (tool === "edit" && typeof path === "string") modified(at(path), typeof newString === "string" && newString ? [newString] : [])
    if (tool === "patch" && typeof patchText === "string") {
      const reading = readPatch(patchText)
      if (!reading.accepted)
        for (const raw of patchTargets(patchText)) {
          const absolute = at(raw)
          if (absolute && scripts.distrust(sessionID, absolute)) log.debug(`patch: file unverifiable, patch text not read (${absolute})`)
        }
      else {
        // A later Update File applies to the added content in OpenCode 2.2.0, but to the content on disk in 2.1.4 (a file
        // that existed, never shown to the model): tracked, `judged` not kept, until a deletion or move of either end.
        // Tracking before the call takes precedence.
        const added = new Set<string>()
        for (const section of reading.sections) {
          const absolute = at(section.path)
          if (section.type === "add") {
            record(absolute, { judged: call.judged, equals: section.content })
            if (absolute) added.add(absolute)
          } else if (section.type === "delete" || movesAway(section)) {
            const target = section.type === "update" && section.moveTo ? at(section.moveTo) : undefined
            for (const path of [absolute, target])
              if (path) {
                scripts.forget(sessionID, path)
                added.delete(path)
              }
          } else modified(absolute, section.added.filter(Boolean), added)
        }
      }
    }
    const shell = tool === "shell" ? shellCommand(input) : undefined
    if (shell)
      for (const file of heredocFiles(shell.command))
        record(resolveLike(shell.cwd, file.path, deps.home), { judged: call.judged, equals: file.content, exact: true })
  }

  await ctx.tool.hook("execute.before", async (event) => {
    const key = approvalKey(event.sessionID, event.id)
    // An approval is valid only for the confirmed call. Removed here: a previous call with the same identifier (confirmed
    // then denied by OpenCode, without `execute.after`), or the `execute` call whose CodeMode script starts this internal call
    // (same identifier, packages/core/src/tool.ts, v2.1.2), does not exempt this one from `evaluate` hardening.
    // The pending entry remains: simultaneous internal calls with the same identifier would lose tracking of a written file.
    approved.take(key)
    directories.take(key)
    liftedSets.take(key)
    // A call made by CodeMode code arrives with its identifier until its own `execute.after`.
    const fromCode = event.tool !== CODEMODE_TOOL && codeCalls.has(key)
    if (event.tool === CODEMODE_TOOL) codeCalls.add(key, true)
    // Unprotected agent chosen by the user: nothing, except the placeholder rule (integrity of the real secret).
    if (await deps.unprotected?.isUnprotected(event.sessionID, event.agent)) {
      const kept = placeholderFinding(event.tool, event.input)
      if (kept) {
        log.info(`${event.tool} → deny (${sourceNote("local", kept.rule)}, unprotected agent ${event.agent}): ${kept.reason}`)
        throw new Error(blockedMessage(kept.reason, kept.rule))
      }
      log.debug(`${event.tool} → allow (unprotected agent ${event.agent})`)
      return
    }
    let decision: Decision
    let executed: ExecutedScript[] | undefined
    // Parts not checked after an internal error: an "allow" decision then becomes an ask.
    const unchecked: string[] = []
    // Settings of this call; an internal error keeps the startup ones, and an allow then becomes an ask.
    let scope: Scope | undefined
    try {
      scope = deps.scopes?.resolve(event.sessionID, event.agent)
    } catch (error) {
      unchecked.push("the settings of this agent")
      log.error("internal error while resolving the settings of this agent", error)
    }
    try {
      executed = executedScripts(event.sessionID, event.tool, event.input, scope)
    } catch (error) {
      unchecked.push("the scripts run by the command")
      log.error("internal error while reading the scripts run by the command", error)
    }
    /**
     * Call not executed (denial, unattended mode, refused confirmation): OpenCode then does not trigger
     * `execute.after` (packages/core/src/tool.ts, v2.0.31), and its directories and sets lifted by the memory are
     * removed here.
     */
    const reject = (error: unknown): never => {
      directories.take(key)
      liftedSets.take(key)
      if (event.tool === CODEMODE_TOOL) codeCalls.take(key)
      throw error
    }
    // Directory where the command runs (error: session directory, as before).
    let cwds: readonly string[] | undefined
    if (event.tool === "shell")
      try {
        const { command, workdir } = args(event.input)
        if (typeof command === "string") {
          cwds = (deps.directoriesOf ?? shellDirectories)(command, workdir, directory, deps.home)
          directories.add(key, cwds)
        }
      } catch (error) {
        unchecked.push("the directories where the command runs")
        log.error("internal error while resolving the shell directory", error)
      }
    try {
      decision = await deps.decider.decide({
        tool: event.tool,
        input: event.input,
        agent: event.agent,
        directory: ctx.location.directory,
        ...(cwds ? { cwds } : {}),
        ...(executed ? { scripts: executed } : {}),
        ...(scope ? { scope } : {}),
        // Apart from the scope: a rule of the global guard.json still applies when the scope cannot be resolved.
        ...(deps.scopes ? { rules: deps.scopes.rules() } : {}),
        ...(fromCode ? { fromCode } : { remembered: remembered(event.sessionID) }),
      })
    } catch (error) {
      log.error("internal error while deciding", error)
      // Input redacted if possible; otherwise no excerpt of the input (the summary is reduced to the tool name).
      let redactedInput: unknown = UNAVAILABLE_INPUT
      try {
        redactedInput = deps.redactor.redactDeep(event.input).value
      } catch (redactError) {
        log.error("internal error while redacting the input: confirmation shows the tool name only", redactError)
      }
      decision = { verdict: "ask", reason: "internal guard plugin error: confirmation required", rule: INTERNAL_ERROR_RULE, source: "default", redactedInput }
    }
    for (const waiver of decision.waived ?? []) log.info(liftedLine(event.tool, waiver))
    const recalled = (decision.waived ?? []).filter((waiver) => waiver.kind === "remembered")
    if (recalled.length) liftedSets.add(key, recalled)
    // A denial stays as is; an ask also names the unchecked part; never an allow on it. The rule of an allow (heredoc
    // data decided by the model) does not name this ask.
    if (unchecked.length && decision.verdict === "allow")
      decision = {
        ...decision,
        verdict: "ask",
        reason: `internal guard plugin error, ${unchecked.join(" and ")} could not be checked: confirmation required`,
        rule: INTERNAL_ERROR_RULE,
        source: "default",
      }
    else if (unchecked.length && decision.verdict === "ask")
      decision = { ...decision, reason: `${decision.reason}; ${unchecked.join(" and ")} could not be checked (internal error)` }
    // Duration of model calls at the end of the line (measures the effect of the retry on timeout).
    const timing = decision.modelMs === undefined ? "" : ` [model ${decision.modelMs} ms${(decision.attempts ?? 1) > 1 ? `, ${decision.attempts} attempts` : ""}]`
    // Asks and denials always logged, with their rule; allows only with `debug`, except a local ask the decision model
    // allowed because a setting left it to it.
    if (decision.verdict === "allow" && !decision.bySetting) log.debug(`${event.tool} → allow (${decision.source}): ${decision.reason}${timing}`)
    else log.info(`${event.tool} → ${decision.verdict} (${sourceNote(decision.source, decision.rule)}): ${decision.reason}${timing}`)
    if (decision.verdict === "deny") return reject(new Error(blockedMessage(decision.reason, decision.rule)))
    /** Executable call (allowed or confirmed): file tracking when it ends; never throws (the tool would run without it). */
    const track = () => {
      // Every agent's files: a script written by one agent may be run by another.
      if (!(deps.scopes ? deps.scopes.tracking() : deps.trackScripts !== false) || !TRACKED_TOOLS.has(event.tool)) return
      try {
        pending.add(key, { judged: decision.judgedInFull === true, previous: trackedBefore(event.sessionID, event.tool, event.input) })
      } catch (error) {
        log.error("internal error while preparing file tracking", error)
      }
    }
    if (decision.verdict !== "ask") {
      // Never after an internal error (the allow then became an ask above), nor on a truncated input.
      if (decision.bySetting && decision.judgedInFull === true) approved.add(key, "model")
      track()
      return
    }
    // Unattended mode (e.g. `--auto`, which would approve every ask client-side): denial.
    if (deps.askAs === "deny") {
      log.info(`${event.tool} → denied (unattended mode)`)
      return reject(new Error(unattendedMessage(decision.reason, decision.rule)))
    }
    let resource: string
    try {
      resource = decision.redactedInput === UNAVAILABLE_INPUT ? event.tool : summarize(event.tool, decision.redactedInput)
    } catch (error) {
      log.error("internal error while summarizing the action", error)
      resource = event.tool
    }
    // Simple rejection → error rethrown as is (step end, like native tools);
    // rejection with feedback → Tool.Error passed to the model.
    try {
      await ctx.permission.assert({
        sessionID: event.sessionID,
        agent: event.agent,
        action: guardAction(deps.redactor, decision.reason, decision.rule, resource, decision.parts),
        resources: [resource],
        metadata: { guard: true, tool: event.tool, reason: decision.reason, ...(decision.rule ? { rule: decision.rule } : {}) },
        source: { type: "tool", messageID: event.messageID, id: event.id },
      })
    } catch (error) {
      // Never the user's feedback text: only the error class.
      log.info(`${event.tool} → confirmation not granted (${(error as Error | undefined)?.name ?? "error"})`)
      return reject(error)
    }
    log.info(`${event.tool} → confirmed by the user`)
    approved.add(key, "user")
    // Memory of confirmations: only this confirmation by the user, of a finding whose targets are all known, with nothing
    // left unchecked, while a delay is set for the call.
    if (decision.rule && decision.targets?.length && !unchecked.length && ((scope?.policy ?? deps.active)?.rememberMinutes ?? 0) > 0)
      confirmed.add(confirmedKey(event.sessionID, decision.rule, decision.targets), clock())
    // A long confirmation does not let directories expire before `evaluate`.
    if (cwds) directories.add(key, cwds)
    track()
  })

  await ctx.tool.hook("execute.after", (event) => {
    const key = approvalKey(event.sessionID, event.id)
    approved.take(key)
    directories.take(key)
    liftedSets.take(key)
    if (event.tool === CODEMODE_TOOL) codeCalls.take(key)
    const call = pending.take(key)
    // Failed call: file unchanged, tracking unchanged.
    if (!call || event.status !== "completed") return
    try {
      recordAfter(event.sessionID, event.tool, event.input, call)
    } catch (error) {
      log.error("internal error while tracking created files", error)
    }
  })

  /** Info line for an ask or a denial added in `permission.evaluate`, once set: a failing log loses nothing. */
  const note = (line: string) => {
    try {
      log.info(line)
    } catch {}
  }

  await ctx.permission.hook("evaluate", async (event) => {
    if (await deps.unprotected?.isUnprotected(event.sessionID, event.agent)) return
    let posed: Posed | undefined
    try {
      posed = review(event)
    } catch (error) {
      // Like execute.before: on internal error, ask rather than let it pass, under `internal-error` (no setting reaches it).
      log.error("internal error in permission.evaluate", error)
      if (event.effect === "allow") {
        const reason = "internal error: the request could not be checked"
        event.effect = "ask"
        event.message = askMessage(reason, INTERNAL_ERROR_RULE)
        posed = { reason, rule: INTERNAL_ERROR_RULE }
      }
    }
    // A shell request without a tool call (OpenCode 2.2.x: the shell condition of a scheduled task, run by OpenCode
    // itself, outside the shell tool and its `execute.before`): when it runs, OpenCode settles every remaining ask
    // without anyone present and allows the commands it scanned. Any ask left (the plugin's, OpenCode's own, or the
    // fallback of an internal error) is denied instead; a denial stays.
    if (event.action === "shell" && event.source === undefined && event.effect === "ask") {
      const reason = posed ? posed.reason : describeRequest(event, deps.redactor)
      event.effect = "deny"
      event.message = blockedMessage(`${reason}; ${UNATTENDED_SHELL}`, posed?.rule)
      note(`shell without a tool call → deny (${sourceNote("not run by a tool call", posed?.rule)}): ${reason}`)
      return
    }
    // Unattended mode: every remaining ask becomes a denial, including OpenCode's native
    // asks (`read *.env` rule, user `ask` rules) that an `--auto` client would approve.
    if (deps.askAs === "deny" && event.effect === "ask") {
      // The rule of an ask set by `review()` goes where a denial names it, not inside the reason.
      const reason = posed ? posed.reason : describeRequest(event, deps.redactor)
      event.effect = "deny"
      event.message = unattendedMessage(reason, posed?.rule)
      note(`permission ${event.action} → deny (${sourceNote("unattended mode", posed?.rule)}): ${reason}`)
    }
  })

  function review(event: PermissionEvaluation): Posed | undefined {
    // Never `shell`: its sub-commands are always checked below (a denial found there does not become an ask).
    if (event.action !== "shell" && isGuardRequest(event)) {
      // Default agents allow `*`: without this forcing, the assert would pass without a question. Already logged by the
      // hook that made the request.
      if (event.effect === "deny") return undefined
      const reason = typeof event.metadata?.reason === "string" ? deps.redactor.redactString(event.metadata.reason).value : "action judged risky"
      const rule = typeof event.metadata?.rule === "string" ? deps.redactor.redactString(event.metadata.rule).value : undefined
      event.effect = "ask"
      event.message = askMessage(reason, rule)
      return { reason, rule }
    }
    // Defense in depth: sub-commands extracted by OpenCode's shell parser.
    if (event.action !== "shell" || event.effect === "deny") return undefined
    const scoped = deps.scopes ? deps.scopes.resolve(event.sessionID, event.agent).policy : deps.active
    // A shell request without a tool call (its ask is denied below), or from CodeMode code: neither an exception nor the
    // memory lifts a finding.
    const unwaived = event.source === undefined || codeCalls.has(approvalKey(event.sessionID, event.source.id))
    const active = unwaived && scoped ? withoutWaivers(scoped) : scoped
    // The user's rules of the version just resolved (the global guard.json's included).
    const custom = deps.scopes ? deps.scopes.rules() : deps.rules
    // Call already confirmed in execute.before: no second ask, but a denial still applies. Allowed there by the decision
    // model on an ask a setting left to it: only the sub-command asks left to the model by a setting are discarded.
    const approval = event.source === undefined ? undefined : approved.get(approvalKey(event.sessionID, event.source.id))
    const confirmed = approval === "user"
    // Directories computed in execute.before; unknown (other source, plugin reloaded meanwhile): session directory.
    const cwds = event.source === undefined ? undefined : directories.get(approvalKey(event.sessionID, event.source.id))
    const credentialContent = deps.readContent ? createCredentialContent({ directories: cwds ?? [ctx.location.directory], home: deps.home }) : undefined
    const realPaths = deps.resolveLinks ? createRealPath({ directories: cwds ?? [ctx.location.directory] }) : undefined
    // Memory: a set confirmed in this session, or for the call `execute.before` let through on a remembered set, any part
    // of it (each sub-command names some of its files); never for another call.
    const sets = event.source === undefined ? undefined : liftedSets.get(approvalKey(event.sessionID, event.source.id))
    const recalls = remembered(event.sessionID)
    const memory = (rule: string, targets: readonly string[], minutes: number) =>
      recalls(rule, targets, minutes) || (sets ?? []).some((set) => set.rule === rule && targets.every((target) => set.targets.includes(target)))
    // Findings lifted by an exception or the memory: logged once each.
    const lifted = new Map<string, Waiver>()
    const waived = (waiver: Waiver) => lifted.set(JSON.stringify([waiver.rule, waiver.kind, waiver.targets]), waiver)
    // A failing sub-command never masks another's denial: each is judged separately, and the error is kept
    // separate (outside `mostSevere`, which the confirmed-call rule would filter).
    let failed = false
    const findings = event.resources.map((resource, index) => {
      try {
        return shellFinding(resource, {
          // An exception or the memory needs the other sub-commands of the call to only read, like a command's other parts.
          ...(event.resources.length > 1 ? { others: event.resources.filter((_, other) => other !== index) } : {}),
          redactor: deps.redactor,
          home: deps.home,
          custom,
          cwd: ctx.location.directory,
          ...(cwds ? { cwds } : {}),
          ...(credentialContent ? { credentialContent } : {}),
          ...(realPaths ? { realPaths } : {}),
          protectedDirs: deps.protectedDirs,
          ...(deps.pluginDirs ? { pluginDirs: deps.pluginDirs } : {}),
          ...(deps.serviceDirs ? { serviceDirs: deps.serviceDirs } : {}),
          active,
          ...(unwaived ? {} : { remembered: memory }),
          waived,
        })
      } catch (error) {
        failed = true
        // A logger that throws does not lose another sub-command's denial.
        try {
          log.error("internal error while checking a shell sub-command in permission.evaluate", error)
        } catch {}
        return undefined
      }
    })
    for (const waiver of lifted.values()) note(liftedLine("shell sub-commands", waiver))
    // Ask coming only from heredoc data: already decided by the model in execute.before (discarded before
    // `mostSevere`, so as not to mask another sub-command); likewise an ask left to the model by a setting, once it
    // allowed the whole command.
    const finding = mostSevere(findings.filter((item) => !item?.dataOnly && !(approval === "model" && item?.verdict === "ask" && bySetting(item))))
    if (finding?.verdict === "deny") {
      // execute.before saw only one ask on the whole command: a rule gap to spot in the log.
      if (confirmed) log.warn(`deny found only in shell sub-commands after approval (rule ${finding.rule})`)
      const reason = deps.redactor.redactString(finding.reason).value
      event.effect = "deny"
      event.message = blockedMessage(reason, finding.rule)
      note(`shell sub-commands → deny (${sourceNote("local", finding.rule)}): ${reason}`)
    } else if (finding && !confirmed) {
      if (event.effect === "allow") {
        const reason = deps.redactor.redactString(finding.reason).value
        event.effect = "ask"
        event.message = askMessage(reason, finding.rule)
        note(`shell sub-commands → ask (${sourceNote("local", finding.rule)}): ${reason}`)
        return { reason, rule: finding.rule }
      }
    } else if (failed && event.effect === "allow") {
      // Like the execute.before fallback: an unchecked sub-command asks, even for an already confirmed call, under
      // `internal-error` (no setting reaches it).
      const reason = "internal error: a shell sub-command could not be checked"
      event.effect = "ask"
      event.message = askMessage(reason, INTERNAL_ERROR_RULE)
      note(`shell sub-commands → ask (${sourceNote("internal error", INTERNAL_ERROR_RULE)}): ${reason}`)
      return { reason, rule: INTERNAL_ERROR_RULE }
    }
    return undefined
  }
}

/** Why a shell request without a tool call is denied rather than asked. */
export const UNATTENDED_SHELL =
  "this shell command is run by OpenCode itself, not by a tool call (the condition of a scheduled task): its confirmation cannot be asked when it runs, so it is denied"

/** Reason shown for an ask converted to a denial (no secret, truncated). */
function describeRequest(event: PermissionEvaluation, redactor: Redactor): string {
  if (event.message) return redactor.redactString(event.message.replace(/^\[guard\]\s*/, "")).value
  try {
    const first = Array.isArray(event.resources) ? String(event.resources[0] ?? "") : ""
    const resource = redactor.redactString(first).value.replace(/\s+/g, " ").slice(0, 120)
    return resource ? `${event.action} (${resource})` : event.action
  } catch {
    return event.action
  }
}
