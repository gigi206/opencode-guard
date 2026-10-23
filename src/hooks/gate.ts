import { UNAVAILABLE_INPUT, type Decider, type Decision, type ExecutedScript } from "../decide.ts"
import { afterLeadingCd, changesDirectory, heredocFiles, scriptRuns, shellFinding } from "../rules/shell.ts"
import { createCredentialContent } from "../credential-content.ts"
import { createRealPath } from "../real-path.ts"
import { placeholderFinding } from "../rules/tools.ts"
import { hiddenHeaders, patchTargets, readPatch } from "../patch.ts"
import { createScriptTracker, isShellScript, resolveLike, shellDirectories, type ScriptTracker } from "../scripts.ts"
import type { UnprotectedGate } from "./unprotected.ts"
import type { ActiveRules } from "../rules/features.ts"
import { mostSevere, type CustomRule } from "../rules/types.ts"
import type { Redactor } from "../secrets/redact.ts"
import type { GuardContext, Logger, PermissionEvaluation } from "../types.ts"

/** Plugin-specific permission action ("ask" requests via `ctx.permission.assert`). */
export const GUARD_ACTION = "guard"

export interface GateDeps {
  readonly decider: Decider
  readonly redactor: Redactor
  readonly home?: string
  readonly rules?: readonly CustomRule[]
  readonly protectedDirs?: readonly string[]
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
  /** Local rule switches (`evaluate` sub-commands); absent = all active. */
  readonly active?: ActiveRules
  /** `scripts` switch: `false` = no tracking or reading of scripts written then executed. */
  readonly trackScripts?: boolean
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

/** Rejection message. The `placeholder` rule specifically asks for another change: no instruction. */
export function blockedMessage(reason: string, rule?: string): string {
  return rule === "placeholder" ? `[guard] Blocked: ${reason}` : `[guard] Blocked: ${reason}. ${NO_EVASION}`
}

/** Explicit denial in unattended mode: the model knows why and does not retry in a loop. */
export function unattendedMessage(reason: string): string {
  return `[guard] Blocked: confirmation required, but unattended mode (askAs: deny) denies it: ${reason}. ${NO_EVASION}`
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
   * Calls already approved via "guard" (session + id → date): avoids a second ask in `evaluate`. The id comes
   * from the provider: without the session, a local server reusing its ids would exempt a call from another session.
   */
  const approvalKey = (sessionID: string, id: string) => `${sessionID}\u0000${id}`
  const clock = deps.now ?? Date.now
  // Check on read: an expired approval no longer exempts from hardening.
  const approved = timedMap<true>(clock)
  /** Executable write/patch/shell/edit calls: the files they create or modify are tracked when they finish. */
  const pending = timedMap<PendingCall>(clock)
  /** Directories of a shell command (`shellDirectories`), re-read by `evaluate` for its sub-commands. */
  const directories = timedMap<readonly string[]>(clock)
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
  function executedScripts(sessionID: string, tool: string, input: unknown): ExecutedScript[] | undefined {
    if (deps.trackScripts === false || tool !== "shell" || !scripts.has(sessionID)) return undefined
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
   * Tracked files the call will modify (edit, patch Update File) → their `judged` (false if they changed since or can no
   * longer be read: the modification registers them again, tracked or unverifiable).
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
          ? reading.sections.flatMap((section) => (section.type === "update" && !section.moveTo ? [section.path] : []))
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
   * tracking stopped. Patch: sections from the exact read; text it rejects although OpenCode applied it (another
   * version): files from the broad read that exist are marked unverifiable.
   */
  function recordAfter(sessionID: string, tool: string, input: unknown, call: PendingCall) {
    const { path, content, newString, patchText } = args(input)
    const at = (raw: string) => resolveLike(directory, raw, deps.home)
    const record = (absolute: string | undefined, check: Parameters<ScriptTracker["record"]>[2]) => {
      if (absolute && scripts.record(sessionID, absolute, check)) log.debug(`${tool}: file tracked (${absolute}${check.judged ? "" : ", local rules only"})`)
    }
    const modified = (absolute: string | undefined, contains: readonly string[]) => {
      if (absolute === undefined) return
      const before = call.previous.get(absolute)
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
      else
        for (const section of reading.sections) {
          const absolute = at(section.path)
          if (section.type === "add") record(absolute, { judged: call.judged, equals: section.content })
          else if (section.type === "delete" || section.moveTo) {
            if (absolute) scripts.forget(sessionID, absolute)
            const target = section.type === "update" && section.moveTo ? at(section.moveTo) : undefined
            if (target) scripts.forget(sessionID, target)
          } else modified(absolute, section.added.filter(Boolean))
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
    // Unprotected agent chosen by the user: nothing, except the placeholder rule (integrity of the real secret).
    if (await deps.unprotected?.isUnprotected(event.sessionID, event.agent)) {
      const kept = placeholderFinding(event.tool, event.input)
      if (kept) throw new Error(blockedMessage(kept.reason, kept.rule))
      log.debug(`${event.tool} → allow (unprotected agent ${event.agent})`)
      return
    }
    let decision: Decision
    let executed: ExecutedScript[] | undefined
    // Parts not checked after an internal error: an "allow" decision then becomes an ask.
    const unchecked: string[] = []
    try {
      executed = executedScripts(event.sessionID, event.tool, event.input)
    } catch (error) {
      unchecked.push("the scripts run by the command")
      log.error("internal error while reading the scripts run by the command", error)
    }
    /**
     * Call not executed (denial, unattended mode, refused confirmation): OpenCode then does not trigger
     * `execute.after` (packages/core/src/tool.ts, v2.0.31), and its directories are removed here.
     */
    const reject = (error: unknown): never => {
      directories.take(key)
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
      decision = { verdict: "ask", reason: "internal guard plugin error: confirmation required", source: "default", redactedInput }
    }
    // A denial stays as is; an ask also names the unchecked part; never an allow on it.
    if (unchecked.length && decision.verdict === "allow")
      decision = { ...decision, verdict: "ask", reason: `internal guard plugin error, ${unchecked.join(" and ")} could not be checked: confirmation required`, source: "default" }
    else if (unchecked.length && decision.verdict === "ask")
      decision = { ...decision, reason: `${decision.reason}; ${unchecked.join(" and ")} could not be checked (internal error)` }
    // Duration of model calls at the end of the line (measures the effect of the retry on timeout).
    const timing = decision.modelMs === undefined ? "" : ` [model ${decision.modelMs} ms${(decision.attempts ?? 1) > 1 ? `, ${decision.attempts} attempts` : ""}]`
    log.debug(`${event.tool} → ${decision.verdict} (${decision.source}): ${decision.reason}${timing}`)
    if (decision.verdict === "deny") return reject(new Error(blockedMessage(decision.reason, decision.rule)))
    /** Executable call (allowed or confirmed): file tracking when it ends; never throws (the tool would run without it). */
    const track = () => {
      if (deps.trackScripts === false || !TRACKED_TOOLS.has(event.tool)) return
      try {
        pending.add(key, { judged: decision.judgedInFull === true, previous: trackedBefore(event.sessionID, event.tool, event.input) })
      } catch (error) {
        log.error("internal error while preparing file tracking", error)
      }
    }
    if (decision.verdict !== "ask") {
      track()
      return
    }
    // Unattended mode (e.g. `--auto`, which would approve every ask client-side): denial.
    if (deps.askAs === "deny") return reject(new Error(unattendedMessage(decision.reason)))
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
        action: GUARD_ACTION,
        resources: [resource],
        metadata: { guard: true, tool: event.tool, reason: decision.reason },
        source: { type: "tool", messageID: event.messageID, id: event.id },
      })
    } catch (error) {
      // Never the user's feedback text: only the error class.
      log.debug(`${event.tool} → confirmation not granted (${(error as Error | undefined)?.name ?? "error"})`)
      return reject(error)
    }
    log.debug(`${event.tool} → confirmed by the user`)
    approved.add(key, true)
    // A long confirmation does not let directories expire before `evaluate`.
    if (cwds) directories.add(key, cwds)
    track()
  })

  await ctx.tool.hook("execute.after", (event) => {
    const key = approvalKey(event.sessionID, event.id)
    approved.take(key)
    directories.take(key)
    const call = pending.take(key)
    // Failed call: file unchanged, tracking unchanged.
    if (!call || event.status !== "completed") return
    try {
      recordAfter(event.sessionID, event.tool, event.input, call)
    } catch (error) {
      log.error("internal error while tracking created files", error)
    }
  })

  await ctx.permission.hook("evaluate", async (event) => {
    if (await deps.unprotected?.isUnprotected(event.sessionID, event.agent)) return
    try {
      review(event)
    } catch (error) {
      // Like execute.before: on internal error, ask rather than let it pass.
      log.error("internal error in permission.evaluate", error)
      if (event.effect === "allow") {
        event.effect = "ask"
        event.message = "[guard] internal error: confirmation required"
      }
    }
    // Unattended mode: every remaining ask becomes a denial, including OpenCode's native
    // asks (`read *.env` rule, user `ask` rules) that an `--auto` client would approve.
    if (deps.askAs === "deny" && event.effect === "ask") {
      event.effect = "deny"
      event.message = unattendedMessage(describeRequest(event, deps.redactor))
    }
  })

  function review(event: PermissionEvaluation) {
    if (event.action === GUARD_ACTION) {
      // Default agents allow `*`: without this forcing, the assert would pass without a question.
      if (event.effect === "deny") return
      const reason = typeof event.metadata?.reason === "string" ? deps.redactor.redactString(event.metadata.reason).value : "action judged risky"
      event.effect = "ask"
      event.message = `[guard] ${reason}`
      return
    }
    // Defense in depth: sub-commands extracted by OpenCode's tree-sitter parser.
    if (event.action !== "shell" || event.effect === "deny") return
    // Call already confirmed in execute.before: no second ask, but a denial still applies.
    const confirmed = event.source !== undefined && approved.has(approvalKey(event.sessionID, event.source.id))
    // Directories computed in execute.before; unknown (other source, plugin reloaded meanwhile): session directory.
    const cwds = event.source === undefined ? undefined : directories.get(approvalKey(event.sessionID, event.source.id))
    const credentialContent = deps.readContent ? createCredentialContent({ directories: cwds ?? [ctx.location.directory], home: deps.home }) : undefined
    const realPaths = deps.resolveLinks ? createRealPath({ directories: cwds ?? [ctx.location.directory] }) : undefined
    // A failing sub-command never masks another's denial: each is judged separately, and the error is kept
    // separate (outside `mostSevere`, which the confirmed-call rule would filter).
    let failed = false
    const findings = event.resources.map((resource) => {
      try {
        return shellFinding(resource, {
          redactor: deps.redactor,
          home: deps.home,
          custom: deps.rules,
          cwd: ctx.location.directory,
          ...(cwds ? { cwds } : {}),
          ...(credentialContent ? { credentialContent } : {}),
          ...(realPaths ? { realPaths } : {}),
          protectedDirs: deps.protectedDirs,
          ...(deps.serviceDirs ? { serviceDirs: deps.serviceDirs } : {}),
          active: deps.active,
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
    // Ask coming only from heredoc data: already decided by the model in execute.before (discarded before
    // `mostSevere`, so as not to mask another sub-command).
    const finding = mostSevere(findings.filter((item) => !item?.dataOnly))
    if (finding?.verdict === "deny") {
      // execute.before saw only one ask on the whole command: a rule gap to spot in the log.
      if (confirmed) log.warn(`deny found only in shell sub-commands after approval (rule ${finding.rule})`)
      event.effect = "deny"
      event.message = blockedMessage(deps.redactor.redactString(finding.reason).value, finding.rule)
    } else if (finding && !confirmed) {
      if (event.effect === "allow") {
        event.effect = "ask"
        event.message = `[guard] ${deps.redactor.redactString(finding.reason).value}`
      }
    } else if (failed && event.effect === "allow") {
      // Like the execute.before fallback: an unchecked sub-command asks, even for an already confirmed call.
      event.effect = "ask"
      event.message = "[guard] internal error: confirmation required"
    }
  }
}

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
