import { createHash } from "node:crypto"
import type { GuardConfig } from "./config.ts"
import { ModelError, type ModelClient } from "./model/client.ts"
import { QUESTIONS, SCRIPTS_NOTE, STATE_NOTE, interpret } from "./model/questions.ts"
import { shellFinding, type ShellRuleContext } from "./rules/shell.ts"
import { toolFinding } from "./rules/tools.ts"
import { INTERNAL_ERROR_RULE, mostSevere, type Finding, type Verdict } from "./rules/types.ts"
import { createCredentialContent } from "./credential-content.ts"
import { createRealPath } from "./real-path.ts"
import { ruleEnabled } from "./rules/features.ts"
import { scriptDirectories, type UnverifiableCause } from "./scripts.ts"
import type { Redactor } from "./secrets/redact.ts"
import type { Logger } from "./types.ts"

/** Script run by the command, created entirely by the agent in the session (`scripts.ts`). */
export interface ExecutedScript {
  /** Path as written in the command. */
  readonly path: string
  readonly content: string
  /** Read by a shell: the shell rules apply to its content. */
  readonly shell: boolean
  /** Content already judged in full by the model: it can be shown to it (otherwise local rules only). */
  readonly forModel: boolean
  /** Existing file that cannot be checked (unreadable, or named by an unreadable patch): empty content, cause. */
  readonly unverifiable?: UnverifiableCause
}

const UNVERIFIABLE_TEXT: Record<UnverifiableCause, string> = {
  "too-large": "larger than the 64 KiB limit",
  link: "it is a symbolic link",
  "not-regular": "it is not a regular file",
  credential: "it is a credential file",
  unreadable: "it cannot be read",
  patch: "its format differs from OpenCode 2.0.31's",
}

export interface ToolCall {
  readonly tool: string
  readonly input: unknown
  readonly agent?: string
  readonly directory?: string
  /** Shell command: directories from which its relative paths start (`shellDirectories`); absent: `directory`. */
  readonly cwds?: readonly string[]
  readonly scripts?: readonly ExecutedScript[]
}

export interface Decision {
  readonly verdict: Verdict
  readonly reason: string
  readonly source: "local" | "model" | "cache" | "model-error" | "default" | "read-only" | "task-list"
  /** Duration of model calls (all attempts included) and number of attempts, for the log. */
  readonly modelMs?: number
  readonly attempts?: number
  /** Local rule that produced the verdict (e.g. `placeholder`). */
  readonly rule?: string
  /** Redacted input (the only form allowed to leave: decision model, permission request, logs). */
  readonly redactedInput: unknown
  /** The model judged the input in full (opinion obtained, input not truncated): condition for tracking created files. */
  readonly judgedInFull?: boolean
}

export interface DeciderDeps {
  readonly config: GuardConfig
  readonly redactor: Redactor
  readonly model?: ModelClient
  readonly home?: string
  /** Directories protected against writes (plugin directory). */
  readonly protectedDirs?: readonly string[]
  /** Directories of the OpenCode service files resolved from the environment (`service.json` recognized under them). */
  readonly serviceDirs?: readonly string[]
  /** Private keys recognized by their content (`credential-content.ts`): true in production; absent = names only. */
  readonly readContent?: boolean
  /** Protected locations recognized through a symbolic link (`real-path.ts`): true in production. */
  readonly resolveLinks?: boolean
  readonly now?: () => number
  /** Log of internal errors from part of the decision (command, tracked script). */
  readonly log?: Pick<Logger, "error">
}

export { INTERNAL_ERROR_RULE }

/** Input that cannot be redacted: nothing leaves (neither to the model nor in the request, which only shows the tool name). */
export const UNAVAILABLE_INPUT = Symbol("guard/unavailable-input")

/**
 * Read-only tools: never submitted to the model. Out of 272 judged reads (real log), its only 4 asks
 * date from the first day (initial threshold 0.4) and would not happen with the current settings; the others came from a
 * timeout (bursts of parallel subagent reads). Credential files remain covered by the
 * local rules (ask), and all output is redacted.
 */
/** Quoted length of an error message in a reason (after redaction). */
const ERROR_SHOWN = 160

const READ_ONLY_TOOLS = new Set(["read", "glob", "grep"])

/**
 * Task list (`todowrite`, present only if `experimental.todo` is true): never submitted to the model. The tool only
 * requests its permission and returns the received list (`core/src/tool/plugin/todo.ts`, v2.1.1): no file or
 * network. Local rules still apply (placeholder, secret, paths, user rules).
 */
const TASK_LIST_TOOLS = new Set(["todowrite"])

/** Tools never submitted to the model, neither for a verdict nor for an opinion attached to a local ask. */
const modelSkipped = (tool: string): boolean => READ_ONLY_TOOLS.has(tool) || TASK_LIST_TOOLS.has(tool)

/**
 * Finding from the shell rules in an executed script: at most one ask (a file contains branches that are not
 * executed), never "data only"; the placeholder rule (write) does not apply to an execution: discarded by the shell
 * rules before the findings are combined (`executedScript`), it never takes the place of another rule's finding.
 * Unverifiable script (created by the agent, unreadable since; or named by an unreadable patch): `script-unverifiable` ask.
 */
export function scriptFinding(script: ExecutedScript, ctx: ShellRuleContext): Finding | undefined {
  // Unknown content: whether read by a shell or not, it could not be checked. Cause `patch`: file not necessarily created by
  // the agent (modified or moved by the patch), separate reason.
  if (script.unverifiable)
    return ruleEnabled("script-unverifiable", ctx.active)
      ? {
          verdict: "ask",
          rule: "script-unverifiable",
          reason:
            script.unverifiable === "patch"
              ? `the script ${script.path} run by this command was named in this session by a patch the plugin could not read (${UNVERIFIABLE_TEXT.patch})`
              : `the script ${script.path} run by this command was created by the agent in this session but can no longer be checked (${UNVERIFIABLE_TEXT[script.unverifiable]})`,
        }
      : undefined
  if (!script.shell) return undefined
  const found = shellFinding(script.content, { ...ctx, executedScript: true })
  if (!found) return undefined
  return { verdict: "ask", rule: found.rule, reason: `${found.reason}, in the script ${script.path} run by this command` }
}

/** Truncates the redacted input for the model (accuracy drops with a long `state`). */
export function truncateInput(input: unknown, max: number): unknown {
  const serialized = JSON.stringify(input) ?? "null"
  if (serialized.length <= max) return input
  return `${serialized.slice(0, max)}…[truncated, ${serialized.length} characters]`
}

export function createDecider(deps: DeciderDeps) {
  const { config, redactor } = deps
  const now = deps.now ?? Date.now
  const cache = new Map<string, { verdict: Verdict; reason: string; expires: number }>()
  /** Name shown in reasons (e.g. "nox-4b: risk 0.10/3"). */
  const label = config.decision?.model ?? "decision model"

  function remember(key: string, verdict: Verdict, reason: string) {
    if (config.cacheMax <= 0 || config.cacheTtlMs <= 0) return
    if (cache.size >= config.cacheMax) cache.delete(cache.keys().next().value!)
    cache.set(key, { verdict, reason, expires: now() + config.cacheTtlMs })
  }

  type Timing = { readonly modelMs?: number; readonly attempts?: number }
  type Consultation =
    | ({ readonly judgement: { verdict: Verdict; reason: string }; readonly source: "model" | "cache"; readonly inFull: boolean } & Timing)
    | ({ readonly error: string; readonly source: "default" | "model-error" } & Timing)

  /** Model call; a timeout (burst, slow server) is retried once, other errors never. */
  async function ask(model: ModelClient, state: Record<string, unknown>) {
    for (let attempts = 1; ; attempts++) {
      try {
        return { ok: true as const, response: await model({ state, questions: QUESTIONS }), attempts }
      } catch (error) {
        if (attempts < 2 && error instanceof ModelError && error.timeout) continue
        return { ok: false as const, error, attempts }
      }
    }
  }

  /** Model opinion (cache included); never throws: an error is described. */
  async function consult(call: ToolCall, redactedInput: unknown, model: ModelClient): Promise<Consultation> {
    let state: Record<string, unknown>
    let key: string
    let inFull: boolean
    try {
      const input = truncateInput(redactedInput, config.maxStateChars)
      inFull = input === redactedInput
      state = { note: STATE_NOTE, tool: call.tool, input, working_directory: call.directory, agent: call.agent }
      const shown = call.scripts?.filter((script) => script.forModel) ?? []
      if (shown.length) state.executed_scripts = scriptsState(shown)
      // Key = everything the model receives: the same input may be judged differently depending on the agent or directory.
      key = createHash("sha256").update(JSON.stringify(state)).digest("hex")
    } catch (error) {
      return { error: describe(`input not serializable (${errorMessage(error)})`), source: "default" }
    }
    const cached = cache.get(key)
    if (cached && cached.expires > now()) return { judgement: { verdict: cached.verdict, reason: cached.reason }, source: "cache", inFull }
    if (cached) cache.delete(key)
    const started = now()
    const answer = await ask(model, state)
    const timing = { modelMs: now() - started, attempts: answer.attempts }
    const unavailable = (error: unknown) => {
      const tried = answer.attempts > 1 ? `, after ${answer.attempts} attempts` : ""
      return { error: describe(`${label} unavailable (${errorMessage(error)}${tried})`), source: "model-error" as const, ...timing }
    }
    if (!answer.ok) return unavailable(answer.error)
    try {
      const judgement = interpret(answer.response, config.thresholds, label)
      remember(key, judgement.verdict, judgement.reason)
      return { judgement, source: "model", inFull, ...timing }
    } catch (error) {
      return unavailable(error)
    }
  }

  /** Scripts executed for the model: path and content redacted, content truncated like the input. */
  function scriptsState(scripts: readonly ExecutedScript[]) {
    return {
      note: SCRIPTS_NOTE,
      files: scripts.map((script) => {
        const content = redactor.redactString(script.content).value
        return {
          path: redactor.redactString(script.path).value,
          content: content.length > config.maxStateChars ? `${content.slice(0, config.maxStateChars)}…[truncated, ${content.length} characters]` : content,
        }
      }),
    }
  }

  /**
   * Reason for a failure, redacted: it quotes up to 160 characters of the server response (a key echoed back
   * in a 401) and goes into the log, the ask, its metadata, and the unattended-mode message.
   */
  function describe(detail: string): string {
    return redactor.redactString(`${detail}: confirmation required`).value
  }

  /**
   * Error message quoted in a reason: redacted FIRST, then cut to 160 characters (cut before, the fragment of a key
   * echoed back in a 401 would no longer be recognized as the known value).
   */
  function errorMessage(error: unknown): string {
    const text = redactor.redactString((error as Error)?.message ?? String(error)).value
    return text.length > ERROR_SHOWN ? `${text.slice(0, ERROR_SHOWN)}…` : text
  }

  /** Duration and attempts of an actual model call (not for a verdict taken from the cache). */
  const timing = (consultation?: Consultation) =>
    consultation?.modelMs === undefined ? {} : { modelMs: consultation.modelMs, attempts: consultation.attempts ?? 1 }

  /** "nox-4b opinion: deny (risk 2.36/3, data destruction 0.96)". */
  const opinion = (judgement: { verdict: Verdict; reason: string }) => {
    const detail = judgement.reason.startsWith(`${label}: `) ? judgement.reason.slice(label.length + 2) : judgement.reason
    return `${label} opinion: ${judgement.verdict} (${detail})`
  }

  /** Log of an internal error; a logger that throws does not change the decision. */
  function report(message: string, error: unknown): void {
    try {
      deps.log?.error(message, error)
    } catch {}
  }

  async function decide(call: ToolCall): Promise<Decision> {
    // Input that cannot be redacted: local rules still judge (a denial holds), but nothing is sent to the
    // model.
    let redactedInput: unknown = UNAVAILABLE_INPUT
    try {
      redactedInput = redactor.redactDeep(call.input).value
    } catch (error) {
      report("internal error while redacting the input", error)
    }
    const unredacted = redactedInput === UNAVAILABLE_INPUT
    // Lazy read: no file opened until an active rule asks for it.
    const directories = call.cwds ?? (call.directory === undefined ? [] : [call.directory])
    const credentialContent = deps.readContent && directories.length > 0 ? createCredentialContent({ directories, home: deps.home }) : undefined
    const realPaths = deps.resolveLinks ? createRealPath({ directories }) : undefined
    const ruleContext = {
      redactor,
      home: deps.home,
      custom: config.rules,
      cwd: call.directory,
      ...(call.cwds ? { cwds: call.cwds } : {}),
      ...(credentialContent ? { credentialContent } : {}),
      ...(realPaths ? { realPaths } : {}),
      protectedDirs: deps.protectedDirs,
      ...(deps.serviceDirs ? { serviceDirs: deps.serviceDirs } : {}),
      active: config.features,
      // Tool check that throws (`rules/tools.ts`, ask for it alone): cause to the log.
      report,
    }
    // A failing part (the command, a tracked script) gives an ask for itself alone: the others keep their
    // finding, denial included. The cause goes to the log; the reason shown stays generic.
    const unchecked: string[] = []
    const guarded = (part: string, evaluate: () => Finding | undefined): Finding | undefined => {
      try {
        return evaluate()
      } catch (error) {
        unchecked.push(part)
        report(`internal error while checking ${part}`, error)
        return { verdict: "ask", rule: INTERNAL_ERROR_RULE, reason: `internal guard plugin error, ${part} could not be checked: confirmation required` }
      }
    }
    const command = guarded("the tool call", () => toolFinding(call.tool, call.input, ruleContext))
    // A script may change directory itself: command and session directories, plus its own `cd`s;
    // its relative paths are also looked up from them to recognize a key by its content.
    const scriptContext = (script: ExecutedScript) => {
      if (call.directory === undefined) return ruleContext
      const cwds = scriptDirectories(script.content, call.cwds ?? [call.directory], call.directory, deps.home)
      return {
        ...ruleContext,
        cwds,
        ...(deps.readContent ? { credentialContent: createCredentialContent({ directories: cwds, home: deps.home }) } : {}),
        ...(deps.resolveLinks ? { realPaths: createRealPath({ directories: cwds }) } : {}),
      }
    }
    // Finding from an executed script: before the command's if it is only "data only" or left to the model (an
    // ask coming from a script is never decided by the model alone); a denial from the command always wins.
    const scripts = mostSevere((call.scripts ?? []).map((script) => guarded("a script run by this command", () => scriptFinding(script, scriptContext(script)))))
    const found = mostSevere([command?.dataOnly || command?.modelDecides ? undefined : command, scripts, command])
    // Reasons sometimes quote the input (`access to a credential file (/tmp/<key>.pem)`): redacted like it,
    // they go into the log, the ask, and the error shown to the model.
    // An ask from another part also names the unchecked part.
    const note = found && found.verdict === "ask" && found.rule !== INTERNAL_ERROR_RULE && unchecked.length ? `; ${unchecked.join(" and ")} could not be checked (internal error)` : ""
    let shown: string
    try {
      shown = redactor.redactString(found?.reason ?? "").value
    } catch (error) {
      report("internal error while redacting a reason", error)
      shown = `rule ${found?.rule}: reason unavailable`
    }
    const local = found && { ...found, reason: `${shown}${note}` }
    if (local?.verdict === "deny") return { verdict: "deny", reason: local.reason, rule: local.rule, source: "local", redactedInput }
    if (local) {
      // Local confirmation: the model opinion is shown to the user; it never changes the verdict (neither stricter:
      // the user keeps control of doubtful cases, nor looser). Unreachable: ask without opinion.
      const consultation = deps.model && !modelSkipped(call.tool) && !unredacted ? await consult(call, redactedInput, deps.model) : undefined
      // Exceptions: an ask rule triggered only by heredoc data (test file written with `cat`), or
      // an ask left to the model (CodeMode script that reads the web without a tool), provided in the latter case that it judged
      // the whole input: the model decides, as for any command with no local rule. Unreachable: ask.
      if (consultation && "judgement" in consultation && (local.dataOnly || (local.modelDecides !== undefined && consultation.inFull))) {
        const { verdict, reason } = consultation.judgement
        return {
          verdict,
          reason: `${local.reason}, ${local.modelDecides ?? "only inside heredoc data"}, decided by ${reason}`,
          rule: local.rule,
          source: consultation.source,
          redactedInput,
          judgedInFull: consultation.inFull,
          ...timing(consultation),
        }
      }
      // Ask left to the model that it could not decide: the reason says why (truncated code, failing model).
      const untried = local.modelDecides === undefined ? "" : "; the code was too long for the decision model to decide"
      if (consultation && "judgement" in consultation)
        return {
          verdict: "ask",
          reason: `${local.reason} — ${opinion(consultation.judgement)}${untried}`,
          rule: local.rule,
          source: "local",
          redactedInput,
          judgedInFull: consultation.inFull,
          ...timing(consultation),
        }
      if (local.modelDecides !== undefined && consultation && "error" in consultation)
        return {
          verdict: "ask",
          reason: `${local.reason} — ${consultation.error}`,
          rule: local.rule,
          source: consultation.source,
          redactedInput,
          ...timing(consultation),
        }
      return { verdict: "ask", reason: local.reason, rule: local.rule, source: "local", redactedInput, ...timing(consultation) }
    }
    if (READ_ONLY_TOOLS.has(call.tool)) return { verdict: "allow", reason: "read-only tool, no local rule matched", source: "read-only", redactedInput }
    if (TASK_LIST_TOOLS.has(call.tool))
      return { verdict: "allow", reason: "task list tool (session state only), no local rule matched", source: "task-list", redactedInput }
    if (!deps.model) return { verdict: "allow", reason: "no local rule matched, decision model disabled", source: "default", redactedInput }
    if (unredacted)
      return {
        verdict: "ask",
        reason: "internal guard plugin error, the input could not be redacted for the decision model: confirmation required",
        rule: INTERNAL_ERROR_RULE,
        source: "default",
        redactedInput,
      }
    const consultation = await consult(call, redactedInput, deps.model)
    if ("judgement" in consultation)
      return { ...consultation.judgement, source: consultation.source, redactedInput, judgedInFull: consultation.inFull, ...timing(consultation) }
    return { verdict: "ask", reason: consultation.error, source: consultation.source, redactedInput, ...timing(consultation) }
  }

  return { decide }
}

export type Decider = ReturnType<typeof createDecider>
