// `guard test`: the verdict the plugin would give to a tool call, from the current directory, without running it. Same
// decider as the plugin (decide.ts), with the settings it would resolve for this directory and agent (configuration,
// guard.json files, sections), the server's environment completed by `service.json`, and the directories it protects.
// The decision model is asked only with `--model` (the call is then sent to it); otherwise, a call no local rule decides
// is said to be the model's. Not replayed: OpenCode's own permission rules, its second check of the shell sub-commands
// (the plugin's rules already split the command), and the scripts written earlier in a session.
import { homedir } from "node:os"
import { parseConfig, resolveVersion } from "../config.ts"
import { createDecider, type Decision } from "../decide.ts"
import { guardPaths, readGuardFiles } from "../guard-file.ts"
import { guardDirectories, knownSecrets } from "../index.ts"
import { createModelClient, ModelError, type ModelClient } from "../model/client.ts"
import { shellDirectories } from "../scripts.ts"
import { createRedactor } from "../secrets/redact.ts"
import { CliError, readSources, realOrUndefined, serverEnv, type CliIo } from "./context.ts"
import { title } from "./pretty.ts"
import type { Segment } from "./style.ts"

export interface TestRequest {
  readonly tool: string
  readonly input: unknown
  readonly agent?: string
  /** Ask the decision model (the call is sent to it). */
  readonly model: boolean
}

/** What the session would get; `model`: a call no local rule decides, left to the decision model (not asked). */
export interface TestOutcome {
  readonly verdict: "allow" | "ask" | "deny" | "model" | "unchecked"
  readonly rule?: string
  readonly source?: string
  readonly reason: string
  readonly notes: readonly string[]
}

export { serverEnv } from "./context.ts"

/** Default main agent of a session. */
const DEFAULT_AGENT = "build"

export async function testCall(io: CliIo, request: TestRequest, client?: ModelClient): Promise<TestOutcome> {
  const env = serverEnv(io.env, readSources(io).globalDir)
  const serverIo = { ...io, env }
  const sources = readSources(serverIo)
  const directory = realOrUndefined(io.cwd) ?? io.cwd
  const files = readGuardFiles(guardPaths(directory, sources.globalDir, io.systemDir))
  const { config } = parseConfig(sources.options, env, () => sources.declarations, {
    files,
    project: directory,
    realPath: realOrUndefined,
    ...(sources.origin ? { origin: sources.origin } : {}),
  })
  const agent = request.agent ?? DEFAULT_AGENT
  const notes: string[] = []
  if (config.unprotectedAgent !== undefined && agent === config.unprotectedAgent) {
    if (config.askAs !== "deny") return { verdict: "unchecked", reason: `no check for the unprotected agent ${agent}, once the user selects it`, notes }
    notes.push(`the unprotected agent ${agent} is checked: unattended mode (askAs: deny) ignores it`)
  }
  const version = resolveVersion(config.layers!, files)
  const scope = version.scope(agent, undefined, undefined)
  const redactor = createRedactor({ extraPatterns: config.secretPatterns, disabledTypes: config.disabledPatterns, allowlist: config.allowlist, env, knownSecrets: knownSecrets(config) })
  redactor.setDisabledTypes(version.redactionOff ?? [])
  const { protectedDirs, pluginDirs, serviceDirs } = guardDirectories(env, sources.globalDir)
  const home = env.HOME ?? homedir()
  // Without `--model`: a stand-in that only records that the model would have been asked.
  let asked = false
  const model: ModelClient | undefined = !config.decision
    ? undefined
    : request.model
      ? (client ?? createModelClient(config.decision))
      : async () => {
          asked = true
          throw new ModelError("not asked")
        }
  if (request.model && !config.decision) notes.push("no decision model is configured: local rules only")
  const decider = createDecider({ config, redactor, ...(model ? { model } : {}), home, protectedDirs, pluginDirs, serviceDirs, readContent: true, resolveLinks: true })
  const command = request.tool === "shell" ? (request.input as { command?: unknown }).command : undefined
  const cwds = typeof command === "string" ? shellDirectories(command, undefined, directory, home) : undefined
  const decision: Decision = await decider.decide({ tool: request.tool, input: request.input, agent, directory, ...(cwds ? { cwds } : {}), scope })
  if (asked && (decision.source === "model-error" || decision.source === "default")) {
    const local = decision.parts?.local
    return {
      verdict: "model",
      ...(decision.rule ? { rule: decision.rule } : {}),
      reason: local ? `${local}; the decision model would decide (run again with --model to ask it)` : "no local rule decides: the decision model would judge this call (run again with --model to ask it)",
      notes,
    }
  }
  let verdict: TestOutcome["verdict"] = decision.verdict
  if (verdict === "ask" && config.askAs === "deny") {
    verdict = "deny"
    notes.push("unattended mode (askAs: deny): this ask is denied")
  }
  return { verdict, ...(decision.rule ? { rule: decision.rule } : {}), source: decision.source, reason: decision.reason, notes }
}

const NOT_REPLAYED = "Not replayed: OpenCode's own permission rules, its second check of the shell sub-commands, scripts written earlier in a session, and plugin options merged from a project's opencode.json."

export async function test(io: CliIo, request: TestRequest): Promise<void> {
  const outcome = await testCall(io, request)
  const what = request.tool === "shell" ? String((request.input as { command?: unknown }).command) : `${request.tool} ${JSON.stringify(request.input)}`
  if (io.pretty) {
    const pretty = io.pretty
    title(pretty, "Verdict", `${request.tool} call, agent ${request.agent ?? DEFAULT_AGENT}, not run`, "settings")
    const style = outcome.verdict === "deny" ? "deny" : outcome.verdict === "ask" ? "ask" : outcome.verdict === "allow" ? "good" : outcome.verdict === "model" ? "model" : "dim"
    const line = (label: string, value: string, valueStyle?: Segment[1]) => pretty.line([["  "], [label.padEnd(8), "dim"], [pretty.clean(value), valueStyle]])
    line("call", what)
    line("verdict", outcome.verdict, style)
    if (outcome.rule) line("rule", outcome.rule, "rule")
    if (outcome.source) line("source", outcome.source, "dim")
    line("reason", outcome.reason)
    for (const note of outcome.notes) line("note", note, "warn")
    pretty.line([["  "], [NOT_REPLAYED, "dim"]])
    return
  }
  io.out(`call: ${what}`)
  io.out(`verdict: ${outcome.verdict}`)
  if (outcome.rule) io.out(`rule: ${outcome.rule}`)
  if (outcome.source) io.out(`source: ${outcome.source}`)
  io.out(`reason: ${outcome.reason}`)
  for (const note of outcome.notes) io.out(`note: ${note}`)
  io.out(NOT_REPLAYED)
}

/** Input of `--tool <name>`: a JSON object. Never quoted back in an error (it may hold a secret). */
export function toolInput(text: string): Record<string, unknown> {
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    throw new CliError("the input of --tool must be a JSON object (not valid JSON)")
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new CliError("the input of --tool must be a JSON object")
  return value as Record<string, unknown>
}
