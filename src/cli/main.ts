// Command line of the guard plugin (`bin/guard`): its rules, its settings in the global guard.json, the settings in
// force and its latest asks and denials. It asks for no confirmation: launched by the agent, it is itself a
// self-protection ask of the plugin (`guard-cli`), the only thing that stops the agent.
import { RULE_FEATURES, TARGETED_RULES } from "../rules/features.ts"
import { OPENCODE_FORMAT_SUMMARIES } from "../secrets/opencode-service.ts"
import { FORMAT_SUMMARIES } from "../secrets/patterns.ts"
import type { Redactor } from "../secrets/redact.ts"
import { CONTROL_CHARACTERS } from "../types.ts"
import { CliError, outputRedactor, type CliIo, type Pretty } from "./context.ts"
import { prettyHelp, USAGE } from "./help.ts"
import { DEFAULT_LAST, last, MAX_LAST } from "./last.ts"
import { explainFormat, isFormat, prettyRedaction, redactionLines } from "./redaction.ts"
import { customRuleLines, explainRule, prettyBuiltins, prettyCustom, ruleLines } from "./rules.ts"
import { completionScript, SHELLS } from "./completion.ts"
import { explainSetting, settings } from "./settings.ts"
import { show } from "./show.ts"
import { status } from "./status.ts"
import { test, toolInput, type TestRequest } from "./test.ts"
import { paint } from "./style.ts"
import { addRule, AGENT_KEYS, agentOn, agentSwitch, directoryOf, exceptPath, MINUTES, removeRule, resetPath, resetRule, setRedaction, setRule, setSwitch, SETTINGS, SWITCHES, trust, writeAgent, unsetSwitch, untrust, type SettingWord, type Target } from "./write.ts"

export { USAGE } from "./help.ts"

class UsageError extends CliError {}

/** Options of `rules add`, each with a value; a pattern or a reason is taken as is, even when it starts with `-`. */
const RULE_OPTIONS = ["pattern", "verdict", "reason", "tools", "flags"] as const
type RuleOption = (typeof RULE_OPTIONS)[number]

interface Parsed {
  readonly positionals: string[]
  agent?: string
  project?: string | true
  path?: string
  all?: boolean
  builtins?: boolean
  custom?: boolean
  explain?: string
  rule?: Partial<Record<RuleOption, string>>
}

/** Options allowed by a command; `--project` takes the next argument as its directory unless it is an option. */
function parse(args: readonly string[], allowed: ReadonlyArray<"agent" | "project" | "path" | "all" | "builtins" | "custom" | "explain" | RuleOption>, explained = "a rule identifier"): Parsed {
  const parsed: Parsed = { positionals: [] }
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!
    const [name, inline] = arg.startsWith("--") && arg.includes("=") ? [arg.slice(0, arg.indexOf("=")), arg.slice(arg.indexOf("=") + 1)] : [arg, undefined]
    if (name === "--agent" && allowed.includes("agent")) {
      const value = inline ?? args[++index]
      if (!value || value.startsWith("-")) throw new UsageError("--agent needs an agent name")
      parsed.agent = value
    } else if (name === "--project" && allowed.includes("project")) {
      const next = args[index + 1]
      parsed.project = inline ?? (next !== undefined && !next.startsWith("-") ? args[++index]! : true)
      if (parsed.project === "") throw new UsageError("--project needs a directory, or nothing")
    } else if (name === "--path" && allowed.includes("path")) {
      const value = inline ?? args[++index]
      if (!value || value.startsWith("-")) throw new UsageError("--path needs a file")
      parsed.path = value
    } else if (RULE_OPTIONS.some((option) => name === `--${option}`) && allowed.includes(name.slice(2) as RuleOption)) {
      const option = name.slice(2) as RuleOption
      const value = inline ?? args[++index]
      if (value === undefined || value === "" || (option !== "pattern" && option !== "reason" && value.startsWith("-"))) throw new UsageError(`--${option} needs a value`)
      parsed.rule = { ...parsed.rule, [option]: value }
    } else if (arg === "--all" && allowed.includes("all")) parsed.all = true
    else if (arg === "--builtins" && allowed.includes("builtins")) parsed.builtins = true
    else if (arg === "--custom" && allowed.includes("custom")) parsed.custom = true
    else if (name === "--explain" && allowed.includes("explain")) {
      const value = inline ?? args[++index]
      if (!value || value.startsWith("-")) throw new UsageError(`--explain needs ${explained}`)
      parsed.explain = value
    } else if (arg.startsWith("-") && arg !== "-") throw new UsageError(`unknown option ${arg}`)
    else parsed.positionals.push(arg)
  }
  return parsed
}

function expect(parsed: Parsed, min: number, max: number, what: string): void {
  if (parsed.positionals.length < min) throw new UsageError(`${what} is required`)
  if (parsed.positionals.length > max) throw new UsageError(`unexpected argument ${parsed.positionals[max]}`)
}

/**
 * A rule's setting (`off`, `ask`, `deny`, `model`) or its removal (`reset`), at the target given by the options; with
 * `--path`, `off` and `reset` add or remove one file's exception instead (a rule that accepts them, never in an agents
 * section).
 */
function setting(word: string, args: readonly string[], io: CliIo): void {
  const parsed = parse(args, ["agent", "project", "path"])
  expect(parsed, 1, 1, "a rule identifier")
  const rule = parsed.positionals[0]!
  if (parsed.path !== undefined) {
    if (word !== "off" && word !== "reset") throw new UsageError(`--path goes with rules off or rules reset only, not with ${word}`)
    if (parsed.agent !== undefined) throw new UsageError("--path does not go with --agent: an agents section accepts no exception")
    if (!TARGETED_RULES.has(rule)) throw new UsageError(`--path goes with ${[...TARGETED_RULES].join(", ")} only: no other rule accepts exceptions`)
  }
  const target: Target = {
    ...(parsed.agent === undefined ? {} : { agent: parsed.agent }),
    ...(parsed.project === undefined ? {} : { project: directoryOf(io, parsed.project === true ? undefined : parsed.project, word === "reset") }),
  }
  if (parsed.path !== undefined) (word === "reset" ? resetPath : exceptPath)(io, rule, parsed.path, target)
  else if (word === "reset") resetRule(io, rule, target)
  else setRule(io, word as SettingWord, rule, target)
}

/** `rules add <id> --pattern <regex> --verdict ask|deny […]` and `rules remove <id>`: the top level of the global guard.json only. */
function ruleEntry(word: "add" | "remove", args: readonly string[], io: CliIo): void {
  const parsed = parse(args, ["agent", "project", ...RULE_OPTIONS])
  if (parsed.agent !== undefined || parsed.project !== undefined) throw new UsageError(`rules ${word} writes the top level of the global guard.json only (no --agent or --project)`)
  expect(parsed, 1, 1, "a rule identifier")
  const id = parsed.positionals[0]!
  const rule = parsed.rule ?? {}
  if (word === "remove") {
    if (parsed.rule) throw new UsageError(`--${Object.keys(rule)[0]} goes with rules add only`)
    return removeRule(io, id)
  }
  if (rule.pattern === undefined) throw new UsageError("--pattern is required")
  if (rule.verdict === undefined) throw new UsageError("--verdict is required")
  const tools = rule.tools === undefined ? undefined : rule.tools.split(",").map((tool) => tool.trim())
  if (tools?.some((tool) => !tool)) throw new UsageError("--tools needs tool names separated by commas, or *")
  addRule(io, id, { pattern: rule.pattern, verdict: rule.verdict, ...(rule.reason === undefined ? {} : { reason: rule.reason }), ...(tools ? { tools } : {}), ...(rule.flags === undefined ? {} : { flags: rule.flags }) })
}

/**
 * `guard test [--agent <name>] [--model] [--tool <name>] [--] <call>`: options first; the rest, from the first other
 * argument or after `--`, is the call: a shell command (its words joined by spaces), or the JSON input of `--tool`.
 */
function testRequest(args: readonly string[]): TestRequest {
  let agent: string | undefined
  let tool: string | undefined
  let model = false
  let index = 0
  for (; index < args.length; index++) {
    const arg = args[index]!
    if (arg === "--") {
      index++
      break
    }
    if (arg === "--model") model = true
    else if (arg === "--agent" || arg === "--tool") {
      const value = args[++index]
      if (!value || value.startsWith("-")) throw new UsageError(`${arg} needs ${arg === "--agent" ? "an agent name" : "a tool name"}`)
      if (arg === "--agent") agent = value
      else tool = value
    } else if (arg.startsWith("--")) throw new UsageError(`unknown option ${arg.split("=")[0]} (put the call after --)`)
    else break
  }
  const rest = args.slice(index)
  if (!rest.length) throw new UsageError(tool ? "the JSON input of the tool is required" : "a command is required")
  if (tool) {
    if (rest.length > 1) throw new UsageError("the input of --tool is one argument: quote the JSON")
    return { tool, input: toolInput(rest[0]!), model, ...(agent ? { agent } : {}) }
  }
  return { tool: "shell", input: { command: rest.join(" ") }, model, ...(agent ? { agent } : {}) }
}

/** `guard agent off|on|set|unset|models`: what `agents.<id>` of the global guard.json relaxes. */
function agentCommand(args: readonly string[], io: CliIo): void {
  const [word, agent, ...rest] = args
  if (!word || !["off", "on", "set", "unset", "models"].includes(word)) throw new UsageError("agent needs off, on, set, unset or models")
  if (!agent || agent.startsWith("-")) throw new UsageError("an agent name is required")
  const switchKey = (key: string | undefined) => {
    if (!key || !AGENT_KEYS.includes(key as (typeof AGENT_KEYS)[number])) throw new UsageError(`a key is required: one of ${AGENT_KEYS.join(", ")}`)
    return key
  }
  switch (word) {
    case "on":
      if (rest.length) throw new UsageError(`unexpected argument ${rest[0]}`)
      return agentOn(io, agent)
    case "off": {
      const models: string[] = []
      for (let index = 0; index < rest.length; index++) {
        const [name, inline] = rest[index]!.startsWith("--model=") ? ["--model", rest[index]!.slice(8)] : [rest[index]!, undefined]
        if (name !== "--model") throw new UsageError(`unexpected argument ${name}`)
        const model = inline ?? rest[++index]
        if (!model || model.startsWith("-")) throw new UsageError("--model needs a provider/model")
        models.push(model)
      }
      return writeAgent(io, agent, { guard: "off", ...(models.length ? { models } : {}) })
    }
    case "set": {
      const key = switchKey(rest[0])
      if (rest.length !== 2) throw new UsageError("set needs a key and true or false")
      return agentSwitch(io, agent, key, rest[1]!)
    }
    case "unset": {
      if (rest[0] === "models") return writeAgent(io, agent, { models: undefined })
      if (rest[0] === "guard") return writeAgent(io, agent, { guard: undefined })
      return writeAgent(io, agent, { [switchKey(rest[0])]: undefined })
    }
    default:
      if (!rest.length) throw new UsageError("models needs at least one provider/model")
      if (rest.some((model) => model.startsWith("-"))) throw new UsageError("a provider/model cannot start with -")
      return writeAgent(io, agent, { models: rest })
  }
}

function run(command: string, args: readonly string[], io: CliIo): void | Promise<void> {
  if ((SETTINGS as readonly string[]).includes(command) || command === "reset" || command === "allow")
    throw new UsageError(`unknown command ${command} (a rule's setting: guard rules ${command === "allow" ? "off" : command} <rule>)`)
  switch (command) {
    case "rules": {
      // `rules <setting> <rule>`: the same as the top-level setting commands.
      const [word, ...rest] = args
      if (word !== undefined && (SETTINGS as readonly string[]).concat("reset").includes(word)) return setting(word, rest, io)
      if (word === "add" || word === "remove") return ruleEntry(word, rest, io)
      if (word === "on" || word === "allow") throw new UsageError(`unknown setting ${word} (guard rules ${word === "on" ? "reset" : "off"} <rule>)`)
      const parsed = parse(args, ["builtins", "custom", "explain"])
      expect(parsed, 0, 0, "")
      if (parsed.explain !== undefined) {
        if (parsed.builtins || parsed.custom) throw new UsageError("--explain cannot be combined with --builtins or --custom")
        if (!RULE_FEATURES.has(parsed.explain)) throw new UsageError(`no built-in rule named ${parsed.explain}`)
        return explainRule(io, parsed.explain)
      }
      const [builtins, custom] = parsed.builtins === parsed.custom ? [true, true] : [Boolean(parsed.builtins), Boolean(parsed.custom)]
      // In a terminal: grouped and aligned sections, colored unless the launcher says otherwise.
      if (io.pretty) {
        if (builtins) prettyBuiltins(io.pretty)
        if (builtins && custom) for (let blank = 0; blank < 2; blank++) io.pretty.line([])
        if (custom) prettyCustom(io, io.pretty)
        return
      }
      // `--builtins` alone: the registry only, as before (no header, no configuration needed); neither or both: the two
      // sections.
      if (!custom) for (const line of ruleLines()) io.out(line)
      else if (!builtins) for (const line of customRuleLines(io)) io.out(line)
      else {
        io.out("Built-in rules:")
        for (const line of ruleLines()) io.out(`  ${line}`)
        for (const line of customRuleLines(io)) io.out(line)
      }
      return
    }
    case "redaction": {
      const parsed = parse(args, ["builtins", "custom", "explain"], "a format name")
      const [word, type] = parsed.positionals
      if (word === "off" || word === "on") {
        if (parsed.builtins || parsed.custom || parsed.explain !== undefined) throw new UsageError(`redaction ${word} takes a format name only`)
        expect(parsed, 2, 2, "a format name")
        if (OPENCODE_FORMAT_SUMMARIES.has(type!)) throw new UsageError(`the format ${type} cannot be turned off: it protects OpenCode's own credentials`)
        if (!FORMAT_SUMMARIES.has(type!)) throw new UsageError(`no built-in redaction format named ${type} (guard redaction lists them)`)
        return setRedaction(io, type!, word === "off")
      }
      expect(parsed, 0, 0, "")
      if (parsed.explain !== undefined) {
        if (parsed.builtins || parsed.custom) throw new UsageError("--explain cannot be combined with --builtins or --custom")
        if (!isFormat(parsed.explain)) throw new UsageError(`no redaction format named ${parsed.explain}`)
        return explainFormat(io, parsed.explain)
      }
      const [builtins, custom] = parsed.builtins === parsed.custom ? [true, true] : [Boolean(parsed.builtins), Boolean(parsed.custom)]
      if (io.pretty) return prettyRedaction(io, io.pretty, builtins, custom)
      for (const line of redactionLines(io, builtins, custom)) io.out(line)
      return
    }
    case "test":
      return test(io, testRequest(args))
    case "set":
    case "unset": {
      const parsed = parse(args, ["agent", "project"])
      expect(parsed, command === "set" ? 2 : 1, command === "set" ? 2 : 1, command === "set" ? "a setting and its value" : "a setting")
      const key = parsed.positionals[0]!
      if (key === "ruleOverrides") throw new UsageError("a rule's setting is changed with guard rules off|ask|deny|model|reset <rule>")
      const projectOnly = (AGENT_KEYS as readonly string[]).includes(key)
      if (!projectOnly && !Object.hasOwn(SWITCHES, key)) throw new UsageError(`unknown setting ${key} (one of ${[...Object.keys(SWITCHES), ...AGENT_KEYS].join(", ")})`)
      if (projectOnly && (parsed.agent !== undefined || parsed.project === undefined)) throw new UsageError(`${key} goes with --project and without --agent (for one agent: guard agent set <agent> ${key} <value>)`)
      // Removal only: a value written by hand in an agents section (ignored by the plugin) can be taken out.
      if (key === MINUTES && parsed.agent !== undefined && command === "set") throw new UsageError(`${MINUTES} does not go with --agent: an agents section does not accept it`)
      const target: Target = {
        ...(parsed.agent === undefined ? {} : { agent: parsed.agent }),
        ...(parsed.project === undefined ? {} : { project: directoryOf(io, parsed.project === true ? undefined : parsed.project, command === "unset") }),
      }
      return command === "set" ? setSwitch(io, key, parsed.positionals[1]!, target) : unsetSwitch(io, key, target)
    }
    case "agent":
      return agentCommand(args, io)
    case "completion": {
      const [shell, extra] = args
      if (!shell || !(SHELLS as readonly string[]).includes(shell)) throw new UsageError(`completion needs a shell: ${SHELLS.join(" or ")}`)
      if (extra !== undefined) throw new UsageError(`unexpected argument ${extra}`)
      for (const line of completionScript(shell as (typeof SHELLS)[number]).trimEnd().split("\n")) io.out(line)
      return
    }
    case "status": {
      if (args.some((arg) => arg !== "--offline")) throw new UsageError(`unexpected argument ${args.find((arg) => arg !== "--offline")}`)
      return status(io, { offline: args.includes("--offline") })
    }
    case "settings": {
      const parsed = parse(args, ["agent", "explain"], "a setting name")
      expect(parsed, 0, 0, "")
      return parsed.explain === undefined ? settings(io, parsed.agent) : explainSetting(io, parsed.explain, parsed.agent)
    }
    case "show": {
      const parsed = parse(args.filter((arg) => arg !== "--offline"), ["agent"])
      expect(parsed, 0, 0, "")
      return show(io, parsed.agent, args.includes("--offline"))
    }
    case "last": {
      const parsed = parse(args, [])
      expect(parsed, 0, 1, "")
      const raw = parsed.positionals[0]
      const count = raw === undefined ? DEFAULT_LAST : Number(raw)
      if (!Number.isInteger(count) || count < 1 || count > MAX_LAST) throw new UsageError(`the count must be a whole number from 1 to ${MAX_LAST}`)
      return last(io, count)
    }
    case "trust":
    case "untrust": {
      const parsed = parse(args, ["all"])
      expect(parsed, 0, parsed.all ? 0 : 1, "")
      const dir = parsed.all ? "*" : directoryOf(io, parsed.positionals[0], command === "untrust")
      return command === "trust" ? trust(io, dir) : untrust(io, dir)
    }
    default:
      throw new UsageError(`unknown command ${command}`)
  }
}

/**
 * Every line printed (settings, warnings, refusals, log lines) goes through the plugin's redactor, built at the first one,
 * then loses its control characters, line breaks included: a repository's guard.json is quoted in them.
 */
function redacted(io: CliIo): CliIo {
  let redactor: Redactor | undefined
  const clean = (text: string) => {
    redactor ??= outputRedactor(io)
    return redactor.redactString(text).value.replace(CONTROL_CHARACTERS, " ")
  }
  const redact = (line: string) => {
    try {
      return clean(line)
    } catch {
      return WITHHELD
    }
  }
  const terminal = io.terminal
  // Colors come last, from `style.ts` only: a line is painted only if its text is already what the redaction prints.
  const pretty: Pretty | undefined = terminal && {
    width: terminal.width,
    color: terminal.color,
    clean: redact,
    line: (segments) => {
      try {
        const plain = segments.map(([text]) => text).join("")
        const unchanged = clean(plain) === plain && segments.every(([text]) => clean(text) === text)
        io.out(unchanged ? paint(segments, terminal.color) : clean(plain))
      } catch {
        io.out(WITHHELD)
      }
    },
  }
  return { ...io, out: (line) => io.out(redact(line)), err: (line) => io.err(redact(line)), ...(pretty ? { pretty } : {}) }
}

const WITHHELD = "(line withheld: redaction failed)"

const isHelp = (word: string | undefined) => word === "--help" || word === "-h"

/** `guard <verb> -h`, and `guard rules <word> -h`, `guard redaction <word> -h`: the help, not a usage error. */
const helpAfter = (command: string, args: readonly string[]) => isHelp(args[0]) || ((command === "rules" || command === "redaction") && isHelp(args[1]))

/** Runs one command; exit code: 0 done (or nothing to change), 1 refused or failed, 2 usage error. `test` is asynchronous. */
export function main(argv: readonly string[], terminal: CliIo): number | Promise<number> {
  const io = redacted(terminal)
  const [command, ...args] = argv
  if (command === undefined || command === "help" || isHelp(command) || helpAfter(command, args)) {
    // In a terminal, the colored layout; otherwise the plain text. After a usage error, the plain text on the error output
    // unless both outputs are terminals (a redirected error output never gets colors).
    if (io.pretty) prettyHelp(io.pretty)
    else for (const line of USAGE.split("\n")) io.out(line)
    return command === undefined ? 2 : 0
  }
  const failed = (error: unknown) => {
    if (error instanceof UsageError) {
      io.err(`guard: ${error.message}`)
      if (io.pretty && io.errorTerminal) prettyHelp(io.pretty)
      else for (const line of USAGE.split("\n")) io.err(line)
      return 2
    }
    io.err(`guard: ${error instanceof CliError ? error.message : `internal error: ${String(error)}`}`)
    return 1
  }
  try {
    const done = run(command, args, io)
    return done ? done.then(() => 0, failed) : 0
  } catch (error) {
    return failed(error)
  }
}
