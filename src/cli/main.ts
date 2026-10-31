// Command line of the guard plugin (`bin/guard`): its rules, its settings in the global guard.json, the settings in
// force and its latest asks and denials. It asks for no confirmation: launched by the agent, it is itself a
// self-protection ask of the plugin (`guard-cli`), the only thing that stops the agent.
import { RULE_FEATURES } from "../rules/features.ts"
import { OPENCODE_FORMAT_SUMMARIES } from "../secrets/opencode-service.ts"
import { FORMAT_SUMMARIES } from "../secrets/patterns.ts"
import type { Redactor } from "../secrets/redact.ts"
import { CONTROL_CHARACTERS } from "../types.ts"
import { CliError, outputRedactor, type CliIo, type Pretty } from "./context.ts"
import { prettyHelp, USAGE } from "./help.ts"
import { DEFAULT_LAST, last, MAX_LAST } from "./last.ts"
import { explainFormat, isFormat, prettyRedaction, redactionLines } from "./redaction.ts"
import { customRuleLines, explainRule, prettyBuiltins, prettyCustom, ruleLines } from "./rules.ts"
import { show } from "./show.ts"
import { paint } from "./style.ts"
import { directoryOf, resetRule, setRedaction, setRule, SETTINGS, trust, untrust, type SettingWord, type Target } from "./write.ts"

export { USAGE } from "./help.ts"

class UsageError extends CliError {}

interface Parsed {
  readonly positionals: string[]
  agent?: string
  project?: string | true
  all?: boolean
  builtins?: boolean
  custom?: boolean
  explain?: string
}

/** Options allowed by a command; `--project` takes the next argument as its directory unless it is an option. */
function parse(args: readonly string[], allowed: ReadonlyArray<"agent" | "project" | "all" | "builtins" | "custom" | "explain">, explained = "a rule identifier"): Parsed {
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

/** A rule's setting (`allow`, `off`, `ask`, `deny`, `model`) or its removal (`reset`), at the target given by the options. */
function setting(word: string, args: readonly string[], io: CliIo): void {
  const parsed = parse(args, ["agent", "project"])
  expect(parsed, 1, 1, "a rule identifier")
  const target: Target = {
    ...(parsed.agent === undefined ? {} : { agent: parsed.agent }),
    ...(parsed.project === undefined ? {} : { project: directoryOf(io, parsed.project === true ? undefined : parsed.project, word === "reset") }),
  }
  if (word === "reset") resetRule(io, parsed.positionals[0]!, target)
  else setRule(io, word as SettingWord, parsed.positionals[0]!, target)
}

function run(command: string, args: readonly string[], io: CliIo): void {
  if ((SETTINGS as readonly string[]).includes(command) || command === "reset" || command === "allow")
    throw new UsageError(`unknown command ${command} (a rule's setting: guard rules ${command === "allow" ? "off" : command} <rule>)`)
  switch (command) {
    case "rules": {
      // `rules <setting> <rule>`: the same as the top-level setting commands.
      const [word, ...rest] = args
      if (word !== undefined && (SETTINGS as readonly string[]).concat("reset").includes(word)) return setting(word, rest, io)
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
    case "show": {
      const parsed = parse(args, ["agent"])
      expect(parsed, 0, 0, "")
      return show(io, parsed.agent)
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

/** Runs one command; exit code: 0 done (or nothing to change), 1 refused or failed, 2 usage error. */
export function main(argv: readonly string[], terminal: CliIo): number {
  const io = redacted(terminal)
  const [command, ...args] = argv
  if (command === undefined || command === "help" || command === "--help" || command === "-h") {
    // In a terminal, the colored layout; otherwise (and after a usage error, on the error output) the plain text.
    if (io.pretty) prettyHelp(io.pretty)
    else for (const line of USAGE.split("\n")) io.out(line)
    return command === undefined ? 2 : 0
  }
  try {
    run(command, args, io)
    return 0
  } catch (error) {
    if (error instanceof UsageError) {
      io.err(`guard: ${error.message}`)
      for (const line of USAGE.split("\n")) io.err(line)
      return 2
    }
    io.err(`guard: ${error instanceof CliError ? error.message : `internal error: ${String(error)}`}`)
    return 1
  }
}
