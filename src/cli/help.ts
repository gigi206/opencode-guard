// `guard help`: the commands, in groups (what they read, what they write in the global guard.json, the plugin's update). The same
// entries give the plain text (`USAGE`, printed as is when the output is not a terminal, and after a usage error) and
// the terminal layout (a banner, the groups as headings, the commands in color, descriptions wrapped to the width).
import { RELAX_SWITCHES } from "../config.ts"
import type { Pretty } from "./context.ts"
import { DEFAULT_LAST, MAX_LAST } from "./last.ts"
import { rowLines, title } from "./pretty.ts"
import type { Segment } from "./style.ts"

interface Entry {
  /** Command and arguments; an option of the entry above starts with `--`. */
  readonly usage: string
  readonly text: string
  /** Verbs of an option shared by several; otherwise it belongs to the command above it. */
  readonly verbs?: readonly string[]
}

const SECTION_VERBS = ["rules", "set", "unset"]

const GROUPS: ReadonlyArray<{ readonly name: string; readonly detail: string; readonly entries: readonly Entry[] }> = [
  {
    name: "Read",
    detail: "nothing is written",
    entries: [
      { usage: "rules [--builtins|--custom]", text: "built-in rules (identifier, group, own verdict, what they check), then yours" },
      { usage: "rules --explain <rule>", text: "one built-in rule: what it checks, how it decides, its typical reason and settings" },
      { usage: "redaction [--builtins|--custom]", text: "redaction formats (built-in ones and their state, OpenCode's), then your patterns" },
      { usage: "redaction --explain <format>", text: "one format: what it catches, its patterns, how to turn it off" },
      { usage: "show [--agent <name>]", text: "the plugin's commit (HEAD or tag), policy settings and exceptions in force for the current directory, and where they come from" },
      { usage: "show --offline", text: "the same, without looking up the repository for HEAD and tags" },
      { usage: "settings [--agent <name>]", text: "every setting: type, value in force, default, where it comes from" },
      { usage: "settings --explain <setting>", text: "one setting, or all: what it does, what it accepts, its state here" },
      { usage: "last [<count>]", text: `latest asks and denials of the plugin's log, in local time (default ${DEFAULT_LAST}, at most ${MAX_LAST})` },
      { usage: "status [--offline]", text: "latest starts of the plugin, errors and warnings since, files not loaded yet, decision model answering" },
      { usage: "test [options] [--] <command>", text: "the verdict the plugin would give to a shell command here, with its rule and reason, never run" },
      { usage: "  --tool <name> '<json>'", text: "another tool call instead, its JSON input as OpenCode passes it (path, command…)" },
      { usage: "  --agent <name>", text: "as this main agent (default: build)" },
      { usage: "  --model", text: "also ask the decision model (the call is sent to it); otherwise a call no local rule decides is said to be its" },
    ],
  },
  {
    name: "Change",
    detail: "in the global guard.json only",
    entries: [
      { usage: "rules off|ask|deny|model <rule>", text: 'set a built-in rule ("off" turns it off, "model" leaves its asks to the decision model)' },
      { usage: "rules reset <rule>", text: "remove the rule's setting there: it applies with its own verdict again" },
      { usage: "  --path <file>", text: "rules off|reset secret-file-read only: add or remove the file's real path in the rule's exceptions there, the rest of the rule unchanged (top level or --project, never --agent)" },
      { usage: "set <setting> <value>", text: "a policy setting: profile, localAsks, selfProtectionByModel, dangerousCommands, sensitiveFiles, scripts, decisionModel, rememberConfirmations (minutes, 1 to 60); with --project only: redactOutputs, redactPrompt, redactWire, outputCheck, promptCheck" },
      { usage: "unset <setting>", text: "remove that setting there" },
      { usage: "  --agent <name>", text: "rules <setting>|reset, set, unset: in the section of this agent (main agent, or subagent); never with --path, nor set rememberConfirmations (unset removes a value written there)", verbs: SECTION_VERBS },
      { usage: "  --project [<dir>]", text: "in the section of this project (default: the git repository of the current directory)", verbs: SECTION_VERBS },
      { usage: "rules add <id>", text: "add one of your rules to rules of the global guard.json (top level only)" },
      { usage: "  --pattern <regex>", text: "required: the regular expression it looks for (in the command, or in the tool's input)" },
      { usage: "  --verdict ask|deny", text: "required: ask for a confirmation, or refuse" },
      { usage: "  --reason <text>", text: "the reason given with each ask or denial (default: custom rule <index> of the global guard.json)" },
      { usage: "  --tools <tools>|*", text: "the tools it checks, separated by commas, or * for every tool (default: shell)" },
      { usage: "  --flags <flags>", text: "flags of the regular expression (i: any case)" },
      { usage: "rules remove <id>", text: "remove it from there (a rule of the rules option of opencode.json stays)" },
      { usage: "redaction off|on <format>", text: "turn a built-in redaction format off, or back on (top level only)" },
      { usage: "agent off <agent>", text: "no checks and no redaction for this agent, as selected by you, on the model it runs" },
      { usage: "  --model <provider/model>", text: "agent off only: limit it to this model (repeat for several)" },
      { usage: "agent on <agent>", text: "take back what guard agent relaxed for this agent, and name what else still relaxes it" },
      { usage: "agent set <agent> <key> <value>", text: "true or false for one protection of this agent: redactOutputs, redactPrompt, redactWire, outputCheck, promptCheck" },
      { usage: "agent unset <agent> <key>", text: "remove that key, or guard, or models" },
      { usage: "agent models <agent> <model>…", text: "limit what is relaxed for this agent to these provider/model" },
      { usage: "trust [<dir>|--all]", text: "add a project to trustedProjects (default: the git repository of the current directory)" },
      { usage: "untrust [<dir>|--all]", text: "remove it" },
    ],
  },
  {
    name: "Plugin",
    detail: "installed from Git, through OpenCode",
    entries: [
      { usage: "update", text: "run opencode plugin update on the configured specifier (not a pinned commit), then say whether the installed commit changed" },
      { usage: "update --check", text: "only run opencode plugin check on the configured specifier" },
    ],
  },
]

const NOTES = [
  "The commands that change settings write only the global guard.json (OpenCode's global configuration directory, from this terminal's environment).",
  "The plugin re-reads it within seconds, without a restart; an agent section counts from the next prompt.",
  `In a project section, ${RELAX_SWITCHES.join(", ")} count from the next start of the plugin.`,
]

const COMPLETION = 'completion script for the shell: eval "$(guard completion zsh)" in its startup file'

const OTHERS: readonly Entry[] = [
  { usage: "completion bash|zsh", text: COMPLETION },
  { usage: "help [<verb>]", text: "this help, or the lines of one verb (also guard <verb> -h)" },
]

const verbOf = (entry: Entry) => entry.usage.split(" ")[0]!
const VERBS = new Set([...GROUPS.flatMap((group) => group.entries), ...OTHERS].filter((entry) => !entry.usage.startsWith(" ")).map(verbOf))

/** The entries of a verb: an option goes with the command above it, unless it names its verbs. */
function ofVerb(entries: readonly Entry[], verb: string): Entry[] {
  let owner = ""
  return entries.filter((entry) => {
    if (!entry.usage.startsWith(" ")) owner = verbOf(entry)
    return entry.verbs ? entry.verbs.includes(verb) : owner === verb
  })
}

/** What the help shows: everything, or the lines of a known verb. */
function shown(word: string | undefined) {
  const verb = word !== undefined && VERBS.has(word) ? word : undefined
  if (verb === undefined) return { verb, groups: GROUPS, others: OTHERS, notes: NOTES }
  const groups = GROUPS.map((group) => ({ ...group, entries: ofVerb(group.entries, verb) })).filter((group) => group.entries.length)
  return { verb, groups, others: ofVerb(OTHERS, verb), notes: groups.some((group) => group.name === "Change") ? NOTES : [] }
}

const COLUMN = Math.max(...GROUPS.flatMap((group) => group.entries.map((entry) => entry.usage.length))) + 4

/** The plain text of the help, of one verb when `word` is a known one. */
export function helpText(word?: string): string {
  const { verb, groups, others, notes } = shown(word)
  const line = (entry: Entry) => `  ${entry.usage.padEnd(COLUMN - 2)}${entry.text}`
  return [
    `Usage: guard ${verb ?? "<command>"} [arguments]`,
    ...groups.flatMap((group) => ["", `${group.name} (${group.detail}):`, ...group.entries.map(line)]),
    ...(others.length && groups.length === 0 ? [""] : []),
    ...others.map(line),
    ...(notes.length ? ["", ...notes] : []),
  ].join("\n")
}

export const USAGE = helpText()

/** Words of a usage, colored: the command, its options, the placeholders. */
function usageSegments(usage: string): Segment[] {
  return usage.split(/(\s+)/).map((word, index): Segment => {
    if (/^\s+$/.test(word) || !word) return [word]
    if (word.startsWith("--") || word.startsWith("[--")) return [word, "ask"]
    if (/^\[?<[^>]+>\]?$/.test(word) || /^\[<[^>]+>\|--\w+\]$/.test(word)) return [word, "dim"]
    return index === 0 ? [word, "rule"] : [word, "good"]
  })
}

/** One row: the usage indented (an option further), then the description from one column for every row. */
function row(pretty: Pretty, usage: string, text: string): void {
  const option = usage.startsWith("  ")
  const indent = option ? 6 : 4
  const words = usageSegments(usage.trim()).map(([word, style]): Segment => [word, option && style ? "ask" : style])
  const column = COLUMN + 2
  const cells: Segment[] = [[" ".repeat(indent)], ...words, [" ".repeat(Math.max(2, column - indent - usage.trim().length))]]
  for (const line of rowLines(pretty, cells, column, text)) pretty.line(line)
}

/** `guard help` in a terminal, of one verb when `word` is a known one. */
export function prettyHelp(pretty: Pretty, word?: string): void {
  const { verb, groups, others, notes } = shown(word)
  title(pretty, "guard", `the guard plugin's command line: guard ${verb ?? "<command>"} [arguments]`, "builtins")
  for (const group of groups) {
    pretty.line([])
    pretty.line([["  "], [group.name, "group"], [`  ${group.detail}`, "dim"]])
    for (const entry of group.entries) row(pretty, entry.usage, entry.text)
  }
  if (others.length) pretty.line([])
  for (const entry of others) row(pretty, entry.usage, entry.text)
  if (notes.length) pretty.line([])
  for (const note of notes) for (const line of rowLines(pretty, [["  "]], 2, note, "dim")) pretty.line(line)
}
