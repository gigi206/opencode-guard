// `guard help`: the commands, in two groups (what they read, what they write in the global guard.json). The same
// entries give the plain text (`USAGE`, printed as is when the output is not a terminal, and after a usage error) and
// the terminal layout (a banner, the groups as headings, the commands in color, descriptions wrapped to the width).
import type { Pretty } from "./context.ts"
import { DEFAULT_LAST, MAX_LAST } from "./last.ts"
import { rowLines, title } from "./pretty.ts"
import type { Segment } from "./style.ts"

interface Entry {
  /** Command and arguments; an option of the entry above starts with `--`. */
  readonly usage: string
  readonly text: string
}

const GROUPS: ReadonlyArray<{ readonly name: string; readonly detail: string; readonly entries: readonly Entry[] }> = [
  {
    name: "Read",
    detail: "nothing is written",
    entries: [
      { usage: "rules [--builtins|--custom]", text: "built-in rules (identifier, group, own verdict, what they check), then yours" },
      { usage: "rules --explain <rule>", text: "one built-in rule: what it checks, how it decides, its typical reason and settings" },
      { usage: "redaction [--builtins|--custom]", text: "redaction formats (built-in ones and their state, OpenCode's), then your patterns" },
      { usage: "redaction --explain <format>", text: "one format: what it catches, its patterns, how to turn it off" },
      { usage: "show [--agent <name>]", text: "policy settings and exceptions in force for the current directory, and where they come from" },
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
      { usage: "set <setting> <value>", text: "a policy setting: profile, localAsks, selfProtectionByModel, dangerousCommands, sensitiveFiles, scripts, decisionModel, rememberConfirmations (minutes, 1 to 60)" },
      { usage: "unset <setting>", text: "remove that setting there" },
      { usage: "  --agent <name>", text: "rules <setting>|reset, set, unset: in the section of this agent (main agent, or subagent); never with --path, nor set rememberConfirmations (unset removes a value written there)" },
      { usage: "  --project [<dir>]", text: "in the section of this project (default: the git repository of the current directory)" },
      { usage: "rules add <id>", text: "add one of your rules to rules of the global guard.json (top level only)" },
      { usage: "  --pattern <regex>", text: "required: the regular expression it looks for (in the command, or in the tool's input)" },
      { usage: "  --verdict ask|deny", text: "required: ask for a confirmation, or refuse" },
      { usage: "  --reason <text>", text: "the reason given with each ask or denial (default: custom rule <index> of the global guard.json)" },
      { usage: "  --tools <tools>|*", text: "the tools it checks, separated by commas, or * for every tool (default: shell)" },
      { usage: "  --flags <flags>", text: "flags of the regular expression (i: any case)" },
      { usage: "rules remove <id>", text: "remove it from there (a rule of the rules option of opencode.json stays)" },
      { usage: "redaction off|on <format>", text: "turn a built-in redaction format off, or back on (top level only)" },
      { usage: "trust [<dir>|--all]", text: "add a project to trustedProjects (default: the git repository of the current directory)" },
      { usage: "untrust [<dir>|--all]", text: "remove it" },
    ],
  },
]

const NOTES = [
  "Only the global guard.json is written (OpenCode's global configuration directory, from this terminal's environment).",
  "The plugin re-reads it within seconds, without a restart; an agent section counts from the next prompt.",
]

const COMPLETION = 'completion script for the shell: eval "$(guard completion zsh)" in its startup file'

const COLUMN = Math.max(...GROUPS.flatMap((group) => group.entries.map((entry) => entry.usage.length))) + 4

export const USAGE = [
  "Usage: guard <command> [arguments]",
  ...GROUPS.flatMap((group) => ["", `${group.name} (${group.detail}):`, ...group.entries.map((entry) => `  ${entry.usage.padEnd(COLUMN - 2)}${entry.text}`)]),
  "  completion bash|zsh".padEnd(COLUMN) + COMPLETION,
  "  help".padEnd(COLUMN) + "this help",
  "",
  ...NOTES,
].join("\n")

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

/** `guard help` in a terminal. */
export function prettyHelp(pretty: Pretty): void {
  title(pretty, "guard", "the guard plugin's command line: guard <command> [arguments]", "builtins")
  for (const group of GROUPS) {
    pretty.line([])
    pretty.line([["  "], [group.name, "group"], [`  ${group.detail}`, "dim"]])
    for (const entry of group.entries) row(pretty, entry.usage, entry.text)
  }
  pretty.line([])
  row(pretty, "completion bash|zsh", COMPLETION)
  row(pretty, "help", "this help")
  pretty.line([])
  for (const note of NOTES) for (const line of rowLines(pretty, [["  "]], 2, note, "dim")) pretty.line(line)
}
