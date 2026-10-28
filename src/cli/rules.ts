// `guard rules`: the built-in rules in the registry order (`rules/features.ts`), with their group, their own verdict
// (before any setting) and what they check: the same text as the table of docs/rules.md (a test compares them); then the
// user's own rules (`rules` option), read and set aside exactly as the plugin does.
import { parseConfig } from "../config.ts"
import { RULE_FEATURES } from "../rules/features.ts"
import { readSources, type CliIo, type Pretty } from "./context.ts"
import { wrap, type Segment } from "./style.ts"

/** Rule → its own verdict and what it checks. */
export const RULE_SUMMARIES: ReadonlyMap<string, { readonly verdict: "deny" | "ask"; readonly description: string }> = new Map(
  (
    [
      ["placeholder", "deny", "the redaction placeholder in a command or in content to write (writing it would destroy the real secret)"],
      ["self-protection", "ask", "writing to OpenCode's configuration or to the plugin directory; adding or removing a plugin or an MCP server through opencode"],
      ["nested-opencode", "ask", "starting another OpenCode agent or server or changing its configuration; a command whose program the plugin cannot determine"],
      ["opencode-service", "ask", "changing the OpenCode service, or printing its password, environment or settings"],
      ["opencode-server-api", "ask", "a call to the OpenCode server API that can bypass the guard; exporting the OpenCode credentials; a copy of the server's memory"],
      ["guard-cli", "ask", "running or naming the guard command line, which changes the plugin's settings (another program named guard too)"],
      ["secret-file-read", "ask", "reading a credential file"],
      ["secret-file-network", "deny", "a credential file and a network tool in the same command, or in inline code that makes network requests"],
      ["secret-network", "deny", "a secret in a network command, a web request, a search, MCP arguments or CodeMode code"],
      ["secret-network-word", "ask", "a secret next to the name of a network tool that is not run"],
      ["secret-variable-network", "ask", "a variable named like a secret in a network command"],
      ["env-dump-network", "deny", "an environment dump sent over the network"],
      ["env-dump-network-word", "ask", "an environment dump next to the name of a network tool that is not run"],
      ["rm", "ask", "rm -r or rm -f"],
      ["rm-critical", "deny", "recursive deletion of /, the home directory or a system directory"],
      ["file-delete", "ask", "rm, unlink or shred run on a file"],
      ["find-delete", "ask", "deletion through find"],
      ["home-move", "ask", "moving the home directory, one of its top-level entries or a system directory"],
      ["permissions-critical", "deny", "recursive permission change on /, the home directory or a system directory"],
      ["recursive-permissions", "ask", "recursive or 777 permission change"],
      ["git-branch-delete", "ask", "forced branch deletion"],
      ["git-clean", "ask", "git clean -f"],
      ["git-discard", "ask", "discarding all changes (git checkout ., stash drop or clear, history rewriting)"],
      ["git-discard-file", "ask", "git restore or git checkout of named files"],
      ["git-push-force", "ask", "forced git push"],
      ["git-push-delete", "ask", "git push that deletes or replaces remote refs"],
      ["git-reset-hard", "ask", "git reset --hard"],
      ["git-checkout-force", "ask", "forced git checkout or git switch"],
      ["git-worktree-force", "ask", "git worktree remove --force"],
      ["git-reflog", "ask", "deleting reflog entries"],
      ["git-config-alias", "ask", "a git alias or configuration given in the command or the environment"],
      ["dd-device", "deny", "dd writing to a device"],
      ["mkfs", "deny", "disk formatting (mkfs, wipefs)"],
      ["shred-device", "deny", "shred on a device"],
      ["write-device", "deny", "tee or a copy writing to a device"],
      ["redirect-device", "deny", "a redirection to a device"],
      ["fork-bomb", "deny", "fork bomb"],
      ["kill", "ask", "forced process kill, or the USR1 signal"],
      ["power", "ask", "shutdown, reboot, stopping system services"],
      ["privilege", "ask", "sudo, doas, su, pkexec"],
      ["crontab", "ask", "changing scheduled tasks"],
      ["install", "ask", "global or system-wide software installation"],
      ["publish", "ask", "package publishing"],
      ["containers", "ask", "removing containers, images or volumes"],
      ["infra", "ask", "infrastructure changes (kubectl delete, terraform destroy…)"],
      ["pipe-to-shell", "deny", "a download run by a shell or an interpreter"],
      ["eval", "ask", "eval"],
      ["base64-exec", "ask", "running decoded content (base64 -d | sh)"],
      ["xargs-dynamic-exec", "ask", "dynamic execution through xargs"],
      ["parallel-dynamic-exec", "ask", "dynamic execution through GNU parallel"],
      ["dynamic-shell-source", "ask", "a shell or interpreter running a file or text named by a variable"],
      ["shell-startup-file", "ask", "a shell startup file chosen by an environment variable or an option"],
      ["awk-dynamic-exec", "ask", "an awk program running non-literal text"],
      ["git-exec-config", "ask", "a git setting that names a program to run"],
      ["interpreter-dangerous-code", "ask", "inline interpreter code that launches a dangerous command"],
      ["interpreter-network", "ask", "inline interpreter code that makes network requests"],
      ["upload", "ask", "HTTP upload"],
      ["gh-upload", "ask", "GitHub CLI upload or API call"],
      ["remote", "ask", "connection or transfer to a remote host (ssh, scp, nc…)"],
      ["protected-write", "ask", "writing to a protected location (startup files, /etc, ~/.ssh, git hooks…)"],
      ["codemode-fetch", "ask", "CodeMode code that makes network requests"],
      ["script-unverifiable", "ask", "a script written by the agent that can no longer be checked"],
    ] as const
  ).map(([rule, verdict, description]) => [rule, { verdict, description }]),
)

/** One line per rule, columns aligned. */
export function ruleLines(): string[] {
  const rows = [...RULE_FEATURES].map(([rule, group]) => [rule, group, RULE_SUMMARIES.get(rule)?.verdict ?? "-", RULE_SUMMARIES.get(rule)?.description ?? ""])
  const width = (column: number) => Math.max(...rows.map((row) => row[column]!.length))
  const [rule, group, verdict] = [width(0), width(1), width(2)]
  return rows.map((row) => `${row[0]!.padEnd(rule)}  ${row[1]!.padEnd(group)}  ${row[2]!.padEnd(verdict)}  ${row[3]}`)
}

/** The plugin's warnings about its `rules` option: each one starts with the option's name. */
const RULES_WARNING = /^(?:invalid )?rules\b/
const NOT_SHOWN =
  "Not shown: a project's opencode.json can replace this whole list, and its rules then apply in that project; guard last names the rule behind each ask or denial."

/** The user's own rules as the plugin reads them, or why none could be read. */
type CustomRules =
  | {
      readonly origin: string
      readonly rows: ReadonlyArray<{ readonly id: string; readonly verdict: string; readonly tools: string; readonly reason: string; readonly pattern: string; readonly builtin: boolean }>
      readonly setAside: readonly string[]
    }
  | { readonly unread: string }

/**
 * From the options the plugin gets without a project's opencode.json (the system entry, loaded last, else the global
 * one), read by the plugin's own `parseConfig`: the rules it applies and the warnings of those it sets aside.
 */
function customRules(io: CliIo): CustomRules {
  try {
    const sources = readSources(io)
    const from = (label: string) => sources.declarations.find((entry) => entry.label === label)
    const origin = from("system")?.options ? "system configuration, which replaces the global entry" : from("global")?.options ? "global configuration" : undefined
    if (!origin) {
      const reasons = sources.declarations.map((entry) => `${entry.label} configuration: ${entry.reason ?? "not read"}`)
      return { unread: `none read, the plugin is not declared (${reasons.join("; ")})` }
    }
    const { config, warnings } = parseConfig(sources.options, io.env)
    return {
      origin,
      rows: config.rules.map((rule) => ({
        id: rule.id,
        verdict: rule.verdict,
        tools: rule.tools.join(","),
        reason: rule.reason,
        pattern: `/${rule.pattern.source}/${rule.pattern.flags}`,
        builtin: RULE_FEATURES.has(rule.id),
      })),
      setAside: warnings.filter((warning) => RULES_WARNING.test(warning)),
    }
  } catch (error) {
    return { unread: `the configuration could not be read (${error instanceof Error ? error.message : String(error)})` }
  }
}

/** The user's own rules, one line each (output that is not a terminal): a section of its own, with a header. */
export function customRuleLines(io: CliIo): string[] {
  const rules = customRules(io)
  if ("unread" in rules) return [`Your rules: ${rules.unread}`]
  const rows = rules.rows.map((row) => [row.id, row.verdict, row.tools, row.reason, `${row.pattern}${row.builtin ? "  (same identifier as a built-in rule)" : ""}`])
  const width = (column: number) => Math.max(0, ...rows.map((row) => row[column]!.length))
  const [id, verdict, tools, reason] = [width(0), width(1), width(2), width(3)]
  return [
    `Your rules (rules option of the ${rules.origin}):`,
    ...(rows.length ? rows.map((row) => `  ${row[0]!.padEnd(id)}  ${row[1]!.padEnd(verdict)}  ${row[2]!.padEnd(tools)}  ${row[3]!.padEnd(reason)}  ${row[4]}`) : ["  none"]),
    ...(rules.setAside.length ? ["  Set aside:", ...rules.setAside.map((warning) => `    ${warning}`)] : []),
    `  ${NOT_SHOWN}`,
  ]
}

/** What `false` turns off, after the group's name (the option to set). */
const GROUPS: Readonly<Record<string, string>> = {
  always: "cannot be turned off",
  sensitiveFiles: "credential files and secrets leaving the machine",
  dangerousCommands: "dangerous actions",
}
const verdictStyle = (verdict: string) => (verdict === "deny" ? "deny" : "ask")

/**
 * Lines of a table row: the fixed cells, then `text` wrapped to the terminal's width from its column, continuation lines
 * aligned on it. Every cell is already cleaned: widths and cuts are those of the printed text.
 */
function rowLines(pretty: Pretty, cells: readonly Segment[], column: number, text: string, style?: Segment[1]): Segment[][] {
  const [first = "", ...rest] = wrap(text, Math.max(20, pretty.width - column))
  return [[...cells, [first, style]], ...rest.map((line): Segment[] => [[" ".repeat(column)], [line, style]])]
}

/** The built-in rules for a terminal: by group (the option that turns it off), aligned, descriptions wrapped. */
export function prettyBuiltins(pretty: Pretty): void {
  const rules = [...RULE_FEATURES].map(([rule, group]) => ({ rule: pretty.clean(rule), group, verdict: RULE_SUMMARIES.get(rule)?.verdict ?? "-", description: pretty.clean(RULE_SUMMARIES.get(rule)?.description ?? "") }))
  const id = Math.max(...rules.map((row) => row.rule.length))
  const column = 4 + id + 2 + 4 + 2
  pretty.line([["Built-in rules", "title"], [`  ${rules.length}`, "dim"]])
  for (const group of new Set(rules.map((row) => row.group))) {
    pretty.line([])
    const members = rules.filter((row) => row.group === group)
    pretty.line([["  "], [group === "always" ? "always active" : group, "group"], [`  ${GROUPS[group] ?? ""} (${members.length})`, "dim"]])
    for (const row of members)
      for (const line of rowLines(pretty, [["    "], [row.rule.padEnd(id), "rule"], ["  "], [row.verdict.padEnd(4), verdictStyle(row.verdict)], ["  "]], column, row.description)) pretty.line(line)
  }
}

/** The user's own rules for a terminal: aligned, reasons wrapped, each pattern alone on the next line, unchanged. */
export function prettyCustom(io: CliIo, pretty: Pretty): void {
  const rules = customRules(io)
  if ("unread" in rules) {
    pretty.line([["Your rules", "title"]])
    pretty.line([])
    for (const line of rowLines(pretty, [["  "]], 2, pretty.clean(rules.unread), "warn")) pretty.line(line)
    return
  }
  const rows = rules.rows.map((row) => ({ id: pretty.clean(row.id), verdict: row.verdict, tools: pretty.clean(row.tools), reason: pretty.clean(row.reason), pattern: pretty.clean(row.pattern), builtin: row.builtin }))
  const [id, tools] = [Math.max(0, ...rows.map((row) => row.id.length)), Math.max(0, ...rows.map((row) => row.tools.length))]
  const column = 4 + id + 2 + 4 + 2 + tools + 2
  pretty.line([["Your rules", "title"], [`  ${rows.length}, rules option of the ${pretty.clean(rules.origin)}`, "dim"]])
  pretty.line([])
  if (!rows.length) pretty.line([["    "], ["none", "dim"]])
  for (const row of rows) {
    const cells: Segment[] = [["    "], [row.id.padEnd(id), "rule"], ["  "], [row.verdict.padEnd(4), verdictStyle(row.verdict)], ["  "], [row.tools.padEnd(tools)], ["  "]]
    for (const line of rowLines(pretty, cells, column, row.reason)) pretty.line(line)
    pretty.line([[" ".repeat(column)], [row.pattern, "dim"]])
    if (row.builtin) pretty.line([[" ".repeat(column)], ["same identifier as a built-in rule", "warn"]])
  }
  if (rules.setAside.length) {
    pretty.line([])
    pretty.line([["  "], ["Set aside", "warn"]])
    for (const warning of rules.setAside) for (const line of rowLines(pretty, [["    "]], 4, pretty.clean(warning), "warn")) pretty.line(line)
  }
  pretty.line([])
  for (const line of rowLines(pretty, [["  "]], 2, NOT_SHOWN, "dim")) pretty.line(line)
}
