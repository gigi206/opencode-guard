// `guard rules`: the built-in rules in the registry order (`rules/features.ts`), with their group, their own verdict
// (before any setting) and what they check: the same text as the table of docs/rules.md (a test compares them); then the
// user's own rules (`rules` option, then the global guard.json's), read and set aside exactly as the plugin does.
import { join } from "node:path"
import { parseConfig, type GuardFile } from "../config.ts"
import { GUARD_FILE, readGuardFiles } from "../guard-file.ts"
import { RULE_DETAILS, ruleSettings } from "../rules/details.ts"
import { RULE_FEATURES, type RuleFeature } from "../rules/features.ts"
import type { CustomRule } from "../rules/types.ts"
import { CliError, mayKeepNote, readSources, resolution, type CliIo, type Pretty, type Sources } from "./context.ts"
import { heading, rowLines, title } from "./pretty.ts"
import { type Segment } from "./style.ts"

/** Rule → its own verdict and what it checks. */
export const RULE_SUMMARIES: ReadonlyMap<string, { readonly verdict: "deny" | "ask"; readonly description: string }> = new Map(
  (
    [
      ["placeholder", "deny", "the redaction placeholder in a command or in content to write (writing it would destroy the real secret)"],
      ["self-protection", "ask", "writing to OpenCode's configuration or to the plugin directory; a command that names them and does more than read; adding or removing a plugin or an MCP server, or updating package plugins, through opencode"],
      ["nested-opencode", "ask", "starting another OpenCode agent or server or changing its configuration; a command whose program the plugin cannot determine"],
      ["opencode-service", "ask", "changing the OpenCode service, or printing its password, environment or settings"],
      ["opencode-server-api", "ask", "a call to the OpenCode server API that can bypass the guard, also from an artifact's page code; exporting the OpenCode credentials; a copy of the server's memory"],
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

const groupLabel = (group: RuleFeature) => (group === "always" ? "always active" : group)

/**
 * One built-in rule explained: what it checks, how it decides, the reason a finding usually carries and the settings
 * that apply to it. Only the registry's own text, at the level of docs/rules.md: never the rule's pattern.
 */
export function explainRule(io: CliIo, rule: string): void {
  const group = RULE_FEATURES.get(rule)
  const summary = RULE_SUMMARIES.get(rule)
  const detail = RULE_DETAILS.get(rule)
  if (!group || !summary) throw new CliError(`${rule} is not a built-in rule`)
  if (!detail) throw new CliError(`no explanation is available for the built-in rule ${rule}`)
  const reason = detail.reason ?? summary.description
  const settings = ruleSettings(rule, group)
  if (io.pretty) {
    const pretty = io.pretty
    title(pretty, `Rule ${pretty.clean(rule)}`, `${groupLabel(group)}, own verdict ${summary.verdict}`, "builtins")
    const block = (name: string, text: string) => {
      pretty.line([])
      heading(pretty, name)
      for (const line of rowLines(pretty, [["    "]], 4, pretty.clean(text))) pretty.line(line)
    }
    block("What it checks", summary.description)
    block("How it decides", detail.how)
    block("Typical reason", reason)
    block("Settings", settings)
    return
  }
  io.out(`Rule: ${rule}`)
  io.out(`  Group: ${group}`)
  io.out(`  Own verdict: ${summary.verdict}`)
  io.out(`  What it checks: ${summary.description}`)
  io.out(`  How it decides: ${detail.how}`)
  io.out(`  Typical reason: ${reason}`)
  io.out(`  Settings: ${settings}`)
}

/** The plugin's warnings about its `rules` option: each one starts with the option's name. */
const RULES_WARNING = /^(?:invalid )?rules\b/
const NOT_SHOWN =
  "Not shown: a project's opencode.json can replace this whole list, and its rules then apply in that project; guard last names the rule behind each ask or denial."

/** The plugin's warnings about the rules of the global guard.json (its top level or a section of it). */
const GUARD_RULES_WARNING = /^global guard\.json(?:, .*?)?: (?:invalid )?rules\b/

type Row = { readonly id: string; readonly verdict: string; readonly tools: string; readonly reason: string; readonly pattern: string; readonly builtin: boolean }

/** The rules of the global guard.json, when it has some (or warnings about them), or why it is ignored. */
type GuardRules = { readonly path: string } & ({ readonly rows: readonly Row[]; readonly setAside: readonly string[] } | { readonly unread: string })

/** The user's own rules as the plugin reads them, or why none could be read; then the global guard.json's. */
type CustomRules = (
  | {
      readonly origin: string
      readonly rows: readonly Row[]
      readonly setAside: readonly string[]
    }
  | { readonly unread: string }
) & { readonly guard?: GuardRules }

const rowOf = (rule: CustomRule): Row => ({
  id: rule.id,
  verdict: rule.verdict,
  tools: rule.tools.join(","),
  reason: rule.reason,
  pattern: `/${rule.pattern.source}/${rule.pattern.flags}`,
  builtin: RULE_FEATURES.has(rule.id),
})

/** The global guard.json as the plugin reads it: its rules and their warnings; nothing when it has neither. */
function guardRules(io: CliIo, sources: Sources): GuardRules | undefined {
  if (!sources.globalDir) return undefined
  const path = join(sources.globalDir, GUARD_FILE)
  const [file] = readGuardFiles({ global: path, projects: [], roots: [] }) as Array<GuardFile | undefined>
  if (!file) return undefined
  if (!file.data) return { path, unread: `ignored: ${file.reason ?? "it cannot be read"} (a running plugin keeps the rules it read from it last)` }
  const version = resolution(io, sources, undefined, [file])
  const rows = (version.guardRules ?? []).map(rowOf)
  const kept = mayKeepNote(version)
  const setAside = [...version.warnings.filter((warning) => GUARD_RULES_WARNING.test(warning)).map((warning) => warning.replace(/^global guard\.json: /, "")), ...(kept ? [kept] : [])]
  return rows.length || setAside.length ? { path, rows, setAside } : undefined
}

/**
 * From the options the plugin gets without a project's opencode.json (the system entry, loaded last, else the global
 * one), read by the plugin's own `parseConfig`: the rules it applies and the warnings of those it sets aside.
 */
function customRules(io: CliIo): CustomRules {
  try {
    const sources = readSources(io)
    const guard = guardRules(io, sources)
    const from = (label: string) => sources.declarations.find((entry) => entry.label === label)
    const origin = from("system")?.options ? "system configuration, which replaces the global entry" : from("global")?.options ? "global configuration" : undefined
    if (!origin) {
      const reasons = sources.declarations.map((entry) => `${entry.label} configuration: ${entry.reason ?? "not read"}`)
      return { unread: `none read, the plugin is not declared (${reasons.join("; ")})`, ...(guard ? { guard } : {}) }
    }
    const { config, warnings } = parseConfig(sources.options, io.env)
    return { origin, rows: config.rules.map(rowOf), setAside: warnings.filter((warning) => RULES_WARNING.test(warning)), ...(guard ? { guard } : {}) }
  } catch (error) {
    return { unread: `the configuration could not be read (${error instanceof Error ? error.message : String(error)})` }
  }
}

/** Rows of rules, one line each, columns aligned. */
function plainRows(rows: readonly Row[], setAside: readonly string[]): string[] {
  const cells = rows.map((row) => [row.id, row.verdict, row.tools, row.reason, `${row.pattern}${row.builtin ? "  (same identifier as a built-in rule)" : ""}`])
  const width = (column: number) => Math.max(0, ...cells.map((row) => row[column]!.length))
  const [id, verdict, tools, reason] = [width(0), width(1), width(2), width(3)]
  return [
    ...(cells.length ? cells.map((row) => `  ${row[0]!.padEnd(id)}  ${row[1]!.padEnd(verdict)}  ${row[2]!.padEnd(tools)}  ${row[3]!.padEnd(reason)}  ${row[4]}`) : ["  none"]),
    ...(setAside.length ? ["  Set aside:", ...setAside.map((warning) => `    ${warning}`)] : []),
  ]
}

/** The global guard.json's section (output that is not a terminal). */
function plainGuard(guard: GuardRules | undefined): string[] {
  if (!guard) return []
  if ("unread" in guard) return [`Your rules in the global guard.json ${guard.path}: ${guard.unread}`]
  return [`Your rules (rules of the global guard.json ${guard.path}):`, ...plainRows(guard.rows, guard.setAside)]
}

/** The user's own rules, one line each (output that is not a terminal): a section of its own, with a header. */
export function customRuleLines(io: CliIo): string[] {
  const rules = customRules(io)
  if ("unread" in rules) return [`Your rules: ${rules.unread}`, ...plainGuard(rules.guard)]
  // The note is about the option's list only: right after it.
  return [`Your rules (rules option of the ${rules.origin}):`, ...plainRows(rules.rows, rules.setAside), `  ${NOT_SHOWN}`, ...plainGuard(rules.guard)]
}

/** What `false` turns off, after the group's name (the option to set). */
const GROUPS: Readonly<Record<string, string>> = {
  always: "cannot be turned off",
  sensitiveFiles: "credential files and secrets leaving the machine",
  dangerousCommands: "dangerous actions",
}
const verdictStyle = (verdict: string) => (verdict === "deny" ? "deny" : "ask")

const count = (n: number) => `${n} ${n === 1 ? "rule" : "rules"}`

/** The built-in rules for a terminal: by group (the option that turns it off), aligned, descriptions wrapped. */
export function prettyBuiltins(pretty: Pretty): void {
  const rules = [...RULE_FEATURES].map(([rule, group]) => ({ rule: pretty.clean(rule), group, verdict: RULE_SUMMARIES.get(rule)?.verdict ?? "-", description: pretty.clean(RULE_SUMMARIES.get(rule)?.description ?? "") }))
  const id = Math.max(...rules.map((row) => row.rule.length))
  const column = 4 + id + 2 + 4 + 2
  title(pretty, "Built-in rules", count(rules.length), "builtins")
  for (const group of new Set(rules.map((row) => row.group))) {
    pretty.line([])
    const members = rules.filter((row) => row.group === group)
    pretty.line([["  "], [group === "always" ? "always active" : group, "group"], [`  ${GROUPS[group] ?? ""} (${members.length})`, "dim"]])
    for (const row of members)
      for (const line of rowLines(pretty, [["    "], [row.rule.padEnd(id), "rule"], ["  "], [row.verdict.padEnd(4), verdictStyle(row.verdict)], ["  "]], column, row.description)) pretty.line(line)
  }
}

/** Rows of rules for a terminal: aligned, reasons wrapped, each pattern alone on the next line, unchanged. */
function prettyRows(pretty: Pretty, given: readonly Row[], setAside: readonly string[]): void {
  const rows = given.map((row) => ({ id: pretty.clean(row.id), verdict: row.verdict, tools: pretty.clean(row.tools), reason: pretty.clean(row.reason), pattern: pretty.clean(row.pattern), builtin: row.builtin }))
  const [id, tools] = [Math.max(0, ...rows.map((row) => row.id.length)), Math.max(0, ...rows.map((row) => row.tools.length))]
  const column = 4 + id + 2 + 4 + 2 + tools + 2
  if (!rows.length) pretty.line([["    "], ["none", "dim"]])
  for (const row of rows) {
    const cells: Segment[] = [["    "], [row.id.padEnd(id), "rule"], ["  "], [row.verdict.padEnd(4), verdictStyle(row.verdict)], ["  "], [row.tools.padEnd(tools)], ["  "]]
    for (const line of rowLines(pretty, cells, column, row.reason)) pretty.line(line)
    pretty.line([[" ".repeat(column)], [row.pattern, "dim"]])
    if (row.builtin) pretty.line([[" ".repeat(column)], ["same identifier as a built-in rule", "warn"]])
  }
  if (setAside.length) {
    pretty.line([])
    pretty.line([["  "], ["Set aside", "warn"]])
    for (const warning of setAside) for (const line of rowLines(pretty, [["    "]], 4, pretty.clean(warning), "warn")) pretty.line(line)
  }
}

/** The global guard.json's rules for a terminal, under a heading with its path. */
function prettyGuard(pretty: Pretty, guard: GuardRules | undefined): void {
  if (!guard) return
  pretty.line([])
  heading(pretty, "From the global guard.json", pretty.clean(guard.path))
  if ("unread" in guard) for (const line of rowLines(pretty, [["    "]], 4, pretty.clean(guard.unread), "warn")) pretty.line(line)
  else {
    pretty.line([])
    prettyRows(pretty, guard.rows, guard.setAside)
  }
}

/** The user's own rules for a terminal: those of the rules option, then the global guard.json's. */
export function prettyCustom(io: CliIo, pretty: Pretty): void {
  const rules = customRules(io)
  if ("unread" in rules) {
    title(pretty, "Your rules", "rules option", "custom")
    pretty.line([])
    for (const line of rowLines(pretty, [["  "]], 2, pretty.clean(rules.unread), "warn")) pretty.line(line)
    prettyGuard(pretty, rules.guard)
    return
  }
  title(pretty, "Your rules", `${count(rules.rows.length)}, from the rules option of the ${pretty.clean(rules.origin)}`, "custom")
  pretty.line([])
  prettyRows(pretty, rules.rows, rules.setAside)
  pretty.line([])
  for (const line of rowLines(pretty, [["  "]], 2, NOT_SHOWN, "dim")) pretty.line(line)
  prettyGuard(pretty, rules.guard)
}
