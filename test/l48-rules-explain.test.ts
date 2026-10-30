// `guard rules --explain <rule>`: one built-in rule's own verdict, what it checks, how it decides, the reason a finding
// usually carries and its settings, in words; never the rule's pattern. The terminal layout wraps and colors it, and
// every line still goes through the redaction. Run in process on test directories.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { main } from "../src/cli/main.ts"
import { RULE_DETAILS } from "../src/rules/details.ts"
import { RULE_SUMMARIES } from "../src/cli/rules.ts"
import { ESCAPES } from "../src/cli/style.ts"
import { RULE_FEATURES } from "../src/rules/features.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>

/** A global configuration that declares the plugin with these options (none: not declared), and the command on it. */
function world(global?: Json) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-explain-")))
  const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "app")]
  for (const dir of [globalDir, systemDir, home, data, project]) mkdirSync(dir, { recursive: true })
  if (global) writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: global }] }))
  const env = { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }
  return (terminal: { width: number; color: boolean } | undefined, ...args: string[]) => {
    const out: string[] = []
    const err: string[] = []
    const code = main(args, { env, cwd: project, systemDir, out: (line: string) => out.push(line), err: (line: string) => err.push(line), ...(terminal ? { terminal } : {}) })
    return { code, out, err }
  }
}

const plain = (lines: readonly string[]) => lines.map((line) => ESCAPES.reduce((text, escape) => text.replaceAll(escape, ""), line))

describe("guard rules --explain", () => {
  it("EX-1: one built-in rule, in words: group, own verdict, what it checks, how it decides, typical reason, settings", () => {
    const run = world()
    const r = run(undefined, "rules", "--explain", "rm")
    assert.equal(r.code, 0)
    assert.equal(r.err.length, 0)
    assert.deepEqual(r.out.slice(0, 3), ["Rule: rm", "  Group: dangerousCommands", "  Own verdict: ask"])
    assert.equal(r.out[3], `  What it checks: ${RULE_SUMMARIES.get("rm")!.description}`)
    assert.equal(r.out[4], `  How it decides: ${RULE_DETAILS.get("rm")!.how}`)
    assert.match(r.out[5]!, /^ {2}Typical reason: file deletion \(rm -r\/-f\)$/)
    assert.match(r.out[6]!, /^ {2}Settings: Part of the dangerousCommands group: /)
    assert.equal(r.out.length, 7)
    // `--explain=<rule>` is the same option.
    assert.deepEqual(run(undefined, "rules", "--explain=rm").out, r.out)
  })

  it("EX-2: every built-in rule has a complete explanation, in the registry's order and without a missing field", () => {
    const run = world()
    assert.equal(RULE_DETAILS.size, RULE_FEATURES.size)
    for (const [rule, group] of RULE_FEATURES) {
      const detail = RULE_DETAILS.get(rule)
      assert.ok(detail, `${rule}: no detail`)
      const r = run(undefined, "rules", "--explain", rule)
      assert.equal(r.code, 0, rule)
      assert.deepEqual(r.out.slice(0, 3), [`Rule: ${rule}`, `  Group: ${group}`, `  Own verdict: ${RULE_SUMMARIES.get(rule)!.verdict}`], rule)
      assert.equal(r.out[3], `  What it checks: ${RULE_SUMMARIES.get(rule)!.description}`, rule)
      assert.equal(r.out[4], `  How it decides: ${detail.how}`, rule)
      assert.equal(r.out[5], `  Typical reason: ${detail.reason}`, rule)
      assert.ok(r.out[6]!.startsWith("  Settings: "), rule)
      assert.equal(r.out.length, 7, rule)
      assert.ok(!r.out.join("\n").includes("undefined"), rule)
    }
  })

  it("EX-3: an unknown identifier, or one of the user's own rules, is a usage error and explains nothing", () => {
    const run = world({ rules: [{ id: "no-prod", pattern: "--env=prod", verdict: "deny" }] })
    for (const rule of ["nope", "no-prod"]) {
      const r = run(undefined, "rules", "--explain", rule)
      assert.equal(r.code, 2, rule)
      assert.equal(r.out.length, 0, rule)
      assert.equal(r.err[0], `guard: no built-in rule named ${rule}`, rule)
      assert.ok(r.err.some((line) => line.startsWith("Usage: guard")), rule)
    }
  })

  it("EX-4: a missing value, a combination with --builtins or --custom, and an extra argument are usage errors", () => {
    const run = world()
    const cases: ReadonlyArray<readonly [string[], RegExp]> = [
      [["rules", "--explain"], /^guard: --explain needs a rule identifier$/],
      [["rules", "--explain="], /^guard: --explain needs a rule identifier$/],
      [["rules", "--explain", "--builtins"], /^guard: --explain needs a rule identifier$/],
      [["rules", "--explain", "rm", "--builtins"], /^guard: --explain cannot be combined with --builtins or --custom$/],
      [["rules", "--custom", "--explain", "rm"], /^guard: --explain cannot be combined with --builtins or --custom$/],
      [["rules", "--explain", "rm", "extra"], /^guard: unexpected argument extra$/],
      [["show", "--explain", "rm"], /^guard: unknown option --explain$/],
    ]
    for (const [args, message] of cases) {
      const r = run(undefined, ...args)
      assert.equal(r.code, 2, args.join(" "))
      assert.equal(r.out.length, 0, args.join(" "))
      assert.match(r.err[0]!, message, args.join(" "))
    }
  })

  it("EX-5: in a terminal, the block is wrapped within the width and colored unless colors are off", () => {
    const run = world()
    const { code, out } = run({ width: 60, color: false }, "rules", "--explain", "rm")
    assert.equal(code, 0)
    assert.deepEqual(out.slice(0, 3), [" Rule rm   dangerousCommands, own verdict ask", "─".repeat(60), ""])
    for (const heading of ["What it checks", "How it decides", "Typical reason", "Settings"]) assert.ok(out.includes(`  ${heading}`), heading)
    const text = out.filter((line) => /^ {4}\S/.test(line))
    assert.ok(text.length > 0)
    for (const line of text) assert.equal(line.length - line.trimStart().length, 4, line)
    for (const line of out) assert.ok(line.length <= 60 || !line.trim().includes(" "), `too long: ${line.length}`)
    // A long identifier: the title's detail goes below the banner.
    const long = run({ width: 60, color: false }, "rules", "--explain", "interpreter-dangerous-code").out
    assert.deepEqual(long.slice(0, 4), [" Rule interpreter-dangerous-code ", " dangerousCommands, own verdict ask", "─".repeat(60), ""])
    // Colors only add the known escape sequences; the plain text is the same.
    const colored = run({ width: 80, color: true }, "rules", "--explain", "rm").out
    assert.ok(colored.some((line) => line.includes("\x1b[")))
    assert.deepEqual(plain(colored), run({ width: 80, color: false }, "rules", "--explain", "rm").out)
  })

  it("EX-6: the identifier is redacted like every line, in the usage error too", () => {
    const token = `ghp_${"a1B2".repeat(9)}`
    const r = world()(undefined, "rules", "--explain", token)
    assert.equal(r.code, 2)
    const text = r.err.join("\n")
    assert.ok(!text.includes(token))
    assert.match(r.err[0]!, /^guard: no built-in rule named \[\[GUARD_REDACTED:/)
  })

  it("EX-7: settings: the group switch, the override values, and the always-active exceptions", () => {
    const run = world()
    const settings = (rule: string) => run(undefined, "rules", "--explain", rule).out.at(-1)!
    assert.match(settings("placeholder"), /^ {2}Settings: Always active and refuse-only: .*accepts only "deny".*no setting can make it ask\.$/)
    assert.match(settings("guard-cli"), /^ {2}Settings: Always active: .*accepts only "deny".*localAsks does not reach it\./)
    assert.match(settings("self-protection"), /^ {2}Settings: Always active: .*"deny" \(and "model" only with selfProtectionByModel\).*localAsks: "model" reaches it only with selfProtectionByModel\. A write to the plugin's settings \(a guard\.json/)
    assert.match(settings("nested-opencode"), /^ {2}Settings: Always active: .*A recognized launch of another OpenCode with its configuration or plugins changed/)
    assert.match(settings("opencode-service"), /^ {2}Settings: Always active: .*A change to the service's environment or settings is never left to the decision model; stopping, restarting or uninstalling it can be\./)
    assert.match(settings("secret-file-read"), /^ {2}Settings: Part of the sensitiveFiles group: "sensitiveFiles": false turns it off\. .*localAsks: "model" when the rule has no setting\./)
    assert.match(settings("rm"), /^ {2}Settings: Part of the dangerousCommands group: "dangerousCommands": false turns it off\. /)
  })
})
