// `guard rules` in a terminal: grouped, aligned and wrapped, colored unless the launcher says otherwise; every field is
// redacted before it is wrapped, and colors are the only escape sequences printed. The terminal is injected (`terminal`),
// as the launcher does; without it, the output is the former one, one line per rule.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { main } from "../src/cli/main.ts"
import { ruleLines } from "../src/cli/rules.ts"
import { ESCAPES, terminalOf } from "../src/cli/style.ts"
import { RULE_FEATURES } from "../src/rules/features.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>

/** A global configuration that declares the plugin with these options (none: not declared), and the command on it. */
function world(global?: Json) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-pretty-")))
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
/** Column of the descriptions: 4 spaces, the longest identifier, 2 spaces, the verdict (4), 2 spaces. */
const COLUMN = 4 + Math.max(...[...RULE_FEATURES.keys()].map((rule) => rule.length)) + 2 + 4 + 2

describe("guard rules in a terminal", () => {
  it("PR-1: without a terminal, the output is the former one", () => {
    const run = world({ rules: [{ id: "no-prod", pattern: "--env=prod", verdict: "deny" }] })
    assert.deepEqual(run(undefined, "rules", "--builtins").out, ruleLines())
    const all = run(undefined, "rules").out
    assert.equal(all[0], "Built-in rules:")
    assert.ok(all.every((line) => !line.includes("\x1b")))
  })

  it("PR-2: grouped by the option that turns them off, aligned, wrapped within the width, without escape sequences when colors are off", () => {
    const { code, out } = world()({ width: 80, color: false }, "rules", "--builtins")
    assert.equal(code, 0)
    assert.ok(out.every((line) => !line.includes("\x1b")))
    assert.equal(out[0], ` Built-in rules   ${RULE_FEATURES.size} rules`)
    assert.equal(out[1], "─".repeat(80))
    const groups = out.flatMap((line, index) => (/^ {2}\S/.test(line) ? [index] : []))
    assert.deepEqual(groups.map((index) => out[index]!.trim().split("  ")[0]), ["always active", "sensitiveFiles", "dangerousCommands"])
    for (const index of groups) assert.equal(out[index - 1], "", "a blank line before each group")
    // Every rule once, in the registry's order, on a line of its own.
    const rows = out.filter((line) => /^ {4}\S/.test(line)).map((line) => line.trim().split(/\s+/)[0])
    assert.deepEqual(rows, [...RULE_FEATURES.keys()])
    // Continuation lines start at the description column.
    const continued = out.filter((line) => /^ {5,}\S/.test(line))
    assert.ok(continued.length > 0)
    for (const line of continued) assert.equal(line.length - line.trimStart().length, COLUMN, line)
    for (const line of out) assert.ok(line.length <= 80 || !line.trim().includes(" "), `too long: ${line.length}`)
  })

  it("PR-3: colors only add the known escape sequences; refusals in red", () => {
    const run = world()
    const colored = run({ width: 80, color: true }, "rules", "--builtins").out
    assert.ok(colored.some((line) => line.includes("\x1b[")))
    assert.deepEqual(plain(colored), run({ width: 80, color: false }, "rules", "--builtins").out)
    assert.ok(colored.find((line) => line.includes("rm-critical"))!.includes("\x1b[1;31mdeny"))
    // Each block its own banner and separator color, both sections printed with two blank lines between them.
    const both = run({ width: 80, color: true }, "rules").out
    const banners = both.filter((line) => line.includes(" Built-in rules ") || line.includes(" Your rules "))
    assert.deepEqual(banners.map((line) => line.slice(0, line.indexOf(" "))), ["\x1b[1;97;44m", "\x1b[1;97;45m"])
    assert.ok(both.includes(`\x1b[34m${"─".repeat(80)}\x1b[39m`))
    assert.ok(both.includes(`\x1b[35m${"─".repeat(80)}\x1b[39m`))
    const custom = plain(both).indexOf(" Your rules   rules option")
    assert.deepEqual(plain(both).slice(custom - 2, custom), ["", ""])
    assert.ok(plain(colored).every((line) => !line.includes("\x1b")))
  })

  it("PR-4: the user's rules: aligned, reason wrapped, the pattern alone on the next line, rules set aside and the note", () => {
    const run = world({
      rules: [
        { id: "no-prod", pattern: "--env=prod", verdict: "deny", reason: "production deployments are forbidden on this machine, whatever the branch or the tag" },
        { id: "eval", pattern: "eval-again", verdict: "ask" },
        { id: "bad", pattern: "(", verdict: "ask" },
      ],
    })
    const { code, out } = run({ width: 60, color: false }, "rules", "--custom")
    assert.equal(code, 0)
    // The title's detail does not fit next to the banner: it goes below it, then the separator line.
    assert.deepEqual(out.slice(0, 3), [" Your rules ", " 2 rules, from the rules option of the global configuration", "─".repeat(60)])
    const row = out.findIndex((line) => line.startsWith("    no-prod"))
    assert.match(out[row]!, /^ {4}no-prod {2}deny {2}shell {2}production /)
    const column = out[row]!.indexOf("production")
    assert.equal(out[row + 1]!.length - out[row + 1]!.trimStart().length, column, "reason continued at its column")
    assert.ok(out.some((line) => line === `${" ".repeat(column)}/--env=prod/`))
    const again = out.indexOf(`${" ".repeat(column)}/eval-again/`)
    assert.equal(out[again + 1], `${" ".repeat(column)}same identifier as a built-in rule`)
    assert.ok(out.includes("  Set aside"))
    assert.ok(out.some((line) => /^ {4}rules\[2\]: invalid regex/.test(line)))
    assert.ok(out.some((line) => line.startsWith("  Not shown: a project's opencode.json")))
    for (const line of out) assert.ok(line.length <= 60 || !line.trim().includes(" "), `too long: ${line}`)
    // Not declared: said in words.
    const none = world()({ width: 60, color: true }, "rules", "--custom").out
    assert.equal(plain(none)[0], " Your rules   rules option")
    assert.ok(plain(none).join(" ").includes("none read, the plugin is not declared"))
  })

  it("PR-5: a secret in a pattern or a passphrase in a reason is redacted before wrapping, in color too", () => {
    const token = `ghp_${"a1B2".repeat(9)}`
    const words = ["velvet", "orbit", "lantern", "seven"]
    const run = world({ rules: [{ id: "leak", pattern: token, verdict: "deny", reason: `DB_PASSWORD="${words.join(" ")}"` }] })
    for (const color of [false, true]) {
      const text = run({ width: 60, color }, "rules").out.join("\n")
      assert.ok(!text.includes(token))
      for (const word of words) assert.ok(!text.includes(word), word)
      assert.match(plain([text])[0]!, /\[\[GUARD_REDACTED:/)
    }
  })

  it("PR-6: an escape sequence written in the user's rule never reaches the terminal", () => {
    const run = world({ rules: [{ id: "esc", pattern: "x\u001b]52;c;Zm9v\u0007", verdict: "ask", reason: "\u001b[2J\u001b[31mred\u001b[0m reason" }] })
    for (const color of [false, true]) {
      const out = plain(run({ width: 80, color }, "rules").out)
      assert.ok(out.every((line) => !/[\x00-\x08\x0b-\x1f\x7f-\x9f]/.test(line)), `color ${color}`)
      assert.ok(out.some((line) => line.includes("red") && line.includes("reason")))
    }
  })

  it("PR-7: the launcher's decision: a terminal only on a TTY, colors unless NO_COLOR or TERM=dumb, width kept from 60 to 120", () => {
    assert.equal(terminalOf({}, false, 100), undefined)
    assert.equal(terminalOf({}, undefined, 100), undefined)
    assert.deepEqual(terminalOf({}, true, 100), { width: 100, color: true })
    assert.deepEqual(terminalOf({ NO_COLOR: "1" }, true, 100), { width: 100, color: false })
    assert.deepEqual(terminalOf({ NO_COLOR: "" }, true, 100), { width: 100, color: true })
    assert.deepEqual(terminalOf({ TERM: "dumb" }, true, 100), { width: 100, color: false })
    assert.equal(terminalOf({}, true, undefined)!.width, 100)
    assert.equal(terminalOf({}, true, 20)!.width, 60)
    assert.equal(terminalOf({}, true, 500)!.width, 120)
    assert.equal(terminalOf({}, true, 0)!.width, 100)
  })
})
