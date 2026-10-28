// `guard show` and `guard last` in a terminal: a banner per block, headings, aligned rows, text wrapped to the width,
// colors unless the launcher says otherwise; each field redacted before it is wrapped. Without a terminal, the output is
// the former one. The terminal is injected (`terminal`), as the launcher does.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { main } from "../src/cli/main.ts"
import { ESCAPES } from "../src/cli/style.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>

/** Test directories: a global configuration declaring the plugin, an optional global guard.json and plugin log. */
function world(setup: { readonly global?: Json; readonly guard?: Json; readonly log?: readonly string[] } = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-showlast-")))
  const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "app")]
  for (const dir of [globalDir, systemDir, home, join(data, "opencode", "log"), join(project, ".git")]) mkdirSync(dir, { recursive: true })
  writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: setup.global ?? {} }] }))
  if (setup.guard) writeFileSync(join(globalDir, "guard.json"), JSON.stringify(setup.guard))
  if (setup.log) writeFileSync(join(data, "opencode", "log", "guard.log"), `${setup.log.join("\n")}\n`)
  const env = { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }
  return (terminal: { width: number; color: boolean } | undefined, ...args: string[]) => {
    const out: string[] = []
    const err: string[] = []
    const code = main(args, { env, cwd: project, systemDir, out: (line: string) => out.push(line), err: (line: string) => err.push(line), ...(terminal ? { terminal } : {}) })
    return { code, out, err }
  }
}

const plain = (lines: readonly string[]) => lines.map((line) => ESCAPES.reduce((text, escape) => text.replaceAll(escape, ""), line))
const fits = (lines: readonly string[], width: number) => lines.every((line) => line.length <= width || !line.trim().includes(" "))
const TOKEN = `ghp_${"a1B2".repeat(9)}`
const LOG = [
  "2026-10-27T09:15:02.120Z INFO shell → ask (local, rule git-reset-hard): git reset --hard (uncommitted changes lost)",
  "2026-10-27T09:15:04.001Z DEBUG read → allow (read-only): read-only tool, no local rule matched",
  "2026-10-28T22:52:43.369Z INFO shell → deny (local, rule rm-critical): recursive deletion of the home directory, which would erase every file of the user without any way back",
  "2026-10-28T22:53:30.000Z INFO shell → ask (model): nox-4b: risk 1.80/3, highest: data destruction 0.81",
  `2026-10-28T22:53:10.000Z INFO webfetch → deny (local, rule secret-network): a secret in a web request (${TOKEN}) \u001b[2Jcleared`,
]

describe("guard show and guard last in a terminal", () => {
  it("PS-1: show: a banner, then the sources read, the project's trust, the settings in force and those set aside", () => {
    const run = world({ global: { localAsks: "model" }, guard: { ruleOverrides: { eval: "deny" }, frobnicate: true } })
    const flat = run(undefined, "show").out
    assert.match(flat[0]!, /^Settings for .+, read from:$/)
    const { code, out } = run({ width: 80, color: false }, "show")
    assert.equal(code, 0)
    assert.ok(out.every((line) => !line.includes("\x1b")))
    assert.match(out[0]!, /^ Settings /)
    assert.ok(out.includes("─".repeat(80)))
    for (const heading of ["  Read from", "  This project", "  Settings in force", "  Set aside"]) assert.ok(out.includes(heading), heading)
    assert.ok(out.includes("    not trusted"))
    assert.ok(out.some((line) => /^ {4}ruleOverrides\.eval +deny +/.test(line)))
    assert.ok(out.some((line) => /^ {4}\S.*frobnicate/.test(line)), "the unknown key is set aside")
    assert.ok(fits(out, 80))
  })

  it("PS-2: show in color: the same text once the known codes and the legend are removed; values colored by their effect", () => {
    const run = world({ global: { localAsks: "model" }, guard: { ruleOverrides: { eval: "deny", rm: "model", kill: "off" }, sensitiveFiles: false, trustedProjects: ["*"] } })
    const colored = run({ width: 100, color: true }, "show").out
    const legend = colored.findIndex((line) => plain([line])[0]!.startsWith("    green keeps a protection, yellow relaxes one"))
    assert.ok(legend > 0, "a legend with colors")
    assert.deepEqual(plain(colored.filter((_, index) => index !== legend)), run({ width: 100, color: false }, "show").out)
    assert.ok(colored[0]!.startsWith("\x1b[1;97;42m Settings "))
    assert.ok(colored.includes("    \x1b[32mtrusted\x1b[39m"))
    const value = (key: string) => colored.find((line) => plain([line])[0]!.startsWith(`    ${key} `))!
    assert.match(value("dangerousCommands"), /\x1b\[32mtrue /, "a protective switch on: green")
    assert.match(value("sensitiveFiles"), /\x1b\[33mfalse/, "a protective switch off: yellow")
    assert.match(value("selfProtectionByModel"), /\x1b\[32mfalse/, "self-protection kept with you: green")
    assert.match(value("localAsks"), /\x1b\[33mmodel/, "confirmations left to the model: yellow")
    assert.match(value("ruleOverrides.eval"), /\x1b\[1;31mdeny/)
    assert.match(value("ruleOverrides.rm"), /\x1b\[35mmodel/)
    assert.match(value("ruleOverrides.kill"), /\x1b\[2moff/)
  })

  it("PS-3: show: a value shaped like a secret, written by mistake in a guard.json, is redacted, in color too", () => {
    const run = world({ guard: { localAsks: TOKEN } })
    for (const color of [false, true]) {
      const text = run({ width: 60, color }, "show").out.join("\n")
      assert.ok(!text.includes(TOKEN))
    }
  })

  it("PL-1: last: by day, time, verdict, rule and tool on a line, the reason wrapped below it", () => {
    const run = world({ log: LOG })
    const flat = run(undefined, "last").out
    assert.match(flat[0]!, /^Latest asks and denials \(.+guard\.log\):$/)
    assert.equal(flat.length, 5)
    const { code, out } = run({ width: 70, color: false }, "last")
    assert.equal(code, 0)
    assert.equal(out[0], " Latest asks and denials   4 entries")
    assert.equal(out[1], "─".repeat(70))
    assert.match(out[2]!, /^ {2}from .*guard\.log$|^ {2}from$/)
    const days = out.filter((line) => /^ {2}\d{4}-\d{2}-\d{2}$/.test(line)).map((line) => line.trim())
    assert.deepEqual(days, ["2026-10-27", "2026-10-28"])
    const row = out.findIndex((line) => line.includes("rm-critical"))
    assert.match(out[row]!, /^ {4}22:52:43Z {2}deny {2}rm-critical +shell$/)
    const column = 4 + "22:52:43Z".length + 2
    assert.equal(out[row + 1]!.length - out[row + 1]!.trimStart().length, column)
    assert.ok(out[row + 2]!.startsWith(" ".repeat(column)), "a long reason continues at its column")
    assert.ok(!out.some((line) => line.includes("read-only tool")), "only asks and denials")
    assert.ok(out.some((line) => /^ {4}22:53:30Z {2}ask {3}\(model\) +shell$/.test(line)), "a model verdict names its source")
    assert.ok(fits(out, 70))
  })

  it("PL-2: last: a secret or an escape sequence in a logged reason never reaches the terminal", () => {
    const run = world({ log: LOG })
    for (const color of [false, true]) {
      const out = plain(run({ width: 70, color }, "last").out)
      assert.ok(!out.join("\n").includes(TOKEN))
      assert.ok(out.every((line) => !/[\x00-\x08\x0b-\x1f\x7f-\x9f]/.test(line)), `color ${color}`)
    }
    assert.deepEqual(plain(run({ width: 70, color: true }, "last").out), run({ width: 70, color: false }, "last").out)
  })

  it("PL-3: last: the model's opinion on its own dimmed line, the duration of the model calls on the entry's line, the whole width", () => {
    const run = world({
      log: [
        "2026-10-29T08:00:00.000Z INFO shell → ask (local, rule in-place-edit): in-place file edit: the original content is overwritten — nox-4b opinion: allow (risk 0.95/3, highest: data destruction 0.29) [model 540 ms]",
        "2026-10-29T08:01:00.000Z INFO shell → ask (model): nox-4b: risk 1.80/3, highest: data destruction 0.81 [model 5100 ms, 2 attempts]",
      ],
    })
    const out = run({ width: 160, color: false }, "last").out
    const column = 4 + "08:00:00Z".length + 2
    const row = out.findIndex((line) => line.includes("in-place-edit"))
    assert.match(out[row]!, /^ {4}08:00:00Z {2}ask {3}in-place-edit {2}shell {2}model 540 ms$/)
    assert.equal(out[row + 1], `${" ".repeat(column)}in-place file edit: the original content is overwritten`)
    assert.equal(out[row + 2], `${" ".repeat(column)}nox-4b opinion: allow (risk 0.95/3, highest: data destruction 0.29)`)
    const model = out.findIndex((line) => line.includes("(model)"))
    assert.match(out[model]!, /shell {2}model 5100 ms, 2 attempts$/)
    assert.equal(out[model + 1], `${" ".repeat(column)}nox-4b: risk 1.80/3, highest: data destruction 0.81`)
    const colored = run({ width: 160, color: true }, "last").out
    assert.ok(colored.includes(`${" ".repeat(column)}\x1b[2mnox-4b opinion: allow (risk 0.95/3, highest: data destruction 0.29)\x1b[22m`))
    assert.deepEqual(plain(colored), out)
  })
})
