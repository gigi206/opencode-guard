// `guard help` (plain outside a terminal, colored layout in one) and `guard rules <setting> <rule>`, aligned on
// `guard redaction off|on`. Fake settings in throwaway directories; nothing is run.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { main, USAGE } from "../src/cli/main.ts"
import { ESCAPES, terminalOf } from "../src/cli/style.ts"
import { toolFinding } from "../src/rules/tools.ts"
import { createRedactor } from "../src/secrets/redact.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>

function world(global: Json = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-hl-")))
  const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "app")]
  for (const dir of [globalDir, systemDir, home, data, project]) mkdirSync(dir, { recursive: true })
  writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: global }] }))
  const env = { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }
  const run = (args: string[], terminal?: { width: number; color: boolean }) => {
    const out: string[] = []
    const err: string[] = []
    const code = main(args, { env, cwd: project, systemDir, out: (line) => out.push(line), err: (line) => err.push(line), ...(terminal ? { terminal } : {}) })
    return { code, out, err }
  }
  const guardFile = join(globalDir, "guard.json")
  return { run, guardFile, guard: () => JSON.parse(readFileSync(guardFile, "utf8")) as Json }
}

const strip = (text: string) => ESCAPES.reduce((acc, escape) => acc.split(escape).join(""), text)

describe("guard help and guard rules <setting> <rule>", () => {
  it("HL-1: help is the plain text outside a terminal, the same words in color in one, and plain after a usage error", () => {
    const w = world()
    assert.equal(w.run(["help"]).out.join("\n"), USAGE)
    const plain = w.run(["help"], { width: 100, color: false }).out.join("\n")
    const colored = w.run(["help"], { width: 100, color: true }).out.join("\n")
    assert.ok(!ESCAPES.some((escape) => plain.includes(escape)))
    assert.ok(ESCAPES.some((escape) => colored.includes(escape)))
    assert.equal(strip(colored), plain)
    for (const word of ["rules off|ask|deny|model", "rules on", "redaction off|on", "--project", "untrust", "Also accepted"]) assert.ok(plain.includes(word), word)
    for (const line of w.run(["help"], { width: 60, color: false }).out) assert.ok(line.length <= 60, line)
    const error = w.run(["rules", "off"], { width: 100, color: true })
    assert.equal(error.code, 2)
    assert.ok(!ESCAPES.some((escape) => error.err.join("\n").includes(escape)))
    assert.equal(terminalOf({ NO_COLOR: "1" }, true, 100)?.color, false)
  })

  it("HL-2: rules off|ask|deny|model|on write like the top-level commands; allow and off are the same", () => {
    const w = world()
    assert.equal(w.run(["rules", "off", "eval"]).code, 0)
    assert.deepEqual(w.guard(), { ruleOverrides: { eval: "off" } })
    assert.match(w.run(["rules", "off", "eval"]).out.join("\n"), /already "off".*nothing changed/)
    assert.match(w.run(["allow", "eval"]).out.join("\n"), /already "off".*nothing changed/)
    assert.equal(w.run(["rules", "ask", "eval", "--agent", "build"]).code, 0)
    assert.deepEqual(w.guard(), { ruleOverrides: { eval: "off" }, agents: { build: { ruleOverrides: { eval: "ask" } } } })
    assert.equal(w.run(["rules", "on", "eval"]).code, 0)
    assert.equal(w.run(["rules", "on", "eval", "--agent", "build"]).code, 0)
    assert.deepEqual(w.guard(), {})
    writeFileSync(w.guardFile, JSON.stringify({ ruleOverrides: { eval: "allow" } }))
    assert.match(w.run(["rules", "off", "eval"]).out.join("\n"), /already "allow".*nothing changed/)
    assert.equal(w.run(["rules", "off", "eval", "--builtins"]).code, 2)
    assert.equal(w.run(["rules", "off"]).code, 2)
  })

  it("HL-3: back on, a rule whose group is off there still does not apply, and the command says why", () => {
    const w = world({ dangerousCommands: false })
    w.run(["rules", "deny", "git-clean"])
    const on = w.run(["rules", "on", "git-clean"])
    assert.equal(on.code, 0)
    assert.match(on.out.join("\n"), /git-clean still does not apply there: its group dangerousCommands is off, set by global configuration/)
    const fine = world()
    fine.run(["rules", "deny", "git-clean"])
    assert.ok(!fine.run(["rules", "on", "git-clean"]).out.join("\n").includes("still does not apply"))
  })

  it("HL-4: the agent running guard rules <setting> is always asked, never left to the model", () => {
    const active = { dangerousCommands: true, sensitiveFiles: true, localAsksByModel: true, selfProtectionByModel: true }
    const ctx = { redactor: createRedactor(), home: "/home/test", cwd: "/home/test/app", active }
    for (const command of ["guard rules on git-clean", "guard rules off eval", "guard help"]) {
      const finding = toolFinding("shell", { command }, ctx)
      assert.equal(`${finding?.verdict}/${finding?.rule}`, "ask/guard-cli", command)
      assert.equal(finding?.modelDecides, undefined, command)
    }
  })
})

describe("bin/guard and a reader that goes away", () => {
  it("HL-5: guard rules | head stops quietly, without an EPIPE error", async () => {
    const { spawnSync } = await import("node:child_process")
    const guard = join(PLUGIN_DIR, "bin", "guard")
    const r = spawnSync("sh", ["-c", `"${process.execPath}" "${guard}" rules | head -1; "${process.execPath}" "${guard}" help | head -1`], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } })
    assert.equal(r.stderr, "")
    assert.deepEqual(r.stdout.trim().split("\n"), ["Built-in rules:", "Usage: guard <command> [arguments]"])
  })
})
