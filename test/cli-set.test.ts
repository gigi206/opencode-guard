// `guard set|unset <setting>`: policy settings written in the global guard.json, at the top level or in an agent's or a
// project's section, refused when the plugin would not apply them there. Throwaway directories only.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { main } from "../src/cli/main.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>

function world(options: Json = {}, system?: Json) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-set-")))
  const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "app")]
  for (const dir of [globalDir, systemDir, home, data, join(project, ".git")]) mkdirSync(dir, { recursive: true })
  writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options }] }))
  if (system) writeFileSync(join(systemDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: system }] }))
  const env = { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }
  const guardFile = join(globalDir, "guard.json")
  const run = (args: string[]) => {
    const out: string[] = []
    const err: string[] = []
    const code = main(args, { env, cwd: project, systemDir, out: (line) => out.push(line), err: (line) => err.push(line) }) as number
    return { code, out: out.join("\n"), err: err.join("\n") }
  }
  return { run, guardFile, project, guard: () => JSON.parse(readFileSync(guardFile, "utf8")) as Json }
}

describe("guard set|unset", () => {
  it("SET-1: a hardening at the top level and in an agent's section; booleans written as booleans; unset removes it and prunes", () => {
    const w = world()
    assert.equal(w.run(["set", "decisionModel", "on"]).code, 0)
    assert.equal(w.run(["set", "scripts", "true", "--agent", "plan"]).code, 0)
    assert.deepEqual(w.guard(), { decisionModel: true, agents: { plan: { scripts: true } } })
    assert.match(w.run(["set", "decisionModel", "true"]).out, /already true .*nothing changed/)
    assert.equal(w.run(["unset", "scripts", "--agent", "plan"]).code, 0)
    assert.deepEqual(w.guard(), { decisionModel: true })
    assert.match(w.run(["unset", "scripts", "--agent", "plan"]).out, /not set .*nothing changed/)
  })
  it("SET-2: a relaxation in the global guard.json is written (a global source); the system configuration keeps the last word, and the command says so", () => {
    const w = world()
    assert.equal(w.run(["set", "dangerousCommands", "off"]).code, 0)
    assert.deepEqual(w.guard(), { dangerousCommands: false })
    const enforced = world({}, { dangerousCommands: true })
    const r = enforced.run(["set", "dangerousCommands", "off"])
    assert.equal(r.code, 0, r.err)
    assert.match(r.out, /dangerousCommands is still true there, set by system configuration/)
    assert.match(enforced.run(["unset", "dangerousCommands"]).out, /dangerousCommands is now true there, set by system configuration/)
  })
  it("SET-3: a project section (the git repository of the current directory)", () => {
    const w = world()
    assert.equal(w.run(["trust"]).code, 0)
    const r = w.run(["set", "localAsks", "model", "--project"])
    assert.equal(r.code, 0, r.err)
    assert.deepEqual((w.guard().projects as Json)[w.project], { localAsks: "model" })
  })
  it("SET-4: usage errors: unknown setting, ruleOverrides (guard rules), missing or invalid value", () => {
    const w = world()
    assert.match(w.run(["set", "frob", "1"]).err, /unknown setting frob \(one of profile, localAsks/)
    assert.match(w.run(["set", "ruleOverrides", "x"]).err, /guard rules off\|ask\|deny\|model\|reset/)
    assert.equal(w.run(["set", "profile"]).code, 2)
    const invalid = w.run(["set", "profile", "lax"])
    assert.equal(invalid.code, 1)
    assert.match(invalid.err, /invalid value for profile: standard or credentials-only expected/)
  })
})
