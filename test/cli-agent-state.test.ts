// What `guard agent …` says of an agent: "fully protected" only when nothing relaxes it any more, otherwise the names of
// what does; values refused for `models`. Fake settings in throwaway directories; the command runs in process.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { after, describe, it } from "node:test"
import { fileURLToPath } from "node:url"
import { main } from "../src/cli/main.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
const base = realpathSync(mkdtempSync(join(tmpdir(), "guard-state-")))
after(() => rmSync(base, { recursive: true, force: true }))

function world(guard: Record<string, unknown>, options: Record<string, unknown> = {}) {
  const root = mkdtempSync(join(base, "w-"))
  const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "app")]
  for (const dir of [globalDir, systemDir, home, data, project]) mkdirSync(dir, { recursive: true })
  writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options }] }))
  const file = join(globalDir, "guard.json")
  writeFileSync(file, JSON.stringify(typeof guard.projects === "function" ? { ...guard, projects: guard.projects(project) } : guard))
  const run = (...args: string[]) => {
    const [out, err]: string[][] = [[], []]
    const code = main(args, { env: { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }, cwd: project, systemDir, out: (line) => out!.push(line), err: (line) => err!.push(line) }) as number
    return { code, out: out!.join("\n"), err: err!.join("\n") }
  }
  return { run, read: () => readFileSync(file, "utf8"), project }
}

const after_on = (guard: Record<string, unknown>, options?: Record<string, unknown>) => world(guard, options).run("agent", "on", "n3").out

describe("guard agent: the state it reports", () => {
  it("AS-1: a policy setting of the section that relaxes: named, without its value", () => {
    assert.match(after_on({ agents: { n3: { dangerousCommands: false } } }), /^agent n3: still relaxed: dangerousCommands, in /)
  })
  it("AS-2: a rule set off in the section", () => {
    assert.match(after_on({ agents: { n3: { ruleOverrides: { rm: "off" } } } }), /^agent n3: still relaxed: ruleOverrides\.rm, in /)
  })
  it("AS-3: a rule left to the model in the section", () => {
    assert.match(after_on({ agents: { n3: { ruleOverrides: { rm: "model" } } } }), /still relaxed: ruleOverrides\.rm/)
  })
  it("AS-4: a setting of the level above relaxes the agent too", () => {
    assert.match(after_on({ sensitiveFiles: false }), /still relaxed: sensitiveFiles/)
  })
  it("AS-5: an exception, by its rule and without its path", () => {
    const file = join(base, "some.env")
    writeFileSync(file, "")
    assert.match(after_on({ exceptions: { "secret-file-read": [file] } }), /still relaxed: exceptions\.secret-file-read, in /)
  })
  it("AS-6: the section of the agent inside a project's", () => {
    const projects = (dir: string) => ({ [dir]: { agents: { n3: { dangerousCommands: false } } } })
    assert.match(after_on({ projects }), /still relaxed: dangerousCommands/)
  })
  it("AS-6b: a project's section written with a path through a link", () => {
    const link = join(mkdtempSync(join(base, "link-")), "app")
    const projects = (dir: string) => {
      symlinkSync(dir, link)
      return { [link]: { agents: { n3: { dangerousCommands: false } } } }
    }
    assert.match(after_on({ projects }), /still relaxed: dangerousCommands/)
  })
  it("AS-7: redaction turned off globally", () => {
    assert.match(after_on({}, { redactOutputs: false }), /still relaxed: redactOutputs/)
  })
  it("AS-8: a redaction format turned off", () => {
    assert.match(after_on({ redactionOff: ["openai_key"] }), /still relaxed: redactionOff\.openai_key/)
  })
  it("AS-9: the agent is the unprotected agent", () => {
    assert.match(after_on({}, { unprotectedAgent: "n3" }), /still relaxed: unprotectedAgent/)
  })
  it("AS-10: what the section still relaxes comes first, then the rest", () => {
    const { run } = world({ agents: { n3: { dangerousCommands: false } } })
    assert.match(run("agent", "set", "n3", "redactWire", "false").out, /^agent n3: redactWire off on any model; still relaxed: dangerousCommands, in /)
  })
  it("AS-11: every verb reports it, not only on", () => {
    const { run } = world({ agents: { n3: { dangerousCommands: false, redactWire: false } } })
    assert.match(run("agent", "unset", "n3", "redactWire").out, /^agent n3: still relaxed: dangerousCommands, in /)
  })
  it("witness: AS-12: nothing in the section: fully protected", () => {
    assert.match(after_on({ agents: { n3: { guard: "off" } } }), /^agent n3: fully protected, in /)
  })
  it("witness: AS-13: a setting of the section that only hardens: fully protected", () => {
    assert.match(after_on({ agents: { n3: { dangerousCommands: true, ruleOverrides: { rm: "deny" } } } }), /^agent n3: fully protected, in /)
  })
  it("witness: AS-14: a section that hardens what the level above relaxes: fully protected", () => {
    assert.match(after_on({ dangerousCommands: false, agents: { n3: { dangerousCommands: true } } }), /^agent n3: fully protected, in /)
  })
  it("witness: AS-15: another agent's section changes nothing", () => {
    assert.match(after_on({ agents: { other: { dangerousCommands: false } } }), /^agent n3: fully protected, in /)
  })
  it("witness: AS-16: on leaves the policy settings in the file", () => {
    const { run, read } = world({ agents: { n3: { dangerousCommands: false, guard: "off" } } })
    run("agent", "on", "n3")
    assert.deepEqual(JSON.parse(read()).agents.n3, { dangerousCommands: false })
  })
  it("witness: AS-17: off keeps the models of the section", () => {
    const { run, read } = world({ agents: { n3: { models: ["linagora/qwen3.8"] } } })
    run("agent", "off", "n3")
    assert.deepEqual(JSON.parse(read()).agents.n3, { guard: "off", models: ["linagora/qwen3.8"] })
  })
})

describe("guard agent models: values refused", () => {
  for (const values of [["--foo/bar"], ["-h"], ["linagora/qwen3.8", "--foo/bar"]]) {
    it(`AS-18: ${values.join(" ")}: a usage error`, () => {
      assert.equal(world({}).run("agent", "models", "n3", ...values).code, 2)
    })
    // Without a slash, the plugin's own check on `models` already refuses it.
    it(`${values[0] === "-h" ? "witness: " : ""}AS-19: ${values.join(" ")}: nothing written`, () => {
      const { run, read } = world({ agents: { n3: { guard: "off" } } })
      const before = read()
      run("agent", "models", "n3", ...values)
      assert.equal(read(), before)
    })
  }
  it("witness: AS-20: a provider/model is written", () => {
    const { run, read } = world({})
    run("agent", "models", "n3", "linagora/qwen3.8")
    assert.deepEqual(JSON.parse(read()).agents.n3, { models: ["linagora/qwen3.8"] })
  })
})
