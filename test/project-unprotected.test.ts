// `unprotectedAgent` and an agent's relaxations reach the plugin only from the global sources: what a project's plugin
// options ask for is ignored and reported, through the real hooks. Nothing is run: commands are only judged.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { describe, it } from "node:test"
import { fileURLToPath } from "node:url"
import { main } from "../src/cli/main.ts"
import { testCall } from "../src/cli/test.ts"
import { SETTING_ENTRIES } from "../src/cli/settings.ts"
import { parseConfig, type PluginDeclaration } from "../src/config.ts"
import { setupGuard } from "../src/index.ts"
import { fakeContext } from "./fake-ctx.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
const AGENT = "build-unprotected"
type Json = Record<string, unknown>
const inputs = (files: readonly Json[] = []) => ({ files: files as never, project: "/w/app", realPath: (path: string) => path, regularFile: () => true })
const declaring = (options: Json) => (): readonly PluginDeclaration[] => [{ label: "global", options }, { label: "system", reason: "it is missing or unreadable" }]

async function plugin(global: Json, project: Json) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-pu-")))
  const [globalDir, systemDir] = [join(root, "global"), join(root, "system")]
  for (const dir of [globalDir, systemDir]) mkdirSync(dir)
  writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: global }] }))
  const fake = fakeContext(project)
  await setupGuard(fake.ctx, {}, systemDir, globalDir)
  fake.switchAgent("ses_1", AGENT)
  await fake.trigger("session.prompt", { sessionID: "ses_1", messageID: "msg_1", prompt: { text: "go" } })
  const rejected = await fake.trigger("tool.execute.before", { sessionID: "ses_1", agent: AGENT, messageID: "msg_1", id: "call_1", tool: "shell", input: { command: "sudo rm -rf /" } }).then(
    () => false,
    () => true,
  )
  return { fake, checked: rejected || fake.asserts.length > 0 }
}

describe("a project cannot unprotect an agent", () => {
  it("PU-1: the value from a project's options alone is ignored, with a warning, through the real hooks", async () => {
    const parsed = parseConfig({ unprotectedAgent: AGENT }, {}, declaring({}), inputs())
    assert.equal(parsed.config.unprotectedAgent, undefined)
    assert.match(parsed.warnings.join("\n"), /unprotectedAgent ignored: a relaxation counts only if the global or system configuration sets it too/)
    assert.equal((await plugin({}, { unprotectedAgent: AGENT })).checked, true)
  })
  it("PU-2: another value than the declared one is ignored too", () => {
    const parsed = parseConfig({ unprotectedAgent: "other" }, {}, declaring({ unprotectedAgent: AGENT }), inputs())
    assert.equal(parsed.config.unprotectedAgent, undefined)
    assert.match(parsed.warnings.join("\n"), /unprotectedAgent ignored/)
  })
  it("PU-3: the warning stays when a guard.json file or a section resolves the settings", () => {
    const file = { label: "project guard.json (/w/app/.opencode/guard.json)", global: false, dir: "/w/app", data: {} }
    assert.match(parseConfig({ unprotectedAgent: AGENT }, {}, declaring({}), inputs([file])).warnings.join("\n"), /unprotectedAgent ignored/)
    assert.match(parseConfig({ unprotectedAgent: AGENT, agents: { x: {} } }, {}, declaring({}), inputs()).warnings.join("\n"), /unprotectedAgent ignored/)
  })
  it("PU-4: a trusted project does not unprotect it either", () => {
    const parsed = parseConfig({ unprotectedAgent: AGENT }, {}, declaring({ trustedProjects: "*" }), inputs())
    assert.equal(parsed.config.unprotectedAgent, undefined)
  })
  it("PU-5: unreadable global configuration: ignored, never applied", () => {
    assert.equal(parseConfig({ unprotectedAgent: AGENT }).config.unprotectedAgent, undefined)
    const failing = () => {
      throw new Error("unreadable")
    }
    assert.equal(parseConfig({ unprotectedAgent: AGENT }, {}, failing, inputs()).config.unprotectedAgent, undefined)
  })
  it("witness: PU-6: the global or system declaration keeps it, without a warning, through the real hooks", async () => {
    for (const declared of [declaring({ unprotectedAgent: AGENT }), () => [{ label: "global", reason: "x" }, { label: "system", options: { unprotectedAgent: AGENT } }]]) {
      const parsed = parseConfig({ unprotectedAgent: AGENT }, {}, declared, inputs())
      assert.equal(parsed.config.unprotectedAgent, AGENT)
      assert.deepEqual(parsed.warnings, [])
    }
    const { fake, checked } = await plugin({ unprotectedAgent: AGENT }, { unprotectedAgent: AGENT })
    assert.equal(checked, false)
    assert.equal(fake.agents.get(AGENT)?.mode, "primary")
  })
  it("witness: PU-7: guard test reads the global declaration", async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-pu-")))
    const [globalDir, systemDir, project] = [join(root, "g"), join(root, "s"), join(root, "w")]
    for (const dir of [globalDir, systemDir, project]) mkdirSync(dir)
    writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: { unprotectedAgent: AGENT } }] }))
    const io = { env: { HOME: root, OPENCODE_CONFIG_DIR: globalDir }, cwd: project, systemDir, out: () => {}, err: () => {} }
    assert.equal((await testCall(io as never, { tool: "shell", input: { command: "rm -rf build" }, agent: AGENT, model: false })).verdict, "unchecked")
  })
})

describe("the command line, with the global declaration", () => {
  it("PU-15: guard settings says where the option counts", () =>
    assert.equal(SETTING_ENTRIES.find((entry) => entry.name === "unprotectedAgent")?.where, "plugin options of the global or system configuration"))
  it("witness: PU-11: guard settings, guard show and guard status keep what the global configuration declares", async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-pu-")))
    const [globalDir, systemDir, project] = [join(root, "g"), join(root, "s"), join(root, "w")]
    for (const dir of [globalDir, systemDir, project]) mkdirSync(dir)
    const options = { unprotectedAgent: AGENT, agents: { sandbox: { guard: "off" } } }
    writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options }] }))
    const run = async (args: string[]) => {
      const lines: string[] = []
      const io = { env: { HOME: root, OPENCODE_CONFIG_DIR: globalDir }, cwd: project, systemDir, out: (line: string) => lines.push(line), err: (line: string) => lines.push(line) }
      assert.equal(await main(args, io), 0, args.join(" "))
      return lines.join("\n")
    }
    assert.match(await run(["settings"]), new RegExp(`unprotectedAgent\\s.*${AGENT}`))
    const show = await run(["show"])
    assert.match(show, /agents\.sandbox\.guard\s+off/)
    assert.doesNotMatch(show, /ignored/)
    assert.doesNotMatch(await run(["status"]), /ignored/)
  })
})

describe("an agent's relaxations in a project's options", () => {
  it("PU-8: guard off and a redaction switch are reported as ignored, and relax nothing", () => {
    const parsed = parseConfig({ agents: { sandbox: { guard: "off", redactWire: false } } }, {}, declaring({}), inputs())
    assert.equal(parsed.config.version?.relaxations?.size ?? 0, 0)
    assert.match(parsed.warnings.join("\n"), /agents\.sandbox: guard ignored: only the global configuration relaxes an agent/)
    assert.match(parsed.warnings.join("\n"), /agents\.sandbox: redactWire ignored: only the global configuration relaxes an agent/)
  })
  it("witness: PU-9: the same section in the global configuration relaxes, without that warning", () => {
    const options = { agents: { sandbox: { guard: "off" } } }
    const parsed = parseConfig(options, {}, declaring(options), inputs())
    assert.equal(parsed.config.version?.relaxations?.get("sandbox")?.guardOff, true)
    assert.deepEqual(parsed.warnings.filter((line) => /ignored/.test(line)), [])
  })
  it("witness: PU-12: a relaxation in force from the global guard.json is not reported as ignored", () => {
    const options = { agents: { sandbox: { guard: "off" } } }
    const file = { label: "global guard.json", global: true, dir: "/g", data: options }
    const parsed = parseConfig(options, {}, declaring({}), inputs([file]))
    assert.equal(parsed.config.version?.relaxations?.get("sandbox")?.guardOff, true)
    assert.deepEqual(parsed.warnings.filter((line) => /ignored/.test(line)), [])
  })
  it("witness: PU-13: nor one in force from a `projects` section of the global guard.json", () => {
    const options = { agents: { sandbox: { redactPrompt: false } } }
    const file = { label: "global guard.json", global: true, dir: "/g", data: { projects: { "/w/app": options } } }
    const parsed = parseConfig(options, {}, declaring({}), inputs([file]))
    assert.ok(parsed.config.version?.relaxations?.get("sandbox")?.off.has("redactPrompt"))
    assert.deepEqual(parsed.warnings.filter((line) => /ignored/.test(line)), [])
  })
  it("PU-14: the same key with another project's section is still reported", () => {
    const options = { agents: { sandbox: { redactPrompt: false } } }
    const file = { label: "global guard.json", global: true, dir: "/g", data: { projects: { "/w/other": options } } }
    const parsed = parseConfig(options, {}, declaring({}), inputs([file]))
    assert.equal(parsed.config.version?.relaxations?.size ?? 0, 0)
    assert.match(parsed.warnings.join("\n"), /agents\.sandbox: redactPrompt ignored/)
  })
  it("witness: PU-10: taking a relaxation back is not reported", () => {
    const parsed = parseConfig({ agents: { sandbox: { guard: "on", redactWire: true } } }, {}, declaring({}), inputs())
    assert.deepEqual(parsed.warnings.filter((line) => /ignored/.test(line)), [])
  })
})
