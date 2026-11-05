// A switch turned off by a project (`redactOutputs`, `dangerousCommands`, a check…) counts only if the global
// configuration declares it for this project: ignored with a warning otherwise, through the real hooks. Nothing is run:
// commands are only judged.
import "./tmp.ts"
import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { describe, it } from "node:test"
import { fileURLToPath } from "node:url"
import { completionScript } from "../src/cli/completion.ts"
import { main } from "../src/cli/main.ts"
import { logState, status } from "../src/cli/status.ts"
import { parseConfig, type GuardFile } from "../src/config.ts"
import { setupGuard } from "../src/index.ts"
import { declaring } from "./declared.ts"
import { fakeContext } from "./fake-ctx.ts"
import { FAKE } from "./fixtures.ts"

type Json = Record<string, unknown>
const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
const FEATURES = ["redactOutputs", "redactPrompt", "redactWire", "dangerousCommands", "sensitiveFiles", "decisionModel", "scripts"] as const
const CHECKS = ["outputCheck", "promptCheck"] as const
const POLICY = ["dangerousCommands", "sensitiveFiles", "decisionModel", "scripts"] as const
const SECTION_KEYS = ["redactOutputs", "redactPrompt", "redactWire", ...CHECKS] as const
const PROJECT = "/w/app"
const inputs = (files: readonly GuardFile[] = []) => ({ files, project: PROJECT, realPath: (path: string) => path, regularFile: () => true })
const section = (settings: Json, label = "global guard.json"): GuardFile => ({ label, global: true, data: { projects: { [PROJECT]: settings } } })
const projectFile = (data: Json): GuardFile => ({ label: "project guard.json (/w/app/.opencode/guard.json)", global: false, dir: PROJECT, data })
const parseProject = (options: Json, global: Json = {}, files: readonly GuardFile[] = []) => parseConfig(options, {}, declaring(global), inputs(files))
const onOf = (config: ReturnType<typeof parseConfig>["config"], name: string) => (name === "outputCheck" ? config.outputCheck !== undefined : name === "promptCheck" ? config.promptCheck !== undefined : config.features[name as (typeof FEATURES)[number]])

/** A session through the real hooks: the project's options over a global configuration in temporary directories. */
async function session(global: Json | undefined, project: Json, guardJson?: Json) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-ps-")))
  const [globalDir, systemDir, app] = [join(root, "global"), join(root, "system"), join(root, "app")]
  for (const dir of [globalDir, systemDir, app]) mkdirSync(dir)
  if (global) writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: global }] }))
  if (guardJson) writeFileSync(join(globalDir, "guard.json"), JSON.stringify(guardJson).replaceAll("<APP>", app))
  const logFile = join(root, "guard.log")
  const fake = fakeContext({ logFile, ...project })
  Object.assign(fake.ctx, { location: { directory: app } })
  await setupGuard(fake.ctx, {}, systemDir, globalDir)
  const output = await fake.trigger("tool.execute.after", { sessionID: "s", agent: "build", messageID: "m", id: "c1", tool: "shell", input: {}, status: "completed", result: { content: `k=${FAKE.openai}` } })
  const prompt = await fake.trigger("session.prompt", { sessionID: "s", messageID: "m2", prompt: { text: `k=${FAKE.anthropic}` } })
  await fake.trigger("tool.execute.before", { sessionID: "s", agent: "build", messageID: "m", id: "c2", tool: "shell", input: { command: "git reset --hard" } })
  return {
    log: () => readFileSync(logFile, "utf8"),
    app,
    outputMasked: !JSON.stringify(output.result).includes(FAKE.openai),
    promptMasked: !prompt.prompt.text.includes(FAKE.anthropic),
    asked: fake.asserts.length > 0,
    wire: fake.hooks.has("session.http.request"),
  }
}

describe("a project cannot turn a protection off", () => {
  for (const name of [...FEATURES, ...CHECKS]) {
    it(`PS-1 ${name}: from a project's options alone, ignored with a warning that gives the command`, () => {
      const parsed = parseProject({ [name]: false })
      assert.equal(onOf(parsed.config, name), true)
      assert.match(parsed.warnings.join("\n"), new RegExp(`${name} false ignored: a relaxation counts only if the global or system configuration sets it too`))
      assert.match(parsed.warnings.join("\n"), new RegExp(`guard set ${name} false --project`))
    })
    it(`PS-2 ${name}: the same with a guard.json file, when the settings are resolved by layers`, () => {
      const parsed = parseProject({ [name]: false }, {}, [projectFile({})])
      assert.equal(onOf(parsed.config, name), true)
      assert.match(parsed.warnings.join("\n"), new RegExp(`${name} false ignored`))
    })
    it(`witness: PS-3 ${name}: declared by the global or system configuration, kept without a warning`, () => {
      for (const declared of [declaring({ [name]: false }), () => [{ label: "global", reason: "x" }, { label: "system", options: { [name]: false } }]]) {
        const parsed = parseConfig({ [name]: false }, {}, declared, inputs())
        assert.equal(onOf(parsed.config, name), false)
        assert.ok(!parsed.warnings.join("\n").includes("ignored"), parsed.warnings.join("\n"))
      }
    })
    it(`witness: PS-4 ${name}: a project's true counts over a global false`, () => {
      assert.equal(onOf(parseProject({ [name]: true }, { [name]: false }).config, name), true)
      assert.equal(onOf(parseProject({ [name]: true }, { [name]: false }, [projectFile({})]).config, name), true)
    })
  }
  it("witness: PS-4b: a project's decisionModel true counts over a global false, with confirmations left to the model too", () => {
    const options = { decisionModel: true, localAsks: "model" }
    const global = { decisionModel: false, localAsks: "model" }
    assert.equal(parseProject(options, global).config.features.decisionModel, true)
    assert.equal(parseProject(options, global, [projectFile({})]).config.features.decisionModel, true)
  })
  it("PS-5: through the real hooks, a project that replaces the options leaves redaction, rules and the wire on, and says so", async () => {
    const off = await session({}, { redactOutputs: false, redactPrompt: false, redactWire: false, dangerousCommands: false })
    assert.deepEqual([off.outputMasked, off.promptMasked, off.asked, off.wire], [true, true, true, true])
    assert.match(off.log(), /WARN redactOutputs false ignored: /)
    assert.ok(!/INFO active \(.*disabled:/.test(off.log()), off.log())
  })
  it("witness: PS-6: declared in the global opencode.json, the hooks are off and the start line says so", async () => {
    const options = { redactOutputs: false, redactPrompt: false, redactWire: false, dangerousCommands: false }
    const off = await session(options, options)
    assert.deepEqual([off.outputMasked, off.promptMasked, off.asked, off.wire], [false, false, false, false])
    assert.match(off.log(), /INFO active \(.*; disabled: dangerousCommands, redactOutputs, redactPrompt, redactWire/)
  })
  it("PS-7: a value that differs from the global one does not count: outputs off from the project, prompts off in the global file", () => {
    const parsed = parseProject({ redactOutputs: false }, { redactPrompt: false })
    assert.equal(parsed.config.features.redactOutputs, true)
  })
  it("PS-8: unreadable global configuration: every switch stays on, never turned off", () => {
    const failing = () => {
      throw new Error("unreadable")
    }
    for (const name of [...FEATURES, ...CHECKS]) {
      assert.equal(onOf(parseConfig({ [name]: false }).config, name), true, name)
      assert.equal(onOf(parseConfig({ [name]: false }, {}, failing, inputs()).config, name), true, name)
    }
  })
  it("PS-9: the object form of a check is a relaxation too", () => {
    for (const value of [{ enabled: false }, "false", "0"]) assert.notEqual(parseProject({ outputCheck: value }).config.outputCheck, undefined, JSON.stringify(value))
  })
  it("PS-10: a section that does not match this project declares nothing", () => {
    const other: GuardFile = { label: "global guard.json", global: true, data: { projects: { "/w/other": { redactOutputs: false, dangerousCommands: false } } } }
    const parsed = parseProject({ redactOutputs: false, dangerousCommands: false }, {}, [other])
    assert.deepEqual([parsed.config.features.redactOutputs, parsed.config.features.dangerousCommands], [true, true])
  })
  it("PS-11: a trusted project does not keep a redaction switch or a check, and its guard.json does not accept them", () => {
    const parsed = parseProject({ redactOutputs: false, redactPrompt: false, redactWire: false, outputCheck: false, promptCheck: false }, { trustedProjects: "*" })
    for (const name of ["redactOutputs", "redactPrompt", "redactWire", "outputCheck", "promptCheck"]) assert.equal(onOf(parsed.config, name), true, name)
  })
  it("witness: PS-11b: a trusted project's guard.json does not accept them", () => {
    const file = parseProject({}, { trustedProjects: "*" }, [projectFile({ redactOutputs: false, outputCheck: false })])
    assert.deepEqual([file.config.features.redactOutputs, file.config.outputCheck !== undefined], [true, true])
  })
  it("PS-11c: the warning names the places that accept them", () => {
    const file = parseProject({}, { trustedProjects: "*" }, [projectFile({ redactOutputs: false })])
    assert.match(file.warnings.join("\n"), /redactOutputs ignored: only the plugin options in opencode\.json accept it, or a projects section of a global source/)
  })
  it("witness: PS-12: a trusted project keeps a policy switch, like its guard.json", () => {
    assert.equal(parseProject({ dangerousCommands: false }, { trustedProjects: "*" }).config.features.dangerousCommands, false)
    assert.equal(parseProject({}, { trustedProjects: "*" }, [projectFile({ dangerousCommands: false })]).config.features.dangerousCommands, false)
  })
  it("witness: PS-13: a value retained by the profile is not reported; a project's profile does not turn the switches off either", () => {
    const kept = parseProject({ profile: "credentials-only", dangerousCommands: false }, { profile: "credentials-only" })
    assert.equal(kept.config.features.dangerousCommands, false)
    assert.ok(!/dangerousCommands false ignored/.test(kept.warnings.join("\n")), kept.warnings.join("\n"))
    const refused = parseProject({ profile: "credentials-only" }, {}, [projectFile({})])
    assert.equal(refused.config.features.dangerousCommands, true)
  })
  it("witness: PS-14: an invalid value never turns a switch off", () => {
    for (const name of FEATURES) assert.equal(onOf(parseProject({ [name]: "maybe" }).config, name), true, name)
    assert.notEqual(parseProject({ promptCheck: "maybe" }).config.promptCheck, undefined)
  })
})

describe("what was already refused stays refused", () => {
  it("witness: PS-15: ruleOverrides off, profile, and selfProtectionByModel where it would change a finding, from a project's options", () => {
    for (const files of [[], [projectFile({})]]) {
      assert.equal(parseProject({ ruleOverrides: { rm: "off" } }, {}, files).config.policy.overrides?.has("rm") ?? false, false)
      assert.equal(parseProject({ profile: "credentials-only" }, {}, files).config.features.dangerousCommands, true)
      assert.equal(parseProject({ selfProtectionByModel: true, localAsks: "model" }, { localAsks: "model" }, files).config.policy.selfProtectionByModel ?? false, false)
    }
  })
  it("witness: PS-16: a guard key at the top level is an unknown option", () => {
    assert.match(parseProject({ guard: "off" }).warnings.join("\n"), /unknown option guard, ignored/)
  })
})

describe("a projects section of a global source declares a switch", () => {
  it("PS-20: a matching section turns a redaction switch or a check off, on its own", () => {
    for (const name of SECTION_KEYS) assert.equal(onOf(parseProject({}, {}, [section({ [name]: false })]).config, name), false, name)
  })
  it("PS-20b: the section accepts them without a warning", () => {
    for (const name of SECTION_KEYS) {
      const { warnings } = parseProject({ [name]: false }, {}, [section({ [name]: false })])
      assert.ok(!warnings.join("\n").includes("ignored"), warnings.join("\n"))
    }
  })
  it("witness: PS-20c: a section turns a policy switch off, as it always did", () => {
    for (const name of POLICY) {
      const parsed = parseProject({}, {}, [section({ [name]: false })])
      assert.equal(onOf(parsed.config, name), false, name)
      assert.ok(!parsed.warnings.join("\n").includes("ignored"), parsed.warnings.join("\n"))
    }
  })
  it("witness: PS-20d: the same value in a project's options stays off", () => {
    for (const name of [...FEATURES, ...CHECKS]) assert.equal(onOf(parseProject({ [name]: false }, {}, [section({ [name]: false })]).config, name), false, name)
  })
  it("PS-21: the section of the global opencode.json counts too, and the keys are not reported as ignored there", () => {
    const parsed = parseProject({ redactOutputs: false, projects: { [PROJECT]: { redactOutputs: false, outputCheck: false } } }, { projects: { [PROJECT]: { redactOutputs: false, outputCheck: false } } })
    assert.equal(parsed.config.outputCheck, undefined)
    assert.ok(!parsed.warnings.join("\n").includes("ignored"), parsed.warnings.join("\n"))
  })
  it("PS-22: a project replacing the options, through the real hooks: the section turns redaction off here", async () => {
    const off = await session({}, {}, { projects: { "<APP>": { redactOutputs: false } } })
    assert.equal(off.outputMasked, false)
    assert.match(off.log(), /INFO active \(.*; disabled: redactOutputs/)
  })
  it("PS-23: a section turns a switch back on over the global file, a project's true over the section", () => {
    assert.equal(parseProject({ redactOutputs: false }, { redactOutputs: false }, [section({ redactOutputs: true })]).config.features.redactOutputs, true)
  })
  it("witness: PS-23b: a project's true counts over a section's false", () => {
    assert.equal(parseProject({ redactOutputs: true }, {}, [section({ redactOutputs: false })]).config.features.redactOutputs, true)
  })
  it("PS-24: a check turned back on by a section is active over a global file that turns it off", async () => {
    const decision = { baseURL: "http://127.0.0.1:9/v1", model: "nox-4b", timeoutMs: 100 }
    const options = { decision, promptCheck: false, outputCheck: false }
    const on = await session(options, options, { projects: { "<APP>": { promptCheck: true } } })
    assert.match(on.log(), /INFO active \(.*; output check: off; prompt check: active\)/)
  })
  it("witness: PS-24b: the same for the output check", async () => {
    const decision = { baseURL: "http://127.0.0.1:9/v1", model: "nox-4b", timeoutMs: 100 }
    const options = { decision, promptCheck: false, outputCheck: false }
    const on = await session(options, options, { projects: { "<APP>": { outputCheck: true } } })
    assert.match(on.log(), /INFO active \(.*; output check: active; prompt check: off\)/)
  })
  it("witness: PS-24c: a switch the global profile turns off is declared by that profile", () => {
    for (const files of [[], [section({ dangerousCommands: true })]]) {
      const parsed = parseProject({ dangerousCommands: false }, { profile: "credentials-only" }, files)
      assert.equal(parsed.config.features.dangerousCommands, false)
      assert.ok(!parsed.warnings.join("\n").includes("dangerousCommands false ignored"), parsed.warnings.join("\n"))
    }
  })
  it("PS-28: a change while the plugin runs is reported: these switches count from the next start", async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-ps-")))
    const [globalDir, systemDir, app] = [join(root, "global"), join(root, "system"), join(root, "app")]
    for (const dir of [globalDir, systemDir, app]) mkdirSync(dir)
    const logFile = join(root, "guard.log")
    const fake = fakeContext({ logFile })
    Object.assign(fake.ctx, { location: { directory: app } })
    let now = 1_000_000
    await setupGuard(fake.ctx, {}, systemDir, globalDir, { now: () => now, intervalMs: 2000 })
    writeFileSync(join(globalDir, "guard.json"), JSON.stringify({ projects: { [app]: { redactOutputs: false } } }))
    now += 2500
    await fake.trigger("tool.execute.before", { sessionID: "s", agent: "build", messageID: "m", id: "c1", tool: "shell", input: { command: "ls" } })
    assert.match(readFileSync(logFile, "utf8"), /WARN redactOutputs: changed in guard\.json, counts from the next start/)
  })
  it("PS-25: an agent section does not declare a project's switch", () => {
    const file: GuardFile = { label: "global guard.json", global: true, data: { agents: { sandbox: { redactOutputs: false } } } }
    assert.equal(parseProject({ redactOutputs: false }, {}, [file]).config.features.redactOutputs, true)
  })
  it("witness: PS-26b: invalid values and a check's settings in a section leave it on", () => {
    const parsed = parseProject({}, {}, [section({ redactOutputs: "maybe", promptCheck: "maybe", outputCheck: { threshold: 0.9 } })])
    assert.equal(parsed.config.features.redactOutputs, true)
    assert.notEqual(parsed.config.promptCheck, undefined)
    assert.notEqual(parsed.config.outputCheck, undefined)
  })
  it("PS-26: invalid values and a check's settings in a section are reported", () => {
    const all = parseProject({}, {}, [section({ redactOutputs: "maybe", promptCheck: "maybe", outputCheck: { threshold: 0.9 } })]).warnings.join("\n")
    assert.match(all, /invalid value for redactOutputs/)
    assert.match(all, /invalid value for promptCheck/)
    assert.match(all, /outputCheck: its settings are ignored here/)
  })
  it("witness: PS-27: the global guard.json's top level still does not accept them", () => {
    const parsed = parseProject({}, {}, [{ label: "global guard.json", global: true, data: { redactOutputs: false } }])
    assert.equal(parsed.config.features.redactOutputs, true)
    assert.match(parsed.warnings.join("\n"), /global guard\.json: redactOutputs ignored/)
  })
})

describe("the system configuration keeps the last word", () => {
  const withSystem = (global: Json, system: Json) => () => [
    { label: "global", options: global },
    { label: "system", options: system },
  ]
  const parseWith = (effective: Json, global: Json, system: Json, settings: Json) => parseConfig(effective, {}, withSystem(global, system), inputs([section(settings)]))
  it("PS-34: a true over a section's false, whether or not the global file repeats it", () => {
    const value = { redactOutputs: true }
    assert.equal(parseWith(value, value, value, { redactOutputs: false }).config.features.redactOutputs, true)
  })
  it("PS-35: a false over a section's true, whether or not the global file repeats it", () => {
    const value = { redactOutputs: false }
    assert.equal(parseWith(value, value, value, { redactOutputs: true }).config.features.redactOutputs, false)
  })
  it("witness: PS-36: the same with a global file that says nothing", () => {
    assert.equal(parseWith({ redactOutputs: true }, {}, { redactOutputs: true }, { redactOutputs: false }).config.features.redactOutputs, true)
    assert.equal(parseWith({ redactOutputs: false }, {}, { redactOutputs: false }, { redactOutputs: true }).config.features.redactOutputs, false)
  })
  it("witness: PS-37: no system configuration: a value both the global file and the options write stays the section's", () => {
    const value = { dangerousCommands: true }
    assert.equal(parseProject(value, value, [section({ dangerousCommands: false })]).config.features.dangerousCommands, false)
  })
})

describe("the checks a project stops by way of the model are named", () => {
  const decision = { baseURL: "http://127.0.0.1:9/v1", model: "nox-4b", timeoutMs: 100 }
  const CUT = /WARN output check and prompt check not running: the decision model in use is not the one the global configuration declares/
  it("PS-38: decision replaced by another address", async () => {
    const log = (await session({ decision }, { decision: { ...decision, baseURL: "http://127.0.0.1:8/v1" } })).log()
    assert.match(log, CUT)
  })
  it("PS-39: decision removed", async () => {
    for (const project of [{}, { decision: false }]) assert.match((await session({ decision }, project)).log(), CUT)
  })
  it("PS-40: only the check the global file leaves on", async () => {
    assert.match((await session({ decision, outputCheck: false }, {})).log(), /WARN prompt check not running: /)
  })
  it("witness: PS-41: nothing for a user without a declared model, nor when the checks run or the model is switched off by the user", async () => {
    for (const [global, project] of [[{}, {}], [undefined, {}], [{ decision }, { decision }], [{ decision, decisionModel: false }, {}], [{ decision, outputCheck: false, promptCheck: false }, {}]] as const)
      assert.doesNotMatch((await session(global, project)).log(), /not running: the decision model/, JSON.stringify(global))
  })
  it("witness: PS-41b: nor when the model the user declares is unusable: nothing was replaced", async () => {
    for (const broken of [{ decision: { baseURL: decision.baseURL } }, { decision: { baseURL: decision.baseURL, model: "{env:GUARD_PS_MISSING}" } }])
      assert.doesNotMatch((await session(broken, broken)).log(), /not running: the decision model/, JSON.stringify(broken))
  })
})

describe("the command line tells the truth", () => {
  function world(global: Json = {}, app = "app") {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-ps-cli-")))
    const [globalDir, systemDir, home, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, app)]
    for (const dir of [globalDir, systemDir, home, join(project, ".git")]) mkdirSync(dir, { recursive: true })
    writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: global }] }))
    const runIn = (cwd: string, ...args: string[]) => {
      const [out, err]: [string[], string[]] = [[], []]
      const code = main(args, { env: { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: home }, cwd, systemDir, out: (line) => out.push(line), err: (line) => err.push(line) })
      return { code, out: out.join("\n"), err: err.join("\n") }
    }
    const run = (...args: string[]) => runIn(project, ...args)
    return { run, runIn, guardFile: join(globalDir, "guard.json"), project, home, systemDir, globalDir }
  }
  it("PS-30: guard set writes a redaction switch in the project's section; guard show and guard options read it; unset takes it back", () => {
    const w = world()
    assert.equal(w.run("set", "redactOutputs", "off", "--project").code, 0)
    assert.deepEqual(JSON.parse(readFileSync(w.guardFile, "utf8")).projects[w.project], { redactOutputs: false })
    const show = w.run("show").out
    assert.match(show, /redactOutputs\s+false\s+global guard\.json, projects\[/)
    assert.match(w.run("options").out, /redactOutputs\s+boolean\s+false\s+true\s+global guard\.json, projects\[.*overridden/)
    assert.equal(w.run("unset", "redactOutputs", "--project").code, 0)
    assert.match(w.run("show").out, /redactOutputs\s+true\s+default/)
  })
  const misplaced = [["set", "redactOutputs", "false"], ["set", "outputCheck", "false", "--agent", "x", "--project"]]
  it("witness: PS-31b: guard set does not write a redaction switch at the top level or for an agent", () => {
    for (const args of misplaced) assert.notEqual(world().run(...args).code, 0, args.join(" "))
  })
  it("PS-31: the refusal names the right command", () => {
    for (const args of misplaced) assert.match(world().run(...args).err, /goes with --project and without --agent/)
  })
  it("PS-32: a check turned off for this project, in guard show and guard options", () => {
    const w = world()
    assert.equal(w.run("set", "promptCheck", "false", "--project").code, 0)
    assert.match(w.run("show").out, /promptCheck\s+false\s+global guard\.json, projects\[/)
    assert.match(w.run("options").out, /promptCheck\s+boolean[^\n]*false\s+true/)
  })
  it("PS-33: the value of the global opencode.json keeps its origin", () => {
    assert.match(world({ redactWire: false }).run("show").out, /redactWire\s+false\s+global configuration/)
  })
  /** The words of the warning's command, as a shell reads them (only these quotes occur); the command goes to `main`. */
  const commandOf = (warning: string) =>
    [...warning.slice(warning.indexOf("guard set ")).matchAll(/'((?:[^']|'\\'')*)'|(\S+)/g)].map((word) => word[2] ?? word[1]!.replaceAll("'\\''", "'")).slice(1)
  for (const app of ["app", "my app", "it's $(mine)"])
    it(`PS-42: the warning's command, from another directory, writes the refused project's section (${app})`, () => {
      const w = world({}, app)
      const refused = parseConfig({ redactOutputs: false }, {}, declaring({}), { files: [], project: w.project, realPath: (path: string) => path, regularFile: () => true })
      const command = commandOf(refused.warnings.find((line) => line.includes("guard set"))!)
      assert.deepEqual(command, ["set", "redactOutputs", "false", "--project", w.project])
      const code = w.runIn(w.home, ...command).code
      assert.deepEqual([code, Object.keys(JSON.parse(readFileSync(w.guardFile, "utf8")).projects)], [0, [w.project]])
    })
  it("PS-42b: the same from the log of a real start, redaction and all", async () => {
    const started = await session({}, { redactOutputs: false })
    const command = commandOf(started.log().split("\n").find((line) => line.includes("guard set"))!)
    assert.deepEqual(command, ["set", "redactOutputs", "false", "--project", started.app])
  })
  it("PS-43: guard set and guard unset say when the value counts", () => {
    const w = world()
    assert.match(w.run("set", "redactOutputs", "false", "--project").out, /redactOutputs counts from the next start of the plugin/)
    assert.match(w.run("unset", "redactOutputs", "--project").out, /redactOutputs counts from the next start of the plugin/)
  })
  it("witness: PS-43b: a setting read at once has no such line", () => {
    assert.doesNotMatch(world().run("set", "scripts", "false", "--project").out, /next start/)
  })
  it("PS-44: the help says it", () => {
    assert.match(world().run("help").out, /In a project section, redactOutputs, redactPrompt, redactWire, outputCheck, promptCheck count from the next start of the plugin/)
  })
  it("PS-45: guard show gives the five switches with the reservation, in any origin", () => {
    const w = world()
    w.run("set", "redactOutputs", "false", "--project")
    const show = w.run("show").out
    assert.match(show, /redactOutputs\s+false\s+global guard\.json, projects\[.*\(read when the plugin starts\)/)
    for (const name of ["redactPrompt", "redactWire"]) assert.match(show, new RegExp(`${name}\\s+true\\s+default \\(read when the plugin starts\\)`))
  })
  it("witness: PS-45b: not for a setting read at once", () => {
    assert.doesNotMatch(world().run("show").out.split("\n").find((line) => /^\s+scripts\s/.test(line))!, /read when/)
  })
  const model = { decision: { baseURL: "http://127.0.0.1:9/v1", model: "nox-4b" } }
  it("PS-46: without a declared model, guard show does not give the checks as on", () => {
    const show = world().run("show").out
    for (const name of CHECKS) assert.match(show, new RegExp(`${name}\\s+inactive\\s+default \\(read when the plugin starts\\): no decision model`))
  })
  it("witness: PS-47: with a declared model, they are", () => {
    const show = world(model).run("show").out
    for (const name of CHECKS) assert.match(show, new RegExp(`${name}\\s+true\\s+default`))
  })
  it("PS-48: guard set answers that the system configuration keeps the last word, whatever the global file repeats", () => {
    const w = world({ redactOutputs: true })
    writeFileSync(join(w.systemDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: { redactOutputs: true } }] }))
    assert.match(w.run("set", "redactOutputs", "false", "--project").out, /redactOutputs is still true there, set by system configuration/)
  })
  it("PS-49: guard set foo lists the five switches too", () => {
    assert.match(world().run("set", "foo", "true").err, /one of .*redactOutputs, redactPrompt, redactWire, outputCheck, promptCheck/)
  })
  it("PS-50: guard options: a check's enabled key and its true say what they do", () => {
    const w = world()
    for (const name of ["outputCheck", "promptCheck", "outputCheck.enabled", "promptCheck.enabled"]) assert.match(w.run("options", "--explain", name).out, /a project's true turns it back on only where a global source leaves it on/, name)
    for (const name of ["outputCheck.enabled", "promptCheck.enabled"]) assert.match(w.run("options", "--explain", name).out, /a project section of a global source/, name)
  })
  it("PS-51: guard status shows the refusals of the latest start", () => {
    const line = (time: string, level: string, text: string) => `2026-11-05T10:00:${time}.000Z ${level} ${text}`
    const refusal = "redactOutputs false ignored: a relaxation counts only if the global or system configuration sets it too (x); for this project: guard set redactOutputs false --project /a"
    const state = logState([line("00", "WARN", "old ignored: a relaxation counts only if x"), line("00", "INFO", "active (first)"), line("30", "WARN", refusal), line("30", "WARN", "other"), line("30", "INFO", "active (second)")])
    assert.deepEqual(state.refused?.map((entry) => entry.text), [refusal])
  })
  it("PS-51b: through a real start, in its log", async () => {
    const lines = (await session({}, { redactOutputs: false })).log().trim().split("\n")
    assert.equal(logState(lines).refused?.length, 1)
  })
  it("PS-51c: a real start with nothing to refuse has an empty list", async () => {
    const lines = (await session({}, {})).log().trim().split("\n")
    assert.deepEqual(logState(lines).refused, [])
  })
  it("PS-52: a clean start refuses nothing", () => {
    const line = (level: string, text: string) => `2026-11-05T10:00:30.000Z ${level} ${text}`
    assert.deepEqual(logState([line("WARN", "other"), line("INFO", "active (x)")]).refused, [])
  })
  it("PS-53: guard status prints them", async () => {
    const w = world()
    const log = join(w.home, "guard.log")
    const now = new Date().toISOString()
    writeFileSync(log, `${now} WARN redactOutputs false ignored: a relaxation counts only if x; for this project: guard set redactOutputs false --project /a\n${now} INFO active (x)\n`)
    writeFileSync(join(w.globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: { logFile: log } }] }))
    const out: string[] = []
    await status({ env: { HOME: w.home, OPENCODE_CONFIG_DIR: w.globalDir, XDG_DATA_HOME: w.home }, cwd: w.project, systemDir: w.systemDir, out: (text) => out.push(text), err: () => {} }, { offline: true })
    assert.match(out.join("\n"), /1 setting\(s\) refused by the latest start/)
    assert.match(out.join("\n"), /guard set redactOutputs false --project \/a/)
  })
  describe("completion", { skip: !existsSync("/bin/bash") && !existsSync("/usr/bin/bash") && "bash not installed" }, () => {
    const complete = (...line: string[]) => {
      const words = ["guard", ...line]
      const script = `${completionScript("bash")}\nCOMP_WORDS=(${words.map((word) => `'${word}'`).join(" ")}); COMP_CWORD=${words.length - 1}\n_guard; printf '%s\\n' "\${COMPREPLY[@]}"`
      return execFileSync("bash", ["--norc", "--noprofile", "-c", script], { encoding: "utf8", env: { PATH: process.env.PATH ?? "/usr/bin:/bin" } }).split("\n").filter(Boolean)
    }
    it("PS-54: set and unset offer the five switches, promptCheck from prom", () => {
      for (const command of ["set", "unset"]) {
        assert.deepEqual(complete(command, "red").sort(), ["redactOutputs", "redactPrompt", "redactWire"])
        assert.deepEqual(complete(command, "out"), ["outputCheck"])
        assert.deepEqual(complete(command, "prom"), ["promptCheck"])
      }
    })
    it("PS-55: their values, then --project alone", () => {
      assert.deepEqual(complete("set", "redactWire", "o").sort(), ["off", "on"])
      assert.deepEqual(complete("set", "promptCheck", "true", ""), ["--project"])
      assert.deepEqual(complete("unset", "outputCheck", ""), ["--project"])
    })
    it("witness: PS-56: pro still gives profile alone", () => {
      assert.deepEqual(complete("set", "pro"), ["profile"])
    })
  })
})
