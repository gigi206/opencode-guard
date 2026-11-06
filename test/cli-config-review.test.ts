// What `guard settings`, `guard show` and `guard status` say is what the plugin does, and a project's shorter
// `rememberConfirmations` is kept. Fake settings in throwaway directories; no model is called, nothing is run.
import "./tmp.ts"
import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs"
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

type Json = Record<string, unknown>
const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
const DECISION = { baseURL: "https://decision.example.invalid/v1", model: "m" }
const RULE = { id: "own-rule", pattern: "kubectl apply", verdict: "deny", reason: "fake" }

function world(setup: { options?: Json; raw?: string; guard?: Json; project?: Json }) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-review-")))
  const [globalDir, systemDir, home, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "project")]
  for (const dir of [globalDir, systemDir, home, join(project, ".opencode")]) mkdirSync(dir, { recursive: true })
  const place = (text: string) => text.replaceAll("<PROJECT>", project)
  writeFileSync(join(globalDir, "opencode.json"), place(setup.raw ?? JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: setup.options ?? {} }] })))
  if (setup.guard) writeFileSync(join(globalDir, "guard.json"), place(JSON.stringify(setup.guard)))
  if (setup.project) writeFileSync(join(project, ".opencode", "guard.json"), JSON.stringify(setup.project))
  const io = { env: { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: home }, cwd: project, systemDir }
  const run = (...args: string[]) => {
    const [out, err]: string[][] = [[], []]
    main(args, { ...io, out: (line) => out.push(line), err: (line) => err.push(line) })
    return { out, err }
  }
  return { run, io, home, project }
}
const row = (lines: readonly string[], name: string) => lines.find((line) => line.startsWith(`${name} `))?.trim().split(/ {2,}/)
const shownOnce = (lines: readonly string[], text: string) => lines.filter((line) => line.includes(text)).length

describe("guard settings: what the global guard.json sets", () => {
  it("CR-1: rules, redactionOff and trustedProjects show the value and the file they come from", () => {
    const { out } = world({ guard: { rules: [RULE], redactionOff: ["aws_access_key"], trustedProjects: ["<PROJECT>"] } }).run("settings")
    assert.deepEqual(row(out, "rules")!.slice(2), ["1 rule", "none", "global guard.json", "overridden"])
    assert.deepEqual(row(out, "redactionOff")!.slice(2), ["aws_access_key", "none", "global guard.json", "overridden"])
    assert.deepEqual(row(out, "trustedProjects")!.slice(2), ["1 project", "none", "global guard.json", "overridden"])
  })
  it("CR-2: rule settings and agent sections of guard.json name that file too", () => {
    const { out } = world({ guard: { ruleOverrides: { rm: "off" }, agents: { foo: { scripts: false } }, projects: { "/x": { scripts: false } } } }).run("settings")
    assert.deepEqual(row(out, "ruleOverrides")!.slice(2), ["1 rule", "none", "global guard.json", "overridden"])
    assert.deepEqual(row(out, "agents")!.slice(2), ["1 agent", "none", "global guard.json", "overridden"])
    assert.deepEqual(row(out, "projects")!.slice(2), ["1 project", "none", "global guard.json", "overridden"])
  })
  it("CR-3: set in both files, both are named, and the values add up", () => {
    const { out } = world({ options: { rules: [{ ...RULE, id: "other" }], redactionOff: ["github_token"] }, guard: { rules: [RULE], redactionOff: ["aws_access_key"] } }).run("settings")
    assert.deepEqual(row(out, "rules")!.slice(2), ["2 rules", "none", "global opencode.json and global guard.json", "overridden"])
    assert.equal(row(out, "redactionOff")![4], "global opencode.json and global guard.json")
    assert.match(row(out, "redactionOff")![2]!, /github_token/)
    assert.match(row(out, "redactionOff")![2]!, /aws_access_key/)
  })
  it("CR-3b: agent sections of both files add up in the count", () => {
    const { out } = world({ options: { agents: { foo: { scripts: false } } }, guard: { agents: { bar: { scripts: false } } } }).run("settings")
    assert.deepEqual(row(out, "agents")!.slice(2), ["2 agents", "none", "global opencode.json and global guard.json", "overridden"])
  })
})

describe("guard settings: ignored means refused", () => {
  const accepted: ReadonlyArray<readonly [string, Json]> = [
    ["logFile", { logFile: false }],
    ["logFile", { logFile: "FALSE" }],
    ["logFile", { logFile: "~/my.log" }],
    ["askAs", { askAs: "DENY" }],
    ["profile", { profile: "Standard" }],
    ["debug", { debug: "TRUE" }],
    ["outputCheck.threshold", { outputCheck: { threshold: "0,3" } }],
  ]
  const stable: ReadonlyArray<readonly [string, Json]> = [
    ["logFile", { logFile: "relative.log" }],
    ["decision.baseURL", { decision: { ...DECISION, baseURL: `${DECISION.baseURL}/` } }],
  ]
  for (const [title, [name, options]] of [...accepted.map((item) => ["CR-4", item] as const), ...stable.map((item) => ["witness: CR-4b", item] as const)])
    it(`${title}: ${JSON.stringify(options)} is accepted`, () => {
      const { run } = world({ options })
      assert.notEqual(row(run("settings").out, name)!.at(-1), "ignored")
      assert.doesNotMatch(run("settings", "--explain", name).out.join("\n"), /not accepted/)
    })
  const refused: ReadonlyArray<readonly [string, Json]> = [
    ["cacheMax", { cacheMax: 999_999 }],
    ["askAs", { askAs: "bogus" }],
    ["profile", { profile: "bogus" }],
    ["debug", { debug: "maybe" }],
    ["logFile", { logFile: 12 }],
    ["outputCheck.threshold", { outputCheck: { threshold: 7 } }],
    ["thresholds.askRisk", { thresholds: { askRisk: 9 } }],
    ["decision.protocol", { decision: { ...DECISION, protocol: "bogus" } }],
    ["decision.model", { decision: { model: "alone" } }],
    ["unprotectedAgent", { unprotectedAgent: "build" }],
  ]
  for (const [name, options] of refused)
    it(`witness: CR-5: ${JSON.stringify(options)} stays ignored`, () => {
      const { run } = world({ options })
      assert.equal(row(run("settings").out, name)!.at(-1), "ignored")
      assert.match(run("settings", "--explain", name).out.join("\n"), /ignored: not accepted/)
    })
  it("witness: CR-5c: a protocol that is not a text stays ignored", () => {
    assert.equal(row(world({ options: { decision: { ...DECISION, protocol: 1 } } }).run("settings").out, "decision.protocol")!.at(-1), "ignored")
  })
  it("CR-5d: an apiKey that is not a text leaves no key set", () => {
    const cells = row(world({ options: { decision: { ...DECISION, apiKey: 1 } } }).run("settings").out, "decision.apiKey")!
    assert.deepEqual([cells[2], cells.at(-1)], ["not set", "same as default"])
  })
  it("witness: CR-5b: a key guard.json does not read is ignored", () => {
    assert.equal(row(world({ guard: { askAs: "deny" } }).run("settings").out, "askAs")!.at(-1), "ignored")
  })
  it("CR-6: a log file the plugin refuses is not shown in force", () => {
    const w = world({ options: { logFile: "~/.ssh/guard.log" } })
    const cells = row(w.run("settings").out, "logFile")!
    assert.equal(cells.at(-1), "ignored")
    assert.doesNotMatch(cells[2]!, /\.ssh/)
    assert.match(w.run("show", "--offline").out.join("\n"), /logFile refused \(it is a credential file\)/)
  })
})

describe("guard show lists what guard settings announces", () => {
  it("CR-7: each warning is listed, as many as announced", () => {
    const w = world({ options: { askAs: "bogus", cacheMax: 999_999, nope: 1, ruleOverrides: { rmm: "off" } } })
    const { out } = w.run("show", "--offline")
    for (const text of ["invalid value for askAs", "invalid value for cacheMax", "unknown option nope", "unknown rule"]) assert.equal(shownOnce(out, text), 1, text)
    const announced = Number(/^(\d+) warning/.exec(w.run("settings").err[0]!)![1])
    assert.equal(announced, out.length - out.indexOf("Set aside:") - 2)
  })
  it("CR-8: a warning counts once", () => {
    const w = world({ project: { ruleOverrides: { rm: "off" } } })
    assert.match(w.run("settings").err[0]!, /^1 warning/)
    assert.equal(shownOnce(w.run("show", "--offline").out, "ruleOverrides.rm"), 1)
  })
})

describe("guard status shows the settings the latest start refused", () => {
  const stamp = (level: string, text: string) => `2026-11-05T10:00:30.000Z ${level} ${text}`
  const refusals = [
    "decision ignored: a project does not choose its decision model, the global configuration's stays; for this project: x",
    'askAs "ask" ignored: the global configuration asks for "deny"; for this project: x',
    "maxStateChars ignored: a project does not choose what the decision model reads",
    "thresholds askNoul ignored: less strict than the global configuration; for this project: x",
    'rules "a" ignored: the global configuration uses the identifier, and its setting stays; rename the rule in the project',
    "outputCheck settings ignored, defaults used: they count only if the global or system configuration sets it too (x)",
    "project guard.json (/a/.opencode/guard.json): ruleOverrides.rm \"off\" ignored: its directory is not trusted, so its settings can only harden (trustedProjects, in the global configuration)",
    "unknown option nope, ignored",
    "invalid value for cacheMax (999999), using default 500",
    "logFile refused (it is a credential file): logging to the default log file",
    'unprotectedAgent cannot be the built-in agent "build": no unprotected agent',
  ]
  it("CR-9: every refusal of the start, whatever its reason", () => {
    const state = logState([...refusals.map((text) => stamp("WARN", text)), stamp("INFO", "active (x)")])
    assert.deepEqual(state.refused.map((entry) => entry.text), refusals)
  })
  it("CR-10: all are printed, not only the last ones", async () => {
    const w = world({})
    const logFile = join(w.home, "guard.log")
    const now = new Date().toISOString()
    writeFileSync(logFile, [...refusals.map((text) => `${now} WARN ${text}`), `${now} INFO active (x)`, ""].join("\n"))
    writeFileSync(join(w.io.env.OPENCODE_CONFIG_DIR, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: { logFile } }] }))
    const out: string[] = []
    await status({ ...w.io, out: (text) => out.push(text), err: () => {} }, { offline: true })
    assert.match(out.join("\n"), /11 setting\(s\) refused by the latest start/)
    for (const text of refusals) assert.ok(out.some((line) => line.includes(text)), text)
  })
  it("CR-10b: a value refused because something is missing, and a section that relaxes for no model", () => {
    const missing = [
      "secretPatterns[0]: missing pattern",
      "decision.model is empty or missing: decision model disabled",
      "decision.baseURL is empty or missing: decision model disabled",
      "agents.build: models must be a list of provider/model: this section relaxes for no model",
    ]
    assert.deepEqual(logState([...missing.map((text) => stamp("WARN", text)), stamp("INFO", "active (x)")]).refused.map((entry) => entry.text), missing)
  })
  it("witness: CR-11: a start's other warnings are not refusals", () => {
    const others = [
      "decision model disabled: local rules only",
      "decision model disabled (decisionModel: false): local rules only",
      "localAsks retained but the decision model is disabled: these asks stay with you",
      "logFile is not an absolute path: it is resolved against the OpenCode server's working directory",
      "decision.baseURL uses plain HTTP to a host that is not local",
      "decision.apiKey is shorter than 8 characters: it cannot be redacted verbatim (logs, requests)",
      "outputCheck requested but inactive: global configuration: it cannot be read",
    ]
    const state = logState([...others.map((text) => stamp("WARN", text)), stamp("INFO", "active (x)")])
    assert.deepEqual(state.refused, [])
  })
})

describe("a check with no model it may use", () => {
  it("CR-12: guard settings says what guard show says", () => {
    const w = world({})
    const shown = w.run("show", "--offline").out
    for (const name of ["outputCheck", "promptCheck"]) {
      assert.match(shown.join("\n"), new RegExp(`${name}\\s+inactive`), name)
      assert.equal(row(w.run("settings").out, name)![2], "inactive", name)
      assert.equal(row(w.run("settings").out, `${name}.enabled`)![2], "inactive", name)
      assert.match(w.run("settings", "--explain", name).out.join("\n"), /no decision model/, name)
    }
  })
  it("witness: CR-13: with the model declared, it is on", () => {
    const { out } = world({ options: { decision: DECISION } }).run("settings")
    assert.equal(row(out, "outputCheck")![2], "true")
    assert.equal(row(out, "promptCheck")![2], "true")
  })
  it("witness: CR-14: turned off, it says false", () => {
    assert.equal(row(world({ options: { decision: DECISION, outputCheck: false } }).run("settings").out, "outputCheck")![2], "false")
  })
})

describe("start: the checks a project stops", () => {
  async function start(global: Json, project: Json) {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-review-")))
    const [globalDir, systemDir, app] = [join(root, "global"), join(root, "system"), join(root, "app")]
    for (const dir of [globalDir, systemDir, app]) mkdirSync(dir)
    writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: global }] }))
    const logFile = join(root, "guard.log")
    const fake = fakeContext({ logFile, ...project })
    Object.assign(fake.ctx, { location: { directory: app } })
    await setupGuard(fake.ctx, {}, systemDir, globalDir)
    return readFileSync(logFile, "utf8")
  }
  const CUT = /not running: the decision model in use/
  it("CR-15: an entry without options replaces nothing, even when the declared model cannot be used", async () => {
    assert.doesNotMatch(await start({ decision: { ...DECISION, apiKey: "" } }, {}), CUT)
    assert.doesNotMatch(await start({ decision: { baseURL: DECISION.baseURL } }, {}), CUT)
  })
  it("witness: CR-16: a project that replaces the model is still named when it is trusted", async () => {
    const dir = "/"
    assert.match(await start({ decision: DECISION, trustedProjects: [dir] }, { decision: { ...DECISION, baseURL: "https://other.example.invalid/v1" } }), CUT)
  })
})

describe("rememberConfirmations from a guard.json", () => {
  const PROJECT = "/w/app"
  const inputs = (files: readonly GuardFile[]) => ({ files, project: PROJECT, realPath: (path: string) => path, regularFile: () => true })
  const globalFile = (data: Json): GuardFile => ({ label: "global guard.json", global: true, data })
  const projectFile = (data: Json): GuardFile => ({ label: "project guard.json (/w/app/.opencode/guard.json)", global: false, dir: PROJECT, data })
  const delay = (options: Json, files: readonly GuardFile[], global: Json = {}) => {
    const parsed = parseConfig(options, {}, declaring(global), inputs(files))
    return { minutes: parsed.config.policy.rememberMinutes ?? 0, warnings: parsed.warnings.join("\n") }
  }
  it("CR-17: shorter, from a project's options or its guard.json: kept, without a warning", () => {
    for (const read of [delay({ rememberConfirmations: 3 }, [globalFile({ rememberConfirmations: 5 })]), delay({}, [globalFile({ rememberConfirmations: 5 }), projectFile({ rememberConfirmations: 3 })])]) {
      assert.equal(read.minutes, 3)
      assert.doesNotMatch(read.warnings, /rememberConfirmations/)
    }
  })
  it("witness: CR-18: longer: refused, the delay in place stays", () => {
    for (const read of [delay({ rememberConfirmations: 9 }, [globalFile({ rememberConfirmations: 5 })]), delay({}, [globalFile({ rememberConfirmations: 5 }), projectFile({ rememberConfirmations: 9 })])]) {
      assert.equal(read.minutes, 5)
      assert.match(read.warnings, /rememberConfirmations 9 ignored/)
    }
  })
  it("witness: CR-19: no delay in place: any delay is a relaxation", () => {
    for (const read of [delay({ rememberConfirmations: 3 }, [globalFile({})]), delay({}, [globalFile({}), projectFile({ rememberConfirmations: 3 })])]) {
      assert.equal(read.minutes, 0)
      assert.match(read.warnings, /rememberConfirmations 3 ignored/)
    }
  })
  it("witness: CR-20: 0 turns it off, from anywhere", () => {
    assert.equal(delay({}, [globalFile({ rememberConfirmations: 5 }), projectFile({ rememberConfirmations: 0 })]).minutes, 0)
  })
  it("witness: CR-20b: a project's opencode.json is compared with the global opencode.json alone", () => {
    for (const held of [0, 2]) assert.deepEqual(delay({ rememberConfirmations: 3 }, [globalFile({ rememberConfirmations: held })], { rememberConfirmations: 5 }), { minutes: 3, warnings: "" })
    assert.equal(delay({}, [globalFile({ rememberConfirmations: 2 }), projectFile({ rememberConfirmations: 3 })], { rememberConfirmations: 5 }).minutes, 2)
  })
  it("CR-21: no other relaxation comes with it: the same project without the delay gives the same reading", () => {
    const others = { ruleOverrides: { rm: "off" }, localAsks: "model", selfProtectionByModel: true, profile: "credentials-only", dangerousCommands: false, sensitiveFiles: false, scripts: false, decisionModel: false, exceptions: { "secret-file-read": ["/w/app/x"] } }
    const read = (project: Json) => parseConfig({}, {}, declaring({}), inputs([globalFile({ rememberConfirmations: 5 }), projectFile(project)])).config
    const { rememberMinutes, ...policy } = read({ rememberConfirmations: 3, ...others }).policy
    assert.equal(rememberMinutes, 3)
    const { rememberMinutes: _, ...without } = read(others).policy
    assert.deepEqual(policy, without)
    assert.equal(policy.overrides?.get("rm"), undefined)
    assert.ok(!policy.localAsksByModel)
    assert.equal(policy.exceptions?.size ?? 0, 0)
    assert.deepEqual([policy.dangerousCommands, policy.sensitiveFiles], [true, true])
  })
})

describe("guard settings --explain says when a relaxation counts", () => {
  const relaxing = (name: string) => world({}).run("settings", "--explain", name).out.find((line) => line.includes("Relaxing"))
  for (const name of ["ruleOverrides", "profile", "localAsks", "selfProtectionByModel", "allowlist", "askAs", "maxStateChars", "decision.model", "decision.baseURL", "thresholds.askNoul"])
    it(`CR-22: ${name}: a trusted project is named`, () => assert.match(relaxing(name) ?? "", /in a trusted project/))
  it("witness: CR-23: what the text says of a trusted project is what the reading does", () => {
    const project = world({ guard: { trustedProjects: ["<PROJECT>"] }, project: { ruleOverrides: { rm: "off" }, localAsks: "model", profile: "credentials-only" } })
    const { out } = project.run("settings")
    assert.equal(row(out, "ruleOverrides.rm")![2], "off")
    assert.equal(row(out, "localAsks")![2], "model")
  })
  it("witness: CR-23b: and what it says of an entry of a project's own, trusted or not", () => {
    const global = { decision: DECISION, askAs: "deny", maxStateChars: 3000, thresholds: { askNoul: 0.2 }, allowlist: [] }
    const project = { decision: { ...DECISION, model: "other" }, askAs: "ask", maxStateChars: 6000, thresholds: { askNoul: 0.9 }, allowlist: ["fake-entry"], profile: "credentials-only" }
    const read = (trustedProjects: readonly string[]) => parseConfig(project, {}, declaring({ ...global, trustedProjects }), { files: [], project: "/w/app", realPath: (path: string) => path, regularFile: () => true }).config
    const [trusted, not] = [read(["/w/app"]), read([])]
    assert.deepEqual([trusted.decision?.model, trusted.askAs, trusted.maxStateChars, trusted.thresholds.askNoul, trusted.allowlist.length, trusted.profile], ["other", "ask", 6000, 0.9, 1, "credentials-only"])
    assert.deepEqual([not.decision?.model, not.askAs, not.maxStateChars, not.thresholds.askNoul, not.allowlist.length, not.profile], ["m", "deny", 3000, 0.2, 0, "standard"])
  })
})

describe("small displays of guard settings", () => {
  it("CR-24: a reference belongs to the setting of that name under its parent", () => {
    const options = { decision: { ...DECISION, apiKey: "{env:K}", timeoutMs: "{env:TM}" }, outputCheck: { timeoutMs: 2000 } }
    const { run } = world({ raw: JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options }] }) })
    assert.doesNotMatch(run("settings", "--explain", "outputCheck.timeoutMs").out.join("\n"), /Reference/)
    assert.match(run("settings", "--explain", "decision.timeoutMs").out.join("\n"), /Reference: \{env:TM\}/)
  })
  it("CR-25: --agent: the row of ruleOverrides counts the rule rows of that agent", () => {
    const { out } = world({ guard: { ruleOverrides: { rm: "off" }, agents: { foo: { ruleOverrides: { eval: "deny", "git-force": "deny" } } } } }).run("settings", "--agent", "foo")
    const rows = out.filter((line) => line.startsWith("ruleOverrides."))
    assert.equal(row(out, "ruleOverrides")![2], `${rows.length} rules`)
    assert.ok(rows.length >= 2)
  })
  it("CR-26: guard agent completes its subcommands", () => {
    const script = `${completionScript("bash")}\nCOMP_WORDS=(guard agent ''); COMP_CWORD=2\n_guard; printf '%s\\n' "\${COMPREPLY[@]}"`
    const words = execFileSync("bash", ["--norc", "--noprofile", "-c", script], { encoding: "utf8", env: { PATH: process.env.PATH ?? "/usr/bin:/bin" } }).split("\n").filter(Boolean)
    assert.deepEqual(words.sort(), ["models", "off", "on", "set", "unset"])
  })
})
