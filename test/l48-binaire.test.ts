// Lot 48 step D: the `guard` command line (`bin/guard`, modules of `src/cli/`), which writes the global guard.json; the
// prompt hook always registered (an agent section written while OpenCode runs counts from the next prompt); the
// `guard-cli` self-protection rule; changes of the plugin's settings never left to the decision model. Each command runs
// in process on configuration directories of the test (one test launches the launcher under Node); the plugin runs as
// OpenCode sets it up, with a test clock. The command line is imported inside each test, so that the code without it
// fails on assertions, not on loading.
import "./tmp.ts"
import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import * as gate from "../src/hooks/gate.ts"
import { setupGuard } from "../src/index.ts"
import { RULE_FEATURES, type ActiveRules } from "../src/rules/features.ts"
import { toolFinding } from "../src/rules/tools.ts"
import type { Finding } from "../src/rules/types.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>
type Main = (argv: readonly string[], io: unknown) => number

/** Configuration directories of a test, a project (git repository) and the command line run in process on them (`cli`). */
async function world(setup: { readonly global?: Json; readonly cli?: boolean } = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-bin-")))
  const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "work", "app")]
  for (const dir of [globalDir, systemDir, home, data, join(project, ".git"), join(project, "sub", "deep")]) mkdirSync(dir, { recursive: true })
  if (setup.global) writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: setup.global }] }))
  const env = { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }
  const main = setup.cli === false ? undefined : ((await import(new URL("../src/cli/main.ts", import.meta.url).href)) as { main: Main }).main
  const guardFile = join(globalDir, "guard.json")
  return {
    root,
    globalDir,
    systemDir,
    home,
    data,
    project,
    env,
    guardFile,
    read: () => JSON.parse(readFileSync(guardFile, "utf8")) as Json,
    run: (args: readonly string[], cwd = project) => {
      const out: string[] = []
      const err: string[] = []
      const code = main!(args, { env, cwd, systemDir, out: (line: string) => out.push(line), err: (line: string) => err.push(line) })
      return { code, out: out.join("\n"), err: err.join("\n") }
    },
  }
}
type World = Awaited<ReturnType<typeof world>>

/** Plugin set up as OpenCode does on the world's directories (session directory: its project), test clock. */
async function plugin(w: World, options: Json = {}) {
  const logFile = join(w.root, "plugin.log")
  const fake = fakeContext({ logFile, ...options })
  ;(fake.ctx.location as { directory: string }).directory = w.project
  fake.agents.set("plan", { mode: "primary", permissions: [] })
  let now = 1_000_000
  await (setupGuard as (...args: unknown[]) => Promise<void>)(fake.ctx, {}, w.systemDir, w.globalDir, { now: () => now, intervalMs: 2000 })
  let call = 0
  return {
    ...fake,
    log: () => readFileSync(logFile, "utf8"),
    tick: (ms = 2000) => (now += ms),
    prompt: async (sessionID: string, agent: string) => {
      fake.switchAgent(sessionID, agent)
      await fake.trigger("session.prompt", { sessionID, messageID: `msg_${++call}`, prompt: { text: "go" } })
    },
    /** Verdict of a shell call in `execute.before`: deny (blocked), ask (a confirmation was requested) or allow. */
    verdict: async (command: string, sessionID = "ses_1", agent = "build") => {
      const before = fake.asserts.length
      try {
        await fake.trigger("tool.execute.before", { sessionID, agent, messageID: "msg_0", id: `call_${++call}`, tool: "shell", input: { command } })
      } catch (error) {
        if (/Blocked/.test(String(error))) return "deny"
        throw error
      }
      return fake.asserts.length > before ? "ask" : "allow"
    },
  }
}

const HOME = "/home/test"
const ctx = { redactor: createRedactor(), home: HOME, cwd: `${HOME}/app`, protectedDirs: ["/opt/guard", "/srv/cfg"], pluginDirs: ["/opt/guard"] }
const DECISION = { baseURL: "http://127.0.0.1:9/v1", model: "m" }
const declaredBy = (options: Json) => () => [{ label: "global", options }, { label: "system", reason: "it is missing or unreadable" }]
/** Settings declared in the global configuration too (relaxations retained). */
const relaxed = (options: Json) => parseConfig(options, {}, declaredBy(options) as Parameters<typeof parseConfig>[2])
const policyOf = (options: Json) => (relaxed(options).config as { policy?: ActiveRules }).policy
const marked = (finding?: Finding) => Boolean(finding && (finding.dataOnly || finding.modelDecides !== undefined))
const brief = (finding?: Finding) => finding && [finding.verdict, finding.rule, marked(finding)]
const shell = (command: string, extra: Json = {}) => brief(toolFinding("shell", { command }, { ...ctx, ...extra }))
const ALLOW = async () => ({ answers: { risk: { score: 0.1 }, destructive: { noul: 0.01 }, exfiltration: { noul: 0.01 }, credentials: { noul: 0.01 }, privilege_persistence: { noul: 0.01 } } })
const BY_MODEL = { localAsks: "model", selfProtectionByModel: true }

async function decide(options: Json, tool: string, input: unknown) {
  const { config } = relaxed({ decision: DECISION, ...options })
  const decider = createDecider({ config, redactor: createRedactor(), home: HOME, model: ALLOW as never })
  return decider.decide({ tool, input, directory: `${HOME}/app` })
}

async function gateWith(options: Json) {
  const { config } = relaxed({ decision: DECISION, ...options })
  const fake = fakeContext()
  const redactor = createRedactor()
  const log = { debug() {}, info() {}, warn() {}, error() {} }
  const decider = createDecider({ config, redactor, home: HOME, model: ALLOW as never })
  await gate.registerGate(fake.ctx, { decider, redactor, log, home: HOME, rules: config.rules, active: (config as { policy?: ActiveRules }).policy })
  return {
    fake,
    before: (command: string) => fake.trigger("tool.execute.before", { sessionID: "ses_1", agent: "build", messageID: "msg_1", id: "call_1", tool: "shell", input: { command } }),
    evaluate: (command: string) => fake.trigger("permission.evaluate", { sessionID: "ses_1", action: "shell", resources: [command], effect: "allow", message: undefined as string | undefined }),
  }
}

describe("lot 48 step D: the command line", () => {
  it("BIN-1: Node runs the launcher without any option; help, rules, a write, exit codes", { skip: Boolean(process.versions.bun) }, async () => {
    const w = await world()
    const launcher = join(PLUGIN_DIR, "bin", "guard")
    assert.ok(readFileSync(launcher, "utf8").startsWith("#!/usr/bin/env node\n"))
    assert.ok((statSync(launcher).mode & 0o111) !== 0, "executable")
    // Environment built here, never inherited.
    const env = { ...w.env, PATH: `${dirname(process.execPath)}:/usr/bin:/bin`, TMPDIR: tmpdir() }
    const run = (...args: string[]) => spawnSync(process.execPath, [launcher, ...args], { cwd: w.project, env, encoding: "utf8", timeout: 60_000 })
    const help = run("help")
    assert.equal(help.status, 0, help.stderr)
    assert.match(help.stdout, /^Usage: guard <command>/)
    const rules = run("rules", "--builtins")
    assert.equal(rules.status, 0, rules.stderr)
    assert.equal(rules.stderr, "")
    assert.equal(rules.stdout.trim().split("\n").length, RULE_FEATURES.size)
    const allow = run("allow", "eval")
    assert.equal(allow.status, 0, allow.stderr)
    assert.ok(allow.stdout.includes(w.guardFile))
    assert.deepEqual(w.read(), { ruleOverrides: { eval: "allow" } })
    assert.equal(run("frobnicate").status, 2)
    assert.equal(run("allow", "nope").status, 1)
    assert.equal(run().status, 2)
  })

  it("BIN-2: rules lists the registry in order with group, own verdict and description, as docs/rules.md does", async () => {
    const w = await world()
    const r = w.run(["rules", "--builtins"])
    assert.equal(r.code, 0)
    const lines = r.out.split("\n")
    assert.deepEqual(lines.map((line) => line.split(/\s+/)[0]), [...RULE_FEATURES.keys()])
    const docs = readFileSync(join(PLUGIN_DIR, "docs", "rules.md"), "utf8")
    const rows = [...docs.matchAll(/^\| `([a-z0-9-]+)` \| (always active|`sensitiveFiles`|`dangerousCommands`) \| `(deny|ask)` \| (.*) \|$/gm)]
    assert.equal(rows.length, RULE_FEATURES.size)
    for (const [index, row] of rows.entries()) {
      const [rule, group, verdict, description] = [row[1]!, row[2]!, row[3]!, row[4]!.replaceAll("`", "").replaceAll("\\|", "|")]
      const feature = RULE_FEATURES.get(rule)!
      assert.equal(group, feature === "always" ? "always active" : `\`${feature}\``, rule)
      assert.match(lines[index]!, new RegExp(`^${rule}\\s+${feature}\\s+${verdict}\\s+`), rule)
      assert.ok(lines[index]!.endsWith(`  ${description}`), `${rule}: ${lines[index]}`)
    }
    assert.ok(lines.some((line) => /^guard-cli\s+always\s+ask\s+/.test(line)))
  })

  it("BIN-3: creation, addition, --agent, --project (git root or given), both, removal; unknown keys and mode kept, emptied objects removed", async () => {
    const w = await world()
    let r = w.run(["allow", "eval"])
    assert.equal(r.code, 0, r.err)
    assert.equal(r.out, `ruleOverrides.eval set to "allow" in the top level of ${w.guardFile}`)
    assert.equal(statSync(w.guardFile).mode & 0o777, 0o600)
    assert.equal(w.run(["deny", "git-reset-hard", "--agent", "build"]).code, 0)
    assert.equal(w.run(["ask", "rm", "--project"], join(w.project, "sub", "deep")).code, 0)
    assert.equal(w.run(["model", "privilege", "--project", w.home]).code, 0)
    assert.equal(w.run(["off", "kill", "--agent", "plan", "--project", "."]).code, 0)
    assert.deepEqual(w.read(), {
      ruleOverrides: { eval: "allow" },
      agents: { build: { ruleOverrides: { "git-reset-hard": "deny" } } },
      projects: { [w.project]: { ruleOverrides: { rm: "ask" }, agents: { plan: { ruleOverrides: { kill: "off" } } } }, [w.home]: { ruleOverrides: { privilege: "model" } } },
    })
    r = w.run(["allow", "eval"])
    assert.equal(r.code, 0)
    assert.match(r.out, /is already "allow" .*: nothing changed/)
    // Removal: emptied objects removed, the others kept.
    assert.equal(w.run(["reset", "kill", "--project", w.project, "--agent", "plan"]).code, 0)
    assert.equal(w.run(["reset", "privilege", "--project", w.home]).code, 0)
    assert.deepEqual(w.read(), { ruleOverrides: { eval: "allow" }, agents: { build: { ruleOverrides: { "git-reset-hard": "deny" } } }, projects: { [w.project]: { ruleOverrides: { rm: "ask" } } } })
    for (const args of [["reset", "eval"], ["reset", "git-reset-hard", "--agent", "build"], ["reset", "rm", "--project"]]) assert.equal(w.run(args).code, 0, args.join(" "))
    assert.deepEqual(w.read(), {})
    r = w.run(["reset", "eval"])
    assert.equal(r.code, 0)
    assert.match(r.out, /is not set in the top level of .*: nothing changed/)
    // Unknown keys and the file's mode kept.
    writeFileSync(w.guardFile, JSON.stringify({ note: "mine", agents: { build: { comment: 1, ruleOverrides: { eval: "deny" } } } }))
    chmodSync(w.guardFile, 0o640)
    assert.equal(w.run(["reset", "eval", "--agent", "build"]).code, 0)
    assert.equal(w.run(["ask", "kill"]).code, 0)
    assert.deepEqual(w.read(), { note: "mine", agents: { build: { comment: 1 } }, ruleOverrides: { kill: "ask" } })
    assert.equal(statSync(w.guardFile).mode & 0o777, 0o640)
    assert.deepEqual(readdirSync(w.globalDir).sort(), ["guard.json"])
    // Still set by the global opencode.json: said after the removal.
    const set = await world({ global: { ruleOverrides: { eval: "deny" } } })
    writeFileSync(set.guardFile, JSON.stringify({ ruleOverrides: { eval: "ask" } }))
    r = set.run(["reset", "eval"])
    assert.equal(r.code, 0)
    assert.match(r.out, /ruleOverrides\.eval is still "deny" there, set by global configuration/)
    // A directory that does not exist: refused.
    assert.equal(set.run(["allow", "eval", "--project", join(set.root, "missing")]).code, 1)
  })

  it("BIN-4: refused values, with the plugin's reason, nothing written", async () => {
    const w = await world({ global: { rules: [{ id: "no-deploy", verdict: "ask", pattern: "deploy" }] } })
    writeFileSync(w.guardFile, '{"keep": true}\n')
    for (const [args, reason] of [
      [["allow", "nope"], 'ruleOverrides["nope"] ignored: unknown rule'],
      [["deny", "internal-error"], "ruleOverrides.internal-error ignored: an internal error always asks"],
      [["allow", "no-deploy"], 'ruleOverrides["no-deploy"] ignored: it names one of your rules'],
      [["off", "self-protection"], 'ruleOverrides.self-protection "off" ignored: this rule is always active (only "deny" is accepted)'],
      [["allow", "placeholder"], 'ruleOverrides.placeholder "allow" ignored: this rule is always active'],
      [["ask", "guard-cli"], 'ruleOverrides.guard-cli "ask" ignored: this rule is always active'],
      [["model", "self-protection"], 'ruleOverrides.self-protection "model" ignored: this rule is always active ("model" needs selfProtectionByModel)'],
      [["model", "guard-cli"], 'ruleOverrides.guard-cli "model" ignored: this rule is about a change of the plugin\'s settings, never left to the decision model'],
    ] as const) {
      const r = w.run(args)
      assert.equal(r.code, 1, args.join(" "))
      assert.ok(r.err.includes("refused, nothing written") && r.err.includes(reason), r.err)
      assert.equal(readFileSync(w.guardFile, "utf8"), '{"keep": true}\n')
    }
    // "model" on an always-active rule: only where selfProtectionByModel is retained, never for guard-cli.
    writeFileSync(w.guardFile, JSON.stringify({ agents: { plan: { selfProtectionByModel: true } } }))
    assert.equal(w.run(["model", "self-protection", "--agent", "build"]).code, 1)
    assert.equal(w.run(["model", "self-protection"]).code, 1)
    assert.equal(w.run(["model", "self-protection", "--agent", "plan"]).code, 0)
    assert.equal(w.run(["model", "guard-cli", "--agent", "plan"]).code, 1)
    assert.equal(w.run(["deny", "guard-cli"]).code, 0)
    assert.deepEqual(w.read(), { agents: { plan: { selfProtectionByModel: true, ruleOverrides: { "self-protection": "model" } } }, ruleOverrides: { "guard-cli": "deny" } })
    // Usage errors.
    for (const args of [["allow"], ["allow", "eval", "extra"], ["allow", "eval", "--agent"], ["allow", "eval", "--path", "x"], ["show", "x"], ["trust", "a", "b"]]) assert.equal(w.run(args).code, 2, args.join(" "))
  })

  it("BIN-5: a file the plugin would ignore is never replaced (link, invalid, not an object, too large, not a regular file); nor a misshapen section", async () => {
    for (const [name, prepare, reason] of [
      ["link", (w: World) => (writeFileSync(join(w.root, "target.json"), "{}"), symlinkSync(join(w.root, "target.json"), w.guardFile)), "it is a symbolic link"],
      ["invalid", (w: World) => writeFileSync(w.guardFile, '{"a": '), "it is not valid JSON"],
      ["array", (w: World) => writeFileSync(w.guardFile, "[1]"), "it is not a JSON object"],
      ["large", (w: World) => writeFileSync(w.guardFile, JSON.stringify({ pad: "x".repeat(70_000) })), "it is larger than 65536 bytes"],
      ["directory", (w: World) => mkdirSync(w.guardFile), "it is not a regular file"],
      ["unreadable", (w: World) => (writeFileSync(w.guardFile, "{}"), chmodSync(w.guardFile, 0)), "it cannot be read"],
    ] as const) {
      // Every file is readable by root.
      if (name === "unreadable" && process.getuid?.() === 0) continue
      const w = await world()
      prepare(w)
      const before = lstatSync(w.guardFile)
      const r = w.run(["allow", "eval"])
      assert.equal(r.code, 1, name)
      assert.ok(r.err.includes(`${w.guardFile} is left as is: ${reason}`), r.err)
      const after = lstatSync(w.guardFile)
      assert.deepEqual([after.ino, after.mtimeMs, after.size, after.mode], [before.ino, before.mtimeMs, before.size, before.mode], name)
      if (name === "link") assert.equal(readFileSync(join(w.root, "target.json"), "utf8"), "{}")
    }
    for (const [content, args, reason] of [
      [{ agents: "x" }, ["allow", "eval", "--agent", "build"], '"agents" in the global guard.json is not an object'],
      [{ ruleOverrides: [] }, ["allow", "eval"], "ruleOverrides in the top level of the global guard.json is not an object"],
      [{ trustedProjects: "/x" }, ["trust"], 'trustedProjects in the global guard.json is neither "*" nor a list'],
      [{ pad: "x".repeat(65_490) }, ["allow", "eval"], "would be larger than 65536 bytes"],
    ] as const) {
      const w = await world()
      const text = JSON.stringify(content)
      writeFileSync(w.guardFile, text)
      const r = w.run(args)
      assert.equal(r.code, 1, args.join(" "))
      assert.ok(r.err.includes(reason), r.err)
      assert.equal(readFileSync(w.guardFile, "utf8"), text)
      assert.deepEqual(readdirSync(w.globalDir), ["guard.json"])
    }
  })

  it("BIN-6: trust and untrust (real path, git root, --all, warnings, missing directory, still trusted elsewhere)", async () => {
    const w = await world()
    let r = w.run(["trust"], join(w.project, "sub", "deep"))
    assert.equal(r.code, 0, r.err)
    assert.equal(r.out, `${w.project} added to trustedProjects in ${w.guardFile}`)
    assert.match(w.run(["trust", w.project]).out, /is already listed .*: nothing changed/)
    r = w.run(["trust", join(w.root, "missing")])
    assert.equal(r.code, 1)
    assert.ok(r.err.includes("does not exist"), r.err)
    r = w.run(["trust", "/"])
    assert.equal(r.code, 0)
    assert.ok(r.err.includes("warning: every project under / becomes trusted"), r.err)
    assert.ok(w.run(["trust", w.home]).err.includes(`warning: every project under ${w.home} becomes trusted`))
    assert.deepEqual(w.read(), { trustedProjects: [w.project, "/", w.home] })
    for (const dir of ["/", w.home]) assert.equal(w.run(["untrust", dir]).code, 0)
    r = w.run(["trust", "--all"])
    assert.ok(r.err.includes("warning: every project becomes trusted"), r.err)
    assert.deepEqual(w.read(), { trustedProjects: [w.project, "*"] })
    assert.equal(w.run(["untrust", "--all"]).code, 0)
    assert.equal(w.run(["untrust"]).code, 0)
    assert.deepEqual(w.read(), {})
    assert.equal(w.run(["trust", "--all"]).code, 0)
    assert.deepEqual(w.read(), { trustedProjects: "*" })
    r = w.run(["untrust", w.project])
    assert.equal(r.code, 1)
    assert.ok(r.err.includes("remove it first with untrust --all"), r.err)
    assert.equal(w.run(["untrust", "--all"]).code, 0)
    assert.deepEqual(w.read(), {})
    // A `.git` file (worktree) marks the project too.
    const tree = join(w.root, "tree")
    mkdirSync(join(tree, "sub"), { recursive: true })
    writeFileSync(join(tree, ".git"), "gitdir: elsewhere\n")
    assert.equal(w.run(["trust"], join(tree, "sub")).out, `${tree} added to trustedProjects in ${w.guardFile}`)
    assert.equal(w.run(["untrust", tree]).code, 0)
    // A directory that no longer exists can still be removed.
    const gone = join(w.root, "gone")
    writeFileSync(w.guardFile, JSON.stringify({ trustedProjects: [gone], other: 1 }))
    assert.equal(w.run(["untrust", gone]).code, 0)
    assert.deepEqual(w.read(), { other: 1 })
    // Listed by the global opencode.json too: still trusted, said.
    const listed = await world()
    writeFileSync(join(listed.globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: { trustedProjects: [listed.project] } }] }))
    r = listed.run(["untrust"])
    assert.equal(r.code, 0)
    assert.ok(r.out.includes(`${listed.project} is still trusted`), r.out)
  })
})

describe("lot 48 step D: effect without a restart", () => {
  it("BIN-7: the plugin starts without guard.json; allow, then --agent (next prompt), then trust apply after the re-read", async () => {
    const w = await world()
    const p = await plugin(w)
    assert.equal(await p.verdict("git reset --hard"), "ask")
    assert.equal(w.run(["allow", "git-reset-hard"]).code, 0)
    p.tick()
    assert.equal(await p.verdict("git reset --hard"), "allow")
    assert.equal(await p.verdict("sudo ls", "ses_1", "plan"), "ask")
    assert.equal(w.run(["allow", "privilege", "--agent", "plan"]).code, 0)
    p.tick()
    // Main agent not recorded yet: only the hardenings of the calling agent's section.
    assert.equal(await p.verdict("sudo ls", "ses_1", "plan"), "ask")
    await p.prompt("ses_1", "plan")
    assert.equal(await p.verdict("sudo ls", "ses_1", "plan"), "allow")
    // A project guard.json relaxes only once the project is trusted.
    mkdirSync(join(w.project, ".opencode"))
    writeFileSync(join(w.project, ".opencode", "guard.json"), JSON.stringify({ ruleOverrides: { "git-clean": "off" } }))
    p.tick()
    assert.equal(await p.verdict("git clean -fdx"), "ask")
    assert.equal(w.run(["trust"]).code, 0)
    p.tick()
    assert.equal(await p.verdict("git clean -fdx"), "allow")
  })

  it("BIN-8: the prompt hook is always there, reads a session only while an agent section is in force", async () => {
    const w = await world({ cli: false })
    const p = await plugin(w, { redactPrompt: false })
    await p.prompt("ses_1", "plan")
    assert.equal(p.lookups.session, 0)
    writeFileSync(w.guardFile, JSON.stringify({ agents: { plan: { ruleOverrides: { privilege: "off" } } } }))
    p.tick()
    await p.prompt("ses_1", "plan")
    assert.equal(await p.verdict("sudo ls", "ses_1", "plan"), "allow")
    assert.equal(p.lookups.session, 1)
    // The only prompt hook (no redaction): the main agents'.
    assert.equal(p.hooks.get("session.prompt")?.length, 1)
    assert.equal(await p.verdict("sudo ls", "ses_2", "plan"), "ask")
    rmSync(w.guardFile)
    p.tick()
    await p.prompt("ses_1", "plan")
    assert.equal(p.lookups.session, 1)
    assert.equal(await p.verdict("sudo ls", "ses_1", "plan"), "ask")
  })
})

describe("lot 48 step D: show and last", () => {
  it("BIN-9: show: settings in force with their origin, trust, what is set aside and what is not read; no other option's value", async () => {
    const w = await world({
      global: {
        decision: { baseURL: "https://decision.example.invalid/v1", model: "m", apiKey: "KEY-MARKER-1", headers: { "X-Test-Header": "HEADER-MARKER-2" } },
        ruleOverrides: { eval: "deny" },
      },
    })
    writeFileSync(
      w.guardFile,
      JSON.stringify({
        agents: { build: { ruleOverrides: { "git-reset-hard": "off" } } },
        projects: { [w.project]: { ruleOverrides: { rm: "deny" } } },
        trustedProjects: [join(w.root, "elsewhere")],
      }),
    )
    mkdirSync(join(w.project, ".opencode"))
    writeFileSync(join(w.project, ".opencode", "guard.json"), JSON.stringify({ ruleOverrides: { "git-clean": "off" } }))
    const r = w.run(["show", "--agent", "build"], join(w.project, "sub"))
    assert.equal(r.code, 0, r.err)
    for (const pattern of [
      new RegExp(`^Settings for ${join(w.project, "sub")} with the main agent build, read from:$`, "m"),
      /^ {2}global configuration \(opencode\.json\): declares the plugin$/m,
      /^ {2}Not read: the plugin options OpenCode merges from a project's opencode\.json/m,
      /^This project: not trusted \(trustedProjects: none\)$/m,
      /^ {2}dangerousCommands\s+true\s+default$/m,
      /^ {2}ruleOverrides\.eval\s+deny\s+global configuration$/m,
      /^ {2}ruleOverrides\.git-reset-hard\s+off\s+global guard\.json, agents\.build$/m,
      new RegExp(`^ {2}ruleOverrides\\.rm\\s+deny\\s+global guard\\.json, projects\\["${w.project}"\\]$`, "m"),
      /^Set aside:$/m,
      /ruleOverrides\.git-clean "off" ignored: its directory is not trusted/,
      /trustedProjects: ".*elsewhere" does not exist, ignored/,
    ])
      assert.match(r.out, pattern)
    for (const secret of ["KEY-MARKER-1", "HEADER-MARKER-2", "X-Test-Header", "decision.example.invalid"]) assert.ok(!r.out.includes(secret) && !r.err.includes(secret), secret)
    // Without --agent: the agent section does not count.
    assert.match(w.run(["show"]).out, /^ {2}ruleOverrides\.eval\s+deny\s+global configuration$/m)
    assert.ok(!w.run(["show"]).out.includes("git-reset-hard"))
  })

  it("BIN-10: last: asks and denials of the plugin's log with time, rule and reason, from the end; logFile as the plugin reads it", async () => {
    const w = await world()
    const log = join(w.data, "opencode", "log", "guard.log")
    mkdirSync(dirname(log), { recursive: true })
    writeFileSync(`${log}.1`, "2026-10-27T09:00:00.000Z INFO webfetch → deny (local, rule secret-network): secret in a web request\n")
    writeFileSync(
      log,
      [
        "2026-10-28T10:00:00.000Z INFO active (decision model: disabled; confirmations: ask)",
        "2026-10-28T10:00:01.000Z DEBUG read → allow (local): no rule",
        "2026-10-28T10:00:02.000Z INFO shell → ask (local, rule git-reset-hard): git reset --hard discards uncommitted changes",
        "2026-10-28T10:00:03.000Z INFO shell → confirmed by the user",
        "2026-10-28T10:00:04.000Z INFO shell → deny (local, rule rm-critical): recursive deletion of the home directory",
        "2026-10-28T10:00:05.000Z INFO shell sub-commands → ask (local, rule privilege): privilege escalation",
        "2026-10-28T10:00:06.000Z WARN guard.json re-read",
        "",
      ].join("\n"),
    )
    let r = w.run(["last", "2"])
    assert.equal(r.code, 0, r.err)
    assert.deepEqual(r.out.split("\n"), [
      `Latest asks and denials (${log}):`,
      "2026-10-28T10:00:04.000Z  deny  rm-critical  shell: recursive deletion of the home directory",
      "2026-10-28T10:00:05.000Z  ask  privilege  shell sub-commands: privilege escalation",
    ])
    r = w.run(["last"])
    assert.deepEqual(r.out.split("\n").slice(1, 3), [
      "2026-10-27T09:00:00.000Z  deny  secret-network  webfetch: secret in a web request",
      "2026-10-28T10:00:02.000Z  ask  git-reset-hard  shell: git reset --hard discards uncommitted changes",
    ])
    for (const count of ["0", "201", "x", "1.5"]) assert.equal(w.run(["last", count]).code, 2, count)
    // logFile of the plugin's options; refused in a protected location (OpenCode's configuration), like the plugin.
    const custom = join(w.root, "logs", "custom.log")
    mkdirSync(dirname(custom))
    writeFileSync(custom, "2026-10-28T11:00:00.000Z INFO edit → ask (local, rule self-protection): write to OpenCode's configuration\n")
    writeFileSync(join(w.globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: { logFile: custom } }] }))
    assert.match(w.run(["last", "1"]).out, /11:00:00\.000Z {2}ask {2}self-protection {2}edit: write/)
    writeFileSync(join(w.globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: { logFile: join(w.globalDir, "x.log") } }] }))
    assert.match(w.run(["last", "1"]).out, /10:00:05\.000Z {2}ask {2}privilege/)
    writeFileSync(join(w.globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: { logFile: false } }] }))
    assert.equal(w.run(["last"]).out, "The plugin writes no log file (logFile: false).")
  })
})

describe("lot 48 step D: guard-cli, the command line asks", () => {
  it("BIN-11: by its name, by its path, through an interpreter, read-only subcommands included; review() too; never the decision model", async () => {
    for (const command of [
      "guard rules",
      "guard show",
      "guard last 5",
      "guard allow eval --agent build",
      "/usr/local/bin/guard trust --all",
      "~/.local/bin/guard untrust",
      "sudo guard reset eval",
      "env X=1 guard rules",
      "timeout 5 guard show",
      'bash -c "guard deny eval"',
      "cd /tmp && guard rules",
      "node /opt/guard/bin/guard rules",
      "node ~/.local/bin/guard rules",
      "node /opt/guard/src/cli/main.ts show",
      "bun run /opt/guard/src/cli/write.ts",
      "/opt/guard/src/cli/main.ts",
    ])
      assert.deepEqual(shell(command), ["ask", "guard-cli", false], command)
    assert.deepEqual(shell("node bin/guard rules", { cwd: "/opt/guard" }), ["ask", "guard-cli", false])
    assert.deepEqual(shell("node ./src/cli/main.ts", { cwd: "/opt/guard" }), ["ask", "guard-cli", false])
    assert.deepEqual(shell("node main.ts", { cwd: "/opt/guard/src/cli" }), ["ask", "guard-cli", false])
    for (const command of ["git commit -m 'guard: fix'", "echo guard", "ls src/guard", "grep -r guard src", "node src/cli/main.ts", "cat notes.txt"])
      assert.notEqual(shell(command)?.[1], "guard-cli", command)
    assert.equal(RULE_FEATURES.get("guard-cli"), "always")
    // Shell sub-commands (`permission.evaluate`, review()).
    const reviewed = await (await gateWith({})).evaluate("guard show")
    assert.equal(reviewed.effect, "ask")
    assert.ok(String(reviewed.message).includes("guard-cli"), String(reviewed.message))
    // Never left to the decision model; "deny" accepted.
    const options = { ...BY_MODEL, ruleOverrides: { "guard-cli": "model" } }
    assert.ok(relaxed(options).warnings.includes('ruleOverrides.guard-cli "model" ignored: this rule is about a change of the plugin\'s settings, never left to the decision model'))
    assert.deepEqual(shell("guard rules", { active: policyOf(options) }), ["ask", "guard-cli", false])
    const decision = await decide(options, "shell", { command: "guard allow eval" })
    assert.deepEqual([decision.verdict, decision.rule], ["ask", "guard-cli"])
    assert.deepEqual(shell("guard rules", { active: policyOf({ ruleOverrides: { "guard-cli": "deny" } }) }), ["deny", "guard-cli", false])
  })

  it("BIN-12: what changes the plugin's settings is never left to the model, selfProtectionByModel included; the rest of self-protection is", async () => {
    const active = policyOf(BY_MODEL)
    for (const command of [
      "echo '{}' > ~/.config/opencode/guard.json",
      "echo '{}' > /home/test/app/.opencode/guard.json",
      "echo '{}' > .opencode/opencode.jsonc",
      "echo '{}' > /etc/opencode/opencode.json",
      "echo '{}' > /srv/cfg/guard.json",
      "echo x > /opt/guard/src/index.ts",
      "mv ~/.config/opencode /tmp/old-config",
      "opencode plugin remove guard",
      // A final name known only once expanded may be any file of the directory.
      "rm ~/.config/opencode/*.json",
      "echo x > ~/.config/opencode/$NAME",
    ])
      assert.deepEqual(shell(command, { active }), ["ask", "self-protection", false], command)
    for (const [tool, input] of [
      ["write", { path: `${HOME}/.config/opencode/guard.json`, content: "{}" }],
      ["edit", { path: `${HOME}/app/.opencode/opencode.json`, oldString: "a", newString: "b" }],
      ["patch", { patchText: `*** Begin Patch\n*** Add File: ${HOME}/app/.opencode/guard.json\n+{}\n*** End Patch` }],
    ] as const)
      assert.deepEqual(brief(toolFinding(tool, input, { ...ctx, active })), ["ask", "self-protection", false], tool)
    // A link from an agent file to the settings: its real path counts.
    const realPaths = (absolute: string) => (absolute === `${HOME}/.config/opencode/agents/a.md` ? [`${HOME}/.config/opencode/guard.json`] : undefined)
    assert.deepEqual(shell("echo x > ~/.config/opencode/agents/a.md", { active, realPaths }), ["ask", "self-protection", false])
    // The rest of self-protection: still left to the model.
    for (const command of ["echo x > ~/.config/opencode/agents/a.md", "echo x > /home/test/app/.opencode/commands/c.md", "echo x > /srv/cfg/skills/s.md"])
      assert.deepEqual(shell(command, { active }), ["ask", "self-protection", true], command)
    assert.deepEqual(brief(toolFinding("write", { path: `${HOME}/.config/opencode/agents/a.md`, content: "x" }, { ...ctx, active })), ["ask", "self-protection", true])
    // With a model that allows: decide, then execute.before.
    const settings = await decide(BY_MODEL, "shell", { command: "echo '{}' > ~/.config/opencode/guard.json" })
    const agent = await decide(BY_MODEL, "shell", { command: "echo x > ~/.config/opencode/agents/a.md" })
    assert.deepEqual([settings.verdict, settings.rule, agent.verdict], ["ask", "self-protection", "allow"])
    const g = await gateWith(BY_MODEL)
    await g.before("echo '{}' > ~/.config/opencode/guard.json")
    assert.equal(g.fake.asserts.length, 1)
    const h = await gateWith(BY_MODEL)
    await h.before("echo x > ~/.config/opencode/agents/a.md")
    assert.equal(h.fake.asserts.length, 0)
  })

  it("BIN-13 (guard): default settings: self-protection unchanged for every target, no real path looked up past it", () => {
    for (const command of ["echo '{}' > ~/.config/opencode/guard.json", "echo x > ~/.config/opencode/agents/a.md", "echo x > /opt/guard/src/index.ts", "opencode plugin remove guard", "echo x > ~/.config/opencode/$NAME"])
      assert.deepEqual(shell(command), ["ask", "self-protection", false], command)
    let lookups = 0
    const realPaths = () => (lookups++, undefined)
    assert.deepEqual(shell("echo x > ~/.config/opencode/agents/a.md", { realPaths }), ["ask", "self-protection", false])
    assert.deepEqual(brief(toolFinding("write", { path: `${HOME}/.config/opencode/agents/a.md`, content: "x" }, { ...ctx, realPaths })), ["ask", "self-protection", false])
    assert.equal(lookups, 0)
    assert.deepEqual(shell("git reset --hard"), ["ask", "git-reset-hard", false])
    assert.equal(shell("ls -la"), undefined)
  })
})

describe("lot 48 step D: documentation", () => {
  it("BIN-14: configuration.md describes the command line, README points to it, rules.md lists guard-cli", () => {
    const configuration = readFileSync(join(PLUGIN_DIR, "docs", "configuration.md"), "utf8")
    for (const text of ["## The `guard` command", "`guard allow <rule>`", "`--agent <name>`", "`--project [<dir>]`", "`guard trust [<dir>\\|--all]`", "`guard show [--agent <name>]`", "`guard last [<count>]`", "No confirmation in the terminal", "next prompt", "never left to the decision model"])
      assert.ok(configuration.includes(text), text)
    assert.ok(readFileSync(join(PLUGIN_DIR, "README.md"), "utf8").includes("docs/configuration.md#the-guard-command"))
    const rules = readFileSync(join(PLUGIN_DIR, "docs", "rules.md"), "utf8")
    assert.ok(rules.includes("| `guard-cli` | always active |"))
    assert.ok(rules.includes("another program named `guard`"))
  })
})
