// Lot 48 step E: corrections before the common review. A rule set to "ask" leaves none of its confirmations to the
// decision model (heredoc data, CodeMode's fetch); "model" on a rule that only denies is ignored with a warning, by the
// command line too; the plugin directories of a configuration directory and the service subcommands that change its
// environment or settings are changes of the plugin's settings, never left to the decision model. Only symbols the
// code of step D already exports are imported, so that it fails on assertions, not on loading.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { RULE_SUMMARIES } from "../src/cli/rules.ts"
import { parseConfig } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import * as gate from "../src/hooks/gate.ts"
import { RULE_FEATURES, type ActiveRules } from "../src/rules/features.ts"
import { toolFinding } from "../src/rules/tools.ts"
import type { Finding } from "../src/rules/types.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

type Json = Record<string, unknown>
const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
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

/** Heredoc written to a file: `rm` (no setting) asks first, then `privilege` in the same data. */
const TWO_RULES = "cat > notes.md <<'EOF'\nrm -rf build\nsudo apt install x\nEOF"
const ONE_RULE = "cat > notes.md <<'EOF'\nsudo apt install x\nEOF"
const FETCH = { code: "await fetch('https://x.invalid')" }

describe("lot 48 step E: a rule set to ask leaves none of its confirmations to the model", () => {
  it("COR-1: heredoc data: an ask of a rule set to ask is never marked, whichever ask won the combination", async () => {
    const active = policyOf({ ruleOverrides: { privilege: "ask" } })
    assert.deepEqual(shell(TWO_RULES, { active }), ["ask", "privilege", false])
    assert.deepEqual(shell(ONE_RULE, { active }), ["ask", "privilege", false])
    assert.deepEqual(shell(TWO_RULES, { active: policyOf({ ...BY_MODEL, ruleOverrides: { privilege: "ask" } }) }), ["ask", "privilege", false])
    // Through the decider with a model that allows, then the shell sub-commands OpenCode checks.
    const decision = await decide({ ruleOverrides: { privilege: "ask" } }, "shell", { command: TWO_RULES })
    assert.deepEqual([decision.verdict, decision.rule], ["ask", "privilege"])
    const reviewed = await (await gateWith({ ruleOverrides: { privilege: "ask" } })).evaluate(TWO_RULES)
    assert.equal(reviewed.effect, "ask")
    assert.ok(String(reviewed.message).includes("privilege"), String(reviewed.message))
    // A rule set to ask that does not ask there: the data stays with the model.
    assert.deepEqual(shell(ONE_RULE, { active: policyOf({ ruleOverrides: { rm: "ask" } }) }), ["ask", "privilege", true])
  })

  it("COR-2 (guard): without a setting, heredoc data is still left to the model", async () => {
    assert.deepEqual(shell(TWO_RULES), ["ask", "rm", true])
    assert.deepEqual(shell(ONE_RULE), ["ask", "privilege", true])
    const decision = await decide({}, "shell", { command: TWO_RULES })
    assert.equal(decision.verdict, "allow")
    assert.equal((await (await gateWith({})).evaluate(TWO_RULES)).effect, "allow")
  })

  it("COR-3: CodeMode's fetch: set to ask, the user confirms; without a setting, the model decides", async () => {
    const active = policyOf({ ruleOverrides: { "codemode-fetch": "ask" } })
    assert.deepEqual(brief(toolFinding("execute", FETCH, { ...ctx, active })), ["ask", "codemode-fetch", false])
    const asked = await decide({ ruleOverrides: { "codemode-fetch": "ask" } }, "execute", FETCH)
    assert.deepEqual([asked.verdict, asked.rule], ["ask", "codemode-fetch"])
    // Guard: no setting.
    assert.deepEqual(brief(toolFinding("execute", FETCH, ctx)), ["ask", "codemode-fetch", true])
    assert.equal((await decide({}, "execute", FETCH)).verdict, "allow")
  })
})

/** Configuration directories of a test, a project, and the command line run in process on them. */
async function world() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-cor-")))
  const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "work", "app")]
  for (const dir of [globalDir, systemDir, home, data, join(project, ".git")]) mkdirSync(dir, { recursive: true })
  writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: {} }] }))
  const env = { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }
  const { main } = (await import(new URL("../src/cli/main.ts", import.meta.url).href)) as { main: (argv: readonly string[], io: unknown) => number }
  const guardFile = join(globalDir, "guard.json")
  return {
    guardFile,
    run: (args: readonly string[]) => {
      const err: string[] = []
      const code = main(args, { env, cwd: project, systemDir, out: () => {}, err: (line: string) => err.push(line) })
      return { code, err: err.join("\n") }
    },
  }
}

describe("lot 48 step E: model on a rule that only denies", () => {
  const WARNING = 'ruleOverrides.placeholder "model" ignored: this rule only denies, it has no confirmation to leave to the decision model'

  it("COR-4: a warning that says so, with or without selfProtectionByModel; the setting has no effect", () => {
    for (const options of [{ selfProtectionByModel: true, ruleOverrides: { placeholder: "model" } }, { ruleOverrides: { placeholder: "model" } }]) {
      const { warnings, config } = relaxed(options)
      assert.ok(warnings.includes(WARNING), warnings.join("\n"))
      assert.equal((config as { policy?: ActiveRules }).policy?.overrides?.has("placeholder") ?? false, false)
    }
    // Every always-active rule that only denies (its own verdict) gets it.
    const denyOnly = [...RULE_FEATURES].filter(([rule, feature]) => feature === "always" && RULE_SUMMARIES.get(rule)?.verdict === "deny").map(([rule]) => rule)
    assert.deepEqual(denyOnly, ["placeholder"])
    // In an agent section too.
    const section = { agents: { plan: { selfProtectionByModel: true, ruleOverrides: { placeholder: "model" } } } }
    const sectioned = parseConfig(section, {}, declaredBy(section) as Parameters<typeof parseConfig>[2], { files: [], realPath: () => undefined })
    assert.ok(sectioned.warnings.some((line) => line.includes(WARNING)), sectioned.warnings.join("\n"))
  })

  it("COR-5: the command line refuses it with the same warning, nothing written", async () => {
    const w = await world()
    writeFileSync(w.guardFile, JSON.stringify({ agents: { plan: { selfProtectionByModel: true } } }))
    const before = readFileSync(w.guardFile, "utf8")
    const r = w.run(["model", "placeholder", "--agent", "plan"])
    assert.equal(r.code, 1, r.err)
    assert.ok(r.err.includes("refused, nothing written") && r.err.includes(WARNING), r.err)
    assert.equal(readFileSync(w.guardFile, "utf8"), before)
    // Guard: a rule that asks takes "model" where selfProtectionByModel is retained.
    assert.equal(w.run(["model", "self-protection", "--agent", "plan"]).code, 0)
  })

  it("COR-6 (guard): no warning for model on a rule that asks", () => {
    for (const options of [{ ruleOverrides: { eval: "model" } }, { selfProtectionByModel: true, ruleOverrides: { "self-protection": "model" } }]) {
      const { warnings } = relaxed(options)
      assert.deepEqual(warnings.filter((line) => line.includes("ruleOverrides")), [], JSON.stringify(options))
    }
  })
})

describe("lot 48 step E: plugin directories and service settings are never left to the model", () => {
  it("COR-7: the plugin or plugins directory of each configuration directory, by a tool, a command or a link", async () => {
    const active = policyOf(BY_MODEL)
    for (const command of [
      "echo x > ~/.config/opencode/plugin/p.ts",
      "cp p.ts ~/.config/opencode/plugins/",
      "echo x > .opencode/plugins/p.js",
      "echo x > /home/test/repo/.opencode/plugin/p.ts",
      "echo x > /etc/opencode/plugins/p.ts",
      "echo x > /srv/cfg/plugins/p.ts",
      "rm -rf ~/.config/opencode/plugin",
      "mv ~/.config/opencode/plugins /tmp/old-plugins",
      "ln -s /tmp/evil ~/.config/opencode/plugins/evil",
    ])
      assert.deepEqual(shell(command, { active }), ["ask", "self-protection", false], command)
    for (const [tool, input] of [
      ["write", { path: `${HOME}/.config/opencode/plugins/p.ts`, content: "x" }],
      ["edit", { path: `${HOME}/app/.opencode/plugin/p.ts`, oldString: "a", newString: "b" }],
      ["patch", { patchText: `*** Begin Patch\n*** Add File: /srv/cfg/plugin/p.ts\n+x\n*** End Patch` }],
    ] as const)
      assert.deepEqual(brief(toolFinding(tool, input, { ...ctx, active })), ["ask", "self-protection", false], tool)
    // A link from an agent file to a plugin directory: its real path counts.
    const realPaths = (absolute: string) => (absolute === `${HOME}/.config/opencode/agents/a.md` ? [`${HOME}/.config/opencode/plugins/a.ts`] : undefined)
    assert.deepEqual(shell("echo x > ~/.config/opencode/agents/a.md", { active, realPaths }), ["ask", "self-protection", false])
    // With a model that allows: decide, then execute.before.
    const decision = await decide(BY_MODEL, "shell", { command: "echo x > ~/.config/opencode/plugins/p.ts" })
    assert.deepEqual([decision.verdict, decision.rule], ["ask", "self-protection"])
    const g = await gateWith(BY_MODEL)
    await g.before("echo x > ~/.config/opencode/plugins/p.ts")
    assert.equal(g.fake.asserts.length, 1)
  })

  it("COR-8: service set and unset, in every form the rules read; review() too", async () => {
    const active = policyOf(BY_MODEL)
    for (const command of [
      "opencode service set env OPENCODE_CONFIG_DIR /tmp/x",
      "opencode service unset env GUARD_ASK_AS",
      "opencode service set password x",
      "/usr/local/bin/opencode service set env A b",
      "opencode --print-logs service unset env A",
      "X=1 opencode service set env A b",
    ])
      assert.deepEqual(shell(command, { active }), ["ask", "opencode-service", false], command)
    // "model" on the rule: the other service changes are left to the model, never these.
    const ruled = policyOf({ selfProtectionByModel: true, ruleOverrides: { "opencode-service": "model" } })
    assert.deepEqual(shell("opencode service set env A b", { active: ruled }), ["ask", "opencode-service", false])
    assert.deepEqual(shell("opencode service restart", { active: ruled }), ["ask", "opencode-service", true])
    const decision = await decide(BY_MODEL, "shell", { command: "opencode service set env A b" })
    assert.deepEqual([decision.verdict, decision.rule], ["ask", "opencode-service"])
    const g = await gateWith(BY_MODEL)
    await g.before("opencode service unset env A")
    assert.equal(g.fake.asserts.length, 1)
  })

  it("COR-9 (guard): agents, commands, skills, other names and the other service subcommands stay left to the model", async () => {
    const active = policyOf(BY_MODEL)
    for (const command of [
      "echo x > ~/.config/opencode/agents/a.md",
      "echo x > /home/test/app/.opencode/commands/c.md",
      "echo x > /srv/cfg/skills/s.md",
      "echo x > ~/.config/opencode/plugins-notes/n.md",
      "echo x > ~/.config/opencode/agent/plugin.md",
    ])
      assert.deepEqual(shell(command, { active }), ["ask", "self-protection", true], command)
    for (const command of ["opencode service restart", "opencode service stop", "opencode uninstall", "opencode pair"])
      assert.deepEqual(shell(command, { active }), ["ask", "opencode-service", true], command)
    assert.equal((await decide(BY_MODEL, "shell", { command: "echo x > ~/.config/opencode/agents/a.md" })).verdict, "allow")
    assert.equal((await decide(BY_MODEL, "shell", { command: "opencode service restart" })).verdict, "allow")
  })

  it("COR-10 (guard): default settings: same verdict, rule and mark for every new target", () => {
    for (const command of ["echo x > ~/.config/opencode/plugins/p.ts", "echo x > .opencode/plugin/p.ts", "echo x > ~/.config/opencode/agents/a.md"])
      assert.deepEqual(shell(command), ["ask", "self-protection", false], command)
    for (const command of ["opencode service set env A b", "opencode service restart"]) assert.deepEqual(shell(command), ["ask", "opencode-service", false], command)
    assert.deepEqual(brief(toolFinding("write", { path: `${HOME}/.config/opencode/plugins/p.ts`, content: "x" }, ctx)), ["ask", "self-protection", false])
  })
})
