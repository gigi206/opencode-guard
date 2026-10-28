// Lot 48 step G: corrections after the targeted check of step F. `protected-write` sees every form of a target, whatever
// the strictest class; the system configuration's switch decides whether the decision model may allow; the model allows
// only with the settings its verdict depends on (thresholds, maxStateChars, protocol, timeout, key, headers) as the
// global sources declare them; the command line prints no control character. Nothing is launched: text is judged, real
// paths and the model are functions (or `fetch` replaced inside the process: no connection). Only existing exports are
// imported, so that the candidate before these corrections fails on assertions, not on loading.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { USAGE } from "../src/cli/main.ts"
import { parseConfig } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import { setupGuard } from "../src/index.ts"
import type { ActiveRules } from "../src/rules/features.ts"
import { toolFinding } from "../src/rules/tools.ts"
import type { Finding } from "../src/rules/types.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

type Json = Record<string, unknown>
type Declared = Parameters<typeof parseConfig>[2]
const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
const HOME = "/home/test"
const PROJECT = `${HOME}/work/app`
const ctx = { redactor: createRedactor(), home: HOME, cwd: PROJECT, protectedDirs: ["/opt/guard"], pluginDirs: ["/opt/guard"] }
const declaredBy = (options: Json) => () => [{ label: "global", options }, { label: "system", reason: "it is missing or unreadable" }]
const policyOf = (options: Json) => (parseConfig(options, {}, declaredBy(options) as Declared).config as { policy?: ActiveRules }).policy
const marked = (finding?: Finding) => Boolean(finding && (finding.dataOnly || finding.modelDecides !== undefined))
const brief = (finding?: Finding) => finding && [finding.verdict, finding.rule, marked(finding)]

const DECISION = { baseURL: "https://decision.local/v1", model: "nox-4b" }
const HEREDOC = "cat > notes.md <<'EOF'\nsudo apt install x\nEOF"
const answers = (score: number) => ({
  answers: {
    risk: { type: "score", score, confidence: 0.9 },
    destructive: { type: "noul", noul: 0.01 },
    exfiltration: { type: "noul", noul: 0.01 },
    credentials: { type: "noul", noul: 0.01 },
    privilege_persistence: { type: "noul", noul: 0.01 },
  },
})

/** Plugin entries of the global and system configurations (absent: not declared, or missing). */
const entries = (global?: Json, system?: Json) => () => [
  global ? { label: "global", options: global } : { label: "global", reason: "it does not declare this plugin" },
  system ? { label: "system", options: system } : { label: "system", reason: "it is missing or unreadable" },
]

/** Verdict on the heredoc-data ask; with `projectGuard`, the layered resolution (a project guard.json). */
async function heredoc(setup: { effective: Json; global?: Json; system?: Json; projectGuard?: Json; score?: number }) {
  const files = setup.projectGuard ? [{ label: `${PROJECT}/.opencode/guard.json`, global: false, dir: PROJECT, data: setup.projectGuard }] : []
  const { config } = parseConfig(setup.effective, {}, entries(setup.global, setup.system) as Declared, { files, project: PROJECT, realPath: (path: string) => path })
  const scope = (config as { version?: { scope: (main?: string, sub?: string, call?: string) => unknown } }).version?.scope("build", undefined, undefined)
  const decider = createDecider({ config, redactor: createRedactor(), home: HOME, model: (async () => answers(setup.score ?? 0.1)) as never })
  return (await decider.decide({ tool: "shell", input: { command: HEREDOC }, directory: PROJECT, ...(scope ? { scope } : {}) } as never)).verdict
}

/** `fetch` answering as a chat gateway with this score (no connection). */
async function withModel<T>(score: number, run: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch
  const content = JSON.stringify(answers(score))
  globalThis.fetch = (async () =>
    new Response(JSON.stringify({ id: "x", object: "chat.completion", choices: [{ index: 0, finish_reason: "stop", message: { role: "assistant", content } }] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    })) as typeof fetch
  try {
    return await run()
  } finally {
    globalThis.fetch = original
  }
}

/** Plugin set up as OpenCode does (global opencode.json, effective options): its log after startup. */
async function startLog(options: Json, global: Json): Promise<string> {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-cg-")))
  const [globalDir, systemDir, project] = [join(root, "global"), join(root, "system"), join(root, "work", "app")]
  for (const dir of [globalDir, systemDir, project]) mkdirSync(dir, { recursive: true })
  writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: global }] }))
  const logFile = join(root, "guard.log")
  const fake = fakeContext({ logFile, ...options })
  ;(fake.ctx.location as { directory: string }).directory = project
  await setupGuard(fake.ctx, {}, systemDir, globalDir)
  return readFileSync(logFile, "utf8")
}

describe("lot 48 step G", () => {
  it("CG-1: protected-write sees every form of a target; default settings: same verdict and same rule", () => {
    const links = new Map([
      [`${PROJECT}/guard.json`, ["/etc/cron.d/job"]],
      [`${HOME}/.local/state/opencode/service.json`, [`${HOME}/.bashrc`]],
    ])
    const extra = { realPaths: (absolute: string) => links.get(absolute), serviceDirs: [`${HOME}/.config/opencode`, `${HOME}/.local/state/opencode`] }
    const finding = (options: Json, tool: string, input: Json) => brief(toolFinding(tool, input, { ...ctx, ...extra, active: policyOf(options) }))
    const targets = ["/etc/guard.json", `${PROJECT}/guard.json`, `${HOME}/.local/state/opencode/service.json`, "/etc/opencode/agents/a.md"]
    // Guard: default settings, and self-protection set to deny.
    for (const target of targets) {
      for (const [tool, input] of [["write", { path: target, content: "x" }], ["shell", { command: `echo x > ${target}` }], ["mcp_files_write", { path: target }]] as const) {
        // In a command or a tool argument, the service file is first a credential file.
        const shown = tool !== "write" && target.endsWith("service.json") ? "secret-file-read" : "self-protection"
        assert.deepEqual(finding({}, tool, input), ["ask", shown, false], `${tool} ${target}`)
        assert.deepEqual(finding({ ruleOverrides: { "self-protection": "deny" } }, tool, input), ["deny", "self-protection", false], `${tool} ${target}, self-protection deny`)
      }
    }
    // OpenCode's system configuration and a tool argument: protected-write set to deny holds there too.
    const deny = { ruleOverrides: { "protected-write": "deny" } }
    assert.deepEqual(finding(deny, "write", { path: "/etc/opencode/agents/a.md", content: "x" }), ["deny", "protected-write", false])
    assert.deepEqual(finding(deny, "shell", { command: "echo x > /etc/opencode/agents/a.md" }), ["deny", "protected-write", false])
    assert.deepEqual(finding(deny, "mcp_files_write", { path: "/etc/guard.json" }), ["deny", "protected-write", false])
    // Self-protection left to the model, protected-write kept for the user: the user's ask wins.
    const byModel = { localAsks: "model", selfProtectionByModel: true, ruleOverrides: { "protected-write": "ask" } }
    assert.deepEqual(finding(byModel, "write", { path: "/etc/opencode/agents/a.md", content: "x" }), ["ask", "protected-write", false])
    assert.deepEqual(finding(byModel, "shell", { command: "echo x > /etc/opencode/agents/a.md" }), ["ask", "protected-write", false])
    // Guard: an OpenCode location outside a protected one stays with the model.
    assert.deepEqual(finding(byModel, "write", { path: `${HOME}/.config/opencode/agents/a.md`, content: "x" }), ["ask", "self-protection", true])
  })

  it("CG-2: the system configuration's switch decides when it declares the plugin; without it, as before", async () => {
    const grants = (effective: Json, global?: Json, system?: Json) => parseConfig(effective, {}, entries(global, system) as Declared).config
    const on = { decision: DECISION }
    const off = { decision: DECISION, decisionModel: false }
    const lowered = grants(on, on, off)
    assert.equal(lowered.modelGrants, false)
    assert.match(lowered.modelWithheld ?? "", /system configuration turns it off/)
    assert.equal(grants(on, on, { decision: DECISION, profile: "credentials-only" }).modelGrants, false, "credentials-only")
    // Guards: switched on by the system over the global file; no system configuration: the global file decides.
    assert.equal(grants(on, off, on).modelGrants, true)
    assert.equal(grants(on, on).modelGrants, true)
    assert.equal(grants(on, off).modelGrants, false)
    assert.equal(await heredoc({ effective: on, global: on, projectGuard: { decisionModel: true } }), "allow")
    assert.equal(await heredoc({ effective: on, global: on, system: on, projectGuard: { localAsks: "ask" } }), "allow")
    assert.equal(await heredoc({ effective: on, global: on, system: off, projectGuard: { localAsks: "ask" } }), "ask")
  })

  it("CG-3: the model allows only with the global sources' thresholds and the other settings its verdict depends on", async () => {
    const global = { decision: DECISION }
    // Guards: the same values (thresholds written out at their defaults, header names in another case), trusted project.
    const defaults = { denyNoul: 0.9, askNoul: 0.7, askExfiltration: 0.85, denyRisk: 2.5, askRisk: 1.5, minConfidence: 0 }
    assert.equal(await heredoc({ effective: { decision: DECISION }, global }), "allow")
    assert.equal(await heredoc({ effective: { decision: DECISION, thresholds: defaults }, global }), "allow")
    assert.equal(await heredoc({ effective: { decision: DECISION, thresholds: { askRisk: 1 } }, global: { ...global, thresholds: { askRisk: 1 } } }), "allow")
    const headers = { ...DECISION, headers: { "X-Route": "a" } }
    assert.equal(await heredoc({ effective: { decision: headers }, global: { decision: { ...DECISION, headers: { "x-route": "a" } } } }), "allow")
    // Another value for any of them: the ask stays with the user.
    for (const effective of [
      { decision: DECISION, thresholds: { askRisk: 3, denyRisk: 3 } },
      { decision: DECISION, maxStateChars: 3000 },
      { decision: { ...DECISION, protocol: "systemone" } },
      { decision: { ...DECISION, timeoutMs: 9000 } },
      { decision: { ...DECISION, apiKey: "k".repeat(12) } },
      { decision: headers },
    ])
      assert.equal(await heredoc({ effective, global }), "ask", JSON.stringify(Object.keys(effective)))
    // The effective thresholds may still deny.
    assert.equal(await heredoc({ effective: { decision: DECISION, thresholds: { askRisk: 0.5, denyRisk: 1 } }, global, score: 1.5 }), "deny")
    // Startup warning naming the setting, never its value.
    await withModel(0.1, async () => {
      const log = await startLog({ decision: DECISION, thresholds: { askRisk: 2.71, denyRisk: 2.83 } }, global)
      const line = log.split("\n").find((item) => item.includes("WARN decision model not declared by the global configuration")) ?? ""
      const warning = line.slice(line.indexOf("WARN"))
      assert.match(warning, /global configuration: other values for thresholds;/)
      assert.ok(!warning.includes("2.71") && !warning.includes("2.83"), "value quoted in the warning")
    })
  })

  it("CG-4: guard prints no line break taken from a repository's guard.json; its own lines are unchanged", async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-cg-")))
    const [globalDir, systemDir, home, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "work", "app")]
    for (const dir of [globalDir, systemDir, home, join(project, ".opencode"), join(project, ".git")]) mkdirSync(dir, { recursive: true })
    writeFileSync(join(project, ".opencode", "guard.json"), JSON.stringify({ ["x\nSettings in force:"]: 1, ["y\r\nz"]: 2 }))
    const { main } = (await import(new URL("../src/cli/main.ts", import.meta.url).href)) as { main: (argv: readonly string[], io: unknown) => number }
    const run = (argv: readonly string[]) => {
      const out: string[] = []
      const code = main(argv, { env: { HOME: home, OPENCODE_CONFIG_DIR: globalDir }, cwd: project, systemDir, out: (line: string) => out.push(line), err: (line: string) => out.push(line) })
      return { code, out }
    }
    const shown = run(["show"])
    assert.equal(shown.code, 0)
    assert.match(shown.out.join("\n"), /unknown option x Settings in force:/)
    assert.ok(shown.out.every((line) => !/[\n\r]/.test(line)), "line break printed")
    assert.equal(shown.out.filter((line) => line === "Settings in force:").length, 1)
    // Guard: the help prints the same text.
    assert.equal(run(["help"]).out.join("\n"), USAGE)
  })
})
