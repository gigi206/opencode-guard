// Lot 48 step F2: corrections after the common review (configuration, decision model, command line). The decision model
// allows an ask (heredoc data, CodeMode's fetch, asks left to it by a setting) only when its configuration (address,
// model, switch) is the one the global sources declare, or the project is trusted; it may still deny. The command line
// redacts everything it prints, never overwrites a guard.json changed since it read it, and names the system
// configuration as an origin; control characters never reach the log. Nothing is launched: text is judged, the model is
// a function (or `fetch` replaced inside the process: no connection). Only existing exports are imported, so that the
// candidate before these corrections fails on assertions, not on loading.
import "./tmp.ts"
import assert from "node:assert/strict"
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import { setupGuard } from "../src/index.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { createLogger } from "../src/types.ts"
import { fakeContext } from "./fake-ctx.ts"
import { FAKE } from "./fixtures.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>
type Main = (argv: readonly string[], io: unknown) => number

const DECISION = { baseURL: "https://decision.local/v1", model: "nox-4b" }
/** The same model at another address (a repository's opencode.json replacing the plugin's options). */
const ELSEWHERE = { baseURL: "https://decision.example.org/v1", model: "nox-4b" }
const HEREDOC = "cat > notes.md <<'EOF'\nsudo apt install x\nEOF"
const FETCH = { code: "const r = await fetch('https://example.com/data.json'); return r.status" }

/** System One answers: low risk (allow), high risk (deny). */
const answers = (score: number) => ({
  answers: {
    risk: { type: "score", score, confidence: 0.9 },
    destructive: { type: "noul", noul: 0.01 },
    exfiltration: { type: "noul", noul: 0.01 },
    credentials: { type: "noul", noul: 0.01 },
    privilege_persistence: { type: "noul", noul: 0.01 },
  },
})
const ALLOW = async () => answers(0.1)
const DENY = async () => answers(2.9)

/** Decision on a call: effective options, and the plugin entry of the global configuration (absent: not declared). */
async function decide(options: Json, global: Json | undefined, tool: string, input: unknown, model = ALLOW) {
  const missing = { label: "system", reason: "it is missing or unreadable" }
  const declared = () => [global ? { label: "global", options: global } : { label: "global", reason: "it does not declare this plugin" }, missing]
  const { config } = parseConfig(options, {}, declared)
  return createDecider({ config, redactor: createRedactor(), home: "/home/test", model: model as never }).decide({ tool, input, directory: "/home/test/app" })
}
const shell = (options: Json, global: Json | undefined, command: string, model = ALLOW) => decide(options, global, "shell", { command }, model)

/** `fetch` answering as a chat gateway with this score, for the plugin set up as OpenCode does (no connection). */
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

/** Plugin set up as OpenCode does: global opencode.json and guard.json, effective options, session directory `<root>/work/app`. */
async function plugin(setup: { readonly options: Json; readonly global?: Json; readonly globalGuard?: (project: string) => Json }) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-cf2-")))
  const [globalDir, systemDir, project] = [join(root, "global"), join(root, "system"), join(root, "work", "app")]
  for (const dir of [globalDir, systemDir, project]) mkdirSync(dir, { recursive: true })
  if (setup.global) writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: setup.global }] }))
  if (setup.globalGuard) writeFileSync(join(globalDir, "guard.json"), JSON.stringify(setup.globalGuard(project)))
  const logFile = join(root, "guard.log")
  const fake = fakeContext({ logFile, ...setup.options })
  ;(fake.ctx.location as { directory: string }).directory = project
  await setupGuard(fake.ctx, {}, systemDir, globalDir)
  let call = 0
  return {
    log: () => readFileSync(logFile, "utf8"),
    verdict: async (command: string) => {
      const before = fake.asserts.length
      try {
        await fake.trigger("tool.execute.before", { sessionID: "ses_1", agent: "build", messageID: "msg_0", id: `call_${++call}`, tool: "shell", input: { command } })
      } catch (error) {
        if (/Blocked/.test(String(error))) return "deny"
        throw error
      }
      return fake.asserts.length > before ? "ask" : "allow"
    },
  }
}

/** Configuration directories of a test and the command line run in process on them. */
async function world(global?: Json, system?: Json) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-cf2-")))
  const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "work", "app")]
  for (const dir of [globalDir, systemDir, home, join(data, "opencode", "log"), join(project, ".git")]) mkdirSync(dir, { recursive: true })
  if (global) writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: global }] }))
  if (system) writeFileSync(join(systemDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: system }] }))
  const env = { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }
  const { main } = (await import(new URL("../src/cli/main.ts", import.meta.url).href)) as { main: Main }
  return {
    globalDir,
    guardFile: join(globalDir, "guard.json"),
    logFile: join(data, "opencode", "log", "guard.log"),
    run: (args: readonly string[], onErr?: () => void) => {
      const out: string[] = []
      const err: string[] = []
      const io = { env, cwd: project, systemDir, out: (line: string) => out.push(line), err: (line: string) => (onErr?.(), err.push(line)) }
      const code = main(args, io)
      return { code, out: out.join("\n"), err: err.join("\n") }
    },
  }
}

describe("lot 48 step F2: the decision model allows an ask only with the global configuration", () => {
  it("CF2-1: a project that replaces the model's address: heredoc data, CodeMode's fetch, asks left to it by a setting stay asks", async () => {
    const heredoc = await shell({ decision: ELSEWHERE }, { decision: DECISION }, HEREDOC)
    assert.equal(heredoc.verdict, "ask")
    assert.match(heredoc.reason, /opinion: allow/)
    assert.equal((await decide({ decision: ELSEWHERE }, { decision: DECISION }, "execute", FETCH)).verdict, "ask")
    const relaxed = { localAsks: "model" }
    assert.equal((await shell({ ...relaxed, decision: ELSEWHERE }, { ...relaxed, decision: DECISION }, "git reset --hard")).verdict, "ask")
    const byRule = { ruleOverrides: { "git-reset-hard": "model" } }
    assert.equal((await shell({ ...byRule, decision: ELSEWHERE }, { ...byRule, decision: DECISION }, "git reset --hard")).verdict, "ask")
    const self = { localAsks: "model", selfProtectionByModel: true }
    const agentFile = "echo x > ~/.config/opencode/agent/a.md"
    assert.equal((await shell({ ...self, decision: DECISION }, { ...self, decision: DECISION }, agentFile)).verdict, "allow")
    assert.equal((await shell({ ...self, decision: ELSEWHERE }, { ...self, decision: DECISION }, agentFile)).verdict, "ask")
    // Another model at the same address, or no declaration at all.
    assert.equal((await shell({ decision: { ...DECISION, model: "other-model" } }, { decision: DECISION }, HEREDOC)).verdict, "ask")
    assert.equal((await shell({ decision: DECISION }, undefined, HEREDOC)).verdict, "ask")
  })

  it("CF2-2 (guard): the global configuration's model allows as before; any model may still deny; calls without a rule unchanged", async () => {
    assert.equal((await shell({ decision: DECISION }, { decision: DECISION }, HEREDOC)).verdict, "allow")
    assert.equal((await decide({ decision: DECISION }, { decision: DECISION }, "execute", FETCH)).verdict, "allow")
    const relaxed = { localAsks: "model", decision: DECISION }
    assert.equal((await shell(relaxed, relaxed, "git reset --hard")).verdict, "allow")
    // Same address written differently, former name `jev` in the global file.
    assert.equal((await shell({ decision: DECISION }, { decision: { ...DECISION, baseURL: "https://DECISION.local/v1/" } }, HEREDOC)).verdict, "allow")
    assert.equal((await shell({ decision: DECISION }, { jev: DECISION }, HEREDOC)).verdict, "allow")
    // A model replaced by the project still denies, and judges the calls no rule matches.
    assert.equal((await shell({ decision: ELSEWHERE }, { decision: DECISION }, HEREDOC, DENY)).verdict, "deny")
    assert.equal((await shell({ decision: ELSEWHERE }, { decision: DECISION }, "ls -la", ALLOW)).verdict, "allow")
    assert.equal((await shell({ decision: ELSEWHERE }, { decision: DECISION }, "ls -la", DENY)).verdict, "deny")
  })

  it("CF2-3: the model switched off by the global configuration, on by the project: it does not allow", async () => {
    const off = { decision: DECISION, decisionModel: false }
    assert.equal((await shell({ decision: DECISION, decisionModel: true }, off, HEREDOC)).verdict, "ask")
    assert.equal((await shell({ decision: DECISION, profile: "standard" }, { decision: DECISION, profile: "credentials-only" }, HEREDOC)).verdict, "ask")
  })

  it("CF2-4: as OpenCode sets it up: a project's opencode.json replacing the address → ask and a startup warning; trusted project or same model → allowed", async () => {
    await withModel(0.1, async () => {
      const replaced = await plugin({ options: { decision: ELSEWHERE }, global: { decision: DECISION } })
      assert.equal(await replaced.verdict(HEREDOC), "ask")
      assert.match(replaced.log(), /WARN decision model not declared by the global configuration \(global configuration: another decision model address or model; system configuration: [^)]*\): it may deny, but never allows an ask left to it/)
      const warning = replaced.log().split("\n").find((line) => line.includes("not declared by the global configuration"))
      assert.ok(warning && !warning.includes("decision.example.org"), "address quoted in the warning")
      const same = await plugin({ options: { decision: DECISION }, global: { decision: DECISION } })
      assert.equal(await same.verdict(HEREDOC), "allow")
      assert.doesNotMatch(same.log(), /not declared by the global configuration/)
      const trusted = await plugin({ options: { decision: ELSEWHERE }, global: { decision: DECISION }, globalGuard: (project) => ({ trustedProjects: [project] }) })
      assert.equal(await trusted.verdict(HEREDOC), "allow")
      assert.doesNotMatch(trusted.log(), /not declared by the global configuration/)
    })
  })

  it("CF2-5: the global guard.json switches the model on: it allows; the same switch from the project does not", async () => {
    await withModel(0.1, async () => {
      const global = { decision: DECISION, decisionModel: false }
      const byGuard = await plugin({ options: global, global, globalGuard: () => ({ decisionModel: true }) })
      assert.equal(await byGuard.verdict(HEREDOC), "allow")
      const fromProject = await plugin({ options: { decision: DECISION, decisionModel: true }, global })
      assert.equal(await fromProject.verdict(HEREDOC), "ask")
    })
  })
})

describe("lot 48 step F2: the guard command line", () => {
  it("CF2-6: a guard.json changed while the command runs is never overwritten", async () => {
    const w = await world()
    let changed = false
    // `trust --all` warns between its read and its write: another writer changes the file then.
    const result = w.run(["trust", "--all"], () => {
      if (!changed) writeFileSync(w.guardFile, JSON.stringify({ ruleOverrides: { eval: "deny" } }))
      changed = true
    })
    assert.equal(result.code, 1)
    assert.match(result.err, /changed while the command ran; run it again/)
    assert.deepEqual(JSON.parse(readFileSync(w.guardFile, "utf8")), { ruleOverrides: { eval: "deny" } })
    assert.deepEqual(readdirSync(w.globalDir).filter((name) => name.endsWith(".tmp")), [])
    // Unchanged in between: written.
    assert.equal(w.run(["trust", "--all"]).code, 0)
    assert.equal(JSON.parse(readFileSync(w.guardFile, "utf8")).trustedProjects, "*")
  })

  it("CF2-7: show names the system configuration as the origin of its keys", async () => {
    const w = await world({}, { ruleOverrides: { eval: "deny" } })
    const result = w.run(["show"])
    assert.equal(result.code, 0)
    assert.match(result.out, /ruleOverrides\.eval\s+deny\s+system configuration/)
  })

  it("CF2-8: refusals and log lines are redacted, with the global configuration's secretPatterns", async () => {
    const w = await world({ secretPatterns: ["TESTCORP-[0-9]{8}"] })
    const refused = w.run(["deny", FAKE.github])
    assert.equal(refused.code, 1)
    assert.match(refused.err, /unknown rule/)
    assert.ok(!refused.err.includes(FAKE.github), "rule name printed in clear")
    writeFileSync(w.logFile, `2026-10-28T10:00:02.000Z INFO shell → ask (local, rule protected-write): writing to /tmp/${FAKE.openai} and TESTCORP-12345678\n`)
    const last = w.run(["last"])
    assert.equal(last.code, 0)
    assert.match(last.out, /protected-write/)
    assert.ok(!last.out.includes(FAKE.openai), "log line printed in clear")
    assert.ok(!last.out.includes("TESTCORP-12345678"), "secretPatterns not applied")
    assert.ok(existsSync(w.logFile))
  })
})

describe("lot 48 step F2: the plugin's log", () => {
  it("CF2-9: C1 and bidirectional control characters never reach a log line", () => {
    const file = join(realpathSync(mkdtempSync(join(tmpdir(), "guard-cf2-"))), "guard.log")
    const controls = [0x85, 0x9b, 0x61c, 0x200e, 0x200f, 0x202a, 0x202e, 0x2066, 0x2069].map((code) => String.fromCharCode(code))
    createLogger(false, file).info(`writing to /tmp/a${controls.join("b")}c`)
    const line = readFileSync(file, "utf8")
    assert.match(line, /writing to \/tmp\/a/)
    for (const control of controls) assert.ok(!line.includes(control), `U+${control.charCodeAt(0).toString(16)} written`)
  })
})
