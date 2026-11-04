// `agents.<id>` relaxations of the global sources: decided per request. What matters is what each hook leaves in clear:
// the real hooks are triggered, from a real guard.json, for the requests that must stay redacted as much as for the others.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { describe, it } from "node:test"
import { fileURLToPath } from "node:url"
import { main } from "../src/cli/main.ts"
import { registerRedaction } from "../src/hooks/redaction.ts"
import { setupGuard } from "../src/index.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
const SECRET = `ghp_${"a1B2c3D4e5".repeat(4).slice(0, 36)}`
const QWEN = { providerID: "linagora", id: "qwen3.8" }
const OTHER = { providerID: "openai", id: "gpt-x" }
type Json = Record<string, unknown>

async function world(guard: Json, options: { project?: Json; agents?: Json; env?: Json } = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-relax-")))
  const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "project")]
  for (const dir of [globalDir, systemDir, home, data, join(project, ".opencode")]) mkdirSync(dir, { recursive: true })
  writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: {} }] }))
  writeFileSync(join(globalDir, "guard.json"), JSON.stringify(guard))
  if (options.project) writeFileSync(join(project, ".opencode", "guard.json"), JSON.stringify(options.project))
  const fake = fakeContext(options.env ?? {})
  ;(fake.ctx as { location: { directory: string } }).location.directory = project
  fake.agents.set("n3", { mode: "primary", permissions: [] })
  fake.agents.set("reviewer", { mode: "subagent", permissions: [] })
  await setupGuard(fake.ctx, { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }, systemDir)
  fake.switchAgent("ses_1", "n3")
  fake.switchModel("ses_1", QWEN.providerID, QWEN.id)
  const prompt = async (text = "hello", sessionID = "ses_1") => fake.trigger("session.prompt", { sessionID, messageID: `msg_${Math.random()}`, prompt: { text } })
  const http = async (fields: Json) => {
    const request = new Request("https://provider.example/v1/chat", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ messages: [{ content: SECRET }] }) })
    const event = await fake.trigger("session.http.request", { kind: "primary", sessionID: "ses_1", agent: "n3", model: QWEN, ...fields, request })
    return (await (event as { request: Request }).request.text()).includes(SECRET)
  }
  const ws = async (fields: Json) => {
    const event = await fake.trigger("session.experimental.ws.send", { kind: "primary", sessionID: "ses_1", agent: "n3", model: QWEN, ...fields, frame: JSON.stringify({ text: SECRET }) })
    return (event as { frame: string }).frame.includes(SECRET)
  }
  const tool = async (agent = "n3", sessionID = "ses_1") => {
    const event = await fake.trigger("tool.execute.after", { sessionID, agent, id: `call_${Math.random()}`, tool: "bash", status: "completed", result: { content: [{ type: "text", text: SECRET }] } })
    return JSON.stringify((event as { result: unknown }).result).includes(SECRET)
  }
  return { fake, prompt, http, ws, tool, globalDir, systemDir, home, data, project }
}

const RELAXED = { redactOutputs: false, redactPrompt: false, redactWire: false, models: ["linagora/qwen3.8"] }

describe("agent relaxations, request by request", () => {
  it("AR-1: the chosen agent on its model goes out in clear, on every path", async () => {
    const w = await world({ agents: { n3: RELAXED } })
    const before = await w.prompt(`token ${SECRET}`)
    assert.ok((before as { prompt: { text: string } }).prompt.text.includes(SECRET))
    assert.equal(await w.http({}), true)
    assert.equal(await w.ws({}), true)
    assert.equal(await w.tool(), true)
  })

  it("AR-2: title, compaction and generation stay redacted, even carrying the agent's name", async () => {
    const w = await world({ agents: { n3: RELAXED } })
    await w.prompt()
    for (const kind of ["title", "compaction", "generate"]) {
      assert.equal(await w.http({ kind }), false, kind)
      assert.equal(await w.ws({ kind }), false, kind)
    }
    assert.equal(await w.http({ kind: "title", agent: "title" }), false)
  })

  it("AR-3: another model, or no model, stays redacted; on the wire the request's model decides, not the session's", async () => {
    const w = await world({ agents: { n3: RELAXED } })
    await w.prompt()
    assert.equal(await w.http({ model: OTHER }), false)
    assert.equal(await w.http({ model: undefined }), false)
    assert.equal(await w.ws({ model: OTHER }), false)
    w.fake.switchModel("ses_1", OTHER.providerID, OTHER.id)
    await w.prompt()
    assert.equal(await w.tool(), false)
    assert.equal((await w.prompt(`token ${SECRET}`)).prompt.text.includes(SECRET), false)
  })

  it("AR-3b: a session without a model of its own runs its agent's, which decides the same way", async () => {
    const w = await world({ agents: { n3: RELAXED, other: RELAXED } })
    w.fake.agents.set("n3", { mode: "primary", permissions: [], model: QWEN } as never)
    w.fake.switchAgent("ses_2", "n3")
    assert.ok((await w.prompt(`token ${SECRET}`, "ses_2")).prompt.text.includes(SECRET))
    assert.equal(await w.tool("n3", "ses_2"), true)
    w.fake.agents.set("other", { mode: "primary", permissions: [], model: OTHER } as never)
    w.fake.switchAgent("ses_3", "other")
    assert.equal((await w.prompt(`token ${SECRET}`, "ses_3")).prompt.text.includes(SECRET), false)
    assert.equal(await w.tool("other", "ses_3"), false)
  })

  it("AR-4: another agent, or an agent never selected at a prompt, stays redacted", async () => {
    const w = await world({ agents: { n3: RELAXED } })
    assert.equal(await w.http({}), false, "no prompt recorded yet")
    await w.prompt()
    assert.equal(await w.http({ agent: "build" }), false)
    assert.equal(await w.tool("build"), false)
    // A switch made during the turn does not count until the next prompt.
    w.fake.switchAgent("ses_1", "build")
    assert.equal(await w.http({ agent: "build" }), false)
    assert.equal(await w.http({}), true)
    await w.prompt()
    assert.equal(await w.http({}), false)
  })

  it("AR-5: a subagent of the relaxed agent inherits nothing", async () => {
    const w = await world({ agents: { n3: RELAXED } })
    await w.prompt()
    w.fake.switchAgent("ses_child", "reviewer")
    w.fake.setParent("ses_child", "ses_1")
    await w.prompt("task", "ses_child")
    assert.equal(await w.http({ sessionID: "ses_child", agent: "reviewer" }), false)
    assert.equal(await w.http({ sessionID: "ses_child", agent: "n3" }), false)
    assert.equal(await w.tool("reviewer", "ses_child"), false)
    assert.equal(await w.tool("n3", "ses_child"), false)
    // A child session whose own agent is unknown is still not the root.
    w.fake.setParent("ses_blank", "ses_1")
    assert.equal((await w.prompt(`token ${SECRET}`, "ses_blank")).prompt.text.includes(SECRET), false)
    assert.equal(await w.http({ sessionID: "ses_blank" }), false)
    assert.equal(await w.tool("n3", "ses_blank"), false)
  })

  it("AR-1b: with redactPrompt off, the prompt check sees a redacted copy and can only block", async () => {
    const seen: string[] = []
    const fake = fakeContext()
    const relaxed = { guardOff: false, off: new Set(["redactPrompt"]), origins: new Map() }
    await registerRedaction(fake.ctx, {
      redactor: createRedactor(),
      redactPrompt: true,
      redactOutputs: true,
      log: { debug() {}, info() {}, warn() {}, error() {} },
      relaxation: () => relaxed as never,
      promptCheck: { check: async (_: unknown, text: string) => (seen.push(text), { text: "masked", count: 1 }), confirm: async () => undefined } as never,
    } as never)
    const event = await fake.trigger("session.prompt", { sessionID: "ses_1", messageID: "m", prompt: { text: `token ${SECRET}` } })
    assert.equal(seen.length, 1)
    assert.equal(seen[0]!.includes(SECRET), false)
    assert.equal(event.prompt.text, `token ${SECRET}`)
  })

  it("AR-5b: a model written with its variant, as in an agent file, still matches", async () => {
    const w = await world({ agents: { n3: { ...RELAXED, models: ["linagora/qwen3.8#high"] } } })
    await w.prompt()
    assert.equal(await w.http({}), true)
    assert.equal(await w.http({ model: OTHER }), false)
  })

  it("AR-6: a project never relaxes, even trusted, and may take a relaxation back", async () => {
    const asked = await world({ agents: {} }, { project: { agents: { n3: RELAXED } } })
    await asked.prompt()
    assert.equal(await asked.http({}), false)
    const trusted = await world({ trustedProjects: ["*"], agents: {} }, { project: { agents: { n3: { ...RELAXED, guard: "off" } } } })
    await trusted.prompt()
    assert.equal(await trusted.http({}), false)
    const hardened = await world({ agents: { n3: RELAXED } }, { project: { agents: { n3: { redactWire: true } } } })
    await hardened.prompt()
    assert.equal(await hardened.http({}), false)
    assert.equal(await hardened.tool(), true, "the other relaxations stay")
  })

  it("AR-7: only what is listed is relaxed; one key alone leaves the wire net in place", async () => {
    const w = await world({ agents: { n3: { redactOutputs: false, models: ["linagora/qwen3.8"] } } })
    await w.prompt()
    assert.equal(await w.tool(), true)
    assert.equal(await w.http({}), false)
    assert.equal((await w.prompt(`token ${SECRET}`)).prompt.text.includes(SECRET), false)
  })

  it("AR-8: invalid models, a built-in agent and unattended mode relax nothing", async () => {
    for (const models of [[], "linagora/qwen3.8", ["qwen3.8"], [1]]) {
      const w = await world({ agents: { n3: { ...RELAXED, models } } })
      await w.prompt()
      assert.equal(await w.http({}), false, JSON.stringify(models))
    }
    const built = await world({ agents: { build: RELAXED } })
    built.fake.switchAgent("ses_1", "build")
    await built.prompt()
    assert.equal(await built.http({ agent: "build" }), false)
    const unattended = await world({ agents: { n3: RELAXED } }, { env: { askAs: "deny" } })
    await unattended.prompt()
    assert.equal(await unattended.http({}), false)
  })

  it("AR-9: without models, any model of the chosen agent; the agent and the kind still count", async () => {
    const w = await world({ agents: { n3: { redactWire: false } } })
    await w.prompt()
    assert.equal(await w.http({ model: OTHER }), true)
    assert.equal(await w.http({ kind: "title" }), false)
    assert.equal(await w.http({ agent: "build" }), false)
  })

  it("AR-10: guard off lifts the rules for several agents, on their model only, and keeps the placeholder rule", async () => {
    const off = { guard: "off", models: ["linagora/qwen3.8"] }
    const w = await world({ agents: { n3: off, other: off } })
    w.fake.agents.set("other", { mode: "primary", permissions: [] })
    await w.prompt()
    assert.equal(await w.http({}), true)
    assert.equal(await w.http({ kind: "compaction" }), false)
    assert.equal(await w.http({ model: OTHER }), false)
    const call = (input: Json) => w.fake.trigger("tool.execute.before", { sessionID: "ses_1", agent: "n3", messageID: "msg_1", id: `c${Math.random()}`, tool: "shell", input })
    await call({ command: "rm -rf /" })
    await assert.rejects(call({ command: "echo [[GUARD_REDACTED:openai_key]] > f" }), /placeholder|Blocked/i)
    w.fake.switchAgent("ses_2", "other")
    w.fake.switchModel("ses_2", QWEN.providerID, QWEN.id)
    await w.prompt("hi", "ses_2")
    assert.equal(await w.http({ sessionID: "ses_2", agent: "other" }), true)
    w.fake.switchModel("ses_1", OTHER.providerID, OTHER.id)
    await w.prompt()
    await assert.rejects(call({ command: "rm -rf /" }), /Blocked/)
  })

  it("AR-11: redaction alone keeps the local rules", async () => {
    const w = await world({ agents: { n3: RELAXED } })
    await w.prompt()
    const call = { sessionID: "ses_1", agent: "n3", messageID: "msg_1", id: "c1", tool: "shell", input: { command: "rm -rf /" } }
    await assert.rejects(w.fake.trigger("tool.execute.before", call), /Blocked/)
  })

  it("AR-12: guard show marks them, guard agent writes them and takes them back", async () => {
    const w = await world({})
    const env = { HOME: w.home, OPENCODE_CONFIG_DIR: w.globalDir, XDG_DATA_HOME: w.data }
    const run = (...args: string[]) => {
      const out: string[] = []
      const err: string[] = []
      const code = main(args, { env, cwd: w.project, systemDir: w.systemDir, out: (line) => out.push(line), err: (line) => err.push(line) })
      return { code, out: out.join("\n"), err: err.join("\n") }
    }
    const file = () => JSON.parse(readFileSync(join(w.globalDir, "guard.json"), "utf8")) as { agents?: Record<string, Json> }
    assert.equal(run("agent", "off", "n3", "--model", "linagora/qwen3.8").code, 0)
    assert.deepEqual(file().agents?.n3, { guard: "off", models: ["linagora/qwen3.8"] })
    const shown = run("show", "--agent", "n3").out
    assert.match(shown, /agents\.n3\.guard\s+off/)
    assert.match(shown, /agents\.n3\.models\s+linagora\/qwen3\.8/)
    assert.equal(run("agent", "set", "n3", "redactWire", "false").code, 0)
    assert.equal(file().agents?.n3?.redactWire, false)
    assert.equal(run("agent", "on", "n3").code, 0)
    assert.equal(file().agents?.n3, undefined)
    assert.equal(run("agent", "off", "build").code, 1)
    assert.equal(file().agents?.build, undefined)
    assert.equal(run("agent", "off", "n3", "--model", "qwen3.8").code, 1)
    assert.equal(run("agent", "set", "n3", "nope", "false").code, 2)
    assert.equal(run("agent").code, 2)
  })
})
