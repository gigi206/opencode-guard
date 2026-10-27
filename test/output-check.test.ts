import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { describe, it } from "node:test"
import { fileURLToPath } from "node:url"
import { DEFAULT_OUTPUT_CHECK, parseConfig } from "../src/config.ts"
import { registerOutputCheck, withhold, withheldNotice } from "../src/hooks/output-check.ts"
import { setupGuard } from "../src/index.ts"
import { ModelError, type ModelRequest, type ModelResponse } from "../src/model/client.ts"
import { OUTPUT_QUESTION_ID } from "../src/model/questions.ts"
import { declaredOutputCheck, globalConfigDirectory } from "../src/output-check.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"
import { FAKE } from "./fixtures.ts"

const PLUGIN = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const URL_A = "https://ai-api.example.test/v1"
const temp = (prefix: string) => mkdtempSync(join(tmpdir(), `guard-oc-${prefix}-`))
const entry = (options: unknown) => JSON.stringify({ plugins: [{ package: PLUGIN, options }] })

describe("batch 32: outputCheck option", () => {
  const parse = (value: unknown) => parseConfig({ outputCheck: value })
  it("absent, false, empty or enabled false → not requested; true, string, object → provisional or settled values", () => {
    for (const value of [undefined, false, "", "false", "0", { enabled: false }, { enabled: "false" }]) assert.equal(parse(value).config.outputCheck, undefined)
    assert.deepEqual(parse(true).config.outputCheck, DEFAULT_OUTPUT_CHECK)
    assert.deepEqual(parse("TRUE").config.outputCheck, DEFAULT_OUTPUT_CHECK)
    assert.deepEqual(parse({ threshold: "0,8", timeoutMs: 1500 }).config.outputCheck, { threshold: 0.8, timeoutMs: 1500 })
  })
  it("default values calibrated for nox-4b (2026-10-17): threshold 0.45, timeout 1100 ms", () => {
    assert.deepEqual(DEFAULT_OUTPUT_CHECK, { threshold: 0.45, timeoutMs: 1100 })
  })
  it("invalid value, unknown key, threshold out of bounds → warning", () => {
    assert.match(parse("maybe").warnings.join("\n"), /invalid value for outputCheck/)
    assert.match(parse({ threshhold: 1 }).warnings.join("\n"), /unknown option outputCheck\.threshhold/)
    const out = parse({ threshold: 2 })
    assert.equal(out.config.outputCheck?.threshold, DEFAULT_OUTPUT_CHECK.threshold)
    assert.match(out.warnings.join("\n"), /invalid value for outputCheck\.threshold/)
  })
})

describe("batch 32: declaration in the global file (option effective only if present there, same address)", () => {
  const check = (globalDir: string | undefined, env: Record<string, string> = {}, systemDir?: string, effective = URL_A) =>
    declaredOutputCheck({ pluginDir: PLUGIN, effectiveBaseURL: effective, globalDir, systemDir, env })
  const withGlobal = (text: string, name = "opencode.json") => {
    const dir = temp("global")
    writeFileSync(join(dir, name), text)
    return dir
  }
  it("declared with the same address → active (trailing slash, JSONC, old jev name)", () => {
    assert.deepEqual(check(withGlobal(entry({ outputCheck: true, decision: { baseURL: URL_A } }))), { active: true })
    assert.deepEqual(check(withGlobal(entry({ outputCheck: { threshold: 0.9 }, decision: { baseURL: `${URL_A}/` } }))), { active: true })
    const jsonc = `// commentaire\n{ "plugins": [ { "package": "${PLUGIN}", /* c */ "options": { "outputCheck": "true", "jev": { "baseURL": "${URL_A}" }, }, }, ], }`
    assert.deepEqual(check(withGlobal(jsonc, "opencode.jsonc")), { active: true })
  })
  it("{env:…} resolved with the server environment; missing variable → inactive", () => {
    const dir = withGlobal(entry({ outputCheck: "{env:GUARD_OC}", decision: { baseURL: "{env:GUARD_URL}" } }))
    assert.deepEqual(check(dir, { GUARD_OC: "true", GUARD_URL: URL_A }), { active: true })
    assert.equal(check(dir, { GUARD_URL: URL_A }).active, false)
    assert.equal(check(dir, { GUARD_OC: "true" }).active, false)
  })
  it("each ambiguous case → inactive, with a reason in words", () => {
    const reason = (dir: string | undefined) => {
      const state = check(dir)
      assert.equal(state.active, false)
      return state.active ? "" : state.reason
    }
    assert.match(reason(undefined), /global configuration directory unknown/)
    assert.match(reason(temp("empty")), /global configuration: it is missing or unreadable/)
    assert.match(reason(withGlobal("{ not json")), /global configuration: it is not valid JSON/)
    assert.match(reason(withGlobal(JSON.stringify({ plugins: ["/other/plugin"] }))), /does not declare this plugin/)
    assert.match(reason(withGlobal(JSON.stringify({ plugins: [PLUGIN] }))), /outputCheck is not enabled there/)
    assert.match(reason(withGlobal(entry({ decision: { baseURL: URL_A } }))), /outputCheck is not enabled there/)
    assert.match(reason(withGlobal(entry({ outputCheck: false, decision: { baseURL: URL_A } }))), /outputCheck is not enabled there/)
    assert.match(reason(withGlobal(entry({ outputCheck: true, decision: { baseURL: "https://attacker.example.test/v1" } }))), /address differs/)
    assert.match(reason(withGlobal(entry({ outputCheck: true }))), /address differs/)
    assert.match(reason(withGlobal(entry({ outputCheck: true, decision: { baseURL: "{file:~/url.txt}" } }))), /\{file:…\} reference/)
  })
  it("system configuration that declares it → active even without a global file; different effective address → inactive", () => {
    const system = withGlobal(entry({ outputCheck: true, decision: { baseURL: URL_A } }))
    assert.deepEqual(check(temp("none"), {}, system), { active: true })
    assert.equal(check(temp("none"), {}, system, "https://attacker.example.test/v1").active, false)
  })
  it("global directory: OPENCODE_CONFIG_DIR, otherwise XDG_CONFIG_HOME, otherwise ~/.config (like OpenCode 2.0.31)", () => {
    assert.equal(globalConfigDirectory({ OPENCODE_CONFIG_DIR: "/c", XDG_CONFIG_HOME: "/x", HOME: "/h" }), "/c")
    assert.equal(globalConfigDirectory({ XDG_CONFIG_HOME: "/x", HOME: "/h" }), "/x/opencode")
    assert.equal(globalConfigDirectory({ HOME: "/h" }), "/h/.config/opencode")
    assert.equal(globalConfigDirectory({}), undefined)
  })
})

/** Fake model: records the received states and answers with the requested probability (or throws). */
function fakeModel(answer: (request: ModelRequest) => ModelResponse | Error) {
  const states: unknown[] = []
  const model = async (request: ModelRequest) => {
    states.push(request.state)
    const out = answer(request)
    if (out instanceof Error) throw out
    return out
  }
  return { model, states }
}
const noul = (p: number): ModelResponse => ({ answers: { [OUTPUT_QUESTION_ID]: { type: "noul", noul: p } } })

function capture() {
  const lines: string[] = []
  const log = {
    debug: (m: string) => lines.push(`DEBUG ${m}`),
    info: (m: string) => lines.push(`INFO ${m}`),
    warn: (m: string) => lines.push(`WARN ${m}`),
    error: (m: string) => lines.push(`ERROR ${m}`),
  }
  return { log, lines }
}

async function setup(answer: (request: ModelRequest) => ModelResponse | Error, extra: Record<string, unknown> = {}) {
  const fake = fakeContext()
  const { model, states } = fakeModel(answer)
  const { log, lines } = capture()
  await registerOutputCheck(fake.ctx, {
    redactor: createRedactor(),
    model,
    label: "nox-4b",
    threshold: 0.7,
    maxStateChars: 4000,
    askAs: "ask",
    cacheTtlMs: 600_000,
    cacheMax: 500,
    log,
    ...extra,
  })
  return { fake, states, lines }
}

const base = { sessionID: "ses_1", agent: "build", messageID: "msg_1", input: {} }
const done = (tool: string, result: Record<string, unknown>, id = "call_1") => ({ ...base, id, tool, status: "completed" as const, result })

describe("batch 32: output check (fake model)", () => {
  it("redacted copy sent even without redaction at the source: never a known secret in the received state", async () => {
    const { fake, states } = await setup(() => noul(0.1))
    const event = done("webfetch", { output: `token ${FAKE.openai}`, content: [{ type: "text", text: `key=${FAKE.openai}` }] })
    await fake.trigger("tool.execute.after", event)
    assert.equal(states.length, 1)
    const sent = JSON.stringify(states[0])
    assert.ok(!sent.includes(FAKE.openai), sent)
    assert.match(sent, /GUARD_REDACTED/)
    // The hook does not redact the output itself (that is the redaction hook's job): only the copy sent is redacted.
    assert.equal(event.result.output, `token ${FAKE.openai}`)
  })
  it("below the threshold → nothing changes, no request", async () => {
    const { fake, states } = await setup(() => noul(0.2))
    const event = done("chrome-devtools-mcp_evaluate_script", { output: { value: "page title" }, content: [{ type: "text", text: "page title" }] })
    await fake.trigger("tool.execute.after", event)
    assert.equal(states.length, 1)
    assert.equal(fake.asserts.length, 0)
    assert.deepEqual(event.result.output, { value: "page title" })
  })
  it("flagged, confirmation granted → output passed through; a single guard request with the reason", async () => {
    const { fake } = await setup(() => noul(0.9))
    const event = done("webfetch", { output: "db password is hunter-two-x", content: [{ type: "text", text: "db password is hunter-two-x" }] })
    await fake.trigger("tool.execute.after", event)
    assert.equal(fake.asserts.length, 1)
    assert.equal(fake.asserts[0]!.action, "guard · the output of webfetch may contain a secret in clear (nox-4b 0.90): approve to pass it to the agent, reject to withhold it")
    assert.match(String(fake.asserts[0]!.metadata?.reason), /output of webfetch may contain a secret in clear \(nox-4b 0\.90\)/)
    assert.deepEqual(fake.asserts[0]!.source, { type: "tool", messageID: "msg_1", id: "call_1" })
    assert.equal(event.result.output, "db password is hunter-two-x")
  })
  it("rejection → notice in place of the output, strings replaced, numbers kept, the step continues", async () => {
    const { fake } = await setup(() => noul(0.95))
    fake.onAssert(async () => {
      throw Object.assign(new Error("declined"), { name: "Permission.DeclinedError" })
    })
    const event = done("shell", { output: { stdout: "pw=hunter-two-x", exit: 0 }, content: [{ type: "text", text: "pw=hunter-two-x" }], metadata: { output: "pw=hunter-two-x", exit: 0 } })
    await fake.trigger("tool.execute.after", event)
    assert.deepEqual(event.result.content, [{ type: "text", text: withheldNotice("shell", "the user did not approve passing it on") }])
    assert.deepEqual(event.result.output, { stdout: "[guard: output withheld]", exit: 0 })
    assert.deepEqual(event.result.metadata, { output: "[guard: output withheld]", exit: 0 })
  })
  it("rejection with feedback → feedback in the notice, never in the log", async () => {
    const { fake, lines } = await setup(() => noul(0.95))
    fake.onAssert(async () => {
      throw Object.assign(new Error("corrected"), { name: "Permission.CorrectedError", feedback: "use the staging file instead" })
    })
    const event = done("webfetch", { output: "secret thing", content: [{ type: "text", text: "secret thing" }] })
    await fake.trigger("tool.execute.after", event)
    assert.match(JSON.stringify(event.result.content), /User feedback: use the staging file instead/)
    assert.ok(!lines.join("\n").includes("staging file"), lines.join("\n"))
    assert.match(lines.join("\n"), /confirmation not granted \(Permission\.CorrectedError\)/)
  })
  it("unattended mode → withheld without a request", async () => {
    const { fake } = await setup(() => noul(0.95), { askAs: "deny" })
    const event = done("webfetch", { output: "secret thing", content: [{ type: "text", text: "secret thing" }] })
    await fake.trigger("tool.execute.after", event)
    assert.equal(fake.asserts.length, 0)
    assert.match(JSON.stringify(event.result.content), /unattended mode \(askAs: deny\) withholds it/)
  })
  it("model failure (error, rejected question, invalid answer) → output passed through; only one WARN per series", async () => {
    let mode = 0
    const { fake, lines } = await setup((): ModelResponse | Error =>
      mode === 0 ? new ModelError("timed out after 3000 ms", { timeout: true }) : mode === 1 ? { answers: { [OUTPUT_QUESTION_ID]: { error: "max_length_exceeded" } } } : { answers: {} as Record<string, never> },
    )
    for (mode = 0; mode < 3; mode++) {
      const event = done("webfetch", { output: `text ${mode}`, content: [{ type: "text", text: `text ${mode}` }] }, `call_${mode}`)
      await fake.trigger("tool.execute.after", event)
      assert.equal(event.result.output, `text ${mode}`)
    }
    assert.equal(fake.asserts.length, 0)
    assert.equal(lines.filter((line) => line.startsWith("WARN")).length, 1)
    assert.match(lines.join("\n"), /WARN output check unavailable \(timed out after 3000 ms\)/)
  })
  it("value out of range above 1 → flagged", async () => {
    const { fake } = await setup(() => noul(5))
    await fake.trigger("tool.execute.after", done("webfetch", { output: "x1 y2", content: [] }))
    assert.equal(fake.asserts.length, 1)
  })
  it("unprotected agent, reads, writes, todo list, empty output or output made of placeholders → model not called", async () => {
    const unprotected = { isUnprotected: async () => true, notePrompt: async () => false }
    const skipped = await setup(() => noul(0.9), { unprotected })
    await skipped.fake.trigger("tool.execute.after", done("webfetch", { output: "secret thing" }))
    assert.equal(skipped.states.length, 0)
    const { fake, states } = await setup(() => noul(0.9))
    for (const tool of ["read", "glob", "grep", "edit", "write", "patch", "question", "skill", "subagent", "todowrite"])
      await fake.trigger("tool.execute.after", done(tool, { output: "secret thing" }))
    await fake.trigger("tool.execute.after", done("webfetch", { output: "", content: [] }))
    await fake.trigger("tool.execute.after", done("webfetch", { output: "[[GUARD_REDACTED:openai_key]]", content: [{ type: "text", text: "[[GUARD_REDACTED:env:X]] ." }] }))
    assert.equal(states.length, 0)
  })
  it("tool error → checked; withheld: class preserved, message replaced by the notice", async () => {
    class ToolFailure extends Error {
      override name = "ToolFailure"
    }
    const { fake, states } = await setup(() => noul(0.95))
    fake.onAssert(async () => {
      throw Object.assign(new Error("declined"), { name: "Permission.DeclinedError" })
    })
    const event = { ...base, id: "call_e", tool: "shell", status: "error" as const, error: new ToolFailure("cannot connect: password hunter-two-x rejected") }
    await fake.trigger("tool.execute.after", event)
    assert.equal(states.length, 1)
    assert.ok(event.error instanceof ToolFailure)
    assert.equal(event.error.message, withheldNotice("shell", "the user did not approve passing it on"))
  })
  it("error where only the cause carries the text (non-enumerable message) → the cause is judged", async () => {
    const { fake, states } = await setup(() => noul(0.1))
    const error = Object.assign(new Error("tool failed"), { error: new Error("cause-marker-xyz: connection refused") })
    await fake.trigger("tool.execute.after", { ...base, id: "call_c", tool: "shell", status: "error" as const, error })
    assert.match(JSON.stringify(states[0]), /cause-marker-xyz/)
  })
  it("rejection on an error whose message has only a getter → withheld anyway (minimal fallback, same class)", async () => {
    class Weird extends Error {
      override get message() {
        return "original secret text hunter-two-x"
      }
    }
    const error = new Weird()
    delete (error as unknown as Record<string, unknown>).message
    const { fake } = await setup(() => noul(0.95))
    fake.onAssert(async () => {
      throw Object.assign(new Error("declined"), { name: "Permission.DeclinedError" })
    })
    const event = { ...base, id: "call_w", tool: "shell", status: "error" as const, error: error as Error }
    await fake.trigger("tool.execute.after", event)
    assert.ok(event.error instanceof Weird)
    assert.equal(event.error.message, withheldNotice("shell", "the user did not approve passing it on"))
  })
  it("rejection on an error frozen by its constructor → minimal fallback: notice only, same class", async () => {
    // Constructor that freezes the instance: the error rebuilt by redaction can no longer receive the notice.
    class Frozen extends Error {
      constructor(props: { message: string } | string) {
        super(typeof props === "string" ? props : props.message)
        Object.freeze(this)
      }
    }
    const error = new Frozen({ message: "original secret text hunter-two-x" })
    const { fake } = await setup(() => noul(0.95))
    fake.onAssert(async () => {
      throw Object.assign(new Error("declined"), { name: "Permission.DeclinedError" })
    })
    const event = { ...base, id: "call_f", tool: "shell", status: "error" as const, error: error as Error }
    await fake.trigger("tool.execute.after", event)
    assert.ok(event.error instanceof Frozen)
    assert.equal(event.error.message, withheldNotice("shell", "the user did not approve passing it on"))
    assert.ok(!JSON.stringify(Object.getOwnPropertyNames(event.error).map((k) => (event.error as unknown as Record<string, unknown>)[k])).includes("hunter-two-x"))
  })
  it("full replacement impossible → minimal fallback: notice only, same class, nothing from the original output", () => {
    class ToolFailure extends Error {}
    const error = Object.assign(new ToolFailure("original secret text hunter-two-x"), { error: new Error("cause hunter-two-x") })
    const event = { ...base, id: "call_m", tool: "shell", status: "error" as const, error }
    withhold(event, "NOTICE", () => {
      throw new Error("replacement failed")
    })
    assert.ok(event.error instanceof ToolFailure)
    assert.equal(event.error.message, "NOTICE")
    assert.equal((event.error as unknown as { error?: unknown }).error, undefined)
    const completed = { ...done("shell", { output: "secret hunter-two-x" }), result: Object.freeze({ output: "secret hunter-two-x", content: [] }) }
    withhold(completed as never, "NOTICE")
    assert.deepEqual(completed.result, { output: "[guard: output withheld]", content: [{ type: "text", text: "NOTICE" }] })
  })
  it("the request names the call: summary of the redacted input, never a known secret", async () => {
    const { fake } = await setup(() => noul(0.95))
    await fake.trigger("tool.execute.after", { ...done("webfetch", { output: "some page" }), input: { url: `https://x.example.test/?k=${FAKE.openai}` } })
    const resource = fake.asserts[0]!.resources[0]!
    assert.match(resource, /^webfetch: .*\(output check\)$/)
    assert.match(resource, /GUARD_REDACTED/)
    assert.ok(!resource.includes(FAKE.openai))
  })
  it("CodeMode: internal calls ignored, external execute result checked", async () => {
    const { fake, states } = await setup(() => noul(0.1))
    await fake.trigger("tool.execute.before", { ...base, id: "call_cm", tool: "execute", input: { code: "x" } })
    await fake.trigger("tool.execute.after", done("webfetch", { output: "inner output" }, "call_cm"))
    await fake.trigger("tool.execute.after", done("chrome-devtools-mcp_take_snapshot", { output: "inner output 2" }, "call_cm"))
    assert.equal(states.length, 0)
    await fake.trigger("tool.execute.after", done("execute", { output: { output: "script result" }, content: [{ type: "text", text: "script result" }] }, "call_cm"))
    assert.equal(states.length, 1)
    // After the external execute, a call with the same identifier is no longer taken for an internal call.
    await fake.trigger("tool.execute.after", done("webfetch", { output: "later output" }, "call_cm"))
    assert.equal(states.length, 2)
  })
  it("same text in output and content → sent only once (maxStateChars budget not divided)", async () => {
    const { fake, states } = await setup(() => noul(0.1))
    await fake.trigger("tool.execute.after", done("shell", { output: "unique-line-xyz", content: [{ type: "text", text: "unique-line-xyz" }] }))
    assert.equal(JSON.stringify(states[0]).split("unique-line-xyz").length - 1, 1)
  })
  it("cache: same output → a single model call", async () => {
    const { fake, states } = await setup(() => noul(0.1))
    for (const id of ["a", "b"]) await fake.trigger("tool.execute.after", done("webfetch", { output: "same output" }, id))
    assert.equal(states.length, 1)
  })
})

describe("batch 32: startup (option, global file, INFO line)", () => {
  const decision = { baseURL: URL_A, model: "nox-4b", timeoutMs: 300 }
  async function start(options: Record<string, unknown>, globalDir: string | undefined) {
    const file = join(temp("log"), "guard.log")
    await setupGuard(fakeContext({ logFile: file, ...options }).ctx, {}, temp("etc"), globalDir)
    return readFileSync(file, "utf8")
  }
  it("option absent → no mention; requested and declared → active, warning", async () => {
    assert.ok(!(await start({ decision }, undefined)).includes("output check"))
    const global = temp("global")
    writeFileSync(join(global, "opencode.json"), entry({ outputCheck: true, decision }))
    const log = await start({ decision, outputCheck: true }, global)
    assert.match(log, /INFO active \(.*; output check: active\)/)
    assert.match(log, /WARN output check active: tool outputs, redacted, are sent to the decision model/)
  })
  it("requested but not declared in the global file, or model disabled → inactive, with the reason", async () => {
    const empty = temp("global")
    mkdirSync(empty, { recursive: true })
    const log = await start({ decision, outputCheck: true }, empty)
    assert.match(log, /INFO active \(.*; output check: inactive\)/)
    assert.match(log, /WARN outputCheck requested but inactive: global configuration: it is missing or unreadable/)
    assert.ok(!log.includes("output check active"), log)
    const off = await start({ outputCheck: true }, empty)
    assert.match(off, /WARN outputCheck requested but inactive: the decision model is disabled/)
  })
})
