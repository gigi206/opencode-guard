import "./tmp.ts"
// Audit 49 (batch 46): findings proven by a test that failed on the deployed code, kept as non-regression.
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, it } from "node:test"
import { gzipSync } from "node:zlib"
import { parseConfig } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import { registerGate } from "../src/hooks/gate.ts"
import { registerRedaction, WIRE_BLOCKED_MESSAGE } from "../src/hooks/redaction.ts"
import { setupGuard } from "../src/index.ts"
import { createModelClient } from "../src/model/client.ts"
import { placeholderFinding, toolFinding } from "../src/rules/tools.ts"
import { MAX_SERVICE_SECRETS, serviceSecretSource } from "../src/secrets/opencode-service.ts"
import { redactPromptSecrets } from "../src/secrets/prompt.ts"
import { createRedactor, placeholder, type Redactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"
import { FAKE, rand } from "./fixtures.ts"

const quiet = { debug() {}, info() {}, warn() {}, error() {} }

/** Log that keeps lines by level. */
function recordingLog() {
  const lines: Array<{ level: string; message: string }> = []
  const push = (level: string) => (message: string) => lines.push({ level, message })
  return { lines, log: { debug: push("debug"), info: push("info"), warn: push("warn"), error: push("error") } }
}

/** Best of several runs (milliseconds): a loaded machine only makes it longer, never shorter. */
function best(run: () => unknown, tries = 3): number {
  let min = Infinity
  for (let i = 0; i < tries; i++) {
    const start = performance.now()
    run()
    min = Math.min(min, performance.now() - start)
  }
  return min
}

/** Linear growth: four times longer costs no more than `limit` times more (quadratic: about 16). */
function assertLinear(at: (n: number) => () => unknown, n: number, limit = 8) {
  at(n)()
  const small = best(at(n))
  const large = best(at(4 * n))
  assert.ok(large < limit * small + 20, `t(${n}) = ${small.toFixed(1)} ms, t(${4 * n}) = ${large.toFixed(1)} ms`)
}

describe("audit 49: the wire safety net blocks the request if redaction throws", () => {
  const failing: Redactor = {
    redactString: () => {
      throw new Error("redactor failure")
    },
    redactDeep: () => {
      throw new Error("redactor failure")
    },
    containsSecret: () => false,
  }
  async function setup(redactor: Redactor) {
    const fake = fakeContext()
    const { lines, log } = recordingLog()
    await registerRedaction(fake.ctx, { redactor, redactPrompt: true, log })
    return { ...fake, lines }
  }
  const request = (body: string, type = "application/json") =>
    new Request("https://provider.invalid/v1/messages", { method: "POST", body, headers: { "content-type": type } })

  it("http.request: error with fixed message (no content or cause), cause in the log", async () => {
    const { trigger, lines } = await setup(failing)
    await assert.rejects(trigger("session.http.request", { kind: "primary", request: request(`{"a":"${FAKE.openai}"}`) }), (error: unknown) => {
      assert.equal((error as Error).message, WIRE_BLOCKED_MESSAGE)
      return true
    })
    assert.ok(lines.some((line) => line.level === "error" && line.message.includes("request blocked")))
    assert.ok(!WIRE_BLOCKED_MESSAGE.includes(FAKE.openai))
  })

  it("experimental.ws.send: same blocking", async () => {
    const { trigger } = await setup(failing)
    await assert.rejects(trigger("session.experimental.ws.send", { kind: "primary", frame: `{"a":"${FAKE.openai}"}` }), { message: WIRE_BLOCKED_MESSAGE })
  })

  it("a log that throws changes nothing: the request stays blocked", async () => {
    const fake = fakeContext()
    const broken = {
      ...quiet,
      error() {
        throw new Error("log failure")
      },
    }
    await registerRedaction(fake.ctx, { redactor: failing, redactPrompt: true, log: broken })
    await assert.rejects(fake.trigger("session.http.request", { kind: "primary", request: request('{"a":"b"}') }), { message: WIRE_BLOCKED_MESSAGE })
  })

  it("the other redaction hooks still never throw (tool output, prompt)", async () => {
    const { trigger } = await setup(failing)
    await trigger("tool.execute.after", { tool: "read", sessionID: "s", agent: "build", messageID: "m", id: "c", input: {}, status: "completed", result: { content: "x" } })
    await trigger("session.prompt", { sessionID: "s", messageID: "m", prompt: { text: "bonjour" } })
  })

  it("unexamined bodies: reported once per cause, never blocked (non-JSON type, unreadable JSON, non-JSON frame)", async () => {
    const { trigger, lines } = await setup(createRedactor())
    const form = request(`k=${FAKE.openai}`, "application/x-www-form-urlencoded")
    assert.equal((await trigger("session.http.request", { kind: "primary", request: form })).request, form)
    await trigger("session.http.request", { kind: "primary", request: request("k=v", "application/x-www-form-urlencoded") })
    const broken = request("{not json")
    assert.equal((await trigger("session.http.request", { kind: "primary", request: broken })).request, broken)
    const frame = await trigger("session.experimental.ws.send", { kind: "primary", frame: "not json" })
    assert.equal(frame.frame, "not json")
    const warnings = lines.filter((line) => line.level === "warn").map((line) => line.message)
    assert.equal(warnings.filter((line) => line.includes("content-type")).length, 1, warnings.join("\n"))
    assert.equal(warnings.filter((line) => line.includes("body is not valid JSON")).length, 1, warnings.join("\n"))
    assert.equal(warnings.filter((line) => line.includes("frame is not valid JSON")).length, 1, warnings.join("\n"))
  })
})

describe("audit 49: redactor", () => {
  it("SEC-1: the server error message is redacted before being truncated (key fragment echoed back)", async () => {
    const key = rand(40, 21)
    const { config } = parseConfig({ decision: { baseURL: "https://decision.local/v1", model: "nox-4b" } })
    const redactor = createRedactor({ knownSecrets: [{ name: "decision.apiKey", value: key }] })
    // Key starting at character 141: truncated at 160 before redaction, its first 20 characters stayed in clear.
    const head = "Authentication Error, invalid proxy server token passed."
    const message = `${head}${"x".repeat(139 - head.length)} ${key} is not a valid key for this route`
    assert.equal(message.indexOf(key), 140)
    const model = createModelClient(
      { protocol: "chat", baseURL: "https://decision.local/v1", model: "nox-4b", timeoutMs: 2000, apiKey: key },
      async () => new Response(JSON.stringify({ error: { message } }), { status: 401, headers: { "content-type": "application/json" } }),
    )
    const decision = await createDecider({ config, redactor, model }).decide({ tool: "edit", input: { path: "a.ts", oldString: "a", newString: "b" } })
    assert.equal(decision.verdict, "ask")
    assert.ok(decision.reason.includes("HTTP 401"), decision.reason)
    assert.ok(!decision.reason.includes(key.slice(0, 12)), "key fragment in clear in the reason")
    assert.ok(decision.reason.length < 400, `${decision.reason.length} characters`)
  })

  it("SEC-2: known values redacted even in 10,000 characters of all-base64 text, and alone", () => {
    const secret = rand(32, 11)
    const filler = Array.from({ length: 160 }, (_, i) => rand(76, 100 + i)).join("\n")
    const text = `${filler}\n${secret}\n${filler}`
    assert.ok(text.length >= 10_000)
    for (const redactor of [createRedactor({ env: { MY_API_TOKEN: secret } }), createRedactor({ knownSecrets: [{ name: "decision.apiKey", value: secret }] })]) {
      const { value, count } = redactor.redactString(text)
      assert.equal(count, 1)
      assert.ok(!value.includes(secret))
      // The lone value is replaced, never the whole block.
      assert.ok(value.startsWith(filler.slice(0, 1000)) && value.length > 20_000)
    }
  })

  it("SEC-3: gzip content over 4 MB once decompressed: its beginning is examined", () => {
    const redactor = createRedactor()
    const small = gzipSync(Buffer.from(`OPENAI_API_KEY=${FAKE.openai}\n${"a".repeat(1_000_000)}`)).toString("base64")
    assert.ok(redactor.redactString(small).count >= 1, "witness under 4 MB")
    const big = gzipSync(Buffer.from(`OPENAI_API_KEY=${FAKE.openai}\n${"a".repeat(5_000_000)}`)).toString("base64")
    const { value, count } = redactor.redactString(big)
    assert.ok(count >= 1)
    assert.equal(value, placeholder("base64"))
  })

  it("SEC-4: end-of-value trimming in linear time (commas, closers, prompt punctuation)", () => {
    const redactor = createRedactor()
    assertLinear((n) => () => redactor.redactString(`password=x${",".repeat(n)}y`), 20_000)
    assertLinear((n) => () => redactor.redactString(`password=x${")".repeat(n)}y`), 20_000)
    assertLinear((n) => () => redactPromptSecrets(`mdp: x${".".repeat(n)}y`), 20_000)
  })

  it("SEC-4: same values trimmed as before (trailing commas and closers, prompt punctuation)", () => {
    const redactor = createRedactor()
    const secret = rand(24, 31)
    assert.equal(redactor.redactString(`DB_PASSWORD=${secret},,`).value, `DB_PASSWORD=${placeholder("generic_secret")},,`)
    assert.equal(redactor.redactString(`f(token=${secret}))`).value.includes(secret), false)
    assert.equal(redactPromptSecrets(`mon mdp est ${secret}...`).value.includes(secret), false)
    assert.ok(redactPromptSecrets(`mon mdp est ${secret}...`).value.includes("..."))
  })

  it("SEC-6: after 1,000 learned values, redacting an ordinary body costs at most a few times more", () => {
    const body = { messages: Array.from({ length: 4_000 }, (_, i) => ({ role: "user", content: [{ type: "text", text: `ordinary message number ${i} with nothing` }] })) }
    const fresh = createRedactor()
    const taught = createRedactor()
    const entries = Array.from({ length: 1_000 }, (_, i) => `{"type":"key","key":"${rand(24, 1000 + i)}"}`).join("\n")
    assert.equal(taught.redactString(entries).count, 1_000)
    const base = best(() => fresh.redactDeep(body))
    const after = best(() => taught.redactDeep(body))
    assert.ok(after < 4 * base + 50, `fresh ${Math.round(base)} ms, after learning ${Math.round(after)} ms`)
    // Learned values stay redacted, alone, everywhere.
    const learned = rand(24, 1500)
    assert.equal(taught.redactString(`{"type":"key","key":"${learned}"}`).count, 1)
    assert.equal(taught.redactString(`voici ${learned} seul`).value, `voici ${placeholder("opencode_credential")} seul`)
  })

  it("known values contained in one another: the longest first, the shorter elsewhere", () => {
    const long = rand(30, 41)
    const short = long.slice(5, 20)
    const redactor = createRedactor({ knownSecrets: [{ name: "a", value: long }, { name: "b", value: short }] })
    const { value } = redactor.redactString(`x ${long} y ${short} z`)
    assert.equal(value, `x ${placeholder("config:a")} y ${placeholder("config:b")} z`)
  })
})

describe("audit 49: decision", () => {
  const before = (tool: string, input: unknown, id: string) => ({ tool, sessionID: "ses_1", agent: "build", messageID: "msg_1", id, input })
  const evaluation = (id: string) => ({
    sessionID: "ses_1",
    action: "shell",
    resources: ["guard-probe"],
    effect: "allow",
    message: undefined as string | undefined,
    source: { type: "tool", messageID: "msg_1", id },
  })
  // User rule that asks on a neutral word: the `evaluate` hardening sees it per subcommand.
  const rules = [{ id: "probe", verdict: "ask" as const, reason: "probe", pattern: /guard-probe/, tools: ["shell"] }]
  async function setup(verdicts: Array<"ask" | "allow">) {
    const fake = fakeContext()
    let sizes = { approved: 0, pending: 0, directories: 0 }
    let inspect: () => typeof sizes = () => sizes
    const decider = { decide: async () => ({ verdict: verdicts.shift() ?? "allow", reason: "test", source: "local" as const, redactedInput: {} }) }
    await registerGate(fake.ctx, { decider, redactor: createRedactor(), rules, log: quiet, inspect: (fn) => (inspect = fn) })
    return { ...fake, sizes: () => (sizes = inspect()) }
  }

  it("witness: the confirmed call is not asked again in evaluate", async () => {
    const fake = await setup(["ask"])
    await fake.trigger("tool.execute.before", before("shell", { command: "guard-probe" }, "call_1"))
    assert.equal(fake.asserts.length, 1)
    assert.equal((await fake.trigger("permission.evaluate", evaluation("call_1"))).effect, "allow")
  })

  it("DEC-1: a new call with the same identifier does not inherit approval from an unexecuted call", async () => {
    const fake = await setup(["ask", "allow"])
    await fake.trigger("tool.execute.before", before("shell", { command: "guard-probe" }, "call_1"))
    // Call confirmed then rejected by OpenCode: no execute.after. New call, same identifier, never confirmed.
    await fake.trigger("tool.execute.before", before("shell", { command: "guard-probe" }, "call_1"))
    assert.equal((await fake.trigger("permission.evaluate", evaluation("call_1"))).effect, "ask")
  })

  it("DEC-1: an internal shell call of a confirmed CodeMode script (same identifier) does not inherit it", async () => {
    const fake = await setup(["ask", "allow"])
    await fake.trigger("tool.execute.before", before("execute", { code: "await tools.shell({})" }, "call_cm"))
    await fake.trigger("tool.execute.before", before("shell", { command: "guard-probe" }, "call_cm"))
    assert.equal((await fake.trigger("permission.evaluate", evaluation("call_cm"))).effect, "ask")
  })

  it("DEC-1: a pending entry for an internal call is not removed by the next call with the same identifier", async () => {
    const fake = await setup(["allow", "allow"])
    await fake.trigger("tool.execute.before", before("write", { path: "/project/a.sh", content: "x" }, "call_cm"))
    assert.equal(fake.sizes().pending, 1)
    await fake.trigger("tool.execute.before", before("read", { path: "/project/b.txt" }, "call_cm"))
    assert.equal(fake.sizes().pending, 1)
  })

  it("DEC-2: a neighboring check that throws does not lose a denial (MCP tool, execute, webfetch)", () => {
    const reports: string[] = []
    const redactor = { ...createRedactor(), containsSecret: () => { throw new Error("failure") } }
    const ctx = { redactor, report: (message: string) => reports.push(message) }
    const marker = placeholder("openai")
    assert.equal(toolFinding("mcp_tool", { text: marker }, ctx)?.verdict, "deny")
    assert.equal(toolFinding("execute", { code: `const a = "${marker}"` }, ctx)?.verdict, "deny")
    const custom = [{ id: "no-host", verdict: "deny" as const, reason: "no host", pattern: /forbidden\.invalid/, tools: ["webfetch"] }]
    assert.equal(toolFinding("webfetch", { url: "https://forbidden.invalid/" }, { ...ctx, custom })?.verdict, "deny")
    // Without a neighboring denial: ask for the unchecked part, cause in the log.
    const found = toolFinding("webfetch", { url: "https://example.invalid/" }, ctx)
    assert.equal(found?.verdict, "ask")
    assert.equal(found?.rule, "internal-error")
    assert.ok(reports.some((line) => line.includes("the secret check")))
  })

  it("DEC-3: global configuration directory and service.json moved by the server environment", async () => {
    const root = mkdtempSync(join(tmpdir(), "guard-dec3-"))
    const configDir = join(root, "conf")
    const stateDir = join(root, "state")
    mkdirSync(join(stateDir, "opencode"), { recursive: true })
    for (const env of [{ OPENCODE_CONFIG_DIR: configDir }, { XDG_CONFIG_HOME: root, XDG_STATE_HOME: stateDir }]) {
      const dir = "OPENCODE_CONFIG_DIR" in env ? configDir : join(root, "opencode")
      const fake = fakeContext({ logFile: join(root, "guard.log") })
      await setupGuard(fake.ctx, env, join(root, "system"))
      await fake.trigger("tool.execute.before", before("write", { path: join(dir, "agents", "x.md"), content: "x" }, "call_w"))
      assert.equal(fake.asserts.length, 1, JSON.stringify(env))
      assert.equal((fake.asserts[0]!.metadata as { reason?: string }).reason?.includes("OpenCode's configuration"), true)
      const read = () => fake.trigger("tool.execute.before", before("read", { path: join(dir, "service.json") }, "call_r"))
      const blocked = await read().then(() => fake.asserts.length > 1, () => true)
      assert.ok(blocked, `service.json read without confirmation (${JSON.stringify(env)})`)
    }
    const fake = fakeContext({ logFile: join(root, "guard.log") })
    await setupGuard(fake.ctx, { XDG_STATE_HOME: stateDir }, join(root, "system"))
    const state = () => fake.trigger("tool.execute.before", before("read", { path: join(stateDir, "opencode", "service.json") }, "call_s"))
    assert.ok(await state().then(() => fake.asserts.length > 0, () => true), "state service.json read without confirmation")
  })

  it("DEC-4: rules or secretPatterns that are not arrays: reported", () => {
    const rule = { id: "x", verdict: "deny", reason: "x", pattern: "x" }
    assert.ok(parseConfig({ rules: rule }).warnings.includes("rules must be an array, ignored"))
    assert.ok(parseConfig({ secretPatterns: "abc" }).warnings.includes("secretPatterns must be an array, ignored"))
    assert.ok(parseConfig({ secretPatterns: { pattern: "abc" } }).warnings.includes("secretPatterns must be an array, ignored"))
    assert.deepEqual(parseConfig({ rules: [], secretPatterns: [] }).warnings, [])
  })
})

describe("audit 49: missing tests (QUA-2, QUA-5) and bounds", () => {
  it("QUA-2: secretPatterns read from the configuration (object, bare string, invalid or empty pattern reported)", () => {
    const { config, warnings } = parseConfig({ secretPatterns: [{ pattern: "corp-[0-9]{6}", type: "corp" }, "zz-[a-z]{8}", { pattern: "(" }, { type: "vide" }] })
    assert.equal(config.secretPatterns.length, 2)
    assert.equal(warnings.length, 2, warnings.join("\n"))
    const redactor = createRedactor({ extraPatterns: config.secretPatterns })
    assert.equal(redactor.redactString("id corp-123456 et zz-abcdefgh").value, `id ${placeholder("corp")} et ${placeholder("custom")}`)
  })

  it("QUA-5: placeholder rule for the unprotected agent for execute; tools without a finding", () => {
    const marker = placeholder("openai")
    assert.equal(placeholderFinding("execute", { code: `x = "${marker}"` })?.verdict, "deny")
    assert.equal(placeholderFinding("execute", { code: "x = 1" }), undefined)
    for (const tool of ["read", "glob", "grep", "webfetch", "question"]) assert.equal(placeholderFinding(tool, { path: marker, pattern: marker, url: marker }), undefined, tool)
  })

  it("SEC-10: service secrets bounded in memory, the most recent value kept", async () => {
    const dir = mkdtempSync(join(tmpdir(), "guard-sec10-"))
    const source = serviceSecretSource([dir])
    let list: ReturnType<typeof source> = []
    let last = ""
    // Password rewritten endlessly (different size each time: new file seen as changed).
    for (let i = 0; i < MAX_SERVICE_SECRETS + 50; i++) {
      last = `Pw${rand(24, 9000 + i)}`
      writeFileSync(join(dir, "service.json"), JSON.stringify({ password: last, pad: "x".repeat(i) }))
      list = source()
      await new Promise((resolve) => setImmediate(resolve))
    }
    assert.equal(list.length, MAX_SERVICE_SECRETS)
    assert.ok(list.some((item) => item.value === last), "current password forgotten")
    assert.ok(readFileSync(join(dir, "service.json"), "utf8").includes(last))
  })

  it("paths: quotes removed in linear time (long run that is not at the end)", () => {
    const ctx = { redactor: createRedactor() }
    assertLinear((n) => () => toolFinding("read", { path: `a${'"'.repeat(n)}b` }, ctx), 20_000)
  })
})
