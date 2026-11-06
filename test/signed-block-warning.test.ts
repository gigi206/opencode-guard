// Signed blocks leave as they are: a secret in one reaches the provider, and the plugin's log says so, by type and number.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { gzipSync } from "node:zlib"
import { describe, it } from "node:test"
import { UserShellUncheckedError } from "../src/hooks/output-check.ts"
import { registerRedaction } from "../src/hooks/redaction.ts"
import { setupGuard } from "../src/index.ts"
import { createRedactor, type Redactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"
import { FAKE, rand } from "./fixtures.ts"

const SHELL = "The following shell command was executed by the user:\n<shell>cat notes</shell>\n"
const LEARNED = rand(24, 1500)
const thinking = (text: string) => ({ type: "thinking", thinking: text, signature: "sig" })
const body = (...content: unknown[]) => ({ messages: [{ role: "assistant", content }] })
const post = (value: unknown, headers: Record<string, string> = {}) =>
  new Request("https://provider.example.test/v1", { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(value) })

async function wire(redactor: Redactor = createRedactor(), options: { warn?: () => void; error?: () => void; deps?: object } = {}) {
  const fake = fakeContext()
  const lines: Array<{ level: string; message: string }> = []
  const push = (level: string) => (message: string) => void lines.push({ level, message })
  const log = { debug: push("debug"), info: push("info"), warn: options.warn ?? push("warn"), error: options.error ?? push("error") }
  await registerRedaction(fake.ctx, { redactor, redactPrompt: true, log, ...options.deps })
  const send = (value: unknown, sessionID: string | undefined = "s") => fake.trigger("session.http.request", { kind: "primary", sessionID, request: post(value) })
  const frame = (value: unknown, sessionID = "s") => fake.trigger("session.experimental.ws.send", { kind: "primary", sessionID, frame: JSON.stringify(value) })
  const warnings = () => lines.filter((line) => line.level === "warn").map((line) => line.message)
  return { fake, lines, send, frame, warnings }
}

describe("a secret in a signed block goes to the log", () => {
  it("SB-1 HTTP: type and number", async () => {
    const { send, warnings } = await wire()
    await send(body(thinking(`the key is ${FAKE.openai}`)))
    assert.deepEqual(warnings(), ["http.request: 1 secret(s) in signed blocks sent unmasked (openai_key x1)"])
  })
  it("SB-2 WebSocket: type and number", async () => {
    const { frame, warnings } = await wire()
    await frame(body(thinking(`the key is ${FAKE.openai}`)))
    assert.deepEqual(warnings(), ["experimental.ws.send: 1 secret(s) in signed blocks sent unmasked (openai_key x1)"])
  })
  it("SB-3 a compressed body, and several types in one request", async () => {
    const { fake, warnings } = await wire()
    const raw = gzipSync(JSON.stringify(body(thinking(`${FAKE.openai} ${FAKE.github}`), { type: "reasoning", summary: [{ text: FAKE.openai }, { text: FAKE.anthropic }] })))
    await fake.trigger("session.http.request", { kind: "primary", sessionID: "s", request: new Request("https://provider.example.test/v1", { method: "POST", headers: { "content-type": "application/json", "content-encoding": "gzip" }, body: raw }) })
    assert.equal(warnings().length, 1)
    assert.match(warnings()[0]!, /: 3 secret\(s\) /)
    for (const part of ["openai_key x1", "github_token x1", "anthropic_key x1"]) assert.ok(warnings()[0]!.includes(part), warnings()[0])
  })
  it("SB-4 a secret inside base64 is given its own type", async () => {
    const { send, warnings } = await wire()
    await send(body(thinking(`blob ${Buffer.from(`key ${FAKE.openai} end`).toString("base64")}`)))
    assert.equal(warnings().length, 1)
    assert.ok(warnings()[0]!.includes("openai_key x1"), warnings()[0])
  })
  it("SB-5 no value and no excerpt in the log", async () => {
    const { send, lines } = await wire()
    await send(body(thinking(`${FAKE.openai} and ${FAKE.github}`)))
    assert.ok(lines.length > 0)
    const log = JSON.stringify(lines)
    for (const secret of [FAKE.openai, FAKE.github])
      for (let at = 0; at + 6 <= secret.length; at++) assert.ok(!log.includes(secret.slice(at, at + 6)), `excerpt at ${at}`)
  })
  it("SB-6 through the plugin itself, in its log file", async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-sb-")))
    for (const dir of ["global", "system", "app"]) mkdirSync(join(root, dir))
    const logFile = join(root, "guard.log")
    const fake = fakeContext({ logFile })
    Object.assign(fake.ctx, { location: { directory: join(root, "app") } })
    await setupGuard(fake.ctx, {}, join(root, "system"), join(root, "global"))
    await fake.trigger("session.http.request", { kind: "primary", sessionID: "s", agent: "build", request: post(body(thinking(FAKE.openai))) })
    assert.ok(readFileSync(logFile, "utf8").includes("1 secret(s) in signed blocks sent unmasked (openai_key x1)"))
  })
})

describe("one warning per secret in a session", () => {
  it("SB-7 a block sent again, over HTTP or WebSocket", async () => {
    const { send, frame, warnings } = await wire()
    const value = body(thinking(FAKE.openai))
    for (let i = 0; i < 5; i++) await send(value)
    await frame(value)
    assert.equal(warnings().length, 1)
  })
  it("SB-8 the same secret in another block: nothing; a new one: a warning that counts it alone", async () => {
    const { send, warnings } = await wire()
    await send(body(thinking(FAKE.openai)))
    await send(body(thinking(FAKE.openai), thinking(`still ${FAKE.openai}`)))
    assert.equal(warnings().length, 1)
    await send(body(thinking(FAKE.openai), thinking(`still ${FAKE.openai}`), thinking(`${FAKE.openai} ${FAKE.github}`)))
    assert.deepEqual(warnings().slice(1), ["http.request: 1 secret(s) in signed blocks sent unmasked (github_token x1)"])
  })
  it("SB-9 another session has its own warning", async () => {
    const { send, warnings } = await wire()
    await send(body(thinking(FAKE.openai)), "a")
    await send(body(thinking(FAKE.openai)), "b")
    assert.equal(warnings().length, 2)
  })
  it("SB-10 the memory is bounded: past 8,192 entries the oldest is gone, and its block is reported again", async () => {
    const { send, warnings } = await wire()
    const value = body(thinking(FAKE.openai))
    await send(value)
    await send(body(...Array.from({ length: 4100 }, (_, i) => thinking(`clean ${i}`))))
    await send(body(...Array.from({ length: 4100 }, (_, i) => thinking(`other ${i}`))))
    await send(value)
    assert.equal(warnings().length, 2)
  })
  it("SB-11 a block seen again stays in memory: only the blocks left aside drop out", async () => {
    const { send, warnings } = await wire()
    const value = thinking(FAKE.openai)
    await send(body(value))
    for (let round = 0; round < 4; round++) await send(body(value, ...Array.from({ length: 4000 }, (_, i) => thinking(`round ${round} ${i}`))))
    assert.equal(warnings().length, 1)
  })
  it("SB-17 the memory holds exactly 8,192 entries, and a secret stays recent only when found in a new block", async () => {
    const { send, warnings } = await wire()
    const value = body(thinking(FAKE.openai))
    await send(value)
    await send(body(...Array.from({ length: 8190 }, (_, i) => thinking(`clean ${i}`))))
    await send(value)
    assert.equal(warnings().length, 1)
    await send(body(thinking(`still ${FAKE.openai}`)))
    assert.equal(warnings().length, 2)
  })
})

describe("the `!` command check and signed blocks", () => {
  const check = (seen: string[]) => async (texts: readonly string[]) => (seen.push(...texts), { masked: new Map<string, string>(), words: 0, parts: 0 })
  it("SB-12 a block holding a `!` command text does not go to the decision model, and is reported", async () => {
    const seen: string[] = []
    const { send, warnings } = await wire(createRedactor(), { deps: { userShell: { check: check(seen) } } })
    await send(body(thinking(`${SHELL}${FAKE.openai}`)))
    assert.deepEqual(seen, [])
    assert.equal(warnings().length, 1)
  })
  it("SB-13 a request the `!` check blocks does not spend the warning of the one that leaves", async () => {
    let fail = true
    const userShell = {
      check: async () => {
        if (fail) throw new UserShellUncheckedError("timed out")
        return { masked: new Map<string, string>(), words: 0, parts: 0 }
      },
    }
    const { send, warnings } = await wire(createRedactor(), { deps: { userShell } })
    const value = body(thinking(FAKE.openai), { type: "text", text: SHELL })
    await assert.rejects(send(value))
    assert.ok(!warnings().some((line) => line.includes("signed")))
    fail = false
    await send(value)
    assert.equal(warnings().filter((line) => line.includes("signed")).length, 1)
  })
  it("SB-18 the same over WebSocket", async () => {
    let fail = true
    const userShell = {
      check: async () => {
        if (fail) throw new UserShellUncheckedError("timed out")
        return { masked: new Map<string, string>(), words: 0, parts: 0 }
      },
    }
    const { frame, warnings } = await wire(createRedactor(), { deps: { userShell } })
    const value = body(thinking(FAKE.openai), { type: "text", text: SHELL })
    await assert.rejects(frame(value))
    assert.ok(!warnings().some((line) => line.includes("signed")))
    fail = false
    await frame(value)
    assert.equal(warnings().filter((line) => line.includes("signed")).length, 1)
  })
})

describe("the check changes nothing in what is sent", () => {
  it("witness: a body whose only secret is in a signed block is not rebuilt", async () => {
    const { fake } = await wire()
    const request = post(body(thinking(FAKE.openai)))
    assert.equal((await fake.trigger("session.http.request", { kind: "primary", sessionID: "s", request })).request, request)
    const text = JSON.stringify(body(thinking(FAKE.openai)))
    assert.equal((await fake.trigger("session.experimental.ws.send", { kind: "primary", sessionID: "s", frame: text })).frame, text)
  })
  it("witness: the signed block keeps every byte, the text beside it is masked as before", async () => {
    const { send } = await wire()
    const block = { signature: "sig", thinking: `${FAKE.openai}  é​`, type: "thinking" }
    const sent = await (await send(body(block, { type: "text", text: FAKE.github }))).request.text()
    assert.equal(sent, JSON.stringify(body(block, { type: "text", text: "[[GUARD_REDACTED:github_token]]" })))
  })
  it("witness: a value seen in a signed block is not learned, the next bodies stay the same", async () => {
    const redactor = createRedactor()
    const { send } = await wire(redactor)
    await send(body(thinking(`{"type":"key","key":"${LEARNED}"}`)))
    const sent = await (await send(body(thinking(`{"type":"key","key":"${LEARNED}"}`), { type: "text", text: `bare ${LEARNED}` }))).request.text()
    assert.ok(sent.includes(`bare ${LEARNED}`))
    assert.equal(redactor.redactString(`bare ${LEARNED}`).count, 0)
  })
  it("witness: a value learned elsewhere is masked as before", async () => {
    const { send } = await wire()
    const sent = await (await send(body({ type: "text", text: `{"type":"key","key":"${LEARNED}"}` }, thinking("nothing"), { type: "text", text: `bare ${LEARNED}` }))).request.text()
    assert.ok(!sent.includes(LEARNED))
  })
  it("SB-16 a log line redacted during the look is not a secret of the block, and the look goes on", async () => {
    let nested = false
    const redactor = createRedactor({
      runtimeSecrets: () => {
        if (nested) redactor.redactString(`line with ${FAKE.github}`)
        return []
      },
    })
    const { send, warnings } = await wire(redactor)
    await send(body({ type: "text", text: "start" }))
    nested = true
    await send(body(thinking(`{"type":"key","key":"${LEARNED}"} ${FAKE.openai}`)))
    assert.deepEqual(warnings(), ["http.request: 2 secret(s) in signed blocks sent unmasked (opencode_credential x1, openai_key x1)"])
    nested = false
    assert.equal(redactor.redactString(`bare ${LEARNED}`).count, 0)
  })
  it("witness: a redaction nested in a look learns as usual", () => {
    let nested = false
    const redactor = createRedactor({
      runtimeSecrets: () => {
        if (nested) redactor.redactString(`{"type":"key","key":"${LEARNED}"}`)
        return []
      },
    })
    nested = true
    redactor.redactDeep("nothing", { onSecret: () => {} })
    nested = false
    assert.equal(redactor.redactString(`bare ${LEARNED}`).count, 1)
  })
  it("SB-19 a plain `redactDeep` nested in a look neither ends the look nor feeds it", () => {
    let nested = true
    const redactor = createRedactor({
      runtimeSecrets: () => {
        if (nested) {
          nested = false
          redactor.redactDeep({ text: FAKE.github })
        }
        return []
      },
    })
    const found: string[] = []
    redactor.redactDeep({ text: FAKE.openai }, { onSecret: (type) => found.push(type) })
    assert.deepEqual(found, ["openai_key"])
  })
  it("SB-14 a value learned in the same body is known in the signed block", async () => {
    const { send, warnings } = await wire()
    await send(body({ type: "text", text: `{"type":"key","key":"${LEARNED}"}` }, thinking(`bare ${LEARNED}`)))
    assert.deepEqual(warnings(), ["http.request: 1 secret(s) in signed blocks sent unmasked (opencode_credential x1)"])
  })
})

describe("what is read in a signed block", () => {
  it("SB-20 `data` outside a `redacted_thinking`", async () => {
    const { send, warnings } = await wire()
    await send(body({ type: "thinking", thinking: "plain", data: FAKE.openai, signature: "sig" }))
    assert.deepEqual(warnings(), ["http.request: 1 secret(s) in signed blocks sent unmasked (openai_key x1)"])
  })
  it("SB-21 a signature that is not text", async () => {
    const { send, warnings } = await wire()
    await send(body({ type: "thinking", thinking: "plain", signature: { note: FAKE.openai } }))
    assert.deepEqual(warnings(), ["http.request: 1 secret(s) in signed blocks sent unmasked (openai_key x1)"])
  })
  it("SB-22 a value beside a placeholder", async () => {
    const { send, warnings } = await wire()
    await send(body(thinking(`MY_PASSWORD=[[GUARD_REDACTED:foo]]${FAKE.password}`)))
    assert.deepEqual(warnings(), ["http.request: 1 secret(s) in signed blocks sent unmasked (generic_secret x1)"])
  })
})

describe("what is not reported", () => {
  it("witness: signature and encrypted content are not read: only chance matches live there", async () => {
    const { send, warnings } = await wire()
    await send(body({ type: "thinking", thinking: "plain", signature: FAKE.openai }, { type: "reasoning", encrypted_content: FAKE.openai }, { type: "redacted_thinking", data: FAKE.openai }, { text: "ok", thoughtSignature: FAKE.openai }))
    assert.deepEqual(warnings(), [])
  })
  it("witness: a block with nothing in it, a placeholder already there", async () => {
    const { send, warnings } = await wire()
    await send(body(thinking("[[GUARD_REDACTED:openai_key]] was masked"), thinking("nothing")))
    assert.deepEqual(warnings(), [])
  })
  it("witness: tool arguments with a crafted `signature` are redacted, not reported", async () => {
    const { send, warnings } = await wire()
    const sent = await (await send(body({ type: "tool_use", id: "t", name: "x", input: { signature: "1", text: FAKE.openai } }))).request.text()
    assert.ok(!sent.includes(FAKE.openai))
    assert.deepEqual(warnings(), [])
  })
  it("witness: `redactWire` relaxed: no look at all", async () => {
    let calls = 0
    const redactor = createRedactor()
    const { send, warnings } = await wire({ ...redactor, redactDeep: (value, options) => (calls++, redactor.redactDeep(value, options)) }, { deps: { relaxation: () => ({ off: new Set(["redactWire"]) }) } })
    await send(body(thinking(FAKE.openai)))
    assert.equal(calls, 0)
    assert.deepEqual(warnings(), [])
  })
})

describe("a failure of the check never stops a request", () => {
  const failingLook = (): Redactor => {
    const redactor = createRedactor()
    return {
      ...redactor,
      redactDeep: (value, options) => {
        if (options?.onSecret) throw new Error("look failed")
        return redactor.redactDeep(value, options)
      },
    }
  }
  it("witness: a look that fails: the request leaves, normal redaction included", async () => {
    const { send } = await wire(failingLook())
    const sent = await (await send(body(thinking(FAKE.openai), { type: "text", text: FAKE.github }))).request.text()
    assert.ok(sent.includes(FAKE.openai))
    assert.ok(!sent.includes(FAKE.github))
  })
  it("SB-15 a look that fails is logged, without blocking", async () => {
    const { send, lines } = await wire(failingLook())
    await send(body(thinking(FAKE.openai)))
    assert.ok(lines.some((line) => line.level === "error" && line.message === "internal error in http.request: signed blocks not checked"))
    assert.ok(!lines.some((line) => line.message.includes("request blocked")))
  })
  it("witness: a logger that throws: the request leaves, over HTTP and WebSocket", async () => {
    const { send, frame } = await wire(createRedactor(), { warn: () => { throw new Error("log failed") } })
    const value = body(thinking(FAKE.openai), { type: "text", text: FAKE.github })
    assert.ok(!(await (await send(value)).request.text()).includes(FAKE.github))
    assert.ok(!(await frame(body(thinking(FAKE.anthropic), { type: "text", text: FAKE.github }))).frame.includes(FAKE.github))
  })
  it("witness: a logger whose `error` throws too: the request leaves, over HTTP and WebSocket", async () => {
    const { send, frame } = await wire(failingLook(), { error: () => { throw new Error("log failed") } })
    const value = body(thinking(FAKE.openai), { type: "text", text: FAKE.github })
    assert.ok(!(await (await send(value)).request.text()).includes(FAKE.github))
    assert.ok(!(await frame(value)).frame.includes(FAKE.github))
  })
  it("SB-23 a look that fails keeps what the blocks before it reported", async () => {
    const redactor = createRedactor()
    let looks = 0
    const failsOnce: Redactor = {
      ...redactor,
      redactDeep: (value, options) => {
        if (options?.onSecret && ++looks === 2) throw new Error("look failed")
        return redactor.redactDeep(value, options)
      },
    }
    const { send, lines, warnings } = await wire(failsOnce)
    const blocks = [thinking(FAKE.openai), thinking("the block that fails")]
    await send(body(...blocks))
    assert.deepEqual(warnings(), ["http.request: 1 secret(s) in signed blocks sent unmasked (openai_key x1)"])
    assert.ok(lines.some((line) => line.level === "error" && line.message === "internal error in http.request: signed blocks not checked"))
    await send(body(...blocks, thinking(`still ${FAKE.openai}`)))
    assert.equal(warnings().length, 1)
  })
  it("witness: a redaction after a look that throws still learns", () => {
    let fail = true
    const accept = () => {
      if (fail) throw new Error("accept failed")
      return true
    }
    const redactor = createRedactor({ extraPatterns: [{ type: "probe", regex: /probe=(?<secret>\w+)/g, accept, learn: true }] })
    assert.throws(() => redactor.redactDeep({ text: "probe=first1234" }, { onSecret: () => {} }))
    fail = false
    assert.equal(redactor.redactString("probe=second5678").count, 1)
    assert.equal(redactor.redactString("bare second5678").count, 1)
  })
})
