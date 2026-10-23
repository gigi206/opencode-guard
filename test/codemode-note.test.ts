import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { setupGuard } from "../src/index.ts"
import { registerOutputCheck } from "../src/hooks/output-check.ts"
import { REDACTION_NOTE } from "../src/hooks/redaction.ts"
import type { ModelRequest } from "../src/model/client.ts"
import { OUTPUT_QUESTION_ID } from "../src/model/questions.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"
import { FAKE } from "./fixtures.ts"

// OpenCode 2.1.3 review: a CodeMode script receives the declared output (redacted, without a note) of its internal calls, and
// the script result has nothing left to redact. The note is added to the script result as soon as an internal call
// (same session, same call identifier) has been redacted.

const base = { sessionID: "ses_1", agent: "build", messageID: "msg_1" }
const PLACEHOLDER = "[[GUARD_REDACTED:openai_key]]"
const start = (id: string) => ({ ...base, id, tool: "execute", input: { code: "return 1" } })
const done = (tool: string, result: Record<string, unknown>, id: string) => ({ ...base, id, tool, input: {}, status: "completed" as const, result })
const text = (value: string) => [{ type: "text", text: value }]
const visible = (event: { result: Record<string, unknown> }) => (event.result.content as Array<{ text: string }>).map((part) => part.text).join("\n")
const notes = (value: string) => value.split(REDACTION_NOTE).length - 1

async function setup(options: Record<string, unknown> = {}) {
  const fake = fakeContext(options)
  await setupGuard(fake.ctx, {})
  return fake
}

describe("2.1.3 review: note for the model in a CodeMode script result", () => {
  it("CMN-1: redacted native internal call → note on the script result, which contains only already-placed placeholders", async () => {
    const { trigger } = await setup()
    await trigger("tool.execute.before", start("call_a"))
    const inner = await trigger("tool.execute.after", done("read", { output: { text: `KEY=${FAKE.openai}` }, content: text(`KEY=${FAKE.openai}`) }, "call_a"))
    assert.ok(!JSON.stringify(inner.result).includes(FAKE.openai))
    const outer = await trigger("tool.execute.after", done("execute", { output: { output: PLACEHOLDER }, content: text(`KEY=${PLACEHOLDER}`) }, "call_a"))
    assert.equal(notes(visible(outer)), 1)
    assert.ok(visible(outer).startsWith(`KEY=${PLACEHOLDER}\n\n`))
  })

  it("CMN-2: redacted internal MCP tool call, script result in JSON → note anyway", async () => {
    const { trigger } = await setup()
    await trigger("tool.execute.before", start("call_b"))
    await trigger("tool.execute.after", done("srv_fetch_doc", { output: `token ${FAKE.github}`, content: text(`token ${FAKE.github}`) }, "call_b"))
    const json = JSON.stringify({ token: PLACEHOLDER }, null, 2)
    const outer = await trigger("tool.execute.after", done("execute", { output: { output: json }, content: text(json) }, "call_b"))
    assert.equal(notes(visible(outer)), 1)
  })

  it("CMN-3: secret redacted in the script result itself, in JSON → note (only the model reads this result)", async () => {
    const { trigger } = await setup()
    await trigger("tool.execute.before", start("call_c"))
    const json = JSON.stringify({ key: FAKE.openai })
    const outer = await trigger("tool.execute.after", done("execute", { output: { output: json }, content: text(json) }, "call_c"))
    assert.ok(!visible(outer).includes(FAKE.openai))
    assert.equal(notes(visible(outer)), 1)
  })

  it("CMN-4: error of a redacted internal call → note on the script result", async () => {
    const { trigger } = await setup()
    await trigger("tool.execute.before", start("call_d"))
    const error = new Error(`curl: (22) 401 avec token=${FAKE.password}`)
    await trigger("tool.execute.after", { ...base, id: "call_d", tool: "shell", input: {}, status: "error" as const, error })
    const outer = await trigger("tool.execute.after", done("execute", { output: { output: "x" }, content: text("caught: token=[[GUARD_REDACTED:password]]") }, "call_d"))
    assert.equal(notes(visible(outer)), 1)
  })

  it("CMN-5: script in error → state cleared: a following script with the same identifier without a redacted internal call has no note", async () => {
    const { trigger } = await setup()
    await trigger("tool.execute.before", start("call_e"))
    await trigger("tool.execute.after", done("read", { output: { text: FAKE.openai }, content: text(FAKE.openai) }, "call_e"))
    await trigger("tool.execute.after", { ...base, id: "call_e", tool: "execute", input: {}, status: "error" as const, error: new Error("script failed") })
    await trigger("tool.execute.before", start("call_e"))
    const content = text(`seen: ${PLACEHOLDER}`)
    const outer = await trigger("tool.execute.after", done("execute", { output: { output: "x" }, content }, "call_e"))
    assert.equal(outer.result.content, content)
  })

  it("CMN-6: literal placeholder in an internal call (nothing redacted) → no note", async () => {
    const { trigger } = await setup()
    await trigger("tool.execute.before", start("call_f"))
    await trigger("tool.execute.after", done("read", { output: { text: `README : ${PLACEHOLDER}` }, content: text(`README : ${PLACEHOLDER}`) }, "call_f"))
    const content = text(`README : ${PLACEHOLDER}`)
    const outer = await trigger("tool.execute.after", done("execute", { output: { output: "x" }, content }, "call_f"))
    assert.equal(outer.result.content, content)
  })

  it("CMN-7: never two notes (text of an already annotated internal call returned by the script)", async () => {
    const { trigger } = await setup()
    await trigger("tool.execute.before", start("call_g"))
    const inner = await trigger("tool.execute.after", done("srv_plain", { content: text(`KEY=${FAKE.openai}`) }, "call_g"))
    const outer = await trigger("tool.execute.after", done("execute", { output: { output: "x" }, content: text(visible(inner)) }, "call_g"))
    assert.equal(notes(visible(outer)), 1)
  })

  it("CMN-8: outside a script, nothing changes (JSON without a note, call with the same identifier after the script ends)", async () => {
    const { trigger } = await setup()
    const json = await trigger("tool.execute.after", done("shell", { content: text(JSON.stringify({ key: FAKE.openai })) }, "call_h"))
    assert.equal(notes(visible(json)), 0)
    await trigger("tool.execute.before", start("call_i"))
    await trigger("tool.execute.after", done("execute", { output: { output: "x" }, content: text("done") }, "call_i"))
    await trigger("tool.execute.after", done("read", { content: text(FAKE.openai) }, "call_i"))
    const content = text(`later ${PLACEHOLDER}`)
    const later = await trigger("tool.execute.after", done("execute", { output: { output: "x" }, content }, "call_i"))
    assert.equal(later.result.content, content)
  })
})

describe("2.1.3 review: the note does not give the output check text to judge", () => {
  it("CMN-9: script result made of placeholders and the note → model not called; other text → called", async () => {
    const fake = fakeContext()
    const states: unknown[] = []
    const model = async (request: ModelRequest) => {
      states.push(request.state)
      return { answers: { [OUTPUT_QUESTION_ID]: { type: "noul" as const, noul: 0.1 } } }
    }
    const log = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} }
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
    })
    await fake.trigger("tool.execute.before", start("call_j"))
    await fake.trigger("tool.execute.after", done("execute", { output: { output: PLACEHOLDER }, content: text(`${PLACEHOLDER}\n\n${REDACTION_NOTE}`) }, "call_j"))
    assert.equal(states.length, 0)
    await fake.trigger("tool.execute.before", start("call_k"))
    await fake.trigger("tool.execute.after", done("execute", { output: { output: "x" }, content: text(`user list: ${PLACEHOLDER}\n\n${REDACTION_NOTE}`) }, "call_k"))
    assert.equal(states.length, 1)
  })
})
