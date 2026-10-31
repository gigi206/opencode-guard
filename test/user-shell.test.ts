// Outputs of the user's `!` commands (OpenCode 2.2.5: added to the conversation without any hook): checked on the wire by
// the output check's search; a model failure blocks the request (the user's choice). Fake decision model only.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { DEFAULT_OUTPUT_CHECK } from "../src/config.ts"
import { createUserShellCheck, USER_SHELL_BLOCKED_MESSAGE } from "../src/hooks/output-check.ts"
import { registerRedaction } from "../src/hooks/redaction.ts"
import { promptWords } from "../src/hooks/secret-check.ts"
import { ModelError, type ModelRequest, type ModelResponse } from "../src/model/client.ts"
import { OUTPUT_QUESTION_ID, OUTPUT_VERIFY_QUESTION_ID, OUTPUT_WORD_QUESTION_ID } from "../src/model/questions.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

const silent = { debug() {}, info() {}, warn() {}, error() {} }
const MARK = "[[GUARD_REDACTED:output_secret]]"
const SHELL = "The following shell command was executed by the user:\n<shell>cat notes</shell>\nconnect as deploy with chocolat82\n"

/** Fake decision model (as in output-check.test.ts): `secrets` are values; `fail` makes every call fail. */
function fakeModel(secrets: readonly string[], fail = false) {
  const requests: ModelRequest[] = []
  const model = async (request: ModelRequest): Promise<ModelResponse> => {
    requests.push(request)
    if (fail) throw new ModelError("timed out", { timeout: true })
    const state = request.state as { output: string; value?: string }
    const choice = request.questions[OUTPUT_WORD_QUESTION_ID]
    if (choice?.type === "choice")
      return { answers: { [OUTPUT_WORD_QUESTION_ID]: { type: "choice", probabilities: Object.fromEntries(Object.entries(choice.criteria).map(([k, w]) => [k, secrets.includes(String(w)) ? 0.95 : 0.01])) } } }
    if (request.questions[OUTPUT_VERIFY_QUESTION_ID]) return { answers: { [OUTPUT_VERIFY_QUESTION_ID]: { type: "noul", noul: secrets.includes(String(state.value)) ? 0.95 : 0.05 } } }
    const words = new Set(promptWords(state.output).map((t) => t.word))
    return { answers: { [OUTPUT_QUESTION_ID]: { type: "noul", noul: secrets.some((s) => words.has(s)) ? 0.9 : 0.05 } } }
  }
  return { model, requests }
}

async function wire(secrets: readonly string[], options: { fail?: boolean; check?: boolean } = {}) {
  const fake = fakeContext()
  const { model, requests } = fakeModel(secrets, options.fail)
  const userShell = options.check === false ? {} : { check: createUserShellCheck({ model, label: "nox-4b", threshold: DEFAULT_OUTPUT_CHECK.threshold, tuning: DEFAULT_OUTPUT_CHECK.tuning }) }
  await registerRedaction(fake.ctx, { redactor: createRedactor(), redactPrompt: true, log: silent, userShell })
  const post = (body: unknown) =>
    fake.trigger("session.http.request", { kind: "primary", request: new Request("https://provider.example.test/v1", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }) })
  return { fake, requests, post }
}

const body = (text: string) => ({ messages: [{ role: "user", content: "hello" }, { role: "user", content: [{ type: "text", text }] }] })

describe("! command outputs on the wire", () => {
  it("USH-1: a password in the output is masked in the body sent; the rest of the body is unchanged", async () => {
    const { post } = await wire(["chocolat82"])
    const sent = JSON.parse(await (await post(body(SHELL))).request.text())
    assert.equal(sent.messages[1].content[0].text, SHELL.replace("chocolat82", MARK))
    assert.equal(sent.messages[0].content, "hello")
  })
  it("USH-2: no ! output in the body → the model is not called; nothing found → the request is unchanged", async () => {
    const { post, requests } = await wire(["chocolat82"])
    const plain = await post(body("just a prompt with chocolat82"))
    assert.equal(requests.length, 0)
    assert.ok((await plain.request.text()).includes("chocolat82"))
    const clean = await wire([])
    const event = await clean.post(body(SHELL))
    assert.ok((await event.request.text()).includes("chocolat82"))
  })
  it("USH-3: the decision model fails → the request is blocked with the plugin's message", async () => {
    const { post } = await wire(["chocolat82"], { fail: true })
    await assert.rejects(post(body(SHELL)), { message: USER_SHELL_BLOCKED_MESSAGE })
  })
  it("USH-4: the same output in the next requests comes from the cache; WebSocket frames too", async () => {
    const { post, requests, fake } = await wire(["chocolat82"])
    await post(body(SHELL))
    const first = requests.length
    await post(body(SHELL))
    assert.equal(requests.length, first)
    const frame = await fake.trigger("session.experimental.ws.send", { kind: "primary", frame: JSON.stringify(body(SHELL)) })
    assert.ok(frame.frame.includes(MARK) && !frame.frame.includes("chocolat82"))
  })
  it("USH-5: without the output check (no checker) the body keeps the technical redaction only", async () => {
    const { post } = await wire(["chocolat82"], { check: false })
    assert.ok((await (await post(body(SHELL))).request.text()).includes("chocolat82"))
  })
})
