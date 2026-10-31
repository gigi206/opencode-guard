// OpenCode 2.2.5 review (dev/plans/maj225): a shell request without a tool call (a scheduled task's condition) is
// denied rather than asked; errors of skipped tools are checked; Google's unsigned-call sentinel is not a signature; a
// connected "Claude Agent" provider is said in the log.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import { CLAUDE_AGENT, CLAUDE_AGENT_WARNING, registerClaudeAgentWarning } from "../src/hooks/claude-agent.ts"
import { registerGate, UNATTENDED_SHELL } from "../src/hooks/gate.ts"
import { registerOutputCheck } from "../src/hooks/output-check.ts"
import { DEFAULT_OUTPUT_CHECK } from "../src/config.ts"
import type { ModelRequest } from "../src/model/client.ts"
import { OUTPUT_QUESTION_ID } from "../src/model/questions.ts"
import { createRedactor, isSignedBlock } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

const silent = { debug() {}, info() {}, warn() {}, error() {} }

async function gate(log = silent) {
  const { config } = parseConfig({})
  const fake = fakeContext()
  const redactor = createRedactor()
  const decider = createDecider({ config, redactor, home: "/home/test" })
  await registerGate(fake.ctx, { decider, redactor, log, home: "/home/test", rules: config.rules })
  const evaluate = (command: string, extra: Record<string, unknown> = {}) =>
    fake.trigger("permission.evaluate", { sessionID: "ses_1", agent: "build", action: "shell", resources: [command], effect: "allow", message: undefined as string | undefined, source: undefined, ...extra })
  return { fake, evaluate }
}

describe("OpenCode 2.2.5: a shell request without a tool call", () => {
  it("M225-1: a local ask becomes a denial, with the reason; OpenCode's own ask too; a command without finding stays allowed", async () => {
    const { evaluate } = await gate()
    const asked = await evaluate("rm -rf build")
    assert.equal(asked.effect, "deny")
    assert.ok(String(asked.message).includes(UNATTENDED_SHELL), String(asked.message))
    assert.equal((await evaluate("make test", { effect: "ask" })).effect, "deny")
    assert.equal((await evaluate("make test")).effect, "allow")
    // A denial stays a denial.
    assert.equal((await evaluate("rm -rf /")).effect, "deny")
  })
  it("M225-2: with a tool call (source), the ask stays an ask", async () => {
    const { evaluate } = await gate()
    const event = await evaluate("rm -rf build", { source: { type: "tool", messageID: "msg_1", id: "call_1" } })
    assert.equal(event.effect, "ask")
  })
  it("M225-3: an internal error of the review, without a tool call, is a denial too", async () => {
    const { evaluate } = await gate()
    // Resources that make the review throw (not an array).
    const event = await evaluate("x", { resources: null })
    assert.equal(event.effect, "deny")
  })
})

describe("OpenCode 2.2.5: errors of skipped tools, Google's sentinel, Claude Agent", () => {
  it("M225-4: an edit error is checked by the model, a successful edit output is not", async () => {
    const fake = fakeContext()
    const requests: ModelRequest[] = []
    const model = async (request: ModelRequest) => (requests.push(request), { answers: { [OUTPUT_QUESTION_ID]: { type: "noul" as const, noul: 0.01 } } })
    await registerOutputCheck(fake.ctx, { redactor: createRedactor(), model, label: "nox-4b", threshold: 0.2, tuning: DEFAULT_OUTPUT_CHECK.tuning, skip: DEFAULT_OUTPUT_CHECK.skip, askAs: "ask", log: silent })
    const base = { sessionID: "ses_1", agent: "build", messageID: "msg_1", input: {}, tool: "edit" }
    await fake.trigger("tool.execute.after", { ...base, id: "a", status: "completed", result: { output: "Edit applied" } })
    assert.equal(requests.length, 0)
    await fake.trigger("tool.execute.after", { ...base, id: "b", status: "error", error: new Error("oldString not found; nearby lines: password: chocolat82") })
    assert.ok(requests.length > 0)
  })
  it("M225-5: a signature equal to Google's sentinel is not a signature; a real one is", () => {
    assert.equal(isSignedBlock({ type: "function_call", signature: "skip_thought_signature_validator", arguments: "{}" }), false)
    assert.equal(isSignedBlock({ type: "text", signature: "EqQBCkgIARABGAIi" }), true)
    assert.equal(isSignedBlock({ signature: "skip_thought_signature_validator", encrypted_content: "x" }), true)
  })
  it("M225-6: Claude Agent connected → one warning; not connected or no integration API → nothing", async () => {
    const lines: string[] = []
    const log = { ...silent, warn: (line: string) => lines.push(line) }
    const asked: string[] = []
    const connected = fakeContext()
    Object.assign(connected.ctx, { integration: { connection: { active: async (id: string) => (asked.push(id), { id: "conn" }) } } })
    await registerClaudeAgentWarning(connected.ctx, log)
    await connected.trigger("session.prompt", { sessionID: "s", prompt: { text: "x" } })
    assert.deepEqual([lines, asked[0]], [[CLAUDE_AGENT_WARNING], CLAUDE_AGENT])
    lines.length = 0
    const absent = fakeContext()
    Object.assign(absent.ctx, { integration: { connection: { active: async () => undefined } } })
    await registerClaudeAgentWarning(absent.ctx, log)
    await registerClaudeAgentWarning(fakeContext().ctx, log)
    assert.deepEqual(lines, [])
  })
})
