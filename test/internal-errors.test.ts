// An internal error never loses a denial, nor allows a part that could not be checked. Errors
// simulated without an exported injection point: user rule whose pattern throws, tracked script whose content
// throws, injectable hook dependencies. Nothing is launched: text is judged.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createDecider, INTERNAL_ERROR_RULE } from "../src/decide.ts"
import { registerGate } from "../src/hooks/gate.ts"
import type { CustomRule } from "../src/rules/types.ts"
import type { ScriptTracker } from "../src/scripts.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

const quiet = { debug() {}, info() {}, warn() {}, error() {} }
const base = { sessionID: "ses_1", agent: "build", messageID: "msg_1", id: "call_1" }
const UNCHECKED = /^internal guard plugin error, .+ could not be checked: confirmation required$/

/** User rule whose pattern throws on text containing `zzfail`: simulated internal error. */
const failing = (): CustomRule => ({
  id: "probe",
  verdict: "ask",
  reason: "probe",
  tools: ["shell"],
  pattern: Object.assign(/zzfail/, {
    test: (text: string) => {
      if (text.includes("zzfail")) throw new Error("simulated internal error")
      return false
    },
  }),
})

/** Tracked script whose content throws when read. */
const brokenScript = () => ({
  path: "s.sh",
  shell: true,
  forModel: false,
  get content(): string {
    throw new Error("simulated internal error")
  },
})

/** Fake log: message and cause message. */
function decider(rules: readonly CustomRule[] = [], errors: string[] = [], extra: Record<string, unknown> = {}) {
  const config = { ...parseConfig({}).config, rules }
  const log = { error: (message: string, error?: unknown) => errors.push(`${message} — ${(error as Error | undefined)?.message}`) }
  return createDecider({ config, redactor: createRedactor(), log, ...extra })
}
const CAUSE = " — simulated internal error"
const PLACEHOLDER = "[[GUARD_REDACTED:openai_key]]"
/** User rule on all tools, whose pattern throws on input containing `zzfail`. */
const failingEverywhere = (): CustomRule => ({ ...failing(), tools: ["*"] })

async function gate(deps: Record<string, unknown> = {}) {
  const fake = fakeContext()
  await registerGate(fake.ctx, { decider: decider(), redactor: createRedactor(), log: quiet, ...deps })
  return fake
}

const evaluation = (resources: string[], effect = "allow") => ({
  ...base,
  action: "shell",
  resources,
  effect,
  message: undefined as string | undefined,
})

describe("decision: a failing part does not hide another part's denial", () => {
  it("tracked script in error, command denied: denial kept; the cause goes to the log", async () => {
    const errors: string[] = []
    const decision = await decider([], errors).decide({ tool: "shell", input: { command: "rm -rf /" }, scripts: [brokenScript()] })
    assert.equal(`${decision.verdict}:${decision.rule}`, "deny:rm-critical")
    assert.deepEqual(errors, [`internal error while checking a script run by this command${CAUSE}`])
  })

  it("tracked script in error, command without a finding: cautious ask (never allowed)", async () => {
    const decision = await decider().decide({ tool: "shell", input: { command: "ls" }, scripts: [brokenScript()] })
    assert.equal(`${decision.verdict}:${decision.rule}`, `ask:${INTERNAL_ERROR_RULE}`)
    assert.match(decision.reason, UNCHECKED)
  })

  it("command in error: cautious ask, generic reason, cause in the log", async () => {
    const errors: string[] = []
    const decision = await decider([failing()], errors).decide({ tool: "shell", input: { command: "echo zzfail" } })
    assert.equal(`${decision.verdict}:${decision.rule}`, `ask:${INTERNAL_ERROR_RULE}`)
    assert.match(decision.reason, UNCHECKED)
    assert.doesNotMatch(decision.reason, /simulated/)
    assert.deepEqual(errors, [`internal error while checking the tool call${CAUSE}`])
  })

  it("another part's ask: the reason also names the unchecked part", async () => {
    const decision = await decider().decide({ tool: "shell", input: { command: "git reset --hard" }, scripts: [brokenScript()] })
    assert.equal(decision.verdict, "ask")
    assert.match(decision.reason, /git reset --hard.*; a script run by this command could not be checked \(internal error\)$/)
  })

  it("user rule that throws on a write: the placeholder denial holds", async () => {
    const decision = await decider([failingEverywhere()]).decide({ tool: "write", input: { path: "a.txt", content: `zzfail ${PLACEHOLDER}` } })
    assert.equal(`${decision.verdict}:${decision.rule}`, "deny:placeholder")
  })

  it("input redaction in error: local rules judge (denial kept), nothing is sent to the model", async () => {
    const errors: string[] = []
    const calls: unknown[] = []
    const model = async (request: unknown) => {
      calls.push(request)
      return { answers: [] }
    }
    const redactor = { ...createRedactor(), redactDeep: () => { throw new Error("simulated internal error") } }
    const broken = decider([], errors, { redactor, model })
    const refused = await broken.decide({ tool: "write", input: { path: "a.txt", content: PLACEHOLDER } })
    assert.equal(`${refused.verdict}:${refused.rule}`, "deny:placeholder")
    const asked = await broken.decide({ tool: "shell", input: { command: "git reset --hard" } })
    assert.equal(asked.verdict, "ask")
    assert.match(asked.reason, /git reset --hard/)
    const unknown = await broken.decide({ tool: "shell", input: { command: "ls" } })
    assert.equal(`${unknown.verdict}:${unknown.rule}`, `ask:${INTERNAL_ERROR_RULE}`)
    assert.match(unknown.reason, /could not be redacted/)
    assert.equal(calls.length, 0)
    assert.equal(errors[0], `internal error while redacting the input${CAUSE}`)
  })
})

describe("permission evaluation: a failing subcommand does not hide another's denial", () => {
  it("failing subcommand next to a denied subcommand: denial", async () => {
    const fake = await gate({ rules: [failing()] })
    for (const resources of [["echo zzfail", "rm -rf /"], ["rm -rf /", "echo zzfail"]]) {
      const event = await fake.trigger("permission.evaluate", evaluation(resources))
      assert.equal(event.effect, "deny", resources.join(" ; "))
      assert.match(event.message ?? "", /recursive deletion/)
    }
  })

  it("failing subcommand next to an ask: the ask's reason is shown", async () => {
    const fake = await gate({ rules: [failing()] })
    const event = await fake.trigger("permission.evaluate", evaluation(["echo zzfail", "git reset --hard"]))
    assert.equal(event.effect, "ask")
    assert.match(event.message ?? "", /git reset --hard/)
  })

  it("log that throws: the other subcommand's denial holds", async () => {
    const log = { ...quiet, error: () => { throw new Error("simulated log failure") } }
    const fake = await gate({ rules: [failing()], log })
    const event = await fake.trigger("permission.evaluate", evaluation(["echo zzfail", "rm -rf /"]))
    assert.equal(event.effect, "deny")
  })

  it("guard: failing subcommand alone, allowed effect → ask", async () => {
    const fake = await gate({ rules: [failing()] })
    const event = await fake.trigger("permission.evaluate", evaluation(["echo zzfail", "ls"]))
    assert.equal(event.effect, "ask")
    assert.match(event.message ?? "", /internal error/)
  })
})

describe("execution: an unchecked part is never allowed", () => {
  const throwingTracker = {
    has: () => true,
    read: () => {
      throw new Error("simulated internal error")
    },
    record: () => false,
    forget: () => {},
    distrust: () => false,
  } as unknown as ScriptTracker
  const throwingDirectories = () => {
    throw new Error("simulated internal error")
  }

  it("reading tracked scripts in error: ask instead of allowing", async () => {
    const fake = await gate({ scripts: throwingTracker })
    await fake.trigger("tool.execute.before", { ...base, tool: "shell", input: { command: "bash ./x.sh" } })
    assert.equal(fake.asserts.length, 1)
    assert.match(String(fake.asserts[0]?.metadata?.reason), UNCHECKED)
    assert.match(String(fake.asserts[0]?.metadata?.reason), /the scripts run by the command/)
  })

  it("command directories in error: ask instead of allowing", async () => {
    const fake = await gate({ directoriesOf: throwingDirectories })
    await fake.trigger("tool.execute.before", { ...base, tool: "shell", input: { command: "ls" } })
    assert.equal(fake.asserts.length, 1)
    assert.match(String(fake.asserts[0]?.metadata?.reason), /the directories where the command runs/)
  })

  it("a denial stays as is; an ask keeps its reason and names the unchecked part", async () => {
    const fake = await gate({ directoriesOf: throwingDirectories, scripts: throwingTracker })
    await assert.rejects(fake.trigger("tool.execute.before", { ...base, tool: "shell", input: { command: "rm -rf /" } }), /recursive deletion/)
    await fake.trigger("tool.execute.before", { ...base, id: "call_2", tool: "shell", input: { command: "git reset --hard" } })
    assert.match(String(fake.asserts.at(-1)?.metadata?.reason), /git reset --hard.*the directories where the command runs could not be checked \(internal error\)$/)
  })
})
