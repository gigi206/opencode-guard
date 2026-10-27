// Lot 48 step A: why the plugin asks or denies. The rule is named in denials, unattended denials and the asks set by
// `permission.evaluate`; a request's action carries the rule and the reason (OpenCode shows only the action of a plugin's
// request); asks and denials are logged at info level with their rule. Nothing is launched: text is judged.
// Only the gate's namespace is imported, so that the deployed code (without the new exports) fails on assertions.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { setupGuard } from "../src/index.ts"
import * as gate from "../src/hooks/gate.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { createLogger } from "../src/types.ts"
import { fakeContext } from "./fake-ctx.ts"
import { FAKE } from "./fixtures.ts"

/** Constant part of the action: never redacted. */
const PREFIX = "guard · "
const RESET = "git reset --hard (uncommitted changes lost)"
const base = { sessionID: "ses_1", agent: "build", messageID: "msg_1" }
const before = (tool: string, input: unknown, id = "call_1") => ({ ...base, id, tool, input })
const evaluation = (action: string, resources: string[], effect = "allow", extra: Record<string, unknown> = {}) => ({
  sessionID: "ses_1",
  action,
  resources,
  effect,
  message: undefined as string | undefined,
  source: { type: "tool", messageID: "msg_1", id: "call_9" },
  ...extra,
})

function capture() {
  const lines: string[] = []
  const log = {
    debug: (m: string) => lines.push(`DEBUG ${m}`),
    info: (m: string) => lines.push(`INFO ${m}`),
    warn: (m: string) => lines.push(`WARN ${m}`),
    error: (m: string) => lines.push(`ERROR ${m}`),
  }
  return { lines, log }
}

/** Gate with a fixed decision (no redaction by `decide.ts`: what is checked is the gate's own). */
async function gateWith(decide: () => Promise<unknown>, deps: Record<string, unknown> = {}) {
  const fake = fakeContext()
  const { lines, log } = capture()
  await gate.registerGate(fake.ctx, { decider: { decide } as never, redactor: createRedactor(), log, ...deps })
  return { fake, lines }
}
const fixed = (decision: Record<string, unknown>) => async () => ({ source: "local", redactedInput: {}, ...decision })

async function guard(options: Record<string, unknown> = {}) {
  const fake = fakeContext(options)
  await setupGuard(fake.ctx, {})
  return fake
}

/** The last request made by `execute.before`, given to `permission.evaluate` as OpenCode does (default agent: `effect`). */
async function roundTrip(fake: ReturnType<typeof fakeContext>, effect = "allow", withMetadata = true) {
  const request = fake.asserts.at(-1)!
  return fake.trigger("permission.evaluate", {
    sessionID: request.sessionID,
    agent: request.agent,
    action: request.action,
    resources: request.resources,
    ...(withMetadata ? { metadata: request.metadata } : {}),
    source: request.source,
    effect,
    message: undefined as string | undefined,
  })
}

describe("VIS-1: the rule is named in denials, unattended denials and the asks of permission.evaluate", () => {
  it("VIS-1: denial in execute.before names its rule; the anti-evasion instruction stays", async () => {
    const fake = await guard()
    await assert.rejects(fake.trigger("tool.execute.before", before("shell", { command: "rm -rf ~" })), (error: Error) => {
      assert.match(error.message, /^\[guard\] Blocked \(rule rm-critical\): recursive deletion/)
      assert.ok(error.message.endsWith(gate.NO_EVASION), error.message)
      return true
    })
  })

  it("VIS-1: placeholder names its rule, still without the instruction", async () => {
    assert.equal(gate.blockedMessage("placeholder reason", "placeholder"), "[guard] Blocked (rule placeholder): placeholder reason")
    const fake = await guard()
    await assert.rejects(fake.trigger("tool.execute.before", before("write", { path: "a.ts", content: "[[GUARD_REDACTED:jwt]]" })), (error: Error) => {
      assert.match(error.message, /^\[guard\] Blocked \(rule placeholder\): the content to write contains a redacted secret/)
      assert.doesNotMatch(error.message, /evade/)
      return true
    })
  })

  it("VIS-1 (guard): a decision without a rule keeps today's text", async () => {
    const { fake } = await gateWith(fixed({ verdict: "deny", reason: "nox-4b: risk 2.90/3", source: "model" }))
    await assert.rejects(fake.trigger("tool.execute.before", before("shell", { command: "x" })), (error: Error) => {
      assert.equal(error.message, `[guard] Blocked: nox-4b: risk 2.90/3. ${gate.NO_EVASION}`)
      return true
    })
  })

  it("VIS-1: unattended mode names the rule once, where a denial names it; OpenCode's own asks unchanged", async () => {
    const { fake } = await gateWith(fixed({ verdict: "ask", reason: RESET, rule: "git-reset-hard" }), { askAs: "deny" })
    await assert.rejects(fake.trigger("tool.execute.before", before("shell", { command: "git reset --hard" })), (error: Error) => {
      assert.equal(error.message, `[guard] Blocked (rule git-reset-hard): confirmation required, but unattended mode (askAs: deny) denies it: ${RESET}. ${gate.NO_EVASION}`)
      return true
    })
    const unattended = await guard({ askAs: "deny" })
    const sub = await unattended.trigger("permission.evaluate", evaluation("shell", ["git reset --hard"]))
    assert.equal(sub.effect, "deny")
    assert.equal(sub.message, `[guard] Blocked (rule git-reset-hard): confirmation required, but unattended mode (askAs: deny) denies it: ${RESET}. ${gate.NO_EVASION}`)
    const native = await unattended.trigger("permission.evaluate", evaluation("read", [".env"], "ask"))
    assert.equal(native.message, `[guard] Blocked: confirmation required, but unattended mode (askAs: deny) denies it: read (.env). ${gate.NO_EVASION}`)
  })

  it("VIS-1: asks and denials set on shell sub-commands name their rule", async () => {
    const fake = await guard()
    const ask = await fake.trigger("permission.evaluate", evaluation("shell", ["git reset --hard"]))
    assert.equal(ask.effect, "ask")
    assert.equal(ask.message, `[guard] Confirmation required (rule git-reset-hard): ${RESET}`)
    const deny = await fake.trigger("permission.evaluate", evaluation("shell", ["rm -rf ~"]))
    assert.equal(deny.effect, "deny")
    assert.match(String(deny.message), /^\[guard\] Blocked \(rule rm-critical\): recursive deletion/)
  })
})

describe("VIS-2: rule and reason in the request's action, from execute.before to permission.evaluate", () => {
  it("VIS-2: with a rule; recognized by the prefix alone", async () => {
    const fake = await guard()
    await fake.trigger("tool.execute.before", before("shell", { command: "git reset --hard" }))
    const request = fake.asserts[0]!
    assert.equal(request.action, `${PREFIX}git-reset-hard: ${RESET}`)
    assert.deepEqual(request.metadata, { guard: true, tool: "shell", reason: RESET, rule: "git-reset-hard" })
    const event = await roundTrip(fake)
    assert.equal(event.effect, "ask")
    assert.equal(event.message, `[guard] Confirmation required (rule git-reset-hard): ${RESET}`)
    const bare = await roundTrip(fake, "allow", false)
    assert.equal(bare.effect, "ask")
    assert.equal(bare.message, "[guard] action judged risky")
  })

  it("VIS-2: decision of the model without a rule", async () => {
    const reason = "nox-4b: risk 2.10/3, highest: data destruction 0.91"
    const { fake } = await gateWith(fixed({ verdict: "ask", reason, source: "model" }))
    await fake.trigger("tool.execute.before", before("shell", { command: "x" }))
    assert.equal(fake.asserts[0]!.action, `${PREFIX}${reason}`)
    assert.equal(fake.asserts[0]!.metadata?.rule, undefined)
    const event = await roundTrip(fake)
    assert.equal(event.effect, "ask")
    assert.equal(event.message, `[guard] ${reason}`)
  })

  it("VIS-2: long reason on one line, invisible characters written out, cut at 160 characters", async () => {
    const reason = `first line\nsecond \u001b[31m ${"x".repeat(400)}`
    const { fake } = await gateWith(fixed({ verdict: "ask", reason, rule: "probe" }))
    await fake.trigger("tool.execute.before", before("shell", { command: "x" }))
    const action = fake.asserts[0]!.action
    assert.ok(action.startsWith(`${PREFIX}probe: first line second \\u001b[31m xxx`), action)
    const detail = [...action.slice(PREFIX.length)]
    assert.equal(detail.length, 160)
    assert.equal(detail.at(-1), "…")
    assert.ok(!/[\n\u001b]/.test(action), action)
    assert.equal(fake.asserts[0]!.metadata?.reason, reason)
    assert.equal((await roundTrip(fake)).effect, "ask")
  })

  it("VIS-2: a secret known to the redactor never reaches the action", async () => {
    const known = `vis${"Q7w".repeat(6)}`
    const redactor = createRedactor({ knownSecrets: [{ name: "probe", value: known }] })
    const { fake } = await gateWith(fixed({ verdict: "ask", reason: `token ${FAKE.openai} and ${known} in the command`, rule: "probe" }), { redactor })
    await fake.trigger("tool.execute.before", before("shell", { command: "x" }))
    const action = fake.asserts[0]!.action
    assert.ok(action.startsWith(`${PREFIX}probe: token [[GUARD_REDACTED:`), action)
    assert.ok(action.endsWith(" in the command"), action)
    assert.ok(!action.includes(FAKE.openai) && !action.includes(known), action)
    const event = await roundTrip(fake)
    assert.equal(event.effect, "ask")
    assert.ok(!String(event.message).includes(FAKE.openai) && !String(event.message).includes(known))
  })

  it("VIS-2: internal error, named as such (also when an allowed decision carried a rule)", async () => {
    const { fake } = await gateWith(async () => {
      throw new Error("decider broken")
    })
    await fake.trigger("tool.execute.before", before("shell", { command: "x" }))
    assert.equal(fake.asserts[0]!.action, `${PREFIX}internal-error: internal guard plugin error: confirmation required`)
    assert.equal(fake.asserts[0]!.metadata?.rule, "internal-error")
    const event = await roundTrip(fake)
    assert.equal(event.effect, "ask")
    assert.equal(event.message, "[guard] Confirmation required (rule internal-error): internal guard plugin error: confirmation required")
    const failing = () => {
      throw new Error("directories broken")
    }
    const data = await gateWith(fixed({ verdict: "allow", reason: "decided by the model", rule: "file-delete", source: "model" }), { directoriesOf: failing })
    await data.fake.trigger("tool.execute.before", before("shell", { command: "x" }))
    assert.equal(data.fake.asserts[0]!.action, `${PREFIX}internal-error: internal guard plugin error, the directories where the command runs could not be checked: confirmation required`)
    assert.equal((await roundTrip(data.fake)).effect, "ask")
  })

  it("VIS-2: input unavailable (decider and input redaction broken): the action still carries the reason", async () => {
    const redactor = {
      ...createRedactor(),
      redactDeep: () => {
        throw new Error("redaction broken")
      },
    }
    const { fake } = await gateWith(async () => {
      throw new Error("decider broken")
    }, { redactor })
    await fake.trigger("tool.execute.before", before("shell", { command: "x" }))
    assert.deepEqual(fake.asserts[0]!.resources, ["shell"])
    assert.equal(fake.asserts[0]!.action, `${PREFIX}internal-error: internal guard plugin error: confirmation required`)
    assert.equal((await roundTrip(fake)).effect, "ask")
  })

  it("VIS-2: an error while building the action gives the bare action, and the request is still made", async () => {
    const redactor = {
      ...createRedactor(),
      redactString: () => {
        throw new Error("redaction broken")
      },
    }
    const { fake } = await gateWith(fixed({ verdict: "ask", reason: RESET, rule: "git-reset-hard" }), { redactor })
    await fake.trigger("tool.execute.before", before("shell", { command: "git reset --hard" }))
    assert.equal(fake.asserts.length, 1)
    assert.equal(fake.asserts[0]!.action, "guard")
    assert.equal(fake.asserts[0]!.metadata?.rule, "git-reset-hard")
    assert.equal((await roundTrip(fake)).effect, "ask")
  })

  it("VIS-2: recognized by metadata.guard alone", async () => {
    const fake = await guard()
    const event = await fake.trigger("permission.evaluate", evaluation("other", ["x"], "allow", { metadata: { guard: true, reason: "r" } }))
    assert.equal(event.effect, "ask")
    assert.equal(event.message, "[guard] r")
  })

  it("VIS-2 (guard): an agent rule's denial stays a denial", async () => {
    const fake = await guard()
    await fake.trigger("tool.execute.before", before("shell", { command: "git reset --hard" }))
    const event = await roundTrip(fake, "deny")
    assert.equal(event.effect, "deny")
    assert.equal(event.message, undefined)
  })

  it("VIS-2 (guard): a shell request marked guard still has its sub-commands checked", async () => {
    const fake = await guard()
    const event = await fake.trigger("permission.evaluate", evaluation("shell", ["rm -rf ~"], "allow", { metadata: { guard: true, reason: "r" } }))
    assert.equal(event.effect, "deny")
    assert.match(String(event.message), /Blocked \(rule rm-critical\)/)
  })
})

describe("VIS-3: asks and denials logged at info level with their rule", () => {
  it("VIS-3: execute.before: asks, denials and answers at info level; allows at debug level", async () => {
    const ask = await gateWith(fixed({ verdict: "ask", reason: RESET, rule: "git-reset-hard" }))
    await ask.fake.trigger("tool.execute.before", before("shell", { command: "git reset --hard" }))
    assert.deepEqual(ask.lines, [`INFO shell → ask (local, rule git-reset-hard): ${RESET}`, "INFO shell → confirmed by the user"])
    class DeclinedError extends Error {
      override name = "DeclinedError"
    }
    const declined = await gateWith(fixed({ verdict: "ask", reason: "nox-4b: risk 2.10/3", source: "model", modelMs: 12 }))
    declined.fake.onAssert(async () => {
      throw new DeclinedError("private user feedback")
    })
    await assert.rejects(declined.fake.trigger("tool.execute.before", before("shell", { command: "x" })), DeclinedError)
    assert.deepEqual(declined.lines, ["INFO shell → ask (model): nox-4b: risk 2.10/3 [model 12 ms]", "INFO shell → confirmation not granted (DeclinedError)"])
    const deny = await gateWith(fixed({ verdict: "deny", reason: "fork bomb", rule: "fork-bomb" }))
    await assert.rejects(deny.fake.trigger("tool.execute.before", before("shell", { command: "x" })))
    assert.deepEqual(deny.lines, ["INFO shell → deny (local, rule fork-bomb): fork bomb"])
    const allow = await gateWith(fixed({ verdict: "allow", reason: "nox-4b: risk 0.10/3", source: "model" }))
    await allow.fake.trigger("tool.execute.before", before("shell", { command: "ls" }))
    assert.deepEqual(allow.lines, ["DEBUG shell → allow (model): nox-4b: risk 0.10/3"])
    const unattended = await gateWith(fixed({ verdict: "ask", reason: RESET, rule: "git-reset-hard" }), { askAs: "deny" })
    await assert.rejects(unattended.fake.trigger("tool.execute.before", before("shell", { command: "git reset --hard" })))
    assert.deepEqual(unattended.lines, [`INFO shell → ask (local, rule git-reset-hard): ${RESET}`, "INFO shell → denied (unattended mode)"])
    const unprotected = await gateWith(fixed({ verdict: "allow", reason: "-" }), { unprotected: { isUnprotected: async () => true } })
    await assert.rejects(unprotected.fake.trigger("tool.execute.before", before("write", { path: "a.ts", content: "[[GUARD_REDACTED:jwt]]" })))
    assert.match(unprotected.lines.join("\n"), /^INFO write → deny \(local, rule placeholder, unprotected agent build\): the content to write contains a redacted secret/)
  })

  it("VIS-3: permission.evaluate logs each ask or denial it sets, nothing else", async () => {
    const { fake, lines } = await gateWith(fixed({ verdict: "allow", reason: "-" }), { askAs: "deny" })
    await fake.trigger("permission.evaluate", evaluation("shell", ["ls"]))
    await fake.trigger("permission.evaluate", evaluation("shell", ["git reset --hard"], "ask"))
    assert.deepEqual(lines, ["INFO permission shell → deny (unattended mode): shell (git reset --hard)"])
    const quiet = await gateWith(fixed({ verdict: "allow", reason: "-" }))
    await quiet.fake.trigger("permission.evaluate", evaluation("shell", ["ls"]))
    await quiet.fake.trigger("permission.evaluate", evaluation(`${PREFIX}r`, ["x"], "allow", { metadata: { guard: true, reason: "r" } }))
    assert.deepEqual(quiet.lines, [])
    await quiet.fake.trigger("permission.evaluate", evaluation("shell", ["git reset --hard"]))
    await quiet.fake.trigger("permission.evaluate", evaluation("shell", ["rm -rf ~"]))
    assert.equal(quiet.lines[0], `INFO shell sub-commands → ask (local, rule git-reset-hard): ${RESET}`)
    assert.match(quiet.lines[1] ?? "", /^INFO shell sub-commands → deny \(local, rule rm-critical\): recursive deletion/)
    assert.equal(quiet.lines.length, 2)
  })

  it("VIS-3: written without debug, redacted", async () => {
    const file = join(mkdtempSync(join(tmpdir(), "guard-vis-")), "guard.log")
    const redactor = createRedactor()
    const log = createLogger(false, file, (text) => redactor.redactString(text).value)
    // Marker: the file exists whatever is logged afterwards.
    log.warn("start")
    const fake = fakeContext()
    const reason = `upload of ${FAKE.github}`
    await gate.registerGate(fake.ctx, { decider: { decide: fixed({ verdict: "ask", reason, rule: "probe" }) } as never, redactor, log })
    await fake.trigger("tool.execute.before", before("shell", { command: "x" }))
    const text = readFileSync(file, "utf8")
    assert.match(text, /INFO shell → ask \(local, rule probe\): upload of \[\[GUARD_REDACTED:/)
    assert.match(text, /INFO shell → confirmed by the user/)
    assert.doesNotMatch(text, /DEBUG/)
    assert.ok(!text.includes(FAKE.github), text)
  })
})
