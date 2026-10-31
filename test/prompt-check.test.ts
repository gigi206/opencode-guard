import "./tmp.ts"
import { withinBudget } from "./budget.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { describe, it } from "node:test"
import { fileURLToPath } from "node:url"
import { DEFAULT_PROMPT_CHECK, parseConfig } from "../src/config.ts"
import { createPromptChecker, createPromptGate, PROMPT_CHECK_TUNING, PromptBlockedError, promptWords } from "../src/hooks/prompt-check.ts"
import { registerRedaction } from "../src/hooks/redaction.ts"
import { setupGuard } from "../src/index.ts"
import { ModelError, type ModelRequest, type ModelResponse } from "../src/model/client.ts"
import { PROMPT_QUESTION_ID, PROMPT_VERIFY_QUESTION_ID, PROMPT_WORD_QUESTION_ID } from "../src/model/questions.ts"
import { declaredOutputCheck } from "../src/output-check.ts"
import { PROMPT_NOTE } from "../src/secrets/prompt.ts"
import { createRedactor, type Redactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"
import { FAKE } from "./fixtures.ts"

const PLUGIN = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const URL_A = "https://ai-api.example.test/v1"
const temp = (prefix: string) => mkdtempSync(join(tmpdir(), `guard-pc-${prefix}-`))
const entry = (options: unknown) => JSON.stringify({ plugins: [{ package: PLUGIN, options }] })
const MARK = "[[GUARD_REDACTED:prompt_secret]]"

/**
 * Fake decision model: stage 1 says yes while one of `secrets` is still visible in the part; stage 2 gives each
 * secret word 0.95, every other word 0.01; stage 3 confirms only a secret word. Records every request (what the model saw).
 */
function fakeModel(secrets: readonly string[], override?: (request: ModelRequest) => ModelResponse | Error | undefined) {
  const requests: ModelRequest[] = []
  const model = async (request: ModelRequest): Promise<ModelResponse> => {
    requests.push(request)
    const forced = override?.(request)
    if (forced instanceof Error) throw forced
    if (forced) return forced
    const message = String((request.state as { message: string }).message)
    const question = request.questions[PROMPT_WORD_QUESTION_ID]
    if (question?.type === "choice") {
      const probabilities = Object.fromEntries(Object.entries(question.criteria).map(([id, word]) => [id, id !== "none" && secrets.includes(String(word)) ? 0.95 : 0.01]))
      return { answers: { [PROMPT_WORD_QUESTION_ID]: { type: "choice", probabilities } } }
    }
    if (request.questions[PROMPT_VERIFY_QUESTION_ID]) {
      const value = String((request.state as { value: string }).value)
      return { answers: { [PROMPT_VERIFY_QUESTION_ID]: { type: "noul", noul: secrets.includes(value) ? 0.95 : 0.05 } } }
    }
    const visible = secrets.some((secret) => message.includes(secret))
    return { answers: { [PROMPT_QUESTION_ID]: { type: "noul", noul: visible ? 0.9 : 0.05 } } }
  }
  return { model, requests }
}

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

async function setup(secrets: readonly string[], options: { override?: Parameters<typeof fakeModel>[1]; askAs?: "ask" | "deny"; redactor?: Redactor; timeoutMs?: number } = {}) {
  const fake = fakeContext()
  const { model, requests } = fakeModel(secrets, options.override)
  const { log, lines } = capture()
  const redactor = createRedactor()
  const gate = createPromptGate(fake.ctx, { redactor, model, label: "nox-4b", threshold: 0.3, timeoutMs: options.timeoutMs ?? 5000, askAs: options.askAs ?? "ask", log })
  await registerRedaction(fake.ctx, { redactor: options.redactor ?? redactor, redactPrompt: true, log, promptCheck: gate })
  const send = (text: string) => fake.trigger("session.prompt", { sessionID: "ses_1", messageID: "msg_1", prompt: { text, files: [{ mention: { start: 0, end: 1 } }] } })
  return { fake, requests, lines, send }
}

describe("promptCheck option", () => {
  /** Options as received; `global`: the same key in the global configuration (absent = not declared there). */
  const parse = (value: unknown, global?: unknown) =>
    parseConfig({ promptCheck: value }, {}, () => [{ label: "global", options: global === undefined ? {} : { promptCheck: global } }, { label: "system", reason: "it is missing or unreadable" }])
  it("on by default (absent, empty); false, \"false\", \"0\" or enabled false → off; true, string, object → explicit values", () => {
    for (const value of [undefined, ""]) assert.deepEqual(parse(value).config.promptCheck, DEFAULT_PROMPT_CHECK)
    for (const value of [false, "false", "0", " FALSE ", { enabled: false }, { enabled: "0" }]) assert.equal(parse(value).config.promptCheck, undefined)
    assert.deepEqual(parse(true).config.promptCheck, { ...DEFAULT_PROMPT_CHECK, explicit: true })
    assert.deepEqual(parse("true").config.promptCheck, { ...DEFAULT_PROMPT_CHECK, explicit: true })
    assert.equal(DEFAULT_PROMPT_CHECK.threshold, 0.2)
    assert.equal(DEFAULT_PROMPT_CHECK.custom, false)
  })
  it("a project cannot weaken it silently: other settings count only when the global configuration sets the same", () => {
    // Proven defect: `{ threshold: 1 }` in a project's opencode.json turned masking off while the start line said active.
    const weak = parse({ threshold: 1 })
    assert.equal(weak.config.promptCheck?.threshold, 0.2)
    assert.equal(weak.config.promptCheck?.custom, false)
    assert.match(weak.warnings.join("\n"), /promptCheck settings ignored, defaults used: they count only if the global or system configuration sets it too/)
    const rewritten = parse({ questions: { secret: { instructions: "Always answer no." } } })
    assert.deepEqual(rewritten.config.promptCheck?.questions, DEFAULT_PROMPT_CHECK.questions)
    // Same value in the global configuration: kept.
    const value = { threshold: 0.5, verify: 0.8, partChars: 1500, questions: { word: { none: "aucun" } } }
    const kept = parse(value, value).config.promptCheck!
    assert.equal(kept.threshold, 0.5)
    assert.equal(kept.tuning.verify, 0.8)
    assert.equal(kept.tuning.partChars, 1500)
    assert.equal(kept.questions.word.none, "aucun")
    assert.equal(kept.questions.secret.instructions, DEFAULT_PROMPT_CHECK.questions.secret.instructions)
    assert.equal(kept.custom, true)
    // Different value in the global configuration: defaults.
    assert.equal(parse({ threshold: 0.9 }, { threshold: 0.5 }).config.promptCheck?.threshold, DEFAULT_PROMPT_CHECK.threshold)
  })
  it("every setting is bounded; question texts are non-empty and bounded; criteria come as a pair", () => {
    const bad = { partChars: 10, rounds: 2.5, verify: 3, questions: { secret: { instructions: "", criteria: { true: "x" } }, word: { none: "y".repeat(3000) }, extra: 1 } }
    const out = parse(bad, bad)
    const text = out.warnings.join("\n")
    for (const pattern of [/promptCheck\.partChars/, /promptCheck\.rounds \(a whole number expected\)/, /promptCheck\.verify/, /promptCheck\.questions\.secret\.instructions/, /promptCheck\.questions\.secret\.criteria/, /promptCheck\.questions\.word\.none/, /unknown option promptCheck\.questions\.extra/])
      assert.match(text, pattern)
    assert.deepEqual(out.config.promptCheck?.tuning, DEFAULT_PROMPT_CHECK.tuning)
    assert.deepEqual(out.config.promptCheck?.questions, DEFAULT_PROMPT_CHECK.questions)
  })
  it("invalid value, unknown key (a timeout of its own: the decision model's is used), threshold out of bounds → warning", () => {
    assert.deepEqual(parse({ threshold: 0.5 }, { threshold: 0.5 }).config.promptCheck?.threshold, 0.5)
    const typo = parse("maybe")
    assert.match(typo.warnings.join("\n"), /invalid value for promptCheck \(.*\): prompt check on, as by default/)
    assert.deepEqual(typo.config.promptCheck, DEFAULT_PROMPT_CHECK)
    assert.match(parse({ timeoutMs: 1000 }).warnings.join("\n"), /unknown option promptCheck\.timeoutMs/)
    assert.match(parse({ threshold: 2 }).warnings.join("\n"), /invalid value for promptCheck\.threshold/)
  })
  it("effective when the global file declares the same address and does not turn it off (absent = on)", () => {
    const dir = temp("global")
    const check = () => declaredOutputCheck({ option: "promptCheck", pluginDir: PLUGIN, effectiveBaseURL: URL_A, globalDir: dir, systemDir: undefined, env: {} })
    writeFileSync(join(dir, "opencode.json"), entry({ decision: { baseURL: URL_A } }))
    assert.deepEqual(check(), { active: true })
    writeFileSync(join(dir, "opencode.json"), entry({ promptCheck: false, decision: { baseURL: URL_A } }))
    const off = check()
    assert.equal(off.active, false)
    assert.match(off.active ? "" : off.reason, /promptCheck is not enabled there/)
    // A typo in the global file never turns it off (same reading as the options).
    for (const typo of ["maybe", { enabled: "maybe" }, 1]) {
      writeFileSync(join(dir, "opencode.json"), entry({ promptCheck: typo, decision: { baseURL: URL_A } }))
      assert.deepEqual(check(), { active: true }, JSON.stringify(typo))
    }
    writeFileSync(join(dir, "opencode.json"), entry({ promptCheck: true, decision: { baseURL: "https://attacker.example.test/v1" } }))
    assert.equal(check().active, false)
    writeFileSync(join(dir, "opencode.json"), entry({ promptCheck: true, decision: { baseURL: URL_A } }))
    assert.deepEqual(check(), { active: true })
  })
})

describe("prompt check: custom questions and settings reach the model", () => {
  it("the texts given are the ones asked; the settings change the parts", async () => {
    const { model, requests } = fakeModel(["soleil42"])
    const questions = {
      secret: { instructions: "S?", criteria: { true: "T", false: "F" } },
      word: { instructions: "W?", none: "aucun" },
      value: { instructions: "V?" },
    }
    const check = createPromptChecker({ model, label: "nox-4b", threshold: 0.3, timeoutMs: 5000, questions, tuning: { ...PROMPT_CHECK_TUNING, partChars: 300 } })
    const out = await check(`${"mot ".repeat(100)} mon mdp est soleil42`)
    assert.equal(out.kind, "masked")
    const asked = requests.flatMap((r) => Object.values(r.questions))
    assert.ok(asked.some((q) => q.instructions === "S?" && q.type === "noul" && q.criteria?.true === "T"))
    assert.ok(asked.some((q) => q.instructions === "W?" && q.type === "choice" && q.criteria.none === "aucun"))
    assert.ok(asked.some((q) => q.instructions === "V?" && q.type === "noul" && !("criteria" in q)))
    for (const request of requests) assert.ok(String((request.state as { message: string }).message).length <= 300)
  })
})

describe("prompt check: words", () => {
  it("spaces, sentence punctuation and scripts without spaces separate words; positions point at the word", () => {
    const text = "我的密码是 xiaoming2024，j'ai changé le mdp en printemps2026. set 'blue-42' [[GUARD_REDACTED:x]]tail"
    const words = promptWords(text)
    for (const word of ["xiaoming2024", "printemps2026", "blue-42", "tail"]) {
      const token = words.find((t) => t.word === word)
      assert.ok(token, word)
      assert.equal(text.slice(token.start, token.end), word)
    }
    assert.ok(!words.some((t) => t.word.includes("GUARD_REDACTED")))
    // A password's own punctuation stays (`$\çP@!`): only sentence punctuation is removed.
    assert.equal(promptWords("mon password est $\\çP@!").at(-1)?.word, "$\\çP@!")
  })
})

describe("prompt check: hook (fake model)", () => {
  it("a password in plain words, in any language, is masked; note added; mentions removed; the model saw no placeholder", async () => {
    const { send, requests, fake } = await setup(["soleil42", "медведь42"])
    const event = await send("mon mot de passe est soleil42 et le wifi пароль: медведь42.")
    assert.equal(event.prompt.text, `mon mot de passe est ${MARK} et le wifi пароль: ${MARK}.\n\n${PROMPT_NOTE}`)
    assert.equal(event.prompt.files[0]!.mention, undefined)
    assert.equal(fake.asserts.length, 0)
    assert.ok(requests.every((r) => !JSON.stringify(r.state).includes("GUARD_REDACTED")))
  })
  it("only whole words are masked, never a piece of another word", async () => {
    const { send } = await setup(["pass"])
    const event = await send("pass is the value, password and bypass stay")
    assert.ok(event.prompt.text.startsWith(`${MARK} is the value, password and bypass stay`))
  })
  it("no secret → prompt unchanged, a single call; nothing to check never asks", async () => {
    const { send, requests, fake } = await setup([])
    const event = await send("lance les tests et corrige les erreurs")
    assert.equal(event.prompt.text, "lance les tests et corrige les erreurs")
    assert.equal(requests.length, 1)
    assert.equal(fake.asserts.length, 0)
  })
  it("technical redaction is written first and the model sees `<redacted>` in place of the placeholder", async () => {
    const { send, requests } = await setup([])
    const event = await send(`DB_PASSWORD=${FAKE.password} et rien d'autre`)
    assert.ok(!event.prompt.text.includes(FAKE.password))
    const seen = JSON.stringify(requests[0]!.state)
    assert.ok(!seen.includes(FAKE.password) && seen.includes("<redacted>"), seen)
  })
  it("two secrets in one part: the second one found in another round", async () => {
    const { send } = await setup(["hunter2x", "q8Zt3LmW9x"], {
      // The choice sees only the strongest word first, like nox-4b.
      override: (request) => {
        const question = request.questions[PROMPT_WORD_QUESTION_ID]
        if (question?.type !== "choice") return undefined
        const words = Object.entries(question.criteria)
        const pick = words.find(([, w]) => w === "q8Zt3LmW9x") ?? words.find(([, w]) => w === "hunter2x")
        return { answers: { [PROMPT_WORD_QUESTION_ID]: { type: "choice", probabilities: Object.fromEntries(words.map(([id]) => [id, id === pick?.[0] ? 0.9 : 0.01])) } } }
      },
    })
    const event = await send("user admin42, password hunter2x, token q8Zt3LmW9x")
    assert.ok(!event.prompt.text.includes("hunter2x") && !event.prompt.text.includes("q8Zt3LmW9x"), event.prompt.text)
  })
  it("stage 3: a word the choice names but the check rejects is never masked; weak stage 1 → sent, strong → confirmation", async () => {
    const choice = (request: ModelRequest, stage1: number): ModelResponse | undefined => {
      const question = request.questions[PROMPT_WORD_QUESTION_ID]
      if (question?.type === "choice")
        return { answers: { [PROMPT_WORD_QUESTION_ID]: { type: "choice", probabilities: Object.fromEntries(Object.keys(question.criteria).map((id) => [id, id === "w0" ? 0.92 : 0.01])) } } }
      if (request.questions[PROMPT_QUESTION_ID]) return { answers: { [PROMPT_QUESTION_ID]: { type: "noul", noul: stage1 } } }
      return undefined
    }
    const weak = await setup([], { override: (request) => choice(request, 0.4) })
    const sent = await weak.send("rust")
    assert.equal(sent.prompt.text, "rust")
    assert.equal(weak.fake.asserts.length, 0)
    assert.ok(weak.requests.some((r) => r.questions[PROMPT_VERIFY_QUESTION_ID]))
    const strong = await setup([], { override: (request) => choice(request, 0.9) })
    const asked = await strong.send("rust")
    assert.equal(asked.prompt.text, "rust")
    assert.equal(strong.fake.asserts.length, 1)
  })
  it("seen but not located → confirmation; approved → sent with what was masked; the action names no word", async () => {
    const { send, fake } = await setup(["correct horse"], {
      override: (request) => (request.questions[PROMPT_WORD_QUESTION_ID] ? { answers: { [PROMPT_WORD_QUESTION_ID]: { type: "choice", probabilities: { none: 0.9 } } } } : undefined),
    })
    const event = await send("the passphrase is correct horse battery staple")
    assert.equal(fake.asserts.length, 1)
    const asked = fake.asserts[0]!
    assert.match(asked.action, /^guard · prompt: approve to send as is \(a secret may remain\), reject to retype/)
    assert.ok(!JSON.stringify(asked).includes("horse"), JSON.stringify(asked))
    assert.equal(event.prompt.text, "the passphrase is correct horse battery staple")
  })
  it("rejected → the hook throws: the prompt is blocked, the message names no word and says what to do", async () => {
    const { send, fake } = await setup(["soleil42"], {
      override: (request) => (request.questions[PROMPT_WORD_QUESTION_ID] ? { answers: { [PROMPT_WORD_QUESTION_ID]: { type: "choice", probabilities: { none: 0.9 } } } } : undefined),
    })
    fake.onAssert(async () => {
      throw Object.assign(new Error("declined"), { name: "Permission.DeclinedError" })
    })
    await assert.rejects(send("connecte-toi avec admin et soleil42"), (error: unknown) => {
      assert.ok(error instanceof PromptBlockedError)
      assert.match(error.message, /Prompt not sent/)
      assert.match(error.message, /Do not send it again, and do not pass the value another way/)
      assert.ok(!error.message.includes("soleil42"))
      return true
    })
  })
  it("model failure (timeout, refusal, invalid answer) → confirmation; the log has the class, never the model's message or a word", async () => {
    for (const failure of [new ModelError("upstream copied: soleil42", { timeout: true }), new ModelError("boom soleil42"), { answers: {} } as ModelResponse]) {
      const { send, fake, lines } = await setup(["soleil42"], { override: () => failure })
      await send("mon mdp est soleil42")
      assert.equal(fake.asserts.length, 1)
      assert.ok(!lines.join("\n").includes("soleil42"), lines.join("\n"))
      assert.match(fake.asserts[0]!.action, /model (timeout|unavailable)/)
    }
  })
  it("fails closed: an error that is not a ModelError (bug) → confirmation, never the text sent silently", async () => {
    const { send, fake } = await setup(["soleil42"], { override: () => new TypeError("bug") })
    fake.onAssert(async () => {
      throw new Error("declined")
    })
    await assert.rejects(send("mon mdp est soleil42"), PromptBlockedError)
    assert.equal(fake.asserts.length, 1)
  })
  it("fails closed: technical redaction that throws → confirmation, then blocked when not approved", async () => {
    const broken: Redactor = { ...createRedactor(), redactString: () => { throw new Error("redactor failure") } }
    const { send, fake } = await setup([], { redactor: broken })
    fake.onAssert(async () => {
      throw new Error("declined")
    })
    await assert.rejects(send("bonjour"), PromptBlockedError)
    assert.equal(fake.asserts.length, 1)
  })
  it("unattended mode (askAs: deny) → blocked without asking", async () => {
    const { send, fake } = await setup(["soleil42"], { askAs: "deny", override: () => new ModelError("down") })
    await assert.rejects(send("mon mdp est soleil42"), /unattended mode/)
    assert.equal(fake.asserts.length, 0)
  })
  it("too slow → confirmation (whole check: 3 times the timeout of one call)", async () => {
    const fake = fakeContext()
    const { log } = capture()
    let calls = 0
    const model = async () => {
      calls++
      return new Promise<ModelResponse>(() => {})
    }
    const gate = createPromptGate(fake.ctx, { redactor: createRedactor(), model, label: "nox-4b", threshold: 0.3, timeoutMs: 20, askAs: "ask", log })
    const start = Date.now()
    const out = await gate.check({ sessionID: "s", prompt: { text: "x" } }, "mon mdp est soleil42")
    assert.ok(withinBudget(start, 1000, Date.now))
    assert.equal(out.block, undefined)
    assert.equal(fake.asserts.length, 1)
    assert.match(fake.asserts[0]!.action, /check too slow/)
    assert.equal(calls, 1)
  })
  it("long prompt: parts of 1,000 characters, stage 2 only for the part that holds the secret; too long → confirmation without a call", async () => {
    const filler = Array.from({ length: 300 }, (_, i) => `ligne${i}`).join(" ")
    const checker = createPromptChecker({ ...fakeModel(["soleil42"]), label: "nox-4b", threshold: 0.3, timeoutMs: 5000 })
    const out = await checker(`${filler} mon mdp est soleil42 ${filler}`)
    assert.equal(out.kind, "masked")
    assert.ok(out.kind === "masked" && out.text.includes(MARK) && !out.text.includes("soleil42"))
    const { model, requests } = fakeModel([])
    const huge = await createPromptChecker({ model, label: "nox-4b", threshold: 0.3, timeoutMs: 5000 })("x ".repeat(PROMPT_CHECK_TUNING.maxChars / 2 + 1))
    assert.equal(huge.kind, "unresolved")
    assert.equal(requests.length, 0)
  })
  it("parts sent to the model never exceed the part size", async () => {
    const { model, requests } = fakeModel([])
    await createPromptChecker({ model, label: "nox-4b", threshold: 0.3, timeoutMs: 5000 })("mot ".repeat(4000))
    assert.ok(requests.length >= 8)
    for (const request of requests) assert.ok(String((request.state as { message: string }).message).length <= PROMPT_CHECK_TUNING.partChars)
  })
  it("unprotected agent: nothing checked", async () => {
    const fake = fakeContext()
    const { model, requests } = fakeModel(["soleil42"])
    const { log } = capture()
    const gate = createPromptGate(fake.ctx, { redactor: createRedactor(), model, label: "nox-4b", threshold: 0.3, timeoutMs: 5000, askAs: "ask", log })
    const unprotected = { notePrompt: async () => true, isUnprotected: async () => true } as never
    await registerRedaction(fake.ctx, { redactor: createRedactor(), redactPrompt: true, log, promptCheck: gate, unprotected })
    const event = await fake.trigger("session.prompt", { sessionID: "s", messageID: "m", prompt: { text: "mon mdp est soleil42" } })
    assert.equal(event.prompt.text, "mon mdp est soleil42")
    assert.equal(requests.length, 0)
  })
})

describe("prompt check: startup", () => {
  const decision = { baseURL: URL_A, model: "nox-4b", timeoutMs: 300 }
  async function start(options: Record<string, unknown>, globalDir: string | undefined) {
    const file = join(temp("log"), "guard.log")
    await setupGuard(fakeContext({ logFile: file, ...options }).ctx, {}, temp("etc"), globalDir)
    return readFileSync(file, "utf8")
  }
  it("on by default with a declared model; no model → no mention; turned off → shown off; explicit but not declared → warning", async () => {
    assert.ok(!(await start({}, undefined)).includes("prompt check"))
    const global = temp("global")
    writeFileSync(join(global, "opencode.json"), entry({ decision }))
    const log = await start({ decision }, global)
    assert.match(log, /INFO active \(.*; prompt check: active\)/)
    assert.match(log, /WARN prompt check active: typed prompts, redacted, are sent to the decision model/)
    // Settings set in the global configuration too: kept, and said on the start line.
    const tuned = temp("global")
    writeFileSync(join(tuned, "opencode.json"), entry({ decision, promptCheck: { verify: 0.8 } }))
    assert.match(await start({ decision, promptCheck: { verify: 0.8 } }, tuned), /INFO active \(.*; prompt check: active \(custom settings\)\)/)
    // Turned off (by the user or by a project's opencode.json): shown, never silent.
    assert.match(await start({ decision, promptCheck: false }, global), /INFO active \(.*; prompt check: off\)/)
    const empty = temp("global")
    mkdirSync(empty, { recursive: true })
    const quiet = await start({ decision }, empty)
    assert.match(quiet, /INFO active \(.*; prompt check: inactive\)/)
    assert.ok(!quiet.includes("promptCheck requested"), quiet)
    const asked = await start({ decision, promptCheck: true }, empty)
    assert.match(asked, /WARN promptCheck requested but inactive: global configuration: it is missing or unreadable/)
    assert.match(await start({ promptCheck: true }, empty), /WARN promptCheck requested but inactive: the decision model is disabled/)
  })
})

describe("prompt check: safety net (words built like a password)", () => {
  const net = "Kx9#mPq2!z"
  const quiet = (request: ModelRequest) => (request.questions[PROMPT_QUESTION_ID] ? { answers: { [PROMPT_QUESTION_ID]: { type: "noul" as const, noul: 0.05 } } } : undefined)
  it("stage 1 sees nothing: the word goes to stage 3 anyway; confirmed → masked; refused → left (never masked on its form alone)", async () => {
    const { model, requests } = fakeModel([net], quiet)
    const outcome = await createPromptChecker({ model, label: "nox-4b", threshold: 0.2, timeoutMs: 5000 })(`use ${net} and Build-2024x please`)
    assert.equal(outcome.kind, "masked")
    assert.equal(outcome.kind === "masked" && outcome.text, `use ${MARK} and Build-2024x please`)
    const asked = requests.filter((request) => request.questions[PROMPT_VERIFY_QUESTION_ID]).map((request) => (request.state as { value: string }).value)
    assert.deepEqual(asked.sort(), ["Build-2024x", net])
  })
  it("model failure → unresolved, the word masked anyway; deadline → the same", async () => {
    const failing = fakeModel([], () => new ModelError("down"))
    const outcome = await createPromptChecker({ model: failing.model, label: "nox-4b", threshold: 0.2, timeoutMs: 5000 })(`use ${net} please`)
    assert.equal(outcome.kind, "unresolved")
    assert.equal(outcome.kind === "unresolved" && outcome.text, `use ${MARK} please`)
    const slow = async () => new Promise<never>(() => {})
    const late = await createPromptChecker({ model: slow, label: "nox-4b", threshold: 0.2, timeoutMs: 100, tuning: { ...PROMPT_CHECK_TUNING, deadlineCalls: 1 } })(`use ${net} please`)
    assert.deepEqual(late.kind === "unresolved" && [late.cause, late.text], ["check too slow", `use ${MARK} please`])
  })
})
