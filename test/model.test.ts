import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import { createModelClient, endpoint, ModelError, type FetchLike, type ModelResponse } from "../src/model/client.ts"
import { DEFAULT_THRESHOLDS, interpret } from "../src/model/questions.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { FAKE } from "./fixtures.ts"

const chatConfig = {
  protocol: "chat" as const,
  baseURL: "https://gateway.local/v1/",
  model: "nox-4b",
  timeoutMs: 200,
  apiKey: undefined as string | undefined,
  headers: {},
}
const systemOneConfig = { ...chatConfig, protocol: "systemone" as const, baseURL: "https://api.typesafe.ai/v1", model: "jev-latest" }

const answers = (risk: number | undefined, nouls: Partial<Record<string, number>> = {}, confidence = 0.9): ModelResponse => ({
  answers: {
    ...(risk === undefined ? {} : { risk: { type: "score", score: risk, confidence } }),
    destructive: { type: "noul", noul: nouls.destructive ?? 0.01 },
    exfiltration: { type: "noul", noul: nouls.exfiltration ?? 0.01 },
    credentials: { type: "noul", noul: nouls.credentials ?? 0.01 },
    privilege_persistence: { type: "noul", noul: nouls.privilege_persistence ?? 0.01 },
  },
})

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } })
/** Gateway (LiteLLM) response: the System One JSON in choices[0].message.content. */
const chatReply = (body: unknown) =>
  json({ id: "x", object: "chat.completion", choices: [{ index: 0, finish_reason: "stop", message: { role: "assistant", content: JSON.stringify(body) } }] })

describe("client: chat protocol (OpenAI-compatible gateway)", () => {
  it("builds the /chat/completions URL", () => {
    assert.equal(endpoint(chatConfig), "https://gateway.local/v1/chat/completions")
    assert.equal(endpoint(systemOneConfig), "https://api.typesafe.ai/v1/systemone")
  })

  it("sends {model, messages} with the System One request serialized in the last message", async () => {
    let seen: { url: string; init: RequestInit } | undefined
    const client = createModelClient({ ...chatConfig, apiKey: "k123" }, async (url, init) => {
      seen = { url, init }
      return chatReply({ model: "jev-latest", ...answers(0) })
    })
    const result = await client({ state: { a: 1 }, questions: { q: { type: "noul", instructions: "x" } } })
    assert.equal(seen?.url, "https://gateway.local/v1/chat/completions")
    assert.equal((seen?.init.headers as Record<string, string>).authorization, "Bearer k123")
    const body = JSON.parse(String(seen?.init.body))
    assert.deepEqual(Object.keys(body), ["model", "messages"])
    assert.equal(body.model, "nox-4b")
    assert.equal(body.messages.length, 1)
    assert.deepEqual(JSON.parse(body.messages[0].content), { state: { a: 1 }, questions: { q: { type: "noul", instructions: "x" } } })
    assert.equal(result.answers.destructive?.noul, 0.01)
  })

  it("missing or non-JSON content → ModelError", async () => {
    const noContent = createModelClient(chatConfig, async () => json({ choices: [] }))
    await assert.rejects(noContent({ state: {}, questions: {} }), /choices\[0\]\.message\.content/)
    const notJson = createModelClient(chatConfig, async () => json({ choices: [{ message: { content: "Hello" } }] }))
    await assert.rejects(notJson({ state: {}, questions: {} }), /response content is not JSON/)
    const noAnswers = createModelClient(chatConfig, async () => chatReply({ model: "x" }))
    await assert.rejects(noAnswers({ state: {}, questions: {} }), /answers/)
  })

  it("HTTP error → ModelError with the server message", async () => {
    const client = createModelClient(chatConfig, async () =>
      json({ error: { message: "Authentication Error, No api key passed in.", type: "auth_error", code: "401" } }, 401),
    )
    await assert.rejects(client({ state: {}, questions: {} }), /^ModelError: HTTP 401: Authentication Error, No api key passed in\.$/)
  })
})

describe("client: systemone protocol (direct API)", () => {
  it("sends {model, state, questions}", async () => {
    let body: any
    const client = createModelClient(systemOneConfig, async (_url, init) => {
      body = JSON.parse(String(init.body))
      return json(answers(0))
    })
    await client({ state: { a: 1 }, questions: {} })
    assert.deepEqual(Object.keys(body), ["model", "state", "questions"])
  })

  it("no auth header without a key", async () => {
    let headers: Record<string, string> = {}
    const client = createModelClient(systemOneConfig, async (_url, init) => {
      headers = init.headers as Record<string, string>
      return json(answers(0))
    })
    await client({ state: {}, questions: {} })
    assert.equal(headers.authorization, undefined)
  })

  for (const status of [401, 422, 429, 500, 529]) {
    it(`HTTP ${status} → ModelError`, async () => {
      const client = createModelClient(systemOneConfig, async () => new Response("", { status }))
      await assert.rejects(client({ state: {}, questions: {} }), (error: unknown) => error instanceof ModelError && error.message === `HTTP ${status}`)
    })
  }

  it("timeout → ModelError", async () => {
    const client = createModelClient(systemOneConfig, (_url, init) => {
      return new Promise((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => reject(init.signal?.reason))
      })
    })
    await assert.rejects(client({ state: {}, questions: {} }), /timed out after 200 ms/)
  })

  it("non-JSON response or missing answers → ModelError", async () => {
    const notJson = createModelClient(systemOneConfig, async () => new Response("oops", { status: 200 }))
    await assert.rejects(notJson({ state: {}, questions: {} }), /non-JSON/)
    const empty = createModelClient(systemOneConfig, async () => json({ model: "jev-latest" }))
    await assert.rejects(empty({ state: {}, questions: {} }), /answers/)
  })
})

describe("response interpretation", () => {
  const t = DEFAULT_THRESHOLDS
  it("allow / ask / deny according to thresholds", () => {
    assert.equal(interpret(answers(0.2), t).verdict, "allow")
    assert.equal(interpret(answers(1.6), t).verdict, "ask")
    assert.equal(interpret(answers(0.3, { exfiltration: 0.5 }), t).verdict, "allow")
    // Lot 16: ask threshold specific to exfiltration (0.85); the other signals keep 0.7.
    assert.equal(interpret(answers(0.3, { exfiltration: 0.75 }), t).verdict, "allow")
    assert.equal(interpret(answers(0.3, { exfiltration: 0.86 }), t).verdict, "ask")
    assert.equal(interpret(answers(0.3, { destructive: 0.72 }), t).verdict, "ask")
    assert.equal(interpret(answers(2.7), t).verdict, "deny")
    assert.equal(interpret(answers(0.5, { destructive: 0.95 }), t).verdict, "deny")
    assert.match(interpret(answers(0.5, { destructive: 0.95 }), t).reason, /data destruction 0\.95/)
  })
  it("low confidence: ignored by default, ask if minConfidence is enabled", () => {
    assert.equal(interpret(answers(0.2, {}, 0.1), t).verdict, "allow")
    assert.equal(interpret(answers(0.2, {}, 0.1), { ...t, minConfidence: 0.4 }).verdict, "ask")
  })
  it("ignored signals (read-only: 'credentials')", () => {
    const read = answers(0.13, { credentials: 0.95 })
    assert.equal(interpret(read, t).verdict, "deny")
    assert.equal(interpret(read, t, "nox-4b", new Set(["credentials"])).verdict, "allow")
  })
  it("incomplete response → ModelError", () => {
    assert.throws(() => interpret({ answers: { risk: { score: 0 } } }, t), ModelError)
  })
  it("refused question (error field, status 200) → ModelError", () => {
    const refused = answers(0)
    refused.answers.exfiltration = { error: "max_length_exceeded" }
    assert.throws(() => interpret(refused, t), /question `exfiltration` refused \(max_length_exceeded\)/)
  })
  it("`risk` score missing or refused → decision on probabilities alone", () => {
    assert.equal(interpret(answers(undefined), t).verdict, "allow")
    assert.equal(interpret(answers(undefined, { credentials: 0.75 }), t).verdict, "ask")
    const refused = answers(2.9)
    refused.answers.risk = { error: "unsupported question type" }
    assert.equal(interpret(refused, t).verdict, "allow")
  })
  it("the model label appears in the reason", () => {
    assert.match(interpret(answers(0.2), t, "nox-4b").reason, /^nox-4b: risk 0\.20\/3, highest: data destruction 0\.01$/)
  })
})

describe("calibration: real nox-4b answers (2026-10-14)", () => {
  // [tool, destructive, exfiltration, credentials, privilege_persistence, risk, confidence, expected verdict, action]
  const REAL: Array<[string, number, number, number, number, number, number, string, string]> = [
    ["read", 0.01, 0.29, 0.43, 0.02, 0.16, 0.67, "allow", "read src/secrets/redact.ts"],
    ["read", 0.01, 0.23, 0.65, 0.01, 0.13, 0.72, "allow", "read src/auth/token.ts"],
    ["grep", 0.01, 0.11, 0.72, 0.02, 0.23, 0.59, "allow", "grep password src"],
    ["shell", 0.01, 0.05, 0.01, 0.02, 0.49, 0.34, "allow", "npm test 2>&1 | tail"],
    ["shell", 0.01, 0.04, 0.01, 0.02, 0.55, 0.34, "allow", "python -m pytest -q"],
    ["shell", 0.05, 0.08, 0.01, 0.03, 1.28, 0.26, "allow", "npm install lodash"],
    ["edit", 0.38, 0.48, 0.02, 0.04, 0.94, 0.68, "allow", "edit src/index.ts"],
    ["write", 0.17, 0.09, 0.01, 0.02, 0.95, 0.36, "allow", "write docs/notes.md"],
    ["shell", 0.96, 0.08, 0.02, 0.3, 2.62, 0.46, "deny", "python shutil.rmtree(~)"],
    ["shell", 0.93, 0.57, 0.01, 0.03, 2.19, 0.28, "deny", "aws s3 rm --recursive"],
    ["shell", 0.04, 0.9, 0.38, 0.03, 2.51, 0.5, "deny", "node fetch(process.env)"],
    ["shell", 0.83, 0.03, 0.0, 0.03, 1.46, 0.14, "ask", "truncate production.db"],
    ["shell", 0.61, 0.76, 0.01, 0.1, 1.75, 0.15, "ask", "git push --delete main"],
    ["shell", 0.82, 0.52, 0.02, 0.12, 2.07, 0.18, "ask", "gh repo delete"],
  ]
  const READ_ONLY = new Set(["read", "glob", "grep"])
  for (const [tool, d, e, c, p, risk, conf, expected, label] of REAL) {
    it(`${expected.padEnd(5)} ${label}`, () => {
      const response: ModelResponse = {
        answers: {
          risk: { score: risk, confidence: conf },
          destructive: { noul: d },
          exfiltration: { noul: e },
          credentials: { noul: c },
          privilege_persistence: { noul: p },
        },
      }
      const ignore = READ_ONLY.has(tool) ? new Set(["credentials"]) : undefined
      assert.equal(interpret(response, DEFAULT_THRESHOLDS, "nox-4b", ignore).verdict, expected)
    })
  }
})

describe("decision (local rules then model)", () => {
  const { config } = parseConfig({ decision: { baseURL: "https://decision.local/v1", model: "nox-4b" } })
  const redactor = createRedactor()

  it("local deny: the model is not called", async () => {
    let calls = 0
    const decider = createDecider({ config, redactor, model: async () => (calls++, answers(0)) })
    const decision = await decider.decide({ tool: "shell", input: { command: "rm -rf /" } })
    assert.equal(decision.verdict, "deny")
    assert.equal(decision.source, "local")
    assert.equal(calls, 0)
  })

  it("local ask: never relaxed by the model", async () => {
    const decider = createDecider({ config, redactor, model: async () => answers(0) })
    const decision = await decider.decide({ tool: "shell", input: { command: "git reset --hard" } })
    assert.equal(decision.verdict, "ask")
    assert.equal(decision.source, "local")
  })

  it("not decided locally → model, with redacted input", async () => {
    let state: any
    const decider = createDecider({
      config,
      redactor,
      model: async (request) => {
        state = request.state
        return answers(2.8)
      },
    })
    const decision = await decider.decide({ tool: "edit", input: { path: "a.ts", oldString: "x", newString: `k="${FAKE.openai}"` } })
    assert.equal(decision.verdict, "deny")
    assert.equal(decision.source, "model")
    assert.ok(!JSON.stringify(state).includes(FAKE.openai))
    assert.match(state.note, /Untrusted/)
  })

  it("model error → ask", async () => {
    const decider = createDecider({
      config,
      redactor,
      model: async () => {
        throw new ModelError("HTTP 529")
      },
    })
    const decision = await decider.decide({ tool: "shell", input: { command: "cat src/a.ts" } })
    assert.equal(decision.verdict, "ask")
    assert.equal(decision.source, "model-error")
    assert.match(decision.reason, /nox-4b unavailable \(HTTP 529\)/)
  })

  it("cache: one call only for the same action, errors not cached", async () => {
    let calls = 0
    let now = 0
    const decider = createDecider({ config, redactor, now: () => now, model: async () => (calls++, answers(0)) })
    await decider.decide({ tool: "shell", input: { command: "cat a" } })
    await decider.decide({ tool: "shell", input: { command: "cat a" } })
    assert.equal(calls, 1)
    now = config.cacheTtlMs + 1
    await decider.decide({ tool: "shell", input: { command: "cat a" } })
    assert.equal(calls, 2)
  })

  it("read-only: never submitted to the model; shell: 'credentials' signal applied", async () => {
    let calls = 0
    const decider = createDecider({ config, redactor, model: async () => (calls++, answers(0.13, { credentials: 0.65 })) })
    const read = await decider.decide({ tool: "read", input: { path: "src/auth/token.ts" } })
    assert.deepEqual([read.verdict, read.source, calls], ["allow", "read-only", 0])
    assert.equal((await decider.decide({ tool: "shell", input: { command: "cat src/auth/token.ts" } })).verdict, "allow")
    const strong = createDecider({ config, redactor, model: async () => answers(0.13, { credentials: 0.95 }) })
    assert.equal((await strong.decide({ tool: "shell", input: { command: "cat x" } })).verdict, "deny")
  })

  it("model disabled → allow (OpenCode permissions only)", async () => {
    const off = parseConfig({}, {}).config
    const decision = await createDecider({ config: off, redactor }).decide({ tool: "shell", input: { command: "ls" } })
    assert.equal(decision.verdict, "allow")
  })

  it("truncates large inputs sent to the model", async () => {
    let state: any
    const decider = createDecider({ config, redactor, model: async (r) => ((state = r.state), answers(0)) })
    await decider.decide({ tool: "write", input: { path: "a.txt", content: "x".repeat(10_000) } })
    assert.equal(typeof state.input, "string")
    assert.ok(state.input.length < 4100)
  })
})

describe("configuration (everything comes from settings, {env:…} substituted by OpenCode)", () => {
  it("baseURL missing, empty or invalid → decision disabled", () => {
    assert.equal(parseConfig({}).config.decision, undefined)
    const empty = parseConfig({ decision: { baseURL: "", model: "m" } })
    assert.equal(empty.config.decision, undefined)
    assert.match(empty.warnings.join(), /decision\.baseURL is empty or missing/)
    const invalid = parseConfig({ decision: { baseURL: "<ton URL>", model: "m" } })
    assert.equal(invalid.config.decision, undefined)
    assert.match(invalid.warnings.join(), /invalid decision\.baseURL/)
  })
  it("model required: no hardcoded model name", () => {
    const { config, warnings } = parseConfig({ decision: { baseURL: "https://ai-gateway.example.com/v1" } })
    assert.equal(config.decision, undefined)
    assert.match(warnings.join(), /decision\.model is empty or missing/)
  })
  it("algorithmic defaults only: chat protocol, 5000 ms timeout", () => {
    const { config } = parseConfig({ decision: { baseURL: "https://ai-gateway.example.com/v1", model: "nox-4b", apiKey: "k-123456789" } })
    assert.deepEqual(
      { protocol: config.decision?.protocol, model: config.decision?.model, timeoutMs: config.decision?.timeoutMs, apiKey: config.decision?.apiKey },
      { protocol: "chat", model: "nox-4b", timeoutMs: 5000, apiKey: "k-123456789" },
    )
  })
  it("empty apiKey ({env:…} undefined) → decision disabled, without the value in the warning", () => {
    const { config, warnings } = parseConfig({ decision: { baseURL: "https://x.local/v1", model: "m", apiKey: "" } })
    assert.equal(config.decision, undefined)
    assert.match(warnings.join(), /decision\.apiKey is empty/)
  })
  it("apiKey missing or null → no authentication", () => {
    assert.equal(parseConfig({ decision: { baseURL: "http://decision.interne/v1", model: "m", protocol: "systemone" } }).config.decision?.apiKey, undefined)
    assert.equal(parseConfig({ decision: { baseURL: "http://decision.interne/v1", model: "m", apiKey: null } }).config.decision?.apiKey, undefined)
  })
  it("apiKey never included in a warning", () => {
    const secret = "sk-gw-ne-doit-jamais-apparaitre-123"
    const { warnings } = parseConfig({ decision: { baseURL: "https://x.local/v1", model: "m", apiKey: secret, timeoutMs: "abc", modle: 1 }, debug: "maybe" })
    assert.ok(warnings.length >= 3)
    assert.ok(!warnings.join(" ").includes(secret))
  })
  it("text values from {env:…}: numbers, booleans, empty string = unset", () => {
    const { config, warnings } = parseConfig({
      thresholds: { askNoul: "0,8", askRisk: "1.8", minConfidence: "" },
      decision: { baseURL: "https://x.local/v1", model: "m", timeoutMs: "3000" },
      debug: "true",
      redactPrompt: "false",
      maxStateChars: "",
    })
    assert.equal(config.thresholds.askNoul, 0.8)
    assert.equal(config.thresholds.askRisk, 1.8)
    assert.equal(config.thresholds.minConfidence, DEFAULT_THRESHOLDS.minConfidence)
    assert.equal(config.decision?.timeoutMs, 3000)
    assert.equal(config.debug, true)
    assert.equal(config.redactPrompt, false)
    assert.equal(config.maxStateChars, 4000)
    assert.deepEqual(warnings, [])
  })
  it("lot 17: `jev` (former name) alone → same configuration as `decision`, without warning", () => {
    const settings = { baseURL: "https://ai-gateway.example.com/v1", protocol: "chat", model: "nox-4b", apiKey: "k-123456789", timeoutMs: "3000", headers: { "x-team": "a" } }
    const current = parseConfig({ decision: settings })
    const former = parseConfig({ jev: settings })
    assert.equal(current.config.decision?.model, "nox-4b")
    assert.deepEqual(former.config, current.config)
    assert.deepEqual([former.warnings, current.warnings], [[], []])
  })
  it("lot 17: `decision` and `jev` → `decision` kept, `jev` ignored with a warning", () => {
    const settings = { baseURL: "https://ai-gateway.example.com/v1", model: "nox-4b" }
    const { config, warnings } = parseConfig({ decision: settings, jev: { ...settings, model: "jev-latest" } })
    assert.equal(config.decision?.model, "nox-4b")
    assert.deepEqual(warnings, ["jev (former name of decision) ignored: decision is set"])
  })
  it("lot 17: invalid `decision` and valid `jev` → model disabled, never fall back to `jev`", () => {
    const settings = { baseURL: "https://ai-gateway.example.com/v1", model: "nox-4b" }
    const { config, warnings } = parseConfig({ decision: { ...settings, baseURL: "" }, jev: settings })
    assert.equal(config.decision, undefined)
    assert.match(warnings.join("\n"), /decision\.baseURL is empty or missing/)
    assert.match(warnings.join("\n"), /jev \(former name of decision\) ignored/)
  })
  it("lot 17: warnings phrased with the name used (`jev.…`)", () => {
    const { config, warnings } = parseConfig({ jev: { baseURL: "https://x.local/v1", model: "m", apiKey: "", modle: 1 } })
    assert.equal(config.decision, undefined)
    assert.match(warnings.join("\n"), /unknown option jev\.modle/)
    assert.match(warnings.join("\n"), /jev\.apiKey is empty/)
    assert.ok(!warnings.join("\n").includes("decision."))
    assert.match(parseConfig({ jev: "x" }).warnings.join(), /invalid value for jev \(object expected\)/)
  })
  it("lot 18: model settings under `decisionModel` → dedicated message, model not configured, content never quoted", () => {
    const KEY = "sk-gw-must-not-leak-0123456789"
    const settings = { baseURL: "https://ai-gateway.example.com/v1", model: "nox-4b", apiKey: KEY }
    const { config, warnings } = parseConfig({ decisionModel: settings })
    assert.equal(config.decision, undefined)
    assert.equal(config.features.decisionModel, true)
    assert.deepEqual(warnings, ['decisionModel is an on/off switch (true or false); the decision model settings go under "decision"'])
    assert.ok(!warnings.join(" ").includes(KEY) && !warnings.join(" ").includes("example"))
  })
  it("lot 18: an object or array is never copied into a warning; an invalid string is still quoted", () => {
    const KEY = "sk-gw-must-not-leak-0123456789"
    const object = { apiKey: KEY }
    const { warnings } = parseConfig({
      cacheMax: object,
      debug: object,
      askAs: object,
      unprotectedAgent: object,
      logFile: object,
      redactWire: [KEY],
      thresholds: { askNoul: object },
      decision: { baseURL: "https://x.local/v1", model: "m", timeoutMs: object },
    })
    const all = warnings.join("\n")
    assert.ok(!all.includes(KEY), all)
    for (const name of ["cacheMax", "debug", "askAs", "unprotectedAgent", "logFile", "thresholds.askNoul", "decision.timeoutMs"])
      assert.match(all, new RegExp(`invalid value for ${name.replace(".", "\\.")} \\(an object\\)`))
    assert.match(all, /invalid value for redactWire \(an array\)/)
    assert.match(parseConfig({ askAs: "denied" }).warnings.join(), /invalid value for askAs \("denied"\)/)
  })
  it("lot 18: boolean `decision` → model disabled, with the switch hint", () => {
    const { config, warnings } = parseConfig({ decision: false })
    assert.equal(config.decision, undefined)
    assert.deepEqual(warnings, ['invalid value for decision (object expected): decision model disabled; to turn the model off, use "decisionModel": false'])
    assert.doesNotMatch(parseConfig({ jev: "x" }).warnings.join(), /decisionModel/)
  })
  it("invalid or out-of-range text value → default with warning", () => {
    const { config, warnings } = parseConfig({ thresholds: { denyNoul: "beaucoup", askNoul: "1.5" } })
    assert.equal(config.thresholds.denyNoul, DEFAULT_THRESHOLDS.denyNoul)
    assert.equal(config.thresholds.askNoul, DEFAULT_THRESHOLDS.askNoul)
    assert.match(warnings.join(" | "), /invalid value for thresholds\.denyNoul.*invalid value for thresholds\.askNoul/)
  })
  it("inconsistent thresholds → warning", () => {
    assert.match(parseConfig({ thresholds: { askNoul: 0.95 } }).warnings.join(), /inconsistent thresholds/)
  })
  it("invalid values → defaults + warnings", () => {
    const { config, warnings } = parseConfig({ thresholds: { denyNoul: 3 }, rules: [{ pattern: "(", verdict: "deny" }] })
    assert.equal(config.thresholds.denyNoul, DEFAULT_THRESHOLDS.denyNoul)
    assert.equal(config.rules.length, 0)
    assert.equal(warnings.length, 2)
  })
})

describe("post-audit fixes: decision and configuration", () => {
  it("all signals ignored → no crash, decision on the score", () => {
    const all = new Set(["destructive", "exfiltration", "credentials", "privilege_persistence"])
    assert.equal(interpret(answers(0.2), DEFAULT_THRESHOLDS, "nox-4b", all).verdict, "allow")
    assert.equal(interpret(answers(2.8), DEFAULT_THRESHOLDS, "nox-4b", all).verdict, "deny")
  })
  it("cached verdict: only the fields of a decision", async () => {
    const { config } = parseConfig({ decision: { baseURL: "https://decision.local/v1", model: "nox-4b" } })
    const decider = createDecider({ config, redactor: createRedactor(), model: async () => answers(0) })
    await decider.decide({ tool: "shell", input: { command: "cat a" } })
    const cached = await decider.decide({ tool: "shell", input: { command: "cat a" } })
    assert.deepEqual(Object.keys(cached).sort(), ["judgedInFull", "reason", "redactedInput", "source", "verdict"])
  })
  it("JSON content-type not overridable by decision.headers", async () => {
    let headers: Record<string, string> = {}
    const client = createModelClient({ ...chatConfig, headers: { "content-type": "text/plain", "x-team": "a" } }, async (_url, init) => {
      headers = init.headers as Record<string, string>
      return chatReply(answers(0))
    })
    await client({ state: {}, questions: {} })
    assert.equal(headers["content-type"], "application/json")
    assert.equal(headers["x-team"], "a")
  })
  it("unknown or wrong-type options → warnings", () => {
    const { warnings } = parseConfig(
      {
        treshold: {},
        logFile: 42,
        thresholds: { askNoull: 0.5 },
        decision: { baseURL: "https://x.local/v1", model: "m", apiKeyEnv: 3, headers: { a: 1 }, modle: "x" },
      },
    )
    const all = warnings.join(" | ")
    for (const expected of [/unknown option treshold/, /invalid value for logFile/, /unknown option thresholds\.askNoull/, /unknown option decision\.modle/, /unknown option decision\.apiKeyEnv/, /invalid value for decision\.headers\.a/])
      assert.match(all, expected)
  })
})

describe("configuration: askAs", () => {
  it("value, or empty string ({env:GUARD_ASK_AS} undefined) → ask", () => {
    assert.equal(parseConfig({}).config.askAs, "ask")
    assert.equal(parseConfig({ askAs: "deny" }).config.askAs, "deny")
    assert.equal(parseConfig({ askAs: " deny " }).config.askAs, "deny")
    const empty = parseConfig({ askAs: "" })
    assert.equal(empty.config.askAs, "ask")
    assert.deepEqual(empty.warnings, [])
  })
  it("invalid value → ask with warning", () => {
    const { config, warnings } = parseConfig({ askAs: "refuse" })
    assert.equal(config.askAs, "ask")
    assert.match(warnings.join(), /invalid value for askAs/)
  })
})

describe("audit no. 3: decision", () => {
  it("error: null or \"\" = no error; error set → ModelError", () => {
    const ok = answers(0.2)
    ok.answers.destructive = { noul: 0.01, error: null }
    ok.answers.risk = { score: 0.2, confidence: 0.9, error: "" }
    assert.equal(interpret(ok, DEFAULT_THRESHOLDS).verdict, "allow")
    assert.match(interpret(ok, DEFAULT_THRESHOLDS).reason, /risk 0\.20\/3/)
    const refused = answers(0.2)
    refused.answers.destructive = { error: "max_length_exceeded" }
    assert.throws(() => interpret(refused, DEFAULT_THRESHOLDS), ModelError)
  })
  it("minConfidence enabled and confidence missing → ask; disabled → unchanged", () => {
    const response = answers(0.2)
    response.answers.risk = { score: 0.2 }
    const asked = interpret(response, { ...DEFAULT_THRESHOLDS, minConfidence: 0.4 })
    assert.equal(asked.verdict, "ask")
    assert.match(asked.reason, /confidence missing/)
    assert.equal(interpret(response, DEFAULT_THRESHOLDS).verdict, "allow")
  })
  it("cache: key = the whole state (agent, directory)", async () => {
    const { config } = parseConfig({ decision: { baseURL: "https://decision.local/v1", model: "nox-4b" } })
    let calls = 0
    const decider = createDecider({ config, redactor: createRedactor(), model: async () => (calls++, answers(0)) })
    const call = { tool: "shell", input: { command: "make build" } }
    await decider.decide({ ...call, agent: "plan", directory: "/a" })
    await decider.decide({ ...call, agent: "build", directory: "/a" })
    await decider.decide({ ...call, agent: "build", directory: "/b" })
    await decider.decide({ ...call, agent: "build", directory: "/b" })
    assert.equal(calls, 3)
  })
})

describe("audit no. 3: configuration", () => {
  it("logFile \" false \" → no file", () => {
    assert.equal(parseConfig({ logFile: " false " }, { HOME: "/home/x" }).config.logFile, undefined)
  })
  it("allowlist trimmed", () => {
    assert.deepEqual(parseConfig({ allowlist: [" abc123XYZ ", " ", 3] }).config.allowlist, ["abc123XYZ"])
  })
  it("rules[].tools: single string accepted, other type reported", () => {
    const { config, warnings } = parseConfig({
      rules: [
        { pattern: "x", verdict: "ask", tools: "*" },
        { pattern: "y", verdict: "ask", tools: 3 },
      ],
    })
    assert.deepEqual(config.rules[0]?.tools, ["*"])
    assert.deepEqual(config.rules[1]?.tools, ["shell"])
    assert.match(warnings.join(), /rules\[1\]\.tools must be/)
  })
  it("booleans: true/false in any case, 1/0", () => {
    const { config, warnings } = parseConfig({ debug: "True", redactPrompt: "0" })
    assert.equal(config.debug, true)
    assert.equal(config.redactPrompt, false)
    assert.deepEqual(warnings, [])
    assert.match(parseConfig({ debug: "yes" }).warnings.join(), /invalid value for debug/)
  })
  it("headers: values trimmed; line break or invalid name refused, value never quoted", () => {
    const { config, warnings } = parseConfig({
      decision: { baseURL: "https://x.local/v1", model: "m", headers: { "x-a": " v1 ", "x-b": "v\r\nInjected: 1", "bad name": "v" } },
    })
    assert.deepEqual(config.decision?.headers, { "x-a": "v1" })
    const all = warnings.join(" | ")
    assert.match(all, /decision\.headers\.x-b \(line break\)/)
    assert.match(all, /invalid header name/)
    assert.ok(!all.includes("Injected"))
  })
})

describe("audit no. 4: response content in parts", () => {
  const reply = (content: unknown) =>
    json({ id: "x", object: "chat.completion", choices: [{ index: 0, finish_reason: "stop", message: { role: "assistant", content } }] })
  it("text parts concatenated, other parts ignored; no text part → ModelError", async () => {
    const text = JSON.stringify(answers(0.2))
    const parts = [{ type: "reasoning", text: "…" }, { type: "text", text: text.slice(0, 10) }, { type: "text", text: text.slice(10) }]
    const ok = createModelClient(chatConfig, async () => reply(parts))
    assert.equal((await ok({ state: {}, questions: {} })).answers.risk?.score, 0.2)
    const empty = createModelClient(chatConfig, async () => reply([{ type: "reasoning", text: "…" }]))
    await assert.rejects(empty({ state: {}, questions: {} }), ModelError)
  })
})

describe("session ses_ec3c…: source 'cache'", () => {
  it("a reused opinion is marked cache, a fresh opinion model", async () => {
    const { config } = parseConfig({ decision: { baseURL: "https://decision.local/v1", model: "nox-4b" } })
    const decider = createDecider({ config, redactor: createRedactor(), model: async () => answers(0) })
    assert.equal((await decider.decide({ tool: "shell", input: { command: "cat a" } })).source, "model")
    assert.equal((await decider.decide({ tool: "shell", input: { command: "cat a" } })).source, "cache")
  })
})

describe("model opinion shown in local confirmations", () => {
  const { config } = parseConfig({ decision: { baseURL: "https://decision.local/v1", model: "nox-4b" } })
  const redactor = createRedactor()
  it("opinion shown, verdict always 'ask' (neither rejection nor approval)", async () => {
    for (const [answer, word] of [[answers(2.8, { destructive: 0.96 }), "deny"], [answers(0.1), "allow"], [answers(1.6), "ask"]] as const) {
      const decision = await createDecider({ config, redactor, model: async () => answer }).decide({ tool: "shell", input: { command: "rm -rf node_modules" } })
      assert.equal(decision.verdict, "ask")
      assert.equal(decision.source, "local")
      assert.match(decision.reason, new RegExp(`^file deletion \\(rm -r/-f\\) — nox-4b opinion: ${word} \\(risk `))
    }
  })
  it("model unreachable: ask without opinion; local rejection: model not consulted", async () => {
    const down = createDecider({ config, redactor, model: async () => { throw new ModelError("HTTP 529") } })
    assert.equal((await down.decide({ tool: "shell", input: { command: "git reset --hard" } })).reason, "git reset --hard (uncommitted changes lost)")
    let calls = 0
    const counting = createDecider({ config, redactor, model: async () => (calls++, answers(0)) })
    assert.equal((await counting.decide({ tool: "shell", input: { command: "rm -rf /" } })).verdict, "deny")
    assert.equal(calls, 0)
    await counting.decide({ tool: "shell", input: { command: "git push --force" } })
    await counting.decide({ tool: "shell", input: { command: "git push --force" } })
    assert.equal(calls, 1)
  })
  it("no model configured: local reason only", async () => {
    const off = createDecider({ config: parseConfig({}).config, redactor })
    assert.equal((await off.decide({ tool: "shell", input: { command: "git clean -fdx" } })).reason, "git clean -f (untracked files deleted)")
  })
})

describe("session ses_ec361019 (audit by another AI): decision model, client, config", () => {
  it("out-of-range values: clamped when judged, never less than an ask", () => {
    const low = interpret(answers(-5, { destructive: -1 }), DEFAULT_THRESHOLDS, "nox-4b")
    assert.equal(low.verdict, "ask")
    assert.match(low.reason, /out-of-range answer: destructive\.noul -1, risk\.score -5/)
    assert.equal(interpret(answers(-5, { destructive: 0.1 }), DEFAULT_THRESHOLDS).verdict, "ask")
    assert.equal(interpret(answers(0.2, { destructive: 5 }), DEFAULT_THRESHOLDS).verdict, "deny")
    assert.equal(interpret(answers(7), DEFAULT_THRESHOLDS).verdict, "deny")
    const normal = interpret(answers(0.2), DEFAULT_THRESHOLDS)
    assert.deepEqual(Object.keys(normal).sort(), ["reason", "verdict"])
    assert.equal(normal.verdict, "allow")
  })
  it("local reason redacted (path containing a key) before the log, the ask and the error", async () => {
    const { config } = parseConfig({ decision: { baseURL: "https://decision.local/v1", model: "nox-4b" } })
    const decider = createDecider({ config, redactor: createRedactor(), model: async () => answers(0.1) })
    for (const [tool, input] of [["read", { path: `/tmp/${FAKE.openai}.pem` }], ["glob", { pattern: `/tmp/${FAKE.openai}/*.pem` }]] as const) {
      const decision = await decider.decide({ tool, input })
      assert.equal(decision.verdict, "ask")
      assert.ok(!decision.reason.includes(FAKE.openai), decision.reason)
    }
  })
  it("headers: case-insensitive names, content-type and authorization never duplicated", async () => {
    let headers: Record<string, string> = {}
    const client = createModelClient(
      { ...chatConfig, apiKey: "k1", headers: { "Content-Type": "text/plain", Authorization: "Bearer other", "X-Team": "a" } },
      async (_url, init) => {
        headers = init.headers as Record<string, string>
        return json({ choices: [{ message: { content: JSON.stringify(answers(0.1)) } }] })
      },
    )
    await client({ state: {}, questions: {} })
    assert.deepEqual(headers, { "content-type": "application/json", authorization: "Bearer k1", "x-team": "a" })
  })
  it("config: logFile 'False', empty tools, g and y flags", () => {
    assert.equal(parseConfig({ logFile: "False" }).config.logFile, undefined)
    assert.equal(parseConfig({ logFile: " FALSE " }).config.logFile, undefined)
    const { config, warnings } = parseConfig({
      rules: [
        { id: "a", pattern: "x", verdict: "ask", tools: ["", " ", "read"] },
        { id: "b", pattern: "x", verdict: "ask", tools: [""] },
        { id: "c", pattern: "x", verdict: "ask", flags: "giy" },
      ],
    })
    assert.deepEqual(config.rules[0]?.tools, ["read"])
    assert.deepEqual(config.rules[1]?.tools, ["shell"])
    assert.equal(config.rules[2]?.pattern.flags, "i")
    assert.ok(warnings.some((w) => /rules\[0\]\.tools: empty or non-string tool names ignored/.test(w)))
    assert.ok(warnings.some((w) => /rules\[1\]\.tools has no valid tool name/.test(w)))
  })
})

describe("lot 7: 'heredoc data only' ask decided by the model", () => {
  const { config } = parseConfig({ decision: { baseURL: "https://decision.local/v1", model: "nox-4b" } })
  const heredoc = { command: "cat > notes.md <<'EOF'\nsudo apt install x\nEOF" }
  const decide = (model: Parameters<typeof createDecider>[0]["model"], input: unknown = heredoc) =>
    createDecider({ config, redactor: createRedactor(), model }).decide({ tool: "shell", input })
  it("the model verdict applies: allow, ask or deny", async () => {
    const allow = await decide(async () => answers(0.1))
    assert.equal(allow.verdict, "allow")
    assert.equal(allow.source, "model")
    assert.match(allow.reason, /only inside heredoc data, decided by nox-4b/)
    assert.equal((await decide(async () => answers(1.8))).verdict, "ask")
    assert.equal((await decide(async () => answers(2.9))).verdict, "deny")
  })
  it("model unreachable or absent → ask; same rule outside data → ask despite an allow", async () => {
    const down = await decide(async () => {
      throw new ModelError("timed out after 5 ms")
    })
    assert.equal(down.verdict, "ask")
    assert.equal(down.source, "local")
    assert.equal((await createDecider({ config, redactor: createRedactor() }).decide({ tool: "shell", input: heredoc })).verdict, "ask")
    assert.equal((await decide(async () => answers(0.1), { command: "sudo apt install x" })).verdict, "ask")
  })
})

describe("lot 12: key or header too short to be redacted", () => {
  it("apiKey < 8 characters → warning without value or length; normal key → none", () => {
    const short = parseConfig({ decision: { baseURL: "https://nox.invalid/v1", model: "nox-4b", apiKey: "k1" } }, {})
    assert.equal(short.config.decision?.apiKey, "k1")
    const warning = short.warnings.find((w) => w.includes("decision.apiKey is shorter"))
    assert.ok(warning)
    assert.ok(!warning.includes("k1"))
    const normal = parseConfig({ decision: { baseURL: "https://nox.invalid/v1", model: "nox-4b", apiKey: FAKE.openai } }, {})
    assert.ok(!normal.warnings.some((w) => w.includes("shorter")))
  })
  it("short authentication header → warning; another short header → none", () => {
    const { warnings } = parseConfig({ decision: { baseURL: "https://nox.invalid/v1", model: "nox-4b", headers: { "x-api-key": "ab", "x-team": "a" } } }, {})
    assert.ok(warnings.some((w) => w.includes("decision.headers.x-api-key is shorter")))
    assert.ok(!warnings.some((w) => w.includes("x-team")))
  })
})

describe("lot 13: model responses — unprintable error, capped bodies", () => {
  it("question refusal with a deeply nested structure: ModelError, never RangeError", () => {
    let deep: Record<string, unknown> = {}
    for (let i = 0; i < 100_000; i++) deep = { a: deep }
    const response = answers(1, {}) as { answers: Record<string, unknown> }
    response.answers.destructive = { type: "noul", error: deep }
    assert.throws(() => interpret(response as ModelResponse, DEFAULT_THRESHOLDS), (error: unknown) => error instanceof ModelError && /question `destructive` refused/.test((error as Error).message))
  })
  it("5 MB error body: bounded message, read stopped early; normal response > 1 MiB: refused", async () => {
    let pulled = 0
    const huge = () =>
      new ReadableStream<Uint8Array>({
        pull(controller) {
          pulled++
          if (pulled > 80) return controller.close()
          controller.enqueue(new TextEncoder().encode("x".repeat(65_536)))
        },
      })
    const failing = createModelClient(systemOneConfig, async () => new Response(huge(), { status: 500 }))
    // Bounded to 2,000 characters (audit 49): the caller redacts then truncates to 160 (`decide.ts`), never the reverse.
    await assert.rejects(failing({ state: {}, questions: {} }), (error: unknown) => (error as Error).message.length <= 2_020)
    assert.ok(pulled < 10, `pulled ${pulled}`)
    pulled = 0
    const large = createModelClient(systemOneConfig, async () => new Response(huge(), { status: 200 }))
    await assert.rejects(large({ state: {}, questions: {} }), /response larger than/)
  })
})

describe("lot 13: configuration — v1 names, allowlist, logFile, maxStateChars", () => {
  const rule = (tools: unknown, pattern = "x") => parseConfig({ rules: [{ id: "r", verdict: "deny", reason: "r", pattern, tools }] }, {})
  it("v1 tool names: alias added and reported; todowrite reported (conditionally); write and patch never reported", () => {
    const array = rule(["bash", "write"])
    assert.deepEqual(array.config.rules[0]?.tools, ["bash", "write", "shell"])
    assert.ok(array.warnings.some((w) => w.includes('"bash" is the OpenCode v1 name of "shell"')))
    assert.deepEqual(rule("apply_patch").config.rules[0]?.tools, ["apply_patch", "patch"])
    assert.ok(rule(["todowrite"]).warnings.some((w) => w.includes('"todowrite" exists in OpenCode v2 only when "experimental.todo" is enabled')))
    assert.ok(!rule(["todowrite"]).warnings.some((w) => w.includes("no longer exists")))
    assert.ok(!rule(["write", "patch", "shell"]).warnings.length)
    assert.ok(rule(["read"], "filePath").warnings.some((w) => w.includes('"filePath", renamed "path"')))
    // Names inherited from Object.prototype: no alias, no warning.
    const inherited = rule(["constructor", "toString"])
    assert.deepEqual(inherited.config.rules[0]?.tools, ["constructor", "toString"])
    assert.ok(!inherited.warnings.length)
  })
  it("allowlist: non-text entry reported by index and type, never the value; non-array reported", () => {
    const { config, warnings } = parseConfig({ allowlist: ["ok-value-1", 42, null] }, {})
    assert.deepEqual(config.allowlist, ["ok-value-1"])
    assert.ok(warnings.includes("allowlist[1] ignored (string expected, got number)"))
    assert.ok(warnings.includes("allowlist[2] ignored (string expected, got null)"))
    assert.ok(!warnings.some((w) => w.includes("42")))
    assert.ok(parseConfig({ allowlist: "x" }, {}).warnings.includes("allowlist must be an array of strings, ignored"))
  })
  it("logFile: `~` expanded, relative path reported; high maxStateChars reported", () => {
    const home = parseConfig({ logFile: "~/logs/guard.log" }, { HOME: "/home/u" })
    assert.equal(home.config.logFile, "/home/u/logs/guard.log")
    assert.ok(!home.warnings.length)
    assert.ok(parseConfig({ logFile: "logs/guard.log" }, {}).warnings.some((w) => w.includes("not an absolute path")))
    assert.ok(parseConfig({ maxStateChars: 9000 }, {}).warnings.some((w) => w.includes("maxStateChars above 8000")))
    assert.ok(!parseConfig({ maxStateChars: 4000 }, {}).warnings.length)
  })
})

describe("lot 16: reads without model, retry on timeout, exfiltration threshold", () => {
  const { config } = parseConfig({ decision: { baseURL: "https://decision.local/v1", model: "nox-4b" } })
  const redactor = createRedactor()
  const timeout = () => new ModelError("timed out after 5000 ms", { timeout: true })

  it("read, glob, grep without a local finding: allowed without a model call; .env: ask without opinion; shell: model", async () => {
    let calls = 0
    const decider = createDecider({ config, redactor, model: async () => (calls++, answers(0.1)) })
    for (const [tool, input] of [["read", { path: "src/a.ts" }], ["glob", { pattern: "**/*.ts" }], ["grep", { pattern: "TODO", path: "src" }]] as const) {
      const decision = await decider.decide({ tool, input })
      assert.deepEqual([decision.verdict, decision.source], ["allow", "read-only"], tool)
    }
    const env = await decider.decide({ tool: "read", input: { path: "/project/.env" } })
    assert.deepEqual([env.verdict, env.source, env.rule], ["ask", "local", "secret-file-read"])
    assert.ok(!env.reason.includes("opinion"), env.reason)
    assert.equal(calls, 0)
    await decider.decide({ tool: "shell", input: { command: "ls" } })
    assert.equal(calls, 1)
  })
  it("todowrite: never submitted to the model (neither verdict nor opinion); local rules kept", async () => {
    let calls = 0
    const decider = createDecider({ config, redactor, model: async () => (calls++, answers(0.9)) })
    const plain = await decider.decide({ tool: "todowrite", input: { todos: [{ content: "review the plan", status: "pending", priority: "high" }] } })
    assert.deepEqual([plain.verdict, plain.source], ["allow", "task-list"])
    const placeholder = await decider.decide({ tool: "todowrite", input: { todos: [{ content: "[[GUARD_REDACTED:openai_key]]", status: "pending", priority: "low" }] } })
    assert.deepEqual([placeholder.verdict, placeholder.source, placeholder.rule], ["deny", "local", "placeholder"])
    const credential = await decider.decide({ tool: "todowrite", input: { todos: [{ content: "/project/.env", status: "pending", priority: "low" }] } })
    assert.deepEqual([credential.verdict, credential.source, credential.rule], ["ask", "local", "secret-file-read"])
    assert.ok(!credential.reason.includes("opinion"), credential.reason)
    const { config: withRule } = parseConfig({
      decision: { baseURL: "https://decision.local/v1", model: "nox-4b" },
      rules: [{ id: "todo-rule", pattern: "MARQUEUR", verdict: "ask", reason: "r", tools: "*" }],
    })
    const custom = await createDecider({ config: withRule, redactor, model: async () => (calls++, answers(0.9)) }).decide({
      tool: "todowrite",
      input: { todos: [{ content: "MARQUEUR", status: "pending", priority: "low" }] },
    })
    assert.deepEqual([custom.verdict, custom.rule], ["ask", "todo-rule"])
    assert.equal(calls, 0)
  })
  it("timeout then response: verdict of the second attempt, duration and attempts reported", async () => {
    let calls = 0
    const decider = createDecider({ config, redactor, model: async () => (++calls === 1 ? Promise.reject(timeout()) : answers(0.1)) })
    const decision = await decider.decide({ tool: "shell", input: { command: "ls" } })
    assert.deepEqual([decision.verdict, decision.source, decision.attempts, calls], ["allow", "model", 2, 2])
    assert.equal(typeof decision.modelMs, "number")
  })
  it("two timeouts: ask 'unavailable … after 2 attempts'; other error: a single attempt", async () => {
    let calls = 0
    const slow = createDecider({ config, redactor, model: async () => (calls++, Promise.reject(timeout())) })
    const decision = await slow.decide({ tool: "shell", input: { command: "ls" } })
    assert.deepEqual([decision.verdict, decision.source, calls], ["ask", "model-error", 2])
    assert.match(decision.reason, /nox-4b unavailable \(timed out after 5000 ms, after 2 attempts\)/)
    for (const error of [new ModelError("HTTP 529"), new Error("boom")]) {
      let n = 0
      const failing = createDecider({ config, redactor, model: async () => (n++, Promise.reject(error)) })
      assert.equal((await failing.decide({ tool: "shell", input: { command: "ls" } })).verdict, "ask")
      assert.equal(n, 1, error.message)
    }
  })
  it("client: request or body read timeout → ModelError.timeout; HTTP error → no", async () => {
    const abort = () => Object.assign(new Error("aborted"), { name: "TimeoutError" })
    const onRequest = createModelClient(chatConfig, async () => Promise.reject(abort()))
    await assert.rejects(onRequest({ state: {}, questions: {} }), (error: unknown) => error instanceof ModelError && error.timeout)
    const body = new ReadableStream({ pull: (controller) => controller.error(abort()) })
    const onBody = createModelClient(chatConfig, async () => new Response(body, { status: 200 }))
    await assert.rejects(onBody({ state: {}, questions: {} }), (error: unknown) => error instanceof ModelError && error.timeout)
    const http = createModelClient(chatConfig, async () => json({ error: "overloaded" }, 529))
    await assert.rejects(http({ state: {}, questions: {} }), (error: unknown) => error instanceof ModelError && !error.timeout)
  })
  it("effective exfiltration threshold: at least askNoul; option read, inconsistency reported", () => {
    const high = { ...DEFAULT_THRESHOLDS, denyNoul: 0.95, askNoul: 0.9 }
    assert.equal(interpret(answers(0.2, { exfiltration: 0.87 }), high).verdict, "allow")
    assert.equal(interpret(answers(0.2, { exfiltration: 0.91 }), high).verdict, "ask")
    assert.match(interpret(answers(0.2, { exfiltration: 0.86 }), DEFAULT_THRESHOLDS).reason, /exfiltration 0\.86/)
    assert.equal(parseConfig({ thresholds: { askExfiltration: 0.8 } }).config.thresholds.askExfiltration, 0.8)
    assert.ok(parseConfig({ thresholds: { askExfiltration: 0.95 } }).warnings.some((warning) => warning.includes("inconsistent thresholds")))
  })
})

describe("lot 27: model client with a real local server, configuration", () => {
  /** Local HTTP server; `handler` receives each request (body read), the number of requests is counted. */
  const serve = async (handler: (req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse, port: number) => void) => {
    const { createServer } = await import("node:http")
    const seen: Array<{ host: string; url: string; custom: boolean }> = []
    const server = createServer((req, res) => {
      req.resume()
      seen.push({ host: String(req.headers.host ?? "").split(":")[0]!, url: req.url ?? "", custom: req.headers["x-team-key"] !== undefined })
      handler(req, res, (server.address() as { port: number }).port)
    })
    await new Promise<void>((done) => server.listen(0, "127.0.0.1", done))
    const port = (server.address() as { port: number }).port
    return {
      baseURL: `http://127.0.0.1:${port}/v1`,
      seen,
      close: () => {
        server.closeAllConnections?.()
        server.close()
      },
    }
  }
  const client = (baseURL: string, timeoutMs = 2000) =>
    createModelClient({ protocol: "systemone", baseURL, model: "m", timeoutMs, apiKey: "fake-key-123456", headers: { "x-team-key": "fake-header-123456" } })

  it("slow body (headers sent, body never finished): timeout honored, 'timeout' error", async () => {
    const server = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" })
      res.write("{")
      const timer = setInterval(() => res.write(" "), 50)
      res.on("close", () => clearInterval(timer))
    })
    const started = Date.now()
    try {
      await assert.rejects(client(server.baseURL, 300)({ state: {}, questions: {} }), (error: unknown) => error instanceof ModelError && error.timeout)
      assert.ok(Date.now() - started < 2000, `${Date.now() - started} ms`)
    } finally {
      server.close()
    }
  })

  for (const [label, host] of [["same address", "127.0.0.1"], ["other address", "localhost"]] as const) {
    it(`redirect (${label}): refused without being followed, a single request, destination never quoted`, async () => {
      const server = await serve((req, res, port) => {
        if (req.url === "/v1/systemone") {
          res.writeHead(307, { location: `http://${host}:${port}/destination-l27` })
          return res.end(`moved to http://${host}:${port}/destination-l27`)
        }
        res.writeHead(200, { "content-type": "application/json" })
        res.end(JSON.stringify({ answers: {} }))
      })
      try {
        await assert.rejects(client(server.baseURL)({ state: {}, questions: {} }), (error: unknown) => {
          assert.ok(error instanceof ModelError && !error.timeout)
          assert.match(error.message, /^HTTP 307: redirect refused/)
          assert.ok(!error.message.includes("destination-l27"), error.message)
          return true
        })
        assert.equal(server.seen.length, 1)
        assert.ok(!server.seen.some((request) => request.url === "/destination-l27"))
      } finally {
        server.close()
      }
    })
  }

  it("redirect: ask via the decider, without retry", async () => {
    const server = await serve((_req, res, port) => {
      res.writeHead(308, { location: `http://localhost:${port}/elsewhere` })
      res.end()
    })
    try {
      const { config } = parseConfig({ decision: { baseURL: server.baseURL, model: "m", protocol: "systemone" } })
      const decider = createDecider({ config, redactor: createRedactor(), model: client(server.baseURL) })
      const decision = await decider.decide({ tool: "shell", input: { command: "ls" } })
      assert.deepEqual([decision.verdict, decision.source, decision.attempts], ["ask", "model-error", 1])
      assert.match(decision.reason, /redirect refused/)
      assert.equal(server.seen.length, 1)
    } finally {
      server.close()
    }
  })

  it("baseURL over HTTP: warning only toward a non-local machine; never the key", () => {
    const warns = (baseURL: string) =>
      parseConfig({ decision: { baseURL, model: "m", apiKey: "sk-gw-jamais-dans-un-avertissement" } }).warnings.filter((w) => w.includes("plain HTTP"))
    for (const local of ["http://127.0.0.1:8080/v1", "http://127.1/v1", "http://localhost/v1", "http://api.localhost/v1", "http://[::1]:9/v1", "https://decision.example/v1"])
      assert.deepEqual(warns(local), [], local)
    for (const remote of ["http://10.0.0.5/v1", "http://decision.interne/v1", "http://0.0.0.0/v1"]) {
      const found = warns(remote)
      assert.equal(found.length, 1, remote)
      assert.match(found[0]!, /^decision\.baseURL uses plain HTTP to a host that is not local/)
      assert.ok(!found[0]!.includes("sk-gw"))
    }
    // Warning only: the model stays active.
    assert.ok(parseConfig({ decision: { baseURL: "http://10.0.0.5/v1", model: "m" } }).config.decision)
    assert.match(parseConfig({ jev: { baseURL: "http://10.0.0.5/v1", model: "m" } }).warnings.join(), /^jev\.baseURL uses plain HTTP/)
  })

  it("askAs: any case accepted, without warning", () => {
    for (const value of ["DENY", "Deny", " deNy "]) {
      const { config, warnings } = parseConfig({ askAs: value })
      assert.equal(config.askAs, "deny", value)
      assert.deepEqual(warnings, [], value)
    }
    assert.equal(parseConfig({ askAs: "Ask" }).config.askAs, "ask")
    assert.match(parseConfig({ askAs: "Refuse" }).warnings.join(), /invalid value for askAs/)
  })

  it("cache: at most 1 h and 10,000 verdicts; beyond that, default value with warning", () => {
    const ok = parseConfig({ cacheTtlMs: 3_600_000, cacheMax: 10_000 })
    assert.deepEqual([ok.config.cacheTtlMs, ok.config.cacheMax, ok.warnings], [3_600_000, 10_000, []])
    const over = parseConfig({ cacheTtlMs: 3_600_001, cacheMax: "10001" })
    assert.deepEqual([over.config.cacheTtlMs, over.config.cacheMax], [600_000, 500])
    assert.match(over.warnings.join(" | "), /invalid value for cacheTtlMs \(3600001\), using default 600000 \| invalid value for cacheMax \("10001"\), using default 500/)
    assert.deepEqual([parseConfig({ cacheTtlMs: 0, cacheMax: 0 }).config.cacheTtlMs, parseConfig({ cacheMax: 0 }).config.cacheMax], [0, 0])
  })
})

describe("lot 36: CodeMode script that reads the web without a tool, decided by the model if it judged everything", () => {
  const { config } = parseConfig({ decision: { baseURL: "https://decision.example/v1", model: "nox-4b" } })
  const read = { code: "const r = await fetch('https://example.com/data.json'); return r.status" }
  const decide = (model: Parameters<typeof createDecider>[0]["model"], input: unknown = read, cfg = config) =>
    createDecider({ config: cfg, redactor: createRedactor(), model }).decide({ tool: "execute", input })
  it("the model verdict applies: allow, ask or deny", async () => {
    const allow = await decide(async () => answers(0.1))
    assert.equal(allow.verdict, "allow")
    assert.equal(allow.source, "model")
    assert.match(allow.reason, /without tool calls or local addresses, decided by nox-4b/)
    assert.equal((await decide(async () => answers(1.8))).verdict, "ask")
    assert.equal((await decide(async () => answers(2.9))).verdict, "deny")
  })
  it("model unreachable or disabled → ask, never a default allow", async () => {
    const down = await decide(async () => {
      throw new ModelError("timed out after 5 ms")
    })
    assert.equal(down.verdict, "ask")
    assert.equal(down.source, "model-error")
    const disabled = await createDecider({ config, redactor: createRedactor() }).decide({ tool: "execute", input: read })
    assert.equal(disabled.verdict, "ask")
    assert.equal(disabled.source, "local")
  })
  it("code truncated for the model → local ask with its opinion", async () => {
    const { config: small } = parseConfig({ decision: { baseURL: "https://decision.example/v1", model: "nox-4b" }, maxStateChars: 200 })
    const long = { code: `${read.code}\n${"// commentaire de remplissage\n".repeat(40)}` }
    const result = await decide(async () => answers(0.1), long, small)
    assert.equal(result.verdict, "ask")
    assert.equal(result.source, "local")
    assert.match(result.reason, /opinion: allow/)
  })
  it("truncated code submitted twice (cache) → still an ask", async () => {
    const { config: small } = parseConfig({ decision: { baseURL: "https://decision.example/v1", model: "nox-4b" }, maxStateChars: 200 })
    const long = { code: `${read.code}\n${"// commentaire de remplissage\n".repeat(40)}` }
    let calls = 0
    const decider = createDecider({ config: small, redactor: createRedactor(), model: async () => (calls++, answers(0.1)) })
    for (const _ of [1, 2]) assert.equal((await decider.decide({ tool: "execute", input: long })).verdict, "ask")
    assert.equal(calls, 1)
  })
  it("reason for an undecided ask: code too long, model unreachable", async () => {
    const { config: small } = parseConfig({ decision: { baseURL: "https://decision.example/v1", model: "nox-4b" }, maxStateChars: 200 })
    const long = { code: `${read.code}\n${"// commentaire de remplissage\n".repeat(40)}` }
    assert.match((await decide(async () => answers(0.1), long, small)).reason, /too long for the decision model to decide/)
    const down = await decide(async () => {
      throw new ModelError("timed out after 5 ms")
    })
    assert.match(down.reason, /CodeMode code making network requests \(fetch\) — nox-4b unavailable \(timed out/)
    assert.equal(down.source, "model-error")
    assert.equal(down.verdict, "ask")
  })
  it("with tools or a local address: ask despite a model allow", async () => {
    assert.equal((await decide(async () => answers(0.1), { code: `${read.code}; await tools.github.search({ q: "a" })` })).verdict, "ask")
    assert.equal((await decide(async () => answers(0.1), { code: "await fetch('http://127.0.0.1:49374/api')" })).verdict, "ask")
  })
})
