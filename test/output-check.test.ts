import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { describe, it } from "node:test"
import { fileURLToPath } from "node:url"
import { checkRequested, DEFAULT_OUTPUT_CHECK, parseConfig } from "../src/config.ts"
import { MAX_ACTION_DETAIL } from "../src/hooks/gate.ts"
import { promptWords } from "../src/hooks/secret-check.ts"
import { registerOutputCheck, UNCHECKED_NOTE, withhold, withheldNotice } from "../src/hooks/output-check.ts"
import { REDACTION_NOTE } from "../src/hooks/redaction.ts"
import { setupGuard } from "../src/index.ts"
import { ModelError, type ModelRequest, type ModelResponse } from "../src/model/client.ts"
import { OUTPUT_QUESTION_ID, OUTPUT_VERIFY_QUESTION_ID, OUTPUT_WORD_QUESTION_ID, PROMPT_QUESTION_ID, PROMPT_VERIFY_QUESTION_ID, PROMPT_WORD_QUESTION_ID } from "../src/model/questions.ts"
import { declaredOutputCheck, globalConfigDirectory } from "../src/output-check.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { declaring } from "./declared.ts"
import { fakeContext } from "./fake-ctx.ts"
import { FAKE } from "./fixtures.ts"

const PLUGIN = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const URL_A = "https://ai-api.example.test/v1"
const temp = (prefix: string) => mkdtempSync(join(tmpdir(), `guard-oc-${prefix}-`))
const entry = (options: unknown) => JSON.stringify({ plugins: [{ package: PLUGIN, options }] })

describe("batch 32: outputCheck option", () => {
  const parse = (value: unknown) => (checkRequested(value) ? parseConfig({ outputCheck: value }) : parseConfig({ outputCheck: value }, {}, declaring({ outputCheck: value })))
  it("on by default (absent, empty); false, \"false\", \"0\" or enabled false → off; true, string, object → explicit values", () => {
    for (const value of [undefined, ""]) assert.deepEqual(parse(value).config.outputCheck, DEFAULT_OUTPUT_CHECK)
    for (const value of [false, "false", "0", { enabled: false }, { enabled: "false" }]) assert.equal(parse(value).config.outputCheck, undefined)
    assert.deepEqual(parse(true).config.outputCheck, { ...DEFAULT_OUTPUT_CHECK, explicit: true })
    assert.deepEqual(parse("TRUE").config.outputCheck, { ...DEFAULT_OUTPUT_CHECK, explicit: true })
    // Other settings: kept only when the global configuration sets the same (a project could weaken the check).
    const value = { threshold: "0,8", timeoutMs: 1500, partChars: 1000, skip: ["read"], questions: { secret: { instructions: "S?", criteria: { true: "T", false: "F" } }, word: { instructions: "W?" } } }
    const declared = () => [{ label: "global", options: { outputCheck: value } }]
    const kept = parseConfig({ outputCheck: value }, {}, declared).config.outputCheck!
    assert.deepEqual([kept.threshold, kept.timeoutMs, kept.tuning.partChars, kept.skip, kept.questions.secret.criteria?.true, kept.questions.word.instructions, kept.questions.word.none, kept.custom], [0.8, 1500, 1000, ["read"], "T", "W?", DEFAULT_OUTPUT_CHECK.questions.word.none, true])
    const weak = parseConfig({ outputCheck: { timeoutMs: 100 } }, {}, declared)
    assert.equal(weak.config.outputCheck?.timeoutMs, DEFAULT_OUTPUT_CHECK.timeoutMs)
    assert.match(weak.warnings.join("\n"), /outputCheck settings ignored, defaults used/)
  })
  it("default values measured for nox-4b (2026-10-31): threshold 0.2, parts of 2,000 at line ends, timeout 5 s, writes and the task list skipped", () => {
    assert.deepEqual([DEFAULT_OUTPUT_CHECK.threshold, DEFAULT_OUTPUT_CHECK.timeoutMs, DEFAULT_OUTPUT_CHECK.tuning.partChars, DEFAULT_OUTPUT_CHECK.explicit, DEFAULT_OUTPUT_CHECK.custom], [0.2, 5000, 2000, false, false])
    assert.deepEqual([...DEFAULT_OUTPUT_CHECK.skip], ["edit", "write", "apply_patch", "patch", "todowrite", "invalid"])
  })
  it("invalid value (kept on), unknown key, setting out of bounds or not whole, invalid skip → warning", () => {
    const typo = parse("maybe")
    assert.match(typo.warnings.join("\n"), /invalid value for outputCheck \(.*\): output check on, as by default/)
    assert.deepEqual(typo.config.outputCheck, DEFAULT_OUTPUT_CHECK)
    assert.match(parse({ threshhold: 1 }).warnings.join("\n"), /unknown option outputCheck\.threshhold/)
    const out = parse({ threshold: 2, rounds: 1.5, skip: "read" })
    assert.equal(out.config.outputCheck?.threshold, DEFAULT_OUTPUT_CHECK.threshold)
    assert.equal(out.config.outputCheck?.tuning.rounds, DEFAULT_OUTPUT_CHECK.tuning.rounds)
    assert.deepEqual(out.config.outputCheck?.skip, DEFAULT_OUTPUT_CHECK.skip)
    assert.match(out.warnings.join("\n"), /invalid value for outputCheck\.threshold/)
    assert.match(out.warnings.join("\n"), /invalid value for outputCheck\.rounds \(a whole number expected\)/)
    assert.match(out.warnings.join("\n"), /invalid value for outputCheck\.skip/)
    // The old `note` is no longer a question text.
    assert.match(parse({ questions: { note: "N" } }).warnings.join("\n"), /unknown option outputCheck\.questions\.note/)
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
  it("declared with the same address → active (trailing slash, JSONC)", () => {
    assert.deepEqual(check(withGlobal(entry({ outputCheck: true, decision: { baseURL: URL_A } }))), { active: true })
    assert.deepEqual(check(withGlobal(entry({ outputCheck: { threshold: 0.9 }, decision: { baseURL: `${URL_A}/` } }))), { active: true })
    const jsonc = `// commentaire\n{ "plugins": [ { "package": "${PLUGIN}", /* c */ "options": { "outputCheck": "true", "decision": { "baseURL": "${URL_A}" }, }, }, ], }`
    assert.deepEqual(check(withGlobal(jsonc, "opencode.jsonc")), { active: true })
  })
  it("{env:…} resolved with the server environment; missing address variable → inactive; missing switch → on", () => {
    const dir = withGlobal(entry({ outputCheck: "{env:GUARD_OC}", decision: { baseURL: "{env:GUARD_URL}" } }))
    assert.deepEqual(check(dir, { GUARD_OC: "true", GUARD_URL: URL_A }), { active: true })
    assert.deepEqual(check(dir, { GUARD_URL: URL_A }), { active: true })
    assert.equal(check(dir, { GUARD_OC: "false", GUARD_URL: URL_A }).active, false)
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
    // Absent = on: then only the address decides.
    assert.match(reason(withGlobal(JSON.stringify({ plugins: [PLUGIN] }))), /address differs/)
    assert.deepEqual(check(withGlobal(entry({ decision: { baseURL: URL_A } }))), { active: true })
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

/**
 * Fake decision model, like the prompt check's: stage 1 says yes while one of `secrets` is still visible in the part;
 * stage 2 gives each secret word 0.95, every other word 0.01; stage 3 confirms only a secret word. `override` answers
 * first (a failure, a forced score). Records every request.
 */
function fakeModel(secrets: readonly string[], override?: (request: ModelRequest) => ModelResponse | Error | undefined) {
  const requests: ModelRequest[] = []
  const model = async (request: ModelRequest): Promise<ModelResponse> => {
    requests.push(request)
    const forced = override?.(request)
    if (forced instanceof Error) throw forced
    if (forced) return forced
    const state = request.state as { output?: string; message?: string; value?: string }
    const text = String(state.output ?? state.message)
    const choice = request.questions[OUTPUT_WORD_QUESTION_ID] ?? request.questions[PROMPT_WORD_QUESTION_ID]
    if (choice?.type === "choice") {
      const id = request.questions[OUTPUT_WORD_QUESTION_ID] ? OUTPUT_WORD_QUESTION_ID : PROMPT_WORD_QUESTION_ID
      const probabilities = Object.fromEntries(Object.entries(choice.criteria).map(([key, word]) => [key, key !== "none" && secrets.includes(String(word)) ? 0.95 : 0.01]))
      return { answers: { [id]: { type: "choice", probabilities } } }
    }
    for (const id of [OUTPUT_VERIFY_QUESTION_ID, PROMPT_VERIFY_QUESTION_ID])
      if (request.questions[id]) return { answers: { [id]: { type: "noul", noul: secrets.includes(String(state.value)) ? 0.95 : 0.05 } } }
    const id = request.questions[OUTPUT_QUESTION_ID] ? OUTPUT_QUESTION_ID : PROMPT_QUESTION_ID
    const words = new Set(promptWords(text).map((token) => token.word))
    return { answers: { [id]: { type: "noul", noul: secrets.some((secret) => words.has(secret)) ? 0.9 : 0.05 } } }
  }
  return { model, requests }
}
const stage1 = (request: ModelRequest) => Boolean(request.questions[OUTPUT_QUESTION_ID] ?? request.questions[PROMPT_QUESTION_ID])

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

async function setup(secrets: readonly string[], options: { override?: (request: ModelRequest) => ModelResponse | Error | undefined } & Record<string, unknown> = {}) {
  const { override, ...extra } = options
  const fake = fakeContext()
  const { model, requests } = fakeModel(secrets, override)
  const { log, lines } = capture()
  await registerOutputCheck(fake.ctx, {
    redactor: createRedactor(),
    model,
    label: "nox-4b",
    threshold: DEFAULT_OUTPUT_CHECK.threshold,
    tuning: DEFAULT_OUTPUT_CHECK.tuning,
    skip: DEFAULT_OUTPUT_CHECK.skip,
    askAs: "ask",
    log,
    ...extra,
  })
  return { fake, requests, lines }
}

const base = { sessionID: "ses_1", agent: "build", messageID: "msg_1", input: {} }
const done = (tool: string, result: Record<string, unknown>, id = "call_1") => ({ ...base, id, tool, status: "completed" as const, result })
const MARK = "[[GUARD_REDACTED:output_secret]]"
const UNCHECKED = "[[GUARD_REDACTED:output_unchecked]]"
const declined = async () => {
  throw Object.assign(new Error("declined"), { name: "Permission.DeclinedError" })
}
const timeout = () => new ModelError("timed out after 5000 ms", { timeout: true })

describe("output check v2 (fake model)", () => {
  it("redacted copy sent even without redaction at the source: never a known secret in what the model receives", async () => {
    const { fake, requests } = await setup([])
    const event = done("webfetch", { output: `token ${FAKE.openai}`, content: [{ type: "text", text: `key=${FAKE.openai}` }] })
    await fake.trigger("tool.execute.after", event)
    assert.equal(requests.length, 2)
    const sent = JSON.stringify(requests)
    assert.ok(!sent.includes(FAKE.openai), sent)
    assert.match(sent, /<redacted>/)
    // Nothing found by the model: the hook leaves the result to the redaction hook.
    assert.equal(event.result.output, `token ${FAKE.openai}`)
  })
  it("no secret → nothing changes, no confirmation; the state names the tool, `output` holds the text", async () => {
    const { fake, requests } = await setup([])
    const event = done("chrome-devtools-mcp_evaluate_script", { output: "page title", content: [{ type: "text", text: "page title" }] })
    await fake.trigger("tool.execute.after", event)
    assert.deepEqual(requests.map((request) => request.state), [{ tool: "chrome-devtools-mcp_evaluate_script", output: "page title" }])
    assert.equal(fake.asserts.length, 0)
    assert.deepEqual(event.result, { output: "page title", content: [{ type: "text", text: "page title" }] })
  })
  it("word located → masked as a whole word everywhere (output, content, metadata), note added, no confirmation", async () => {
    const { fake, lines } = await setup(["chocolat82"])
    const text = "# deploy notes\nconnect as deploy with chocolat82\nnot chocolat820\n"
    const event = done("read", { output: text, content: [{ type: "text", text }], metadata: { preview: "deploy with chocolat82", lines: 3 } })
    await fake.trigger("tool.execute.after", event)
    assert.equal(fake.asserts.length, 0)
    assert.equal(event.result.output, text.replace("chocolat82\n", `${MARK}\n`))
    assert.match(String(event.result.output), /not chocolat820/)
    assert.equal((event.result.content as Array<{ text: string }>)[0]!.text, `${text.replace("chocolat82\n", `${MARK}\n`)}\n\n${REDACTION_NOTE}`)
    assert.deepEqual(event.result.metadata, { preview: `deploy with ${MARK}`, lines: 3 })
    assert.ok(!lines.join("\n").includes("chocolat82"), lines.join("\n"))
    assert.match(lines.join("\n"), /read → output check: 1 word\(s\) masked, 0 part\(s\) masked whole/)
  })
  it("value seen but not located (strong stage 1) → the part masked whole, its copies too, the unchecked note added", async () => {
    // Stage 1 strong on the part holding the secret, no word confirmed.
    const { fake } = await setup(["s3cr"], { override: (request) => (request.questions[OUTPUT_VERIFY_QUESTION_ID] ? { answers: { [OUTPUT_VERIFY_QUESTION_ID]: { type: "noul", noul: 0.05 } } } : undefined) })
    const filler = Array.from({ length: 60 }, (_, i) => `line ${i} of ordinary text here`).join("\n")
    const text = `${filler}\nthe word is s3cr plus more\n${filler}\n`
    const event = done("bash", { output: text, content: [{ type: "text", text }], metadata: { output: text, description: "x" } })
    await fake.trigger("tool.execute.after", event)
    const out = String(event.result.output)
    assert.ok(!out.includes("s3cr"), out)
    assert.match(out, /output_unchecked/)
    // Only the part holding it: the text before it stays.
    assert.ok(out.startsWith("line 0 of ordinary text here"), out.slice(0, 40))
    assert.equal((event.result.metadata as { output: string }).output, out)
    const shown = (event.result.content as Array<{ text: string }>)[0]!.text
    assert.ok(shown.endsWith(`${REDACTION_NOTE}\n\n${UNCHECKED_NOTE}`), shown.slice(-300))
    assert.equal(fake.asserts.length, 0)
  })
  it("metadata checked too (OpenCode sends metadata.output of an interrupted call): long strings alone, short ones together", async () => {
    const { fake, requests } = await setup(["chocolat82"])
    const event = { ...base, id: "call_i", tool: "bash", status: "error" as const, error: Object.assign(new Error("interrupted"), { metadata: { interrupted: true, output: "connect as deploy with chocolat82", exit: 1, description: "deploy step" } }) }
    await fake.trigger("tool.execute.after", event)
    assert.deepEqual((event.error as unknown as { metadata: unknown }).metadata, { interrupted: true, output: `connect as deploy with ${MARK}`, exit: 1, description: "deploy step" })
    // Message, then the short metadata strings in one text.
    assert.deepEqual(requests.filter(stage1).map((request) => (request.state as { output: string }).output).slice(0, 2).sort(), ["connect as deploy with chocolat82\ndeploy step", "interrupted"])
  })
  it("value seen weakly and not located → passed on (a weak stage 1 alone is mostly a false alarm)", async () => {
    const { fake } = await setup([], { override: (request) => (stage1(request) ? { answers: { [OUTPUT_QUESTION_ID]: { type: "noul", noul: 0.4 } } } : undefined) })
    const event = done("bash", { output: "ordinary build log" })
    await fake.trigger("tool.execute.after", event)
    assert.equal(event.result.output, "ordinary build log")
  })
  it("long output: every part checked, nothing cut; parts end at line ends; a part read again from another line comes from the cache", async () => {
    const { fake, requests } = await setup(["zebra77"])
    const lines = Array.from({ length: 400 }, (_, i) => `${i + 1}: const value${i} = compute(${i}) // ordinary`)
    lines[350] = "351: // log in as admin with zebra77"
    const text = lines.join("\n")
    const event = done("read", { output: text })
    await fake.trigger("tool.execute.after", event)
    // First look at each part (a second look, after a word is found, shows it as <redacted>).
    const parts = requests.filter(stage1).map((request) => String((request.state as { output: string }).output)).filter((part) => !part.includes("<redacted>"))
    assert.ok(parts.length >= 6, String(parts.length))
    assert.ok(parts.join("") === text, "the parts put together give the whole text")
    for (const part of parts.slice(0, -1)) assert.ok(part.endsWith("\n"), JSON.stringify(part.slice(-20)))
    assert.ok(!String(event.result.output).includes("zebra77"))
    // Read again from line 101 (other line numbers): most parts are not sent again.
    const before = requests.length
    const again = lines.slice(100).map((line, i) => line.replace(/^\d+: /, `${i + 1}: `)).join("\n")
    await fake.trigger("tool.execute.after", done("read", { output: again }, "call_2"))
    const sent = requests.slice(before).filter(stage1).length
    assert.ok(sent <= 2, `parts sent again: ${sent}`)
  })
  it("safety net: a word built like a password is put to stage 3 even when stage 1 sees nothing; confirmed → masked, refused → left", async () => {
    const { fake, requests } = await setup(["Xy7#kq2!Lm"], { override: (request) => (stage1(request) ? { answers: { [OUTPUT_QUESTION_ID]: { type: "noul", noul: 0.05 } } } : undefined) })
    const event = done("bash", { output: "token Xy7#kq2!Lm and Build-2024x ok" })
    await fake.trigger("tool.execute.after", event)
    assert.equal(event.result.output, `token ${MARK} and Build-2024x ok`)
    const asked = requests.filter((request) => request.questions[OUTPUT_VERIFY_QUESTION_ID]).map((request) => (request.state as { value: string }).value)
    assert.deepEqual(asked.sort(), ["Build-2024x", "Xy7#kq2!Lm"])
  })
  it("model failure → output held for a confirmation; approved: passed on with the safety-net words masked; one WARN per series", async () => {
    const { fake, lines } = await setup([], { override: (request) => (stage1(request) ? timeout() : undefined) })
    for (const id of ["a", "b"]) {
      const event = done("webfetch", { output: "page with Pass-w0rd99 inside" }, id)
      await fake.trigger("tool.execute.after", event)
      assert.equal(event.result.output, `page with ${MARK} inside`)
    }
    assert.equal(fake.asserts.length, 2)
    assert.equal(fake.asserts[0]!.action, "guard · MODEL TIMEOUT: approve to pass on, reject to withhold: webfetch output not fully checked")
    assert.match(String(fake.asserts[0]!.metadata?.reason), /the output check could not finish \(model timeout\)/)
    assert.deepEqual(fake.asserts[0]!.source, { type: "tool", messageID: "msg_1", id: "a" })
    assert.equal(lines.filter((line) => line.startsWith("WARN")).length, 1)
    assert.match(lines.join("\n"), /WARN output check unavailable \(model timeout\)/)
  })
  it("model failure, rejected → notice in place of the output, strings replaced, numbers kept; refused question or invalid answer count as failures", async () => {
    for (const answer of [{ answers: { [OUTPUT_QUESTION_ID]: { error: "max_length_exceeded" } } }, { answers: {} }] as ModelResponse[]) {
      const { fake } = await setup([], { override: (request) => (stage1(request) ? answer : undefined) })
      fake.onAssert(declined)
      const event = done("shell", { output: { stdout: "pw=hunter-two-x", exit: 0 }, content: [{ type: "text", text: "pw=hunter-two-x" }], metadata: { output: "pw=hunter-two-x", exit: 0 } })
      await fake.trigger("tool.execute.after", event)
      assert.deepEqual(event.result.content, [{ type: "text", text: withheldNotice("shell", "the output check could not finish (model unavailable), and the user did not approve passing it on") }])
      assert.deepEqual(event.result.output, { stdout: "[guard: output withheld]", exit: 0 })
      assert.deepEqual(event.result.metadata, { output: "[guard: output withheld]", exit: 0 })
    }
  })
  it("model failure with feedback → feedback in the notice, never in the log; unattended mode → withheld without a request", async () => {
    const { fake, lines } = await setup([], { override: () => timeout() })
    fake.onAssert(async () => {
      throw Object.assign(new Error("corrected"), { name: "Permission.CorrectedError", feedback: "use the staging file instead" })
    })
    const event = done("webfetch", { output: "secret thing", content: [{ type: "text", text: "secret thing" }] })
    await fake.trigger("tool.execute.after", event)
    assert.match(JSON.stringify(event.result.content), /User feedback: use the staging file instead/)
    assert.ok(!lines.join("\n").includes("staging file"), lines.join("\n"))
    const unattended = await setup([], { override: () => timeout(), askAs: "deny" })
    const held = done("webfetch", { output: "secret thing", content: [{ type: "text", text: "secret thing" }] })
    await unattended.fake.trigger("tool.execute.after", held)
    assert.equal(unattended.fake.asserts.length, 0)
    assert.match(JSON.stringify(held.result.content), /unattended mode \(askAs: deny\) withholds it/)
  })
  it("skipped tools (writes, patches, task list, invalid call, `outputCheck.skip`), unprotected agent, nothing to judge → model not called", async () => {
    const unprotected = { isUnprotected: async () => true, notePrompt: async () => false }
    const skipped = await setup(["thing"], { unprotected })
    await skipped.fake.trigger("tool.execute.after", done("webfetch", { output: "secret thing" }))
    assert.equal(skipped.requests.length, 0)
    const { fake, requests } = await setup(["thing"])
    for (const tool of ["edit", "write", "apply_patch", "patch", "todowrite", "invalid"]) await fake.trigger("tool.execute.after", done(tool, { output: "secret thing" }))
    await fake.trigger("tool.execute.after", done("webfetch", { output: "", content: [] }))
    await fake.trigger("tool.execute.after", done("webfetch", { output: "[[GUARD_REDACTED:openai_key]]", content: [{ type: "text", text: "[[GUARD_REDACTED:env:X]] ." }] }))
    assert.equal(requests.length, 0)
    // Reads, searches, skills and subagents are checked now.
    for (const tool of ["read", "glob", "grep", "skill", "task"]) await fake.trigger("tool.execute.after", done(tool, { output: `${tool} output` }, tool))
    assert.equal(requests.filter(stage1).length, 5)
    const custom = await setup([], { skip: ["read"] })
    await custom.fake.trigger("tool.execute.after", done("read", { output: "file text" }))
    assert.equal(custom.requests.length, 0)
  })
  it("`question` answers are typed by the user: checked with the prompt questions", async () => {
    const { fake, requests } = await setup(["soleil42"])
    const event = done("question", { output: "User answered: password is soleil42" })
    await fake.trigger("tool.execute.after", event)
    assert.ok(requests[0]!.questions[PROMPT_QUESTION_ID])
    assert.deepEqual(Object.keys(requests[0]!.state as object), ["message"])
    assert.equal(event.result.output, `User answered: password is ${MARK}`)
  })
  it("tool error → its message and cause checked; word masked in the message, class kept", async () => {
    class ToolFailure extends Error {
      override name = "ToolFailure"
    }
    const { fake } = await setup(["hunter2x"])
    const event = { ...base, id: "call_e", tool: "shell", status: "error" as const, error: new ToolFailure("cannot connect: password hunter2x rejected") }
    await fake.trigger("tool.execute.after", event)
    assert.ok(event.error instanceof ToolFailure)
    assert.equal(event.error.message, `cannot connect: password ${MARK} rejected`)
    const cause = await setup(["cause-marker-xyz"])
    const nested = { ...base, id: "call_c", tool: "shell", status: "error" as const, error: Object.assign(new Error("tool failed"), { error: new Error("cause-marker-xyz: connection refused") }) }
    await cause.fake.trigger("tool.execute.after", nested)
    assert.match(JSON.stringify(cause.requests), /cause-marker-xyz/)
    assert.ok(!String((nested.error as unknown as { error: Error }).error.message).includes("cause-marker-xyz"))
  })
  it("model failure on an error, rejected → withheld: class preserved, message replaced (getter-only and frozen errors too)", async () => {
    class Weird extends Error {
      override get message() {
        return "original secret text hunter-two-x"
      }
    }
    const weird = new Weird()
    delete (weird as unknown as Record<string, unknown>).message
    class Frozen extends Error {
      constructor(props: { message: string } | string) {
        super(typeof props === "string" ? props : props.message)
        Object.freeze(this)
      }
    }
    const notice = withheldNotice("shell", "the output check could not finish (model timeout), and the user did not approve passing it on")
    for (const error of [new Error("original secret text hunter-two-x"), weird, new Frozen({ message: "original secret text hunter-two-x" })]) {
      const { fake } = await setup([], { override: () => timeout() })
      fake.onAssert(declined)
      const event = { ...base, id: "call_w", tool: "shell", status: "error" as const, error: error as Error }
      await fake.trigger("tool.execute.after", event)
      assert.ok(event.error instanceof (error.constructor as typeof Error))
      assert.equal(event.error.message, notice)
      assert.ok(!JSON.stringify(Object.getOwnPropertyNames(event.error).map((k) => (event.error as unknown as Record<string, unknown>)[k])).includes("hunter-two-x"))
    }
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
  it("the confirmation names the call: summary of the redacted input, never a known secret; long tool name within the limit", async () => {
    const { fake } = await setup([], { override: () => timeout() })
    await fake.trigger("tool.execute.after", { ...done("webfetch", { output: "some page" }), input: { url: `https://x.example.test/?k=${FAKE.openai}` } })
    const resource = fake.asserts[0]!.resources[0]!
    assert.match(resource, /^webfetch: .*\(output check\)$/)
    assert.match(resource, /GUARD_REDACTED/)
    assert.ok(!resource.includes(FAKE.openai))
    const mcp = await setup([], { override: () => timeout() })
    await mcp.fake.trigger("tool.execute.after", done("chrome-devtools-mcp_take_snapshot", { output: "page" }))
    const action = mcp.fake.asserts[0]!.action
    assert.ok([...action.slice("guard · ".length)].length <= MAX_ACTION_DETAIL, action)
  })
  it("CodeMode: internal calls ignored, external execute result checked", async () => {
    const { fake, requests } = await setup([])
    await fake.trigger("tool.execute.before", { ...base, id: "call_cm", tool: "execute", input: { code: "x" } })
    await fake.trigger("tool.execute.after", done("webfetch", { output: "inner output" }, "call_cm"))
    await fake.trigger("tool.execute.after", done("chrome-devtools-mcp_take_snapshot", { output: "inner output 2" }, "call_cm"))
    assert.equal(requests.length, 0)
    await fake.trigger("tool.execute.after", done("execute", { output: { output: "script result" }, content: [{ type: "text", text: "script result" }] }, "call_cm"))
    assert.equal(requests.length, 1)
    await fake.trigger("tool.execute.after", done("webfetch", { output: "later output" }, "call_cm"))
    assert.equal(requests.length, 2)
  })
  it("same text in output and content → checked once; custom questions → the ones sent", async () => {
    const { fake, requests } = await setup([])
    await fake.trigger("tool.execute.after", done("shell", { output: "unique-line-xyz", content: [{ type: "text", text: "unique-line-xyz" }] }))
    assert.equal(requests.length, 1)
    const questions = { ...DEFAULT_OUTPUT_CHECK.questions, secret: { instructions: "S?", criteria: { true: "T", false: "F" } } }
    const custom = await setup([], { questions })
    await custom.fake.trigger("tool.execute.after", done("webfetch", { output: "some page" }))
    assert.deepEqual(custom.requests[0]!.questions[OUTPUT_QUESTION_ID], { type: "noul", instructions: "S?", criteria: { true: "T", false: "F" } })
  })
  it("cache shared by the sessions: same output in another session → no call", async () => {
    const { fake, requests } = await setup([])
    await fake.trigger("tool.execute.after", done("webfetch", { output: "same output" }, "a"))
    await fake.trigger("tool.execute.after", { ...done("webfetch", { output: "same output" }, "b"), sessionID: "ses_2" })
    assert.equal(requests.length, 1)
  })
  it("never a planted value in the log, on every path (clean, masked, unlocated, failure)", async () => {
    const planted = "Planted-v4lue!"
    const paths = [
      await setup([]),
      await setup([planted]),
      await setup(["Planted"], { override: (request) => (request.questions[OUTPUT_VERIFY_QUESTION_ID] ? { answers: { [OUTPUT_VERIFY_QUESTION_ID]: { type: "noul", noul: 0.05 } } } : undefined) }),
      await setup([], { override: () => new ModelError(`gateway echoed ${planted}`) }),
    ]
    for (const { fake, lines } of paths) {
      await fake.trigger("tool.execute.after", done("bash", { output: `value ${planted} here` }))
      assert.ok(!lines.join("\n").includes("Planted"), lines.join("\n"))
    }
  })
})

describe("batch 32: startup (option, global file, INFO line)", () => {
  const decision = { baseURL: URL_A, model: "nox-4b", timeoutMs: 300 }
  async function start(options: Record<string, unknown>, globalDir: string | undefined) {
    const file = join(temp("log"), "guard.log")
    await setupGuard(fakeContext({ logFile: file, ...options }).ctx, {}, temp("etc"), globalDir)
    return readFileSync(file, "utf8")
  }
  it("no model → no mention; option absent or requested, and declared → active, warning; turned off → shown off", async () => {
    assert.ok(!(await start({}, undefined)).includes("output check"))
    const declared = temp("global")
    writeFileSync(join(declared, "opencode.json"), entry({ decision }))
    assert.match(await start({ decision }, declared), /INFO active \(.*; output check: active(?:; prompt check: \w+)?\)/)
    const declaredOff = temp("global")
    writeFileSync(join(declaredOff, "opencode.json"), entry({ outputCheck: false, decision }))
    assert.match(await start({ decision, outputCheck: false }, declaredOff), /INFO active \(.*; output check: off(?:; prompt check: \w+)?\)/)
    const global = temp("global")
    writeFileSync(join(global, "opencode.json"), entry({ outputCheck: true, decision }))
    const log = await start({ decision, outputCheck: true }, global)
    assert.match(log, /INFO active \(.*; output check: active(?:; prompt check: \w+)?\)/)
    assert.match(log, /WARN output check active: tool outputs, redacted, are sent to the decision model/)
  })
  it("requested but not declared in the global file, or model disabled → inactive, with the reason", async () => {
    const empty = temp("global")
    mkdirSync(empty, { recursive: true })
    const log = await start({ decision, outputCheck: true }, empty)
    assert.match(log, /INFO active \(.*; output check: inactive(?:; prompt check: \w+)?\)/)
    assert.match(log, /WARN outputCheck requested but inactive: global configuration: it is missing or unreadable/)
    assert.ok(!log.includes("output check active"), log)
    const off = await start({ outputCheck: true }, empty)
    assert.match(off, /WARN outputCheck requested but inactive: the decision model is disabled/)
    // Absent and not declared: inactive, said on the start line only.
    const quiet = await start({ decision }, empty)
    assert.match(quiet, /INFO active \(.*; output check: inactive(?:; prompt check: \w+)?\)/)
    assert.ok(!quiet.includes("outputCheck requested"), quiet)
  })
})
