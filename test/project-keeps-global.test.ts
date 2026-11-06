// OpenCode hands the plugin one entry's options, whole: a project's entry replaces the global one's. A key the project
// leaves out keeps the global side's value, and what the project sets never relaxes it: read back from the global file,
// on both paths (without layers, and with a guard.json file), and through the real hooks. Nothing is run: commands are
// only judged, and `fetch` is replaced inside the process, no connection.
import "./tmp.ts"
import assert from "node:assert/strict"
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { describe, it } from "node:test"
import { fileURLToPath } from "node:url"
import { main } from "../src/cli/main.ts"
import { OPTION_KEYS, parseConfig, type GuardConfig, type GuardFile, type PluginDeclaration } from "../src/config.ts"
import { setupGuard } from "../src/index.ts"
import { declaredPluginOptions } from "../src/output-check.ts"
import { declaring } from "./declared.ts"
import { fakeContext } from "./fake-ctx.ts"

type Json = Record<string, unknown>
const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
const PROJECT = "/w/app"
const DECISION = { baseURL: "https://decision.local/v1", model: "nox-4b" }
const ELSEWHERE = { baseURL: "https://decision.example.org/v1", model: "nox-4b" }
const HEREDOC = "cat > notes.md <<'EOF'\nsudo apt install x\nEOF"
const RESET = "git reset --hard"
const SECRET_FILE = "/w/app/.env"

const inputs = (files: readonly GuardFile[]) => ({ files, project: PROJECT, realPath: (path: string) => path, regularFile: () => true })
const projectFile: GuardFile = { label: "project guard.json (/w/app/.opencode/guard.json)", global: false, dir: PROJECT, data: {} }
const PATHS = { simple: inputs([]), layers: inputs([projectFile]) }
/** Both paths; `layersDid`: the layered one already read this from the global file. */
const each = (name: string, run: (path: ReturnType<typeof inputs>) => void | Promise<void>, layersDid = false) => {
  for (const [label, path] of Object.entries(PATHS)) it(`${layersDid && label === "layers" ? "witness: " : ""}${name} (${label})`, () => run(path))
}
const overrideOf = (rule: string) => (config: GuardConfig) => (config.policy as { overrides?: ReadonlyMap<string, string> }).overrides?.get(rule)
const policy = (config: GuardConfig) => config.policy as { rememberMinutes?: number; localAsksByModel?: boolean; selfProtectionByModel?: boolean; exceptions?: ReadonlyMap<string, ReadonlySet<string>> }
const feature = (name: keyof GuardConfig["features"]) => (config: GuardConfig) => config.features[name]

/** Key, what the global configuration writes, what it gives; a check turned off counts as `undefined`. */
const OMITTED: ReadonlyArray<readonly [string, unknown, (config: GuardConfig) => unknown, unknown]> = [
  ["decision", DECISION, (config) => config.decision?.baseURL, DECISION.baseURL],
  ["askAs", "deny", (config) => config.askAs, "deny"],
  ["thresholds", { askRisk: 1 }, (config) => config.thresholds.askRisk, 1],
  ["maxStateChars", 7000, (config) => config.maxStateChars, 7000],
  ["rules", [{ id: "corp-rule", pattern: "corpx", verdict: "ask" }], (config) => config.rules.map((rule) => rule.id).join(), "corp-rule"],
  ["secretPatterns", ["corp-[0-9]{6}"], (config) => config.secretPatterns.length, 1],
  ["ruleOverrides", { "git-reset-hard": "deny" }, overrideOf("git-reset-hard"), "deny"],
  ["rememberConfirmations", 5, (config) => policy(config).rememberMinutes, 5],
  ["unprotectedAgent", "build-unprotected", (config) => config.unprotectedAgent, "build-unprotected"],
  ["allowlist", ["corp-value"], (config) => config.allowlist.join(), "corp-value"],
  ["redactionOff", ["jwt"], (config) => config.disabledPatterns.join(), "jwt"],
  ["exceptions", { "secret-file-read": [SECRET_FILE] }, (config) => policy(config).exceptions?.get("secret-file-read")?.has(SECRET_FILE), true],
  ["profile", "credentials-only", (config) => config.profile, "credentials-only"],
  ["localAsks", "model", (config) => policy(config).localAsksByModel, true],
  ["selfProtectionByModel", true, (config) => policy(config).selfProtectionByModel, true],
  ["dangerousCommands", false, feature("dangerousCommands"), false],
  ["sensitiveFiles", false, feature("sensitiveFiles"), false],
  ["decisionModel", false, feature("decisionModel"), false],
  ["scripts", false, feature("scripts"), false],
  ["redactOutputs", false, feature("redactOutputs"), false],
  ["redactPrompt", false, feature("redactPrompt"), false],
  ["redactWire", false, feature("redactWire"), false],
  ["outputCheck", false, (config) => config.outputCheck, undefined],
  ["promptCheck", false, (config) => config.promptCheck, undefined],
  ["logFile", "/w/guard-keep.log", (config) => config.logFile, "/w/guard-keep.log"],
  ["debug", true, (config) => config.debug, true],
  ["cacheTtlMs", 1000, (config) => config.cacheTtlMs, 1000],
  ["cacheMax", 7, (config) => config.cacheMax, 7],
]

const parse = (given: Json, global: Json, path: ReturnType<typeof inputs>) => parseConfig(given, {}, declaring(global), path)
const ignored = (warnings: readonly string[], key: string) => warnings.filter((line) => line.includes(key) && line.includes("ignored"))

describe("a key the project leaves out keeps the global configuration's value", () => {
  it("witness: the table covers every option, the sections apart", () => {
    assert.deepEqual([...OPTION_KEYS].sort(), [...OMITTED.map(([key]) => key), "agents", "projects", "trustedProjects"].sort())
  })
  for (const [key, value, read, expected] of OMITTED)
    each(key, (path) => {
      const { config, warnings } = parse({}, { [key]: value }, path)
      assert.deepEqual(read(config), expected)
      assert.deepEqual(warnings, [])
    }, ["rememberConfirmations", "exceptions"].includes(key))
  each("an entry of the project without options, written with the others", (path) => {
    const { config } = parse({ debug: false }, { askAs: "deny", maxStateChars: 7000 }, path)
    assert.deepEqual([config.askAs, config.maxStateChars], ["deny", 7000])
  })
  each("a project's trustedProjects does not count, nor fill anything in", (path) => {
    assert.equal(parse({ trustedProjects: [PROJECT], decision: ELSEWHERE }, { decision: DECISION }, path).config.decision?.baseURL, DECISION.baseURL)
  })
  each("witness: agents are read from the global sources, whatever the options hold", (path) => {
    const { config } = parse({}, { agents: { plan: { scripts: false } } }, path)
    assert.deepEqual([config.version?.scope("plan", undefined, undefined).scripts, config.version?.scope("build", undefined, undefined).scripts], [false, true])
  })
  each("witness: without a declaration of the plugin, nothing changes", (path) => {
    const declared = () => [{ label: "global", reason: "it does not declare this plugin" }, { label: "system", reason: "it is missing or unreadable" }]
    const { config, warnings } = parseConfig({}, {}, declared, path)
    assert.deepEqual([config.decision, config.askAs, warnings], [undefined, "ask", []])
  })
  each("a global file that cannot be read: a warning, nothing thrown, what the options say", (path) => {
    const invalid = () => [{ label: "global", reason: "it is not valid JSON" }, { label: "system", reason: "it is missing or unreadable" }]
    const failing = (): readonly PluginDeclaration[] => {
      throw new Error("unreadable")
    }
    for (const declared of [invalid, failing]) {
      const { config, warnings } = parseConfig({ askAs: "deny" }, {}, declared, path)
      assert.equal(config.askAs, "deny")
      assert.equal(warnings.filter((line) => line === "settings of the global configuration not kept: it could not be read").length, 1)
    }
  })
  it("witness: the global configuration alone: its own options, no warning, as if nothing were kept", () => {
    const global: Json = { decision: DECISION, askAs: "deny", thresholds: { askRisk: 1 }, maxStateChars: 7000, rules: [{ id: "corp-rule", pattern: "corpx", verdict: "ask" }], secretPatterns: ["corp-[0-9]{6}"], ruleOverrides: { "git-reset-hard": "deny" }, rememberConfirmations: 5, unprotectedAgent: "u", allowlist: ["corp-value"], redactionOff: ["jwt"], localAsks: "model", outputCheck: { threshold: 0.5 }, promptCheck: { threshold: 0.5 } }
    for (const path of Object.values(PATHS)) {
      const { config, warnings } = parse(global, global, path)
      assert.deepEqual(warnings, [])
      assert.deepEqual([config.outputCheck?.threshold, config.promptCheck?.threshold, config.modelGrants], [0.5, 0.5, true])
    }
  })
})

describe("what the project sets does not relax the global configuration's value", () => {
  each("decision: the global model stays, one warning", (path) => {
    const { config, warnings } = parse({ decision: ELSEWHERE }, { decision: DECISION }, path)
    assert.equal(config.decision?.baseURL, DECISION.baseURL)
    assert.equal(ignored(warnings, "decision").length, 1)
    assert.match(warnings.join("\n"), /decision ignored: .*trustedProjects/)
  })
  each("decision removed: the global model stays", (path) => {
    assert.equal(parse({ decision: false }, { decision: DECISION }, path).config.decision?.baseURL, DECISION.baseURL)
  })
  each("askAs ask over deny: deny stays", (path) => {
    const { config, warnings } = parse({ askAs: "ask" }, { askAs: "deny" }, path)
    assert.equal(config.askAs, "deny")
    assert.equal(ignored(warnings, "askAs").length, 1)
  })
  each("witness: askAs deny over ask: stricter, kept", (path) => {
    const { config, warnings } = parse({ askAs: "deny" }, { askAs: "ask" }, path)
    assert.deepEqual([config.askAs, warnings], ["deny", []])
  })
  each("thresholds: stricter kept, weaker ignored by name, the others added", (path) => {
    const { config, warnings } = parse({ thresholds: { askRisk: 2, denyRisk: 1.8, minConfidence: 0.1 } }, { thresholds: { askRisk: 1, denyRisk: 2, askNoul: 0.5, minConfidence: 0.4 } }, path)
    assert.deepEqual([config.thresholds.askRisk, config.thresholds.denyRisk, config.thresholds.askNoul, config.thresholds.minConfidence], [1, 1.8, 0.5, 0.4])
    assert.match(warnings.join("\n"), /thresholds (askRisk, minConfidence|minConfidence, askRisk) ignored/)
    assert.equal(ignored(warnings, "thresholds").length, 1)
  })
  each("maxStateChars: the global value stays, cut shorter or longer", (path) => {
    for (const value of [1000, 7800]) {
      const { config, warnings } = parse({ maxStateChars: value }, { maxStateChars: 7000 }, path)
      assert.equal(config.maxStateChars, 7000)
      assert.equal(ignored(warnings, "maxStateChars").length, 1)
    }
  })
  each("rules add up; the same identifier: the global rule stays", (path) => {
    const global = { rules: [{ id: "corp-rule", pattern: "corpx", verdict: "deny" }] }
    const added = parse({ rules: [{ id: "own-rule", pattern: "ownx", verdict: "ask" }] }, global, path).config.rules
    assert.deepEqual(added.map((rule) => rule.id), ["corp-rule", "own-rule"])
    const same = parse({ rules: [{ id: "corp-rule", pattern: "nothing-matches-this", verdict: "ask" }] }, global, path)
    assert.deepEqual(same.config.rules.map((rule) => [rule.id, rule.verdict, rule.pattern.source]), [["corp-rule", "deny", "corpx"]])
    assert.equal(ignored(same.warnings, "rules").length, 1)
  })
  each("a project's rule does not take the identifier of a built-in rule the global configuration sets", (path) => {
    const { config, warnings } = parse({ rules: [{ id: "git-reset-hard", pattern: "x", verdict: "ask" }] }, { rules: [], ruleOverrides: { "git-reset-hard": "deny" } }, path)
    assert.deepEqual(config.rules, [])
    assert.equal(overrideOf("git-reset-hard")(config), "deny")
    assert.equal(ignored(warnings, "rules").length, 1)
  })
  each("secretPatterns add up; one set aside by the project stays active", (path) => {
    const global = { secretPatterns: ["corp-[0-9]{6}"] }
    assert.equal(parse({ secretPatterns: ["own-[0-9]{6}"] }, global, path).config.secretPatterns.length, 2)
    const aside = parse({ secretPatterns: [{ pattern: "corp-[0-9]{6}", enabled: false }] }, global, path)
    assert.equal(aside.config.secretPatterns.length, 1)
    assert.equal(ignored(aside.warnings, "secretPatterns").length, 1)
  })
  each("ruleOverrides: entry by entry; a stricter one kept", (path) => {
    const config = parse({ ruleOverrides: { rm: "deny" } }, { ruleOverrides: { "git-reset-hard": "deny" } }, path).config
    assert.deepEqual([overrideOf("git-reset-hard")(config), overrideOf("rm")(config)], ["deny", "deny"])
  }, true)
  each("ruleOverrides: a weaker one ignored: the global setting stays, rule off by default included", (path) => {
    for (const rule of ["git-reset-hard", "opaque-image"]) {
      const { config, warnings } = parse({ ruleOverrides: { [rule]: "ask" } }, { ruleOverrides: { [rule]: "deny" } }, path)
      assert.equal(overrideOf(rule)(config), "deny", rule)
      assert.equal(ignored(warnings, rule).length, 1, warnings.join("\n"))
    }
  }, true)
  each("rememberConfirmations: shorter kept, longer ignored, the global delay stays", (path) => {
    assert.equal(policy(parse({ rememberConfirmations: 2 }, { rememberConfirmations: 5 }, path).config).rememberMinutes, 2)
    const longer = parse({ rememberConfirmations: 9 }, { rememberConfirmations: 5 }, path)
    assert.equal(policy(longer.config).rememberMinutes, 5)
    assert.equal(ignored(longer.warnings, "rememberConfirmations").length, 1)
    assert.match(longer.warnings.join("\n"), /guard set rememberConfirmations 9 --project/)
  })
  each("unprotectedAgent: another one ignored, the global one stays", (path) => {
    const { config, warnings } = parse({ unprotectedAgent: "other" }, { unprotectedAgent: "kept" }, path)
    assert.equal(config.unprotectedAgent, "kept")
    assert.equal(ignored(warnings, "unprotectedAgent").length, 1)
  })
  each("witness: allowlist and redactionOff: what the global configuration lists counts, a new entry does not", (path) => {
    const list = parse({ allowlist: ["corp-value", "own-value"] }, { allowlist: ["corp-value"] }, path)
    assert.deepEqual([...list.config.allowlist], ["corp-value"])
    const off = parse({ redactionOff: ["jwt", "github_token"] }, { redactionOff: ["jwt"] }, path)
    assert.deepEqual([...off.config.disabledPatterns], ["jwt"])
  })
  each("a switch at false in the global configuration: true from the project turns it on", (path) => {
    assert.equal(parse({ debug: true }, { redactOutputs: false }, path).config.features.redactOutputs, false)
    assert.equal(parse({ redactOutputs: true }, { redactOutputs: false }, path).config.features.redactOutputs, true)
  })
  each("witness: a setting with no effect on protection: the project decides", (path) => {
    const config = parse({ debug: false, cacheMax: 3, cacheTtlMs: 2000 }, { debug: true, cacheMax: 7, cacheTtlMs: 1000 }, path).config
    assert.deepEqual([config.debug, config.cacheMax, config.cacheTtlMs], [false, 3, 2000])
  })
})

describe("the settings of the checks", () => {
  const strict = { threshold: 0.05, skip: [], questions: { word: { none: "aucun" } } }
  for (const [name, read] of [["outputCheck", (config: GuardConfig) => config.outputCheck], ["promptCheck", (config: GuardConfig) => config.promptCheck]] as const) {
    const settings = name === "outputCheck" ? strict : { threshold: strict.threshold, questions: strict.questions }
    each(`${name}: left out, the global settings stay`, (path) => {
      assert.equal(read(parse({}, { [name]: settings }, path).config)?.threshold, 0.05)
    })
    each(`${name}: switched on without settings, they stay`, (path) => {
      for (const value of [true, "true", { enabled: true }]) {
        const { config, warnings } = parse({ [name]: value }, { [name]: settings }, path)
        assert.deepEqual([read(config)?.threshold, read(config)?.questions.word.none], [0.05, "aucun"], JSON.stringify(value))
        assert.deepEqual(warnings, [])
      }
    })
    each(`${name}: other settings ignored: the global ones stay, one warning`, (path) => {
      const { config, warnings } = parse({ [name]: { threshold: 0.9 } }, { [name]: settings }, path)
      assert.equal(read(config)?.threshold, 0.05)
      assert.equal(warnings.filter((line) => line.startsWith(`${name} settings ignored, the global configuration's stay`)).length, 1)
    })
    each(`${name}: a false refused keeps them`, (path) => {
      const { config } = parse({ [name]: false }, { [name]: settings }, path)
      assert.equal(read(config)?.threshold, 0.05)
    })
    each(`witness: ${name}: no setting in the global configuration: the defaults, as before`, (path) => {
      const { config, warnings } = parse({ [name]: { threshold: 0.9 } }, {}, path)
      assert.equal(read(config)?.threshold, 0.2)
      assert.equal(warnings.filter((line) => line.startsWith(`${name} settings ignored, defaults used`)).length, 1)
    })
  }
  it("witness: a value with a {file:…} reference is not certified: the same as without a project", () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-keep-check-")))
    writeFileSync(join(root, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: { outputCheck: { threshold: 0.05, skip: ["{file:skip.txt}"] } } }] }))
    writeFileSync(join(root, "skip.txt"), "read")
    const declared = async () => (await import("../src/output-check.ts")).declaredPluginOptions({ pluginDir: PLUGIN_DIR, globalDir: root, systemDir: join(root, "none"), env: {} })
    return declared().then((entries) => {
      const resolved = { outputCheck: { threshold: 0.05, skip: ["read"] } }
      const [without, over] = [parseConfig(resolved, {}, () => entries).config.outputCheck, parseConfig({ outputCheck: true }, {}, () => entries).config.outputCheck]
      assert.deepEqual([without?.threshold, over?.threshold], [0.2, 0.2])
    })
  })
})

describe("a trusted project", () => {
  const trusted = (global: Json) => declaring({ ...global, trustedProjects: [PROJECT] })
  each("witness: chooses its decision, askAs, thresholds and maxStateChars", (path) => {
    const { config, warnings } = parseConfig({ decision: ELSEWHERE, askAs: "ask", thresholds: { askRisk: 2 }, maxStateChars: 1000 }, {}, trusted({ decision: DECISION, askAs: "deny", thresholds: { askRisk: 1 }, maxStateChars: 7000 }), path)
    assert.deepEqual([config.decision?.baseURL, config.askAs, config.thresholds.askRisk, config.maxStateChars, warnings], [ELSEWHERE.baseURL, "ask", 2, 1000, []])
  })
  each("still keeps what it leaves out", (path) => {
    const config = parseConfig({ askAs: "ask" }, {}, trusted({ maxStateChars: 7000 }), path).config
    assert.equal(config.maxStateChars, 7000)
  })
  each("never unprotectedAgent nor redactionOff", (path) => {
    const { config } = parseConfig({ unprotectedAgent: "other", redactionOff: ["jwt"] }, {}, trusted({ unprotectedAgent: "kept" }), path)
    assert.deepEqual([config.unprotectedAgent, config.disabledPatterns.length], ["kept", 0])
  })
})

/** Plugin as OpenCode sets it up: the global file as written, the project's options, the model answered inside the process. */
async function session(global: string | Json, project: Json, env: Record<string, string> = {}, files: Record<string, string> = {}, scores: Json = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-keep-")))
  const [globalDir, systemDir, app] = [join(root, "global"), join(root, "system"), join(root, "app")]
  for (const dir of [globalDir, systemDir, app]) mkdirSync(dir)
  writeFileSync(join(globalDir, "opencode.json"), typeof global === "string" ? global : JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: global }] }))
  for (const [name, content] of Object.entries(files)) writeFileSync(join(globalDir, name), content)
  const logFile = join(root, "guard.log")
  const fake = fakeContext({ logFile, ...project })
  Object.assign(fake.ctx, { location: { directory: app } })
  const calls: Json[] = []
  const content = JSON.stringify({ answers: { risk: { type: "score", score: 0.1, confidence: 0.9 }, destructive: { type: "noul", noul: 0.01 }, exfiltration: { type: "noul", noul: 0.01 }, credentials: { type: "noul", noul: 0.01 }, privilege_persistence: { type: "noul", noul: 0.01 }, ...scores } })
  const original = globalThis.fetch
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body ?? "{}")) as Json
    calls.push({ url: String(url), headers: Object.fromEntries(new Headers(init?.headers).entries()), model: body.model })
    return new Response(JSON.stringify({ id: "x", object: "chat.completion", choices: [{ index: 0, finish_reason: "stop", message: { role: "assistant", content } }] }), { status: 200, headers: { "content-type": "application/json" } })
  }) as typeof fetch
  let call = 0
  const verdict = async (command: string) => {
    const before = fake.asserts.length
    try {
      await fake.trigger("tool.execute.before", { sessionID: "s", agent: "build", messageID: "m", id: `c${++call}`, tool: "shell", input: { command } })
    } catch (error) {
      if (/Blocked|unattended/i.test(String(error))) return "deny"
      throw error
    }
    return fake.asserts.length > before ? "ask" : "allow"
  }
  const output = async (text: string) => JSON.stringify((await fake.trigger("tool.execute.after", { sessionID: "s", agent: "build", messageID: "m", id: `c${++call}`, tool: "shell", input: { command: "cat f" }, status: "completed", result: { output: text, content: [{ type: "text", text }] } })).result)
  try {
    await setupGuard(fake.ctx, env, systemDir, globalDir)
    return { verdict, output, calls, log: () => readFileSync(logFile, "utf8"), done: () => void (globalThis.fetch = original) }
  } catch (error) {
    globalThis.fetch = original
    throw error
  }
}

describe("through the real hooks, a project's entry without these options", () => {
  it("decision: the global model answers and allows the heredoc data", async () => {
    const plugin = await session({ decision: DECISION }, {})
    assert.equal(await plugin.verdict(HEREDOC), "allow")
    plugin.done()
    assert.ok(plugin.calls.length > 0)
    assert.ok(plugin.calls.every((item) => String(item.url).startsWith(DECISION.baseURL)))
  })
  it("decision replaced: the same, with the warning at startup", async () => {
    const plugin = await session({ decision: DECISION }, { decision: ELSEWHERE })
    assert.equal(await plugin.verdict(HEREDOC), "allow")
    plugin.done()
    assert.ok(plugin.calls.every((item) => String(item.url).startsWith(DECISION.baseURL)))
    assert.match(plugin.log(), /WARN decision ignored: /)
  })
  it("askAs: an ask becomes a refusal", async () => {
    const plugin = await session({ askAs: "deny" }, {})
    assert.equal(await plugin.verdict(RESET), "deny")
    plugin.done()
  })
  it("ruleOverrides: the global refusal stays", async () => {
    const plugin = await session({ ruleOverrides: { "git-reset-hard": "deny" } }, {})
    assert.equal(await plugin.verdict(RESET), "deny")
    plugin.done()
  })
  it("ruleOverrides: a project's off does not lift it", async () => {
    const plugin = await session({ ruleOverrides: { "git-reset-hard": "deny" } }, { ruleOverrides: { "git-reset-hard": "off" } })
    assert.equal(await plugin.verdict(RESET), "deny")
    plugin.done()
  })
  it("secretPatterns: a global pattern masks an output", async () => {
    const plugin = await session({ secretPatterns: ["corp-[0-9]{6}"], redactOutputs: true }, {})
    assert.ok(!(await plugin.output("value corp-123456 here")).includes("corp-123456"))
    plugin.done()
  })
})

describe("decision kept from the file: the same client and the same masking as the options OpenCode hands", () => {
  const KEY = "guard-kept-value-0123456789"
  const ROUTE = "guard-kept-route-9876543210"
  const written = (headers: unknown) => JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: { decision: { ...DECISION, apiKey: "{env:GUARD_KEEP_VALUE}", headers } } }] })
  const compare = async (headers: unknown, resolved: Json, files: Record<string, string>, expected: string) => {
    const run = async (project: Json) => {
      const plugin = await session(written(headers), project, { GUARD_KEEP_VALUE: KEY }, files)
      try {
        const verdict = await plugin.verdict(HEREDOC)
        return { verdict, masked: await plugin.output(`key ${KEY} and route ${ROUTE} in an output`), calls: plugin.calls }
      } finally {
        plugin.done()
      }
    }
    const [given, kept] = [await run({ decision: { ...DECISION, apiKey: KEY, headers: resolved } }), await run({})]
    assert.deepEqual([given.verdict, kept.verdict], [expected, expected])
    assert.equal(kept.masked, given.masked)
    assert.ok(!kept.masked.includes(KEY) && !kept.masked.includes(ROUTE), kept.masked)
    assert.ok(given.calls.length > 0)
    assert.deepEqual(kept.calls, given.calls)
    assert.equal(kept.calls[0]?.url, `${DECISION.baseURL}/chat/completions`)
    assert.equal((kept.calls[0]?.headers as Json).authorization, `Bearer ${KEY}`)
    assert.equal((kept.calls[0]?.headers as Json)["x-route"], ROUTE)
  }
  it("with {env:}: the model allows, as from the options", () => compare({ "X-Route": ROUTE }, { "X-Route": ROUTE }, {}, "allow"))
  it("with {env:} and {file:}: the value resolved; such a model is not certified, as from the options", () => compare({ "X-Route": "{file:route.txt}" }, { "X-Route": ROUTE }, { "route.txt": `${ROUTE}\n` }, "ask"))
  it("a file gone: empty, as OpenCode resolves it, and nothing thrown", async () => {
    const plugin = await session(written({ "X-Route": "{file:missing.txt}" }), {}, { GUARD_KEEP_VALUE: KEY })
    await plugin.verdict(HEREDOC)
    plugin.done()
    assert.ok(plugin.calls.length > 0)
    assert.equal((plugin.calls[0]?.headers as Json)["x-route"] ?? "", "")
  })
  it("a {file:…} in the project's entry changes nothing: the file is read for the global one only", async () => {
    const plugin = await session({ decision: { ...DECISION, apiKey: KEY } }, { decision: { ...DECISION, apiKey: "{file:/nonexistent}" } })
    await plugin.verdict(HEREDOC)
    plugin.done()
    assert.equal((plugin.calls[0]?.headers as Json).authorization, `Bearer ${KEY}`)
  })
})

/** A global configuration directory holding these files as written, read as the plugin reads it. */
function directory(files: Record<string, string>, env: Record<string, string> = {}) {
  const dir = mkdtempSync(join(tmpdir(), "guard-text-"))
  for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content)
  return { dir, declared: () => declaredPluginOptions({ pluginDir: PLUGIN_DIR, globalDir: dir, systemDir: join(dir, "no-system"), env }) }
}
const fileOf = (plugins: unknown) => JSON.stringify({ plugins })
const entry = (options: Json) => ({ package: PLUGIN_DIR, options })
/** Reason of the global entry, or its options. */
const declaration = (files: Record<string, string>) => {
  const [global] = directory(files).declared()
  return global?.options ?? global?.reason
}

describe("the file is read as OpenCode reads it: nothing changes inside a string", () => {
  const SECRET = "corpx-ab12cd34ef56gh78ij90kl12"
  const VALUES = {
    secretPatterns: ["corpx-[A-Za-z0-9]{8,}", "k-[0-9,]+", "a{1,}b"],
    rules: [{ id: "corp-rule", pattern: "[a,]b", verdict: "ask" }, { id: "corp-other", pattern: "(?:x{2,})", verdict: "ask" }],
    decision: { ...DECISION, apiKey: "abc,}def,]ghi", headers: { "X-Route": "r,]s,}t" } },
  }
  const text = `{ // a comment, with "quotes"
    "plugins": [ /* another */
      ${JSON.stringify(entry(VALUES)).replace(/\}$/, ", }")},
    ],
  }`
  it("a comment and a trailing comma outside the strings are gone, what is inside them stays", () => {
    assert.deepEqual(declaration({ "opencode.json": text }), VALUES)
  })
  each("the values apply as written, a project's entry or none", (path) => {
    for (const given of [VALUES, {}]) {
      const { config, warnings } = parseConfig(given, {}, directory({ "opencode.json": text }).declared, path)
      assert.deepEqual(warnings, [])
      assert.deepEqual(config.secretPatterns.map((item) => item.regex.source), VALUES.secretPatterns)
      assert.deepEqual(config.rules.map((rule) => rule.pattern.source), ["[a,]b", "(?:x{2,})"])
      assert.deepEqual([config.decision?.apiKey, config.decision?.headers], [VALUES.decision.apiKey, VALUES.decision.headers])
    }
  })
  for (const [label, project] of [["without a project", { secretPatterns: VALUES.secretPatterns }], ["with one", {}]] as const)
    it(`${label === "with one" ? "" : "witness: "}a pattern with {8,} masks the whole secret, ${label}`, async () => {
      const plugin = await session({ secretPatterns: VALUES.secretPatterns, redactOutputs: true }, project)
      const output = await plugin.output(`value ${SECRET} here`)
      plugin.done()
      assert.ok(!output.includes("ef56gh78"), output)
    })
  it("what jsonc-parser refuses stays refused, a comment ends where it ends", () => {
    for (const broken of ["[,]", "[1,,]", "{,}"]) assert.equal(declaration({ "opencode.json": `{"plugins": ${fileOf([entry({})]).slice(11, -1)}, "x": ${broken}}` }), "it is not valid JSON", broken)
    assert.equal(declaration({ "opencode.json": `{"plugins": ${fileOf([entry({})]).slice(11, -1)}, "x": 1/**/2}` }), "it is not valid JSON")
    // A backslash before a line end stays in the string: no comment starts inside it.
    assert.equal(declaration({ "opencode.json": `{"plugins": ${fileOf([entry({})]).slice(11, -1)}, "x": "x/*\\\n*/y"}` }), "it is not valid JSON")
    assert.deepEqual(declaration({ "opencode.json": `// a line\r${fileOf([entry({ debug: true })])}` }), { debug: true })
  })
})

describe("the entry in force is the last one, as OpenCode applies them", () => {
  const [ONE, TWO] = [{ decision: { ...DECISION, model: "one" }, askAs: "deny" }, { decision: { ...DECISION, model: "two" } }]
  const both = { "opencode.json": fileOf([entry(ONE)]), "opencode.jsonc": fileOf([entry(TWO)]) }
  each("witness: across the files, no project: opencode.jsonc wins, nothing ignored", (path) => {
    const { config, warnings } = parseConfig(TWO, {}, directory(both).declared, path)
    assert.deepEqual([config.decision?.model, config.askAs, warnings], ["two", "ask", []])
  })
  each("across the files, a project's entry keeps the one in force", (path) => {
    assert.equal(parseConfig({}, {}, directory(both).declared, path).config.decision?.model, "two")
  })
  each("witness: in one file", (path) => {
    const { config, warnings } = parseConfig(TWO, {}, directory({ "opencode.json": fileOf([entry(ONE), entry(TWO)]) }).declared, path)
    assert.deepEqual([config.decision?.model, config.askAs, warnings], ["two", "ask", []])
  })
  each("witness: a text entry replaces the options by none", (path) => {
    const { config, warnings } = parseConfig({}, {}, directory({ "opencode.json": fileOf([entry(ONE), PLUGIN_DIR]) }).declared, path)
    assert.deepEqual([config.decision, config.askAs, warnings], [undefined, "ask", []])
  })
  it("witness: a file without the plugin after the entry changes nothing", () => {
    assert.deepEqual(declaration({ "opencode.json": fileOf([entry(TWO)]), "opencode.jsonc": fileOf(["other-plugin"]) }), TWO)
  })
  it("a removal takes the plugin out: by identifier or *, in the same file or the next", () => {
    const REASON = "it does not declare this plugin"
    for (const removal of ["-guard", "-*"]) {
      assert.equal(declaration({ "opencode.json": fileOf([entry(TWO), removal]) }), REASON, removal)
      assert.equal(declaration({ "opencode.json": fileOf([entry(TWO)]), "opencode.jsonc": fileOf([removal]) }), REASON, removal)
      assert.deepEqual(declaration({ "opencode.json": fileOf([removal, entry(TWO)]) }), TWO, removal)
      assert.deepEqual(declaration({ "opencode.json": fileOf([entry(ONE), removal, entry(TWO)]) }), TWO, removal)
    }
  })
  it("witness: what is not a removal of this plugin leaves the entry in force", () => {
    for (const other of [`-${PLUGIN_DIR}`, "-other", { package: "-guard" }]) assert.deepEqual(declaration({ "opencode.json": fileOf([entry(TWO), other]) }), TWO, JSON.stringify(other))
  })
  it("witness: selected again after a removal, the plugin keeps the options it was loaded with", () => {
    for (const selector of ["guard", "*"]) assert.deepEqual(declaration({ "opencode.json": fileOf([entry(TWO), "-guard", selector]) }), TWO, selector)
    assert.equal(declaration({ "opencode.json": fileOf(["guard"]) }), "it does not declare this plugin")
  })
  it("witness: a malformed file after the entry counts for nothing; alone, nothing is certified", () => {
    assert.deepEqual(declaration({ "opencode.json": fileOf([entry(TWO)]), "opencode.jsonc": "{" }), TWO)
    assert.equal(declaration({ "opencode.json": "{", "opencode.jsonc": fileOf(["other"]) }), "it is not valid JSON")
    assert.equal(declaration({ "opencode.json": "{" }), "it is not valid JSON")
  })
  each("a malformed file before the entry counts for nothing: a project's entry keeps it", (path) => {
    const files = { "opencode.json": "{", "opencode.jsonc": fileOf([entry(ONE)]) }
    const { config, warnings } = parseConfig({}, {}, directory(files).declared, path)
    assert.deepEqual([config.decision?.model, config.askAs, warnings], ["one", "deny", []])
  })
  it("a byte order mark is dropped, as OpenCode's text decoder does", () => {
    assert.deepEqual(declaration({ "opencode.json": `\uFEFF${fileOf([entry(TWO)])}` }), TWO)
  })
  it("a {file:…} is read for the entry in force, from its own file", () => {
    const { dir, declared } = directory({ "key.txt": "right-key-value\n", "opencode.json": fileOf([entry({ decision: { ...DECISION, apiKey: "wrong" } })]), "opencode.jsonc": fileOf(["other", entry({ decision: { ...DECISION, apiKey: "{file:key.txt}" } })]) })
    assert.ok(dir)
    assert.equal(parseConfig({}, {}, declared).config.decision?.apiKey, "right-key-value")
  })
})

describe("{file:…} as OpenCode replaces it", () => {
  const keyed = (reference: string, comment = "") => `{"plugins": [{"package": ${JSON.stringify(PLUGIN_DIR)}, "options": {${comment}"decision": ${JSON.stringify({ ...DECISION, apiKey: reference })}}}]}`
  it("~/ is the home directory", () => {
    const home = mkdtempSync(join(tmpdir(), "guard-home-"))
    writeFileSync(join(home, "k.txt"), "home-key-value")
    assert.equal(parseConfig({}, {}, directory({ "opencode.json": keyed("{file:~/k.txt}") }, { HOME: home }).declared).config.decision?.apiKey, "home-key-value")
  })
  it("a line comment is left alone", () => {
    // Replaced, this content would close the block comment around the line, and the file would no longer parse.
    const files = { "k.txt": "the-key-value", "closing.txt": "*/", "opencode.json": keyed("{file:k.txt}", "/*\n// {file:closing.txt}\n*/") }
    const { config, warnings } = parseConfig({}, {}, directory(files).declared)
    assert.deepEqual([config.decision?.apiKey, warnings], ["the-key-value", []])
  })
  it("witness: the options as the file writes them are not a project's choice", () => {
    const written = { decision: { ...DECISION, apiKey: "{file:k.txt}" } }
    const { config, warnings } = parseConfig(written, {}, directory({ "k.txt": "the-key-value", "opencode.json": fileOf([entry(written)]) }).declared)
    assert.deepEqual(warnings, [])
    assert.equal(config.decision?.apiKey, "{file:k.txt}")
  })
})

describe("a project's value that does not hold leaves the global configuration's", () => {
  for (const name of ["dangerousCommands", "scripts", "decisionModel"] as const)
    for (const value of [false, null, 2])
      each(`${name} ${value} over a credentials-only global that turns it on`, (path) => {
        const global = { profile: "credentials-only", [name]: true, ...(name === "decisionModel" ? { decision: DECISION } : {}) }
        const { config, warnings } = parse({ [name]: value }, global, path)
        assert.equal(config.features[name], true, name)
        assert.equal(config.profile, "credentials-only")
        assert.ok(warnings.some((line) => line.includes(name)), warnings.join("\n"))
      })
  each("the same with the profile written by the project too", (path) => {
    assert.equal(parse({ profile: "credentials-only", dangerousCommands: false }, { profile: "credentials-only", dangerousCommands: true }, path).config.features.dangerousCommands, true)
  }, true)
  it("the same through the real hooks", async () => {
    for (const value of [false, null, 2]) {
      const plugin = await session({ profile: "credentials-only", dangerousCommands: true }, { profile: "credentials-only", dangerousCommands: value })
      assert.equal(await plugin.verdict(RESET), "ask", String(value))
      plugin.done()
    }
  })
  each("witness: a credentials-only global that leaves it off: it stays off, nothing said", (path) => {
    const { config, warnings } = parse({ dangerousCommands: false }, { profile: "credentials-only" }, path)
    assert.deepEqual([config.features.dangerousCommands, warnings], [false, []])
  })
  each("a threshold empty or invalid: the global one stays, one warning", (path) => {
    for (const value of ["", " ", "abc", -1, 9, null, [], {}]) {
      const { config, warnings } = parse({ thresholds: { askRisk: value } }, { thresholds: { askRisk: 0.5 } }, path)
      assert.equal(config.thresholds.askRisk, 0.5, JSON.stringify(value))
      assert.equal(warnings.filter((line) => line.includes("askRisk")).length, 1, warnings.join("\n"))
    }
  })
  each("a threshold invalid, the global one less strict than the default: it stays too", (path) => {
    for (const value of ["abc", ""]) assert.equal(parse({ thresholds: { askRisk: value } }, { thresholds: { askRisk: 2 } }, path).config.thresholds.askRisk, 2, value)
  })
  it("witness: the same through the real hooks: a risk over the global threshold asks", async () => {
    const plugin = await session({ decision: DECISION, thresholds: { askRisk: 0.05 } }, { decision: DECISION, thresholds: { askRisk: "" } })
    assert.equal(await plugin.verdict(HEREDOC), "ask")
    plugin.done()
  })
  each("thresholds: a valid one beside an invalid one counts", (path) => {
    const { config } = parse({ thresholds: { askRisk: "abc", denyRisk: 1 } }, { thresholds: { askRisk: 0.5, denyRisk: 2 } }, path)
    assert.deepEqual([config.thresholds.askRisk, config.thresholds.denyRisk], [0.5, 1])
  })
  each("ruleOverrides: a value the global side wrote and its rule refuses is no reference", (path) => {
    for (const rule of ["self-protection", "nested-opencode", "opencode-service"])
      for (const value of ["ask", "off"]) {
        const global = { selfProtectionByModel: true, ruleOverrides: { [rule]: value } }
        const { config, warnings } = parse({ selfProtectionByModel: true, ruleOverrides: { [rule]: "model" } }, global, path)
        assert.equal(overrideOf(rule)(config), undefined, `${rule} ${value}`)
        assert.ok(warnings.some((line) => line.includes(`ruleOverrides.${rule}`)), `${rule} ${value}`)
      }
  })
  each("ruleOverrides: an invalid value: the global setting stays, one warning", (path) => {
    for (const value of ["banana", "", " ", null, "allow", 0, []]) {
      const { config, warnings } = parse({ ruleOverrides: { "git-reset-hard": value } }, { ruleOverrides: { "git-reset-hard": "deny" } }, path)
      assert.equal(overrideOf("git-reset-hard")(config), "deny", JSON.stringify(value))
      assert.equal(warnings.filter((line) => line.includes("git-reset-hard")).length, 1, warnings.join("\n"))
    }
  })
  each("witness: ruleOverrides: an invalid value on a rule the global configuration does not set: nothing to keep", (path) => {
    const { warnings } = parse({ ruleOverrides: { rm: "banana" } }, { ruleOverrides: { "git-reset-hard": "deny" } }, path)
    assert.deepEqual(warnings.filter((line) => line.includes("banana") || line.includes("ruleOverrides.rm")).map((line) => line.includes("stays")), [false])
  })
  each("ruleOverrides: a value without effect on an always-active rule: the global refusal stays", (path) => {
    for (const value of ["off", "ask", "model"]) {
      const { config } = parse({ ruleOverrides: { "self-protection": value } }, { ruleOverrides: { "self-protection": "deny" } }, path)
      assert.equal(overrideOf("self-protection")(config), "deny", value)
    }
  }, true)
  it("the same through the real hooks", async () => {
    for (const value of ["banana", ""]) {
      const plugin = await session({ ruleOverrides: { "git-reset-hard": "deny" } }, { ruleOverrides: { "git-reset-hard": value } })
      assert.equal(await plugin.verdict(RESET), "deny", value)
      plugin.done()
    }
  })
  each("a project's rule under a built-in identifier: the global setting stays, without rules of its own", (path) => {
    const { config, warnings } = parse({ rules: [{ id: "git-reset-hard", pattern: "x", verdict: "ask" }] }, { ruleOverrides: { "git-reset-hard": "deny" } }, path)
    assert.deepEqual(config.rules, [])
    assert.equal(overrideOf("git-reset-hard")(config), "deny")
    assert.equal(ignored(warnings, "rules").length, 1)
  })
  it("the same through the real hooks", async () => {
    const plugin = await session({ ruleOverrides: { "git-reset-hard": "deny" } }, { rules: [{ id: "git-reset-hard", pattern: "x", verdict: "ask" }] })
    assert.equal(await plugin.verdict(RESET), "deny")
    plugin.done()
  })
  it("the same when a global guard.json or a section sets it", () => {
    const rule = { rules: [{ id: "git-reset-hard", pattern: "x", verdict: "ask" }] }
    const file: GuardFile = { label: "global guard.json", global: true, dir: "/g", data: { ruleOverrides: { "git-reset-hard": "deny" } } }
    const { config, warnings } = parseConfig(rule, {}, declaring({ debug: true }), inputs([file]))
    assert.deepEqual(config.rules, [])
    assert.equal(overrideOf("git-reset-hard")(config), "deny")
    assert.equal(ignored(warnings, "rules").length, 1)
    assert.deepEqual(parse(rule, { agents: { plan: { ruleOverrides: { "git-reset-hard": "deny" } } } }, PATHS.simple).config.rules, [])
    assert.deepEqual(parse(rule, { projects: { [PROJECT]: { ruleOverrides: { "git-reset-hard": "deny" } } } }, PATHS.simple).config.rules, [])
  })
  each("the same under an exception of the global configuration", (path) => {
    const { config } = parse({ rules: [{ id: "secret-file-read", pattern: "x", verdict: "ask" }] }, { exceptions: { "secret-file-read": [SECRET_FILE] } }, path)
    assert.deepEqual(config.rules, [])
    assert.equal(policy(config).exceptions?.get("secret-file-read")?.has(SECRET_FILE), true)
  })
  each("witness: a rule written the same way in both counts once", (path) => {
    const rule = { id: "corp-rule", pattern: "corpx", verdict: "deny" }
    const { config, warnings } = parse({ rules: [rule, { id: "own-rule", pattern: "ownx", verdict: "ask" }] }, { rules: [rule] }, path)
    assert.deepEqual([config.rules.map((item) => item.id), warnings], [["corp-rule", "own-rule"], []])
  })
  each("witness: rules of a global configuration without any: the project's, invalid included as before", (path) => {
    assert.deepEqual(parse({ rules: [{ id: "own-rule", pattern: "ownx", verdict: "ask" }] }, { debug: true }, path).config.rules.map((rule) => rule.id), ["own-rule"])
    assert.equal(parse({ rules: "x" }, { debug: true }, path).warnings.filter((line) => line.includes("rules")).length, 1)
  })
  each("witness: a pattern set aside by the global configuration and written by the project counts", (path) => {
    const global = { secretPatterns: [{ pattern: "corp-[0-9]{6}", enabled: false }] }
    const { config, warnings } = parse({ secretPatterns: ["corp-[0-9]{6}"] }, global, path)
    assert.deepEqual([config.secretPatterns.length, warnings], [1, []])
  })
})

describe("a global configuration with a decision: what it leaves out counts as the default", () => {
  const LOOSE = { denyNoul: 1, askNoul: 1, askExfiltration: 1, denyRisk: 3, askRisk: 3, minConfidence: 0 }
  const DEFAULTS = { denyNoul: 0.9, askNoul: 0.7, askExfiltration: 0.85, denyRisk: 2.5, askRisk: 1.5, minConfidence: 0 }
  each("thresholds less strict than the defaults: ignored, one warning", (path) => {
    const { config, warnings } = parse({ thresholds: LOOSE }, { decision: DECISION }, path)
    assert.deepEqual(config.thresholds, DEFAULTS)
    assert.equal(ignored(warnings, "thresholds").length, 1)
  })
  each("one posed by the global configuration, the others by the default", (path) => {
    const { config } = parse({ thresholds: LOOSE }, { decision: DECISION, thresholds: { askRisk: 1.8 } }, path)
    assert.deepEqual(config.thresholds, { ...DEFAULTS, askRisk: 1.8 })
  })
  each("witness: a stricter one is kept", (path) => {
    const { config, warnings } = parse({ thresholds: { askRisk: 1 } }, { decision: DECISION }, path)
    assert.deepEqual([config.thresholds.askRisk, warnings], [1, []])
  })
  each("maxStateChars other than the default: ignored, one warning", (path) => {
    for (const value of [200, 7000]) {
      const { config, warnings } = parse({ maxStateChars: value }, { decision: DECISION }, path)
      assert.equal(config.maxStateChars, 4000)
      assert.equal(ignored(warnings, "maxStateChars").length, 1)
    }
  })
  each("witness: thresholds not an object: a warning, the defaults", (path) => {
    const { config, warnings } = parse({ thresholds: "x" }, { decision: DECISION }, path)
    assert.deepEqual([config.thresholds, warnings.filter((line) => line.includes("thresholds")).length], [DEFAULTS, 1])
  })
  it("through the real hooks: a risk the model would refuse stays refused", async () => {
    const answers = { risk: { type: "score", score: 2.9, confidence: 0.99 } }
    const plugin = await session({ decision: DECISION }, { decision: DECISION, thresholds: LOOSE }, {}, {}, answers)
    assert.equal(await plugin.verdict(HEREDOC), "deny")
    plugin.done()
  })
  each("witness: a decision that is none does not count", (path) => {
    const { config, warnings } = parse({ thresholds: { askRisk: 3 }, maxStateChars: 200 }, { decision: false }, path)
    assert.deepEqual([config.thresholds.askRisk, config.maxStateChars, warnings.filter((line) => line.includes("ignored"))], [3, 200, []])
  })
  each("witness: a global configuration without decision: the project decides", (path) => {
    const { config, warnings } = parse({ thresholds: LOOSE, maxStateChars: 200 }, { askAs: "deny" }, path)
    assert.deepEqual([config.thresholds, config.maxStateChars, warnings.filter((line) => line.includes("ignored"))], [LOOSE, 200, []])
  })
  each("without decision, a threshold the global configuration leaves out is the project's", (path) => {
    const { config } = parse({ thresholds: { askRisk: 3, denyRisk: 3 } }, { thresholds: { askRisk: 1 } }, path)
    assert.deepEqual([config.thresholds.askRisk, config.thresholds.denyRisk], [1, 3])
  })
  each("a trusted project keeps its own, not an invalid one", (path) => {
    const declared = declaring({ decision: DECISION, thresholds: { askRisk: 0.5 }, trustedProjects: [PROJECT] })
    const { config } = parseConfig({ thresholds: { ...LOOSE, askRisk: "x" } }, {}, declared, path)
    assert.deepEqual(config.thresholds, { ...LOOSE, askRisk: 0.5 })
  })
})

describe("a global file that cannot be read", () => {
  const UNREAD = "settings of the global configuration not kept: it could not be read"
  each("as a directory: a warning, what the options say", (path) => {
    const { dir, declared } = directory({})
    mkdirSync(join(dir, "opencode.json"))
    const { config, warnings } = parseConfig({ askAs: "deny" }, {}, declared, path)
    assert.equal(config.askAs, "deny")
    assert.equal(warnings.filter((line) => line === UNREAD).length, 1)
  })
  it("without the right to read it", { skip: process.getuid?.() === 0 }, () => {
    const { dir, declared } = directory({ "opencode.json": fileOf([entry({ askAs: "deny" })]) })
    chmodSync(join(dir, "opencode.json"), 0o000)
    assert.ok(parseConfig({}, {}, declared).warnings.includes(UNREAD))
    chmodSync(join(dir, "opencode.json"), 0o600)
  })
  each("witness: a missing file: nothing said", (path) => {
    assert.deepEqual(parseConfig({}, {}, directory({}).declared, path).warnings, [])
  })
})

describe("the command line shows what counts", () => {
  it("witness: guard show, settings and status give the global values, whatever a project's opencode.json says, offline", async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-keep-cli-")))
    const [globalDir, systemDir, home, data, project] = ["global", "system", "home", "data", "app"].map((name) => join(root, name)) as [string, string, string, string, string]
    for (const dir of [globalDir, systemDir, home, data, join(project, ".opencode")]) mkdirSync(dir, { recursive: true })
    const entry = (options: Json) => JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options }] })
    writeFileSync(join(globalDir, "opencode.json"), entry({ decision: DECISION, askAs: "deny", maxStateChars: 7000, ruleOverrides: { "git-reset-hard": "deny" }, outputCheck: { threshold: 0.1 } }))
    writeFileSync(join(project, ".opencode", "opencode.json"), entry({ askAs: "ask" }))
    const run = async (...command: string[]) => {
      const out: string[] = []
      await main(command, { env: { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }, cwd: project, systemDir, out: (line: string) => out.push(line), err: () => {} } as never)
      return out.join("\n")
    }
    const shown = await run("show", "--offline")
    assert.match(shown, /ruleOverrides\.git-reset-hard +deny +global configuration/)
    assert.match(shown, /outputCheck +true +global configuration/)
    const settings = await run("settings")
    assert.match(settings, /^askAs +string +deny /m)
    assert.match(settings, /^maxStateChars +integer +7000 /m)
    assert.match(settings, /^outputCheck\.threshold +number +0\.1 /m)
    assert.match(await run("status", "--offline"), /log/)
  })
})
