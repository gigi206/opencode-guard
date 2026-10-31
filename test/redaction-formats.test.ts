// Redaction formats: `guard redaction` (the built-in formats and their state, OpenCode's, the user's patterns),
// `--explain`, `guard show`, and turning a built-in format off (`secretPatterns`, global or system configuration only).
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { main } from "../src/cli/main.ts"
import { outputRedactor } from "../src/cli/context.ts"
import { parseConfig, type PluginDeclaration } from "../src/config.ts"
import { RULE_FEATURES } from "../src/rules/features.ts"
import { OPENCODE_FORMAT_SUMMARIES, OPENCODE_PATTERNS } from "../src/secrets/opencode-service.ts"
import { BUILTIN_PATTERNS, FORMAT_SUMMARIES } from "../src/secrets/patterns.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { setupGuard } from "../src/index.ts"
import { fakeContext } from "./fake-ctx.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>

function world(setup: { readonly global?: Json; readonly system?: Json } = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-redaction-")))
  const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "app")]
  for (const dir of [globalDir, systemDir, home, data, project]) mkdirSync(dir, { recursive: true })
  for (const [dir, options] of [[globalDir, setup.global], [systemDir, setup.system]] as const)
    if (options) writeFileSync(join(dir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options }] }))
  const env = { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }
  const io = (out: string[], err: string[], pretty?: { width: number; color: boolean }) => ({
    env,
    cwd: project,
    systemDir,
    out: (line: string) => out.push(line),
    err: (line: string) => err.push(line),
    ...(pretty ? { terminal: pretty } : {}),
  })
  return Object.assign(
    (...args: string[]) => {
      const out: string[] = []
      const err: string[] = []
      return { code: main(args, io(out, err)), out, err }
    },
    {
      pretty: (...args: string[]) => {
        const out: string[] = []
        const err: string[] = []
        return { code: main(args, io(out, err, { width: 100, color: false })), out, err }
      },
      io: () => io([], []),
    },
  )
}

const JWT_OFF = { type: "jwt", enabled: false }
const FAKE_JWT = `eyJ${"a".repeat(12)}.eyJ${"b".repeat(12)}.${"c".repeat(12)}`
const declared = (global: Json | undefined): (() => readonly PluginDeclaration[]) => () => [{ label: "global", options: global }, { label: "system", reason: "absent" }] as unknown as readonly PluginDeclaration[]

describe("redaction formats", () => {
  it("RF-1: every built-in type has a description, each description a type; OpenCode's are separate; no name is also a rule", () => {
    assert.deepEqual([...new Set(BUILTIN_PATTERNS.map((pattern) => pattern.type))].sort(), [...FORMAT_SUMMARIES.keys()].sort())
    assert.deepEqual([...new Set(OPENCODE_PATTERNS.map((pattern) => pattern.type))].sort(), [...OPENCODE_FORMAT_SUMMARIES.keys()].sort())
    for (const type of [...FORMAT_SUMMARIES.keys(), ...OPENCODE_FORMAT_SUMMARIES.keys()]) assert.ok(!RULE_FEATURES.has(type), type)
  })

  it("RF-2: docs/rules.md lists every format with the same description", () => {
    const docs = readFileSync(new URL("../docs/rules.md", import.meta.url), "utf8")
    const listed = [...docs.matchAll(/^\| `([a-z_]+)` \| (built-in|OpenCode, always active) \| (.+) \|$/gm)].map((match) => [match[1], match[2], match[3]])
    assert.deepEqual(listed, [
      ...[...FORMAT_SUMMARIES].map(([type, text]) => [type, "built-in", text]),
      ...[...OPENCODE_FORMAT_SUMMARIES].map(([type, text]) => [type, "OpenCode, always active", text]),
    ])
  })

  it("RF-3: every pattern and description prints unchanged through the command line's redaction", () => {
    const redactor = outputRedactor(world().io())
    for (const pattern of [...BUILTIN_PATTERNS, ...OPENCODE_PATTERNS]) {
      const text = `/${pattern.regex.source}/${pattern.regex.flags}`
      assert.equal(redactor.redactString(text).value, text, pattern.type)
    }
    for (const text of [...FORMAT_SUMMARIES.values(), ...OPENCODE_FORMAT_SUMMARIES.values()]) assert.equal(redactor.redactString(text).value, text)
  })

  it("RF-4: a format turned off by the global configuration is no longer redacted; elsewhere ignored, with a warning", () => {
    const global = { secretPatterns: [JWT_OFF] }
    const own = parseConfig(global, {}, declared(global))
    assert.deepEqual(own.config.disabledPatterns, ["jwt"])
    assert.deepEqual(own.warnings, [])
    assert.equal(createRedactor({ disabledTypes: own.config.disabledPatterns }).redactString(FAKE_JWT).value, FAKE_JWT)
    assert.notEqual(createRedactor({}).redactString(FAKE_JWT).value, FAKE_JWT)
    // A project's opencode.json (effective options that the global entry does not share): refused.
    const project = parseConfig({ secretPatterns: [JWT_OFF] }, {}, declared({}))
    assert.deepEqual(project.config.disabledPatterns, [])
    assert.ok(project.warnings.some((warning) => /^secretPatterns: turning off the built-in format jwt ignored: a relaxation counts only if the global or system configuration sets it too/.test(warning)))
    // Without the declarations (unknown): refused too.
    assert.deepEqual(parseConfig({ secretPatterns: [JWT_OFF] }).config.disabledPatterns, [])
  })

  it("RF-5: strict entries: enabled only a boolean, unknown or OpenCode formats reported, a pattern of yours kept aside", () => {
    const { config, warnings } = parseConfig({
      secretPatterns: [{ type: "jwt", enabled: "false" }, { type: "nope", enabled: false }, { type: "opencode_credential", enabled: false }, { enabled: false }, { type: "corp", pattern: "corp-[0-9]{6}", enabled: false }, { type: "vide" }],
    })
    assert.deepEqual(config.disabledPatterns, [])
    assert.deepEqual(config.secretPatterns, [])
    assert.deepEqual(warnings, [
      "secretPatterns[0]: enabled must be true or false, entry ignored",
      "secretPatterns[1]: no built-in format named nope",
      "secretPatterns[2]: the built-in format opencode_credential cannot be turned off",
      "secretPatterns[3]: the built-in format to turn off is missing (type)",
      "secretPatterns[5]: missing pattern",
    ])
  })

  it("RF-6: guard redaction lists the formats with their state, then the user's patterns and those set aside", () => {
    const run = world({ global: { secretPatterns: [JWT_OFF, { type: "corp", pattern: "corp-[0-9]{6}" }, { type: "nope", enabled: false }] } })
    const r = run("redaction")
    assert.equal(r.code, 0)
    assert.equal(r.out[0], "Built-in redaction formats:")
    assert.match(r.out.find((line) => line.includes(" jwt "))!, /^ {2}jwt +off +JSON Web Tokens/)
    assert.match(r.out.find((line) => line.includes(" github_token "))!, /^ {2}github_token +on +/)
    assert.match(r.out.find((line) => line.includes(" opencode_pairing "))!, /^ {2}opencode_pairing +always +/)
    const own = r.out.indexOf("Your redaction patterns (secretPatterns option of the global configuration):")
    assert.ok(own > 0)
    assert.match(r.out[own + 1]!, /^ {2}corp +\/corp-\[0-9\]\{6\}\/g$/)
    assert.equal(r.out[own + 2], "  Set aside:")
    assert.equal(r.out[own + 3], "    secretPatterns[2]: no built-in format named nope")
    assert.deepEqual(run("redaction", "--builtins").out, r.out.slice(0, own))
    assert.deepEqual(run("redaction", "--custom").out, r.out.slice(own))
    // Terminal layout: same content, grouped.
    const pretty = run.pretty("redaction").out.join("\n")
    assert.match(pretty, /Redaction formats +\d+ formats, 1 off/)
    assert.match(pretty, /jwt +off +JSON Web Tokens/)
    assert.match(pretty, /\/corp-\[0-9\]\{6\}\/g/)
  })

  it("RF-7: --explain prints every pattern of a type and how to turn it off; unknown names are usage errors", () => {
    const run = world({ global: {} })
    const r = run("redaction", "--explain", "generic_secret")
    assert.equal(r.code, 0)
    assert.deepEqual(r.out.slice(0, 2), ["Format: generic_secret", "  State: on"])
    const patterns = BUILTIN_PATTERNS.filter((pattern) => pattern.type === "generic_secret").map((pattern) => `    /${pattern.regex.source}/${pattern.regex.flags}`)
    assert.equal(patterns.length, 7)
    for (const line of patterns) assert.ok(r.out.includes(line), line)
    assert.ok(r.out.some((line) => line.startsWith('  Setting: Turned off by guard redaction off generic_secret (redactionOff in the global guard.json')))
    assert.ok(!r.out.join("\n").includes("<format>"))
    assert.match(run("redaction", "--explain", "opencode_credential").out.join("\n"), /Cannot be turned off/)
    assert.match(run("redaction", "--explain", "nope").err[0]!, /^guard: no redaction format named nope$/)
    assert.equal(run("redaction", "--explain", "jwt", "--builtins").code, 2)
    assert.match(run("redaction", "--explain").err[0]!, /^guard: --explain needs a format name$/)
    assert.match(run.pretty("redaction", "--explain", "jwt").out.join("\n"), /Format jwt +built-in, on/)
  })

  it("RF-8: guard show lists the formats turned off (relaxes) and the entries set aside", () => {
    const run = world({ global: { secretPatterns: [JWT_OFF, "corp-[0-9]{6}", { type: "nope", enabled: false }] } })
    const r = run("show")
    assert.equal(r.code, 0)
    assert.ok(r.out.some((line) => /^ {2}secretPatterns +1 pattern +global configuration$/.test(line)), r.out.join("\n"))
    assert.ok(r.out.some((line) => /^ {2}secretPatterns\.jwt +off +global configuration$/.test(line)))
    assert.ok(r.out.includes("  secretPatterns[2]: no built-in format named nope"))
    assert.match(run.pretty("show").out.join("\n"), /secretPatterns\.jwt +off +relaxes/)
  })

  it("RF-9: turning a format off changes what the decision model sees: compared with the global declaration", () => {
    const decision = { baseURL: "https://decision.local/v1", model: "nox-4b" }
    const grants = (effective: Json, global: Json) => parseConfig(effective, {}, declared(global)).config.modelGrants
    assert.equal(grants({ decision, secretPatterns: [JWT_OFF] }, { decision, secretPatterns: [JWT_OFF] }), true)
    // The global file turns jwt off, the effective options do not: the model would not see what the global one sees.
    assert.equal(grants({ decision }, { decision, secretPatterns: [JWT_OFF] }), false)
  })
  it("RF-10: the plugin applies a format turned off by the global configuration and says so on its start line; a project's is refused", async () => {
    const start = async (options: Json, global: Json) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-rf-")))
      const [globalDir, etc] = [join(root, "global"), join(root, "etc")]
      for (const dir of [globalDir, etc]) mkdirSync(dir, { recursive: true })
      writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: global }] }))
      const logFile = join(root, "guard.log")
      const fake = fakeContext({ logFile, ...options })
      await setupGuard(fake.ctx, {}, etc, globalDir)
      const event = await fake.trigger("tool.execute.after", { sessionID: "s", agent: "build", messageID: "m", id: "c", tool: "bash", input: { command: "cat token" }, status: "completed", result: { output: FAKE_JWT, content: [{ type: "text", text: FAKE_JWT }] } })
      return { log: readFileSync(logFile, "utf8"), output: JSON.stringify(event.result) }
    }
    const off = await start({ secretPatterns: [JWT_OFF] }, { secretPatterns: [JWT_OFF] })
    assert.match(off.log, /INFO active \(.*; redaction formats off: jwt[;)]/)
    assert.ok(off.output.includes(FAKE_JWT))
    const refused = await start({ secretPatterns: [JWT_OFF] }, {})
    assert.ok(!refused.log.includes("redaction formats off"))
    assert.match(refused.log, /WARN .*secretPatterns: turning off the built-in format jwt ignored/)
    assert.ok(!refused.output.includes(FAKE_JWT))
  })
})
