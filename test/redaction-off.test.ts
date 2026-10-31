// Built-in redaction formats turned off by the global guard.json (`redactionOff`, written by `guard redaction off|on`):
// the command line, the plugin at startup and while it runs (both ways), the places where the key is ignored, and the
// guard-cli rule. Fake values; nothing is run.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { main } from "../src/cli/main.ts"
import { parseConfig, resolveVersion } from "../src/config.ts"
import { setupGuard } from "../src/index.ts"
import { toolFinding } from "../src/rules/tools.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>
const FAKE_JWT = `eyJ${"a".repeat(12)}.eyJ${"b".repeat(12)}.${"c".repeat(12)}`
const JWT_OFF = { type: "jwt", enabled: false }
const DECISION = { baseURL: "https://decision.local/v1", model: "nox-4b" }

function world(global: Json = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-ro-")))
  const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "app")]
  for (const dir of [globalDir, systemDir, home, data, project]) mkdirSync(dir, { recursive: true })
  writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: global }] }))
  const env = { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }
  const run = (...args: string[]) => {
    const out: string[] = []
    const err: string[] = []
    const code = main(args, { env, cwd: project, systemDir, out: (line) => out.push(line), err: (line) => err.push(line) })
    return { code, out, err }
  }
  const guardFile = join(globalDir, "guard.json")
  return { root, globalDir, systemDir, project, run, guardFile, guard: () => JSON.parse(readFileSync(guardFile, "utf8")) as Json }
}

/** The plugin started on a world, with a clock the test moves; `output` runs the tool output hook on a fake JWT. */
async function plugin(w: ReturnType<typeof world>, options: Json = {}) {
  let now = 1_000_000
  const logFile = join(w.root, "guard.log")
  const fake = fakeContext({ logFile, ...options })
  await setupGuard(fake.ctx, {}, w.systemDir, w.globalDir, { now: () => now, intervalMs: 2000 })
  return {
    log: () => readFileSync(logFile, "utf8"),
    later: () => (now += 2500),
    output: async () => {
      const event = await fake.trigger("tool.execute.after", { sessionID: "s", agent: "build", messageID: "m", id: `c${now}`, tool: "bash", input: { command: "cat token" }, status: "completed", result: { output: FAKE_JWT, content: [{ type: "text", text: FAKE_JWT }] } })
      return JSON.stringify(event.result).includes(FAKE_JWT) ? "clear" : "redacted"
    },
  }
}

describe("redaction formats turned off by the global guard.json", () => {
  it("RO-1: guard redaction off|on writes redactionOff of the global guard.json; redaction and show say so", () => {
    const w = world()
    const off = w.run("redaction", "off", "twilio_key")
    assert.equal(off.code, 0)
    assert.deepEqual(w.guard(), { redactionOff: ["twilio_key"] })
    assert.ok(off.err.some((line) => line.startsWith("warning: twilio_key values are no longer redacted")))
    assert.match(w.run("redaction", "off", "twilio_key").out.join("\n"), /already in redactionOff.*nothing changed/)
    assert.ok(w.run("redaction", "--builtins").out.some((line) => /twilio_key/.test(line) && /\boff\b/.test(line)))
    assert.ok(w.run("redaction", "--explain", "twilio_key").out.includes("  State: off"))
    assert.ok(w.run("show").out.some((line) => /^ {2}redactionOff\.twilio_key +off +global guard\.json$/.test(line)))
    const on = w.run("redaction", "on", "twilio_key")
    assert.equal(on.code, 0)
    assert.deepEqual(w.guard(), {})
    assert.match(w.run("redaction", "on", "twilio_key").out.join("\n"), /not in redactionOff.*nothing changed/)
    assert.ok(w.run("redaction", "--explain", "twilio_key").out.includes("  State: on"))
  })

  it("RO-2: unknown names, OpenCode's formats and extra arguments are usage errors; nothing is written", () => {
    const w = world()
    for (const args of [["off", "nope"], ["off", "qr_code"], ["on", "opencode_credential"], ["off"], ["off", "jwt", "x"], ["off", "jwt", "--custom"]]) {
      const r = w.run("redaction", ...args)
      assert.notEqual(r.code, 0, args.join(" "))
    }
    assert.throws(() => readFileSync(w.guardFile))
  })

  it("RO-3: back on, a format that secretPatterns of the global configuration also turns off stays off, and the command says so", () => {
    const w = world({ secretPatterns: [JWT_OFF] })
    w.run("redaction", "off", "jwt")
    const on = w.run("redaction", "on", "jwt")
    assert.match(on.out.join("\n"), /jwt is still off: secretPatterns of the global configuration turns it off/)
    assert.ok(w.run("redaction", "--explain", "jwt").out.includes("  State: off"))
  })

  it("RO-4: the plugin applies it at startup (start line) and keeps the model's right to allow asks", async () => {
    const w = world({ decision: DECISION })
    writeFileSync(w.guardFile, JSON.stringify({ redactionOff: ["jwt"] }))
    const p = await plugin(w, { decision: DECISION })
    assert.match(p.log(), /INFO active \(.*; redaction formats off: jwt[;)]/)
    assert.equal(await p.output(), "clear")
    assert.ok(!p.log().includes("decision model not declared by the global configuration"), p.log())
    // Read like the plugin: the effective options are unchanged, so the model keeps its grants.
    const declared = () => [{ label: "global", options: { decision: DECISION } }, { label: "system", reason: "absent" }] as never
    assert.equal(parseConfig({ decision: DECISION }, {}, declared).config.modelGrants, true)
  })

  it("RO-5: while it runs, off then back on, within the check interval, without a tool call", async () => {
    const w = world()
    const p = await plugin(w)
    assert.equal(await p.output(), "redacted")
    writeFileSync(w.guardFile, JSON.stringify({ redactionOff: ["jwt"] }))
    p.later()
    assert.equal(await p.output(), "clear")
    assert.match(p.log(), /guard\.json re-read \(.*redaction formats off: jwt/)
    rmSync(w.guardFile)
    p.later()
    assert.equal(await p.output(), "redacted")
  })

  it("RO-6: ignored, with a warning, in a project's guard.json, in a section, in opencode.json, and for names that are not built-in formats", () => {
    const layersOf = (options: Json = {}) => parseConfig(options, {}, () => [{ label: "global", options }] as never, { files: [], realPath: (path: string) => path }).config.layers!
    const version = resolveVersion(layersOf(), [
      { label: "global guard.json", global: true, data: { redactionOff: ["jwt", "nope", "qr_code", 3], agents: { build: { redactionOff: ["npm_token"] } }, projects: { "/x": { redactionOff: ["npm_token"] } } } },
      { label: "project guard.json (/p/.opencode/guard.json)", global: false, dir: "/p", data: { redactionOff: ["stripe_key"] } },
    ])
    assert.deepEqual(version.redactionOff, ["jwt"])
    const warnings = version.warnings.join("\n")
    assert.match(warnings, /redactionOff\[1\] ignored: no built-in format named nope/)
    assert.match(warnings, /redactionOff\[2\] ignored: the built-in format qr_code cannot be turned off/)
    assert.match(warnings, /redactionOff\[3\] ignored: a format name expected/)
    assert.match(warnings, /agents\.build: redactionOff ignored: it counts only at the top level of the global guard\.json/)
    assert.match(warnings, /projects\["\/x"\]: redactionOff ignored: it counts only at the top level/)
    assert.match(warnings, /project guard\.json .*: redactionOff ignored: it counts only at the top level/)
    assert.match(parseConfig({ redactionOff: ["jwt"] }).warnings.join("\n"), /redactionOff ignored: it is a key of the global guard\.json; in opencode\.json, turn a format off with secretPatterns/)
  })

  it("RO-7: the agent running guard redaction off|on is always asked, never left to the model", () => {
    // Even with every ask left to the model (localAsks "model", selfProtectionByModel): the ask stays with the user.
    const active = { dangerousCommands: true, sensitiveFiles: true, localAsksByModel: true, selfProtectionByModel: true }
    const ctx = { redactor: createRedactor(), home: "/home/test", cwd: "/home/test/app", active }
    for (const command of ["guard redaction off jwt", "guard redaction on jwt", "~/.local/bin/guard redaction off twilio_key"]) {
      const finding = toolFinding("shell", { command }, ctx)
      assert.equal(`${finding?.verdict}/${finding?.rule}`, "ask/guard-cli", command)
      assert.equal(finding?.modelDecides, undefined, command)
    }
  })

  it("RO-8: setDisabledTypes turns built-in formats off on top of disabledTypes, never OpenCode's, and back on", () => {
    const r = createRedactor({ disabledTypes: ["npm_token"] })
    const npm = `npm_${"a".repeat(36)}`
    assert.notEqual(r.redactString(FAKE_JWT).value, FAKE_JWT)
    r.setDisabledTypes(["jwt", "qr_code"])
    assert.equal(r.redactString(FAKE_JWT).value, FAKE_JWT)
    assert.equal(r.redactString(npm).value, npm)
    r.setDisabledTypes([])
    assert.notEqual(r.redactString(FAKE_JWT).value, FAKE_JWT)
    assert.equal(r.redactString(npm).value, npm)
  })
})
