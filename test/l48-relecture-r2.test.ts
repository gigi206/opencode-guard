// Lot 48 common review R2 (configuration, scopes, command line): each test states the expected behaviour and fails on
// the reviewed candidate. The plugin runs as OpenCode sets it up (`setupGuard`, configuration directories of the test,
// test clock); nothing is launched, text is judged.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import { describe, it } from "node:test"
import { setupGuard } from "../src/index.ts"
import { fakeContext } from "./fake-ctx.ts"
import { FAKE } from "./fixtures.ts"

type Json = Record<string, unknown>

/** Plugin set up as OpenCode does: global and system directories, session directory `<root>/work/app`, test clock. */
async function guard(setup: { readonly globalGuard?: Json; readonly projectGuard?: Json; readonly global?: Json } = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-rl2-")))
  const [globalDir, systemDir, project] = [join(root, "global"), join(root, "system"), join(root, "work", "app")]
  for (const dir of [globalDir, systemDir, join(project, ".opencode")]) mkdirSync(dir, { recursive: true })
  const pluginDir = realpathSync(join(dirname(new URL(import.meta.url).pathname), ".."))
  if (setup.global)
    writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: pluginDir, options: JSON.parse(JSON.stringify(setup.global).replaceAll("<PROJECT>", project)) }] }))
  if (setup.globalGuard) writeFileSync(join(globalDir, "guard.json"), JSON.stringify(setup.globalGuard))
  if (setup.projectGuard) writeFileSync(join(project, ".opencode", "guard.json"), JSON.stringify(setup.projectGuard))
  const logFile = join(root, "guard.log")
  const fake = fakeContext({ logFile, ...(setup.global ? JSON.parse(JSON.stringify(setup.global).replaceAll("<PROJECT>", project)) : {}) })
  ;(fake.ctx.location as { directory: string }).directory = project
  let now = 1_000_000
  await (setupGuard as (...args: unknown[]) => Promise<void>)(fake.ctx, {}, systemDir, globalDir, { now: () => now, intervalMs: 2000 })
  let call = 0
  return {
    globalDir,
    project,
    log: () => readFileSync(logFile, "utf8"),
    tick: (ms = 2000) => (now += ms),
    verdict: async (command: string) => {
      const before = fake.asserts.length
      try {
        await fake.trigger("tool.execute.before", { sessionID: "ses_1", agent: "build", messageID: "msg_0", id: `call_${++call}`, tool: "shell", input: { command } })
      } catch (error) {
        if (/Blocked/.test(String(error))) return "deny"
        throw error
      }
      return fake.asserts.length > before ? "ask" : "allow"
    },
  }
}

const off = (rule: string) => ({ ruleOverrides: { [rule]: "off" } })

describe("lot 48 review R2: guard.json removed while the plugin runs", () => {
  it("RL2-1: a global guard.json read at startup, then removed: its relaxation no longer applies", async () => {
    const plugin = await guard({ globalGuard: off("git-reset-hard") })
    assert.equal(await plugin.verdict("git reset --hard"), "allow")
    rmSync(join(plugin.globalDir, "guard.json"))
    plugin.tick()
    assert.equal(await plugin.verdict("git reset --hard"), "ask")
  })
})

describe("lot 48 review R2: guard last", () => {
  it("RL2-2: no C1 control character of a logged reason reaches the terminal", async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-rl2-")))
    const [globalDir, systemDir, home, data] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data")]
    for (const dir of [globalDir, systemDir, home, join(data, "opencode", "log")]) mkdirSync(dir, { recursive: true })
    // A reason quoting a path chosen by the agent: the logger removes C0 controls only.
    writeFileSync(join(data, "opencode", "log", "guard.log"), "2026-10-28T10:00:02.000Z INFO shell → ask (local, rule protected-write): writing to /tmp/a\u009b2Jb\n")
    const { main } = (await import(new URL("../src/cli/main.ts", import.meta.url).href)) as { main: (argv: readonly string[], io: unknown) => number }
    const out: string[] = []
    const code = main(["last"], { env: { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }, cwd: root, systemDir, out: (line: string) => out.push(line), err: () => {} })
    assert.equal(code, 0)
    assert.match(out.join("\n"), /protected-write/)
    assert.doesNotMatch(out.join("\n"), /[\u0080-\u009f]/)
  })
})

describe("lot 48 review R2: guard show", () => {
  it("RL2-3: a secret written by mistake as a policy value is not printed in clear (the plugin's log masks it)", async () => {
    const plugin = await guard({ globalGuard: { localAsks: FAKE.anthropic, ruleOverrides: { eval: FAKE.github } } })
    assert.match(plugin.log(), /invalid value for localAsks/)
    assert.ok(!plugin.log().includes(FAKE.anthropic) && !plugin.log().includes(FAKE.github))
    const { main } = (await import(new URL("../src/cli/main.ts", import.meta.url).href)) as { main: (argv: readonly string[], io: unknown) => number }
    const out: string[] = []
    const io = { env: { HOME: dirname(plugin.globalDir), OPENCODE_CONFIG_DIR: plugin.globalDir }, cwd: plugin.project, systemDir: join(dirname(plugin.globalDir), "system") }
    const code = main(["show"], { ...io, out: (line: string) => out.push(line), err: (line: string) => out.push(line) })
    assert.equal(code, 0)
    assert.match(out.join("\n"), /invalid value for localAsks/)
    assert.ok(!out.join("\n").includes(FAKE.anthropic), "localAsks value printed in clear")
    assert.ok(!out.join("\n").includes(FAKE.github), "ruleOverrides value printed in clear")
  })
})
