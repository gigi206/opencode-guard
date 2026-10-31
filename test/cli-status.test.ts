// `guard status`: starts and errors read from the plugin's log, plugin files changed after the latest start, the decision
// model answering. Fake log and settings in throwaway directories, a fake model client: nothing leaves.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, realpathSync, utimesSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { main } from "../src/cli/main.ts"
import { logState, pluginFilesChanged, probeModel } from "../src/cli/status.ts"
import { ModelError } from "../src/model/client.ts"
import { FAKE } from "./fixtures.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))

const LOG = [
  "2026-10-31T10:00:00.000Z WARN output check active: tool outputs, redacted, are sent to the decision model",
  "2026-10-31T10:00:00.001Z INFO active (decision model: nox-4b via https://x.example.test/v1 (chat); confirmations: ask)",
  "2026-10-31T10:05:00.000Z ERROR internal error in output check",
  "2026-10-31T11:00:00.000Z WARN prompt check active: typed prompts, redacted, are sent to the decision model",
  "2026-10-31T11:00:00.002Z INFO active (decision model: nox-4b via https://x.example.test/v1 (chat); confirmations: ask; output check: UNAVAILABLE)",
  "2026-10-31T11:00:01.500Z INFO shell → ask (local, rule rm): file deletion",
  "2026-10-31T11:02:00.000Z WARN output check unavailable (model timeout): each output is held for a confirmation until it answers again",
  "2026-10-31T11:03:00.000Z ERROR internal error in tool.execute.after",
  "not a log line",
]

function world(options: Record<string, unknown> = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-st-")))
  const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "app")]
  for (const dir of [globalDir, systemDir, home, data, project, join(data, "opencode", "log")]) mkdirSync(dir, { recursive: true })
  writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options }] }))
  const env = { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data, TZ: "UTC", TEST_KEY: "test-key-value" }
  const log = join(data, "opencode", "log", "guard.log")
  const io = (out: string[] = [], err: string[] = []) => ({ env, cwd: project, systemDir, out: (line: string) => out.push(line), err: (line: string) => err.push(line) })
  const run = async (args: string[]) => {
    const out: string[] = []
    const err: string[] = []
    const code = await main(args, io(out, err))
    return { code, out, err }
  }
  return { root, log, io, run }
}

describe("guard status", () => {
  it("ST-1: the latest starts, newest last; errors and warnings after the latest one, a start's own warnings left out", () => {
    const state = logState(LOG)
    assert.deepEqual(state.starts.map((start) => start.time), ["2026-10-31T10:00:00.001Z", "2026-10-31T11:00:00.002Z"])
    assert.match(state.starts[1]!.details, /output check: UNAVAILABLE$/)
    assert.deepEqual([state.errors, state.warnings], [1, 1])
    assert.deepEqual(state.messages.map((entry) => entry.level), ["WARN", "ERROR"])
    assert.deepEqual(logState(["2026-10-31T11:03:00.000Z ERROR x"]).starts, [])
  })
  it("ST-2: files changed after the start: index.ts and src/ count, the command line's src/cli/ does not", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "guard-st-plugin-")))
    mkdirSync(join(dir, "src", "cli"), { recursive: true })
    for (const file of ["index.ts", "src/config.ts", "src/cli/main.ts"]) writeFileSync(join(dir, file), "")
    const old = new Date("2026-10-01T00:00:00Z")
    for (const file of ["index.ts", "src/config.ts"]) utimesSync(join(dir, file), old, old)
    utimesSync(join(dir, "src/cli/main.ts"), new Date(), new Date())
    assert.equal(pluginFilesChanged(dir), old.getTime())
    utimesSync(join(dir, "src/config.ts"), new Date(), new Date())
    assert.ok(pluginFilesChanged(dir) > old.getTime())
  })
  it("ST-3: the model probe: its duration, or the class of its failure only (never the message a gateway may fill)", async () => {
    const w = world({ decision: { baseURL: "https://decision.example.test/v1", model: "nox-4b", apiKey: "{env:TEST_KEY}" } })
    const answered = await probeModel(w.io(), async () => ({ answers: {} }))
    assert.ok(answered.configured && answered.ms !== undefined && !answered.failure)
    const late = await probeModel(w.io(), async () => {
      throw new ModelError("timed out after 5000 ms", { timeout: true })
    })
    assert.deepEqual(late.configured && late.failure, "timeout")
    const refused = await probeModel(w.io(), async () => {
      throw new ModelError(`HTTP 401: key ${FAKE.openai} refused`)
    })
    assert.deepEqual(refused.configured && refused.failure, "HTTP 401")
    assert.deepEqual(await probeModel(world().io()), { configured: false })
  })
  it("ST-4: the command: plain lines from the log, --offline asks nothing, other arguments are usage errors", async () => {
    const w = world()
    writeFileSync(w.log, LOG.join("\n"))
    const r = await w.run(["status", "--offline"])
    assert.equal(r.code, 0)
    assert.ok(r.out.some((line) => /^start: 2026-10-31 11:00:00 \+00:00 {2}decision model: nox-4b/.test(line)), r.out.join("\n"))
    assert.ok(r.out.includes("since: 1 error(s), 1 warning(s) after the latest start (from any OpenCode instance writing this log)"))
    assert.ok(r.out.includes("model: not asked (--offline)"))
    assert.equal((await w.run(["status", "--now"])).code, 2)
    const empty = world()
    assert.ok((await empty.run(["status", "--offline"])).out.some((line) => line.startsWith("log: No log file yet")))
  })
})
