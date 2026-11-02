// Lot 48 step C: targets of `secret-file-read` restricted. A word without `/` (a name alone) never gives a target: a
// program may look that name up elsewhere (a pattern searched in a tree, another directory), so no exception and no
// memory apply to its finding, for the shell as for the tools. A target, and an exception of the configuration, must be a
// regular file once its links are resolved. Fake credential files are created in the test's temporary directory;
// nothing is launched, text is judged. Only existing exports are imported.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { setupGuard } from "../src/index.ts"
import { createRealPath } from "../src/real-path.ts"
import { shellFinding } from "../src/rules/shell.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"
import { FAKE } from "./fixtures.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>
const RULE = "secret-file-read"

/** A fake credential file in the session directory, and a directory whose name the rule knows. */
function files() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-exn-")))
  const app = join(root, "work", "app")
  const keys = join(root, "secrets", "keys.pem")
  for (const dir of [app, keys]) mkdirSync(dir, { recursive: true })
  const env = join(app, ".env")
  writeFileSync(env, `API_KEY=${FAKE.openai}\n`)
  return { root, app, keys, env }
}

/** Plugin set up as OpenCode does, session directory `<root>/work/app`, with a global guard.json. */
async function guard(globalGuard: Json, fs = files()) {
  const [globalDir, systemDir] = [join(fs.root, "global"), join(fs.root, "system")]
  for (const dir of [globalDir, systemDir]) mkdirSync(dir, { recursive: true })
  writeFileSync(join(globalDir, "guard.json"), JSON.stringify(globalGuard))
  const logFile = join(fs.root, "guard.log")
  const fake = fakeContext({ logFile })
  ;(fake.ctx.location as { directory: string }).directory = fs.app
  await (setupGuard as (...args: unknown[]) => Promise<void>)(fake.ctx, {}, systemDir, globalDir, { now: () => 1_000_000, intervalMs: 2000 })
  let call = 0
  const verdict = async (tool: string, input: Json) => {
    const before = fake.asserts.length
    await fake.trigger("tool.execute.before", { sessionID: "ses_1", agent: "build", messageID: "msg_0", id: `call_${++call}`, tool, input })
    return fake.asserts.length > before ? "ask" : "allow"
  }
  return {
    log: () => readFileSync(logFile, "utf8"),
    shell: (command: string) => verdict("shell", { command }),
    read: (path: string) => verdict("read", { path }),
    grep: (path: string) => verdict("grep", { pattern: "KEY", path }),
    lastAsk: () => {
      const metadata = (fake.asserts.at(-1)?.metadata ?? {}) as Json
      return `${String(metadata.rule)}: ${String(metadata.reason)}`
    },
  }
}

/** Rule context of a shell command run in `dir` (proven directory), an exception configured (the targets are computed). */
const context = (dir: string, excepted: string) =>
  ({
    redactor: createRedactor(),
    home: "/home/test",
    cwd: dir,
    cwds: [dir],
    realPaths: createRealPath({ directories: [dir] }),
    active: { dangerousCommands: true, sensitiveFiles: true, exceptions: new Map([[RULE, new Set([excepted])]]) },
  }) as Parameters<typeof shellFinding>[1]
const targetsOf = (finding: unknown) => (finding as { targets?: readonly string[] } | undefined)?.targets

describe("lot 48 step C: a name alone never gives a target", () => {
  it("EXN-1: a name alone excepted in the current directory still asks in the shell; the reason is unchanged", async () => {
    const fs = files()
    assert.equal(targetsOf(shellFinding("cat .env", context(fs.app, "/nowhere/other"))), undefined)
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    assert.equal(await plugin.shell("cat .env"), "ask")
    assert.equal(plugin.lastAsk(), `${RULE}: access to a credential file (.env)`)
  })

  it("EXN-6: a name alone excepted in the current directory still asks for the read and grep tools", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    assert.equal(await plugin.read(".env"), "ask")
    assert.equal(await plugin.grep(".env"), "ask")
  })

  it("EXN-2: the same file written with ./ or absolute is lifted (control)", async () => {
    const fs = files()
    assert.deepEqual(targetsOf(shellFinding(`cat ${fs.app}/./.env`, context(fs.app, "/nowhere/other"))), [fs.env])
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    assert.equal(await plugin.shell(`cat ${fs.app}/./.env`), "allow")
    assert.equal(await plugin.shell(`cat ${fs.env}`), "allow")
    assert.equal(await plugin.read(`${fs.app}/./.env`), "allow")
    // A relative path never gives a target.
    assert.equal(targetsOf(shellFinding("cat ./.env", context(fs.app, "/nowhere/other"))), undefined)
    assert.equal(await plugin.shell("cat ./.env"), "ask")
    assert.equal(await plugin.read("./.env"), "ask")
  })

  it("EXN-3: a search by name in a tree still asks", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    assert.equal(await plugin.shell("find . -name .env"), "ask")
    assert.equal(await plugin.shell("grep -r --include .env KEY ."), "ask")
    // A name alone next to a path: the whole finding is unfinished.
    assert.equal(await plugin.shell(`cat ./.env; find / -name .env`), "ask")
  })
})

describe("lot 48 step C: a target is a regular file", () => {
  it("EXN-4: a directory is never a target; reading one excepted still asks", async () => {
    const fs = files()
    const finding = shellFinding(`cat ${fs.keys}`, context(fs.app, "/nowhere/other"))
    assert.equal(finding?.rule, RULE)
    assert.equal(targetsOf(finding), undefined)
    const plugin = await guard({ exceptions: { [RULE]: [fs.keys] } }, fs)
    assert.equal(await plugin.shell(`cat ${fs.keys}`), "ask")
    assert.equal(await plugin.read(fs.keys), "ask")
  })

  it("EXN-7: an exception on a directory is ignored with a warning naming it", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [fs.keys] } }, fs)
    assert.match(plugin.log(), new RegExp(`WARN global guard\\.json: exceptions\\.${RULE}\\[0\\] ignored: "${fs.keys}" is not a regular file`))
  })

  it("EXN-5: memory: a name alone or a directory confirmed is not remembered; the same file with ./ is (control)", async () => {
    const fs = files()
    const plugin = await guard({ rememberConfirmations: 10 }, fs)
    assert.equal(await plugin.shell("cat .env"), "ask")
    assert.equal(await plugin.shell("cat .env"), "ask")
    assert.equal(await plugin.read(".env"), "ask")
    assert.equal(await plugin.read(".env"), "ask")
    assert.equal(await plugin.shell(`cat ${fs.keys}`), "ask")
    assert.equal(await plugin.shell(`cat ${fs.keys}`), "ask")
    assert.equal(await plugin.shell(`cat ${fs.env}`), "ask")
    assert.equal(await plugin.shell(`cat ${fs.env}`), "allow")
    // A relative path never gives a target.
    assert.equal(await plugin.shell("cat ./.env"), "ask")
    assert.equal(await plugin.shell("cat ./.env"), "ask")
  })
})
