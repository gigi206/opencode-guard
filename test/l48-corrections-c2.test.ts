// Lot 48, fixes of the targeted verification of step C. An exception (or the memory) for one credential file must never
// lift a command that may read another file: the part that names the file is, like every other part, a program of the
// closed list of readers (`diff` left out); a home-relative word never gives a target (the `HOME` of a command is the
// session's, which the plugin does not see). Fake files and a fake home given to the plugin only, nothing launched.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { after, describe, it } from "node:test"
import { createCredentialContent } from "../src/credential-content.ts"
import { setupGuard } from "../src/index.ts"
import { createRealPath } from "../src/real-path.ts"
import { shellFinding } from "../src/rules/shell.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>
const RULE = "secret-file-read"

const roots: string[] = []
after(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true })
})

/**
 * `<root>/work/app/.env` (the excepted file), `<root>/secrets/.env` (another one), the link `work/cur` to `app` (a path
 * a command could replace), and a fake home with its `.netrc` (`<root>/secrets/.netrc`: another one).
 */
function files() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-crd-")))
  roots.push(root)
  const app = join(root, "work", "app")
  const secrets = join(root, "secrets")
  const home = join(root, "home")
  for (const dir of [app, secrets, home]) mkdirSync(dir, { recursive: true })
  const env = join(app, ".env")
  for (const file of [env, join(secrets, ".env")]) writeFileSync(file, "NAME=dummy\n")
  for (const dir of [home, secrets]) writeFileSync(join(dir, ".netrc"), "machine example.invalid\n")
  const cur = join(root, "work", "cur")
  symlinkSync(app, cur)
  return { root, app, secrets, home, env, cur, netrc: join(home, ".netrc") }
}

/** Rule context of a shell command run in `dir`, with the resolvers of a call and one exception. */
function context(dir: string, home: string, excepted: string) {
  return {
    redactor: createRedactor(),
    home,
    cwd: dir,
    cwds: [dir],
    credentialContent: createCredentialContent({ directories: [dir], home }),
    realPaths: createRealPath({ directories: [dir] }),
    active: { dangerousCommands: true, sensitiveFiles: true, exceptions: new Map([[RULE, new Set([excepted])]]) },
  } as Parameters<typeof shellFinding>[1]
}

/** Plugin set up as OpenCode does (session directory `<root>/work/app`, home `<root>/home`), global options = effective. */
async function guard(options: Json, fs: ReturnType<typeof files>) {
  const { root, app, home } = fs
  const [globalDir, systemDir] = [join(root, "global"), join(root, "system")]
  for (const dir of [globalDir, systemDir, join(app, ".opencode")]) mkdirSync(dir, { recursive: true })
  writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options }] }))
  const fake = fakeContext({ logFile: join(root, "guard.log"), ...options })
  ;(fake.ctx.location as { directory: string }).directory = app
  fake.agents.set("plan", { mode: "primary", permissions: [] })
  await (setupGuard as (...args: unknown[]) => Promise<void>)(fake.ctx, {}, systemDir, globalDir, { now: () => 1_000_000, intervalMs: 2000 }, home)
  let call = 0
  /** Verdict of a tool call in `execute.before`: deny, ask (a confirmation was requested) or allow. */
  const verdict = async (tool: string, input: Json, id = `call_${++call}`) => {
    const before = fake.asserts.length
    try {
      await fake.trigger("tool.execute.before", { sessionID: "ses_1", agent: "build", messageID: "msg_0", id, tool, input })
    } catch (error) {
      if (/Blocked/.test(String(error))) return "deny"
      throw error
    }
    return fake.asserts.length > before ? "ask" : "allow"
  }
  /** Effect left by `permission.evaluate` on the shell sub-commands of the call `id`. */
  const evaluate = async (commands: string[], id: string) => {
    const event = { sessionID: "ses_1", agent: "build", action: "shell", resources: commands, effect: "allow", message: undefined, source: { type: "tool", messageID: "msg_0", id } }
    await fake.trigger("permission.evaluate", event)
    return event.effect
  }
  return {
    shell: (command: string) => verdict("shell", { command }),
    read: (path: string) => verdict("read", { path }),
    /** `permission.evaluate` of a call `execute.before` did not see. */
    evaluate: (commands: string[]) => evaluate(commands, `other_${++call}`),
    /** The same call seen by `execute.before`, then by `permission.evaluate`. */
    seen: async (command: string) => {
      const id = `call_${++call}`
      return [await verdict("shell", { command }, id), await evaluate([command], id)]
    },
  }
}

describe("fixes of the targeted verification: the part that names the excepted file is a reader of the closed list", () => {
  it("CRD-1: its program launches a script that replaces a link on the path, then reads it: the ask stays", () => {
    const fs = files()
    const ctx = context(fs.app, fs.home, fs.env)
    const read = `${fs.cur}/.env`
    // Witness: the excepted file, read through the link, is lifted.
    assert.equal(shellFinding(`cat ${read}`, ctx), undefined)
    const script = `'ln -sfn ${fs.secrets} ${fs.cur}; cat "$0"'`
    const commands = [
      `taskset -c 0 sh -c ${script} ${read}`,
      `setpriv sh -c ${script} ${read}`,
      `prlimit sh -c ${script} ${read}`,
      `busybox sh -c ${script} ${read}`,
      `fakeroot sh -c ${script} ${read}`,
      `repeat 1 sh -c ${script} ${read}`,
      `rbash -c ${script} ${read}`,
      `sqlite3 ${read} '.shell ln -sfn ${fs.secrets} ${fs.cur}'`,
    ]
    const lifted = commands.filter((command) => shellFinding(command, ctx) === undefined).map((command) => command.split(" ")[0])
    assert.deepEqual(lifted, [])
  })

  it("CRD-2: the same through the plugin: execute.before, permission.evaluate and the memory of confirmations", async () => {
    const fs = files()
    const read = `${fs.cur}/.env`
    const command = `taskset -c 0 sh -c 'ln -sfn ${fs.secrets} ${fs.cur}; cat "$0"' ${read}`
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    // Witness: the excepted file is lifted.
    assert.equal(await plugin.shell(`cat ${read}`), "allow")
    const memory = await guard({ rememberConfirmations: 10 }, fs)
    assert.equal(await memory.shell(`cat ${read}`), "ask")
    assert.deepEqual([await plugin.shell(command), await plugin.evaluate([command]), await memory.shell(command)], ["ask", "ask", "ask"])
  })

  it("CRD-4: a program outside the list, even one that launches nothing, names the excepted file: the ask stays", () => {
    const fs = files()
    const ctx = context(fs.app, fs.home, fs.env)
    const programs = ["strings", "jq .", "xxd", "hexdump -C", "file"]
    const lifted = programs.filter((program) => shellFinding(`${program} ${fs.env}`, ctx) === undefined)
    assert.deepEqual(lifted, [])
  })

  it("CRD-5: permission.evaluate: a sibling reads the excepted file with a program outside the list: the ask stays", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    assert.equal(await plugin.evaluate([`cat ${fs.env}`, `strings ${fs.env}`]), "ask")
  })

  it("CRD-6: the memory of confirmations: the remembered file read by a program outside the list: the ask stays", async () => {
    const fs = files()
    const memory = await guard({ rememberConfirmations: 10 }, fs)
    assert.equal(await memory.shell(`cat ${fs.env}`), "ask")
    assert.equal(await memory.shell(`strings ${fs.env}`), "ask")
  })

  it("CRD-7: `diff` is out of the list: it names the excepted file: the ask stays", async () => {
    const fs = files()
    const ctx = context(fs.app, fs.home, fs.env)
    assert.equal(shellFinding(`diff ${fs.env} /dev/null`, ctx)?.rule, RULE)
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    assert.equal(await plugin.shell(`diff ${fs.env} /dev/null`), "ask")
  })

  it("CRD-8: `diff` is out of the list: in another part or in a sibling: the ask stays", async () => {
    const fs = files()
    const ctx = context(fs.app, fs.home, fs.env)
    assert.equal(shellFinding(`cat ${fs.env} | diff - /dev/null`, ctx)?.rule, RULE)
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    assert.equal(await plugin.evaluate([`cat ${fs.env}`, "diff - /dev/null"]), "ask")
  })

  it("CRD-9: read by readers of the list: lifted by the exception and the memory (witness)", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [fs.env, fs.netrc] } }, fs)
    for (const command of [`head -1 ${fs.cur}/.env`, `cat ${fs.env} | wc -l`, `grep -c NAME ${fs.env} && echo found`, `tail -1 ${fs.netrc}`])
      assert.equal(await plugin.shell(command), "allow", command)
    assert.equal(await plugin.read(fs.env), "allow")
    assert.equal(await plugin.evaluate([`cat ${fs.env}`, `head -1 ${fs.env}`]), "allow")
    const memory = await guard({ rememberConfirmations: 10 }, fs)
    assert.equal(await memory.shell(`cat ${fs.cur}/.env`), "ask")
    assert.equal(await memory.shell(`head -1 ${fs.env}`), "allow")
    assert.equal(await memory.read(fs.env), "allow")
  })

  it("CRD-9b: the same files named home-relative (the plugin's home): never lifted by the exception or the memory", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [fs.env, fs.netrc] } }, fs)
    assert.equal(await plugin.shell("tail -1 ~/.netrc"), "ask")
    assert.equal(await plugin.read("~/.netrc"), "ask")
    const memory = await guard({ rememberConfirmations: 10 }, fs)
    assert.equal(await memory.shell("tail -1 ~/.netrc"), "ask")
    assert.equal(await memory.shell("tail -1 ~/.netrc"), "ask")
    assert.equal(await memory.read("~/.netrc"), "ask")
    assert.equal(await memory.read("~/.netrc"), "ask")
  })
})

describe("fixes of the targeted verification: permission.evaluate of a call execute.before did not see", () => {
  it("CRD-3: a home-relative target: `HOME` may have changed in a statement OpenCode does not hand over: the ask stays", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [fs.env, fs.netrc] } }, fs)
    // Witnesses: the whole command seen by execute.before asks; an absolute target is lifted in permission.evaluate.
    assert.equal(await plugin.shell(`export HOME=${fs.secrets}; cat ~/.netrc`), "ask")
    assert.equal(await plugin.evaluate([`cat ${fs.env}`]), "allow")
    // OpenCode hands over the simple commands only: neither a declaration, nor an assignment alone, nor a loop variable.
    assert.equal(await plugin.evaluate(["cat ~/.netrc"]), "ask")
  })

  it("CRD-10: the same with the memory of confirmations: the remembered file by its absolute path is lifted (witness)", async () => {
    const fs = files()
    const memory = await guard({ rememberConfirmations: 10 }, fs)
    assert.equal(await memory.shell(`cat ${fs.netrc}`), "ask")
    assert.equal(await memory.shell(`cat ${fs.netrc}`), "allow")
  })

  it("CRD-10b: the same file named home-relative is never remembered: the ask stays, in permission.evaluate too", async () => {
    const fs = files()
    const memory = await guard({ rememberConfirmations: 10 }, fs)
    assert.equal(await memory.shell("cat ~/.netrc"), "ask")
    assert.equal(await memory.shell("cat ~/.netrc"), "ask")
    assert.equal(await memory.evaluate(["cat ~/.netrc"]), "ask")
  })

  it("CRD-11: the same target by its absolute path in a call execute.before saw: lifted there and in permission.evaluate (witness)", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [fs.netrc] } }, fs)
    assert.deepEqual(await plugin.seen(`cat ${fs.netrc}`), ["allow", "allow"])
  })

  it("CRD-11b: the same file named home-relative in a call execute.before saw: asked there, never lifted", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [fs.netrc] } }, fs)
    // permission.evaluate does not ask again for the call the user has just confirmed.
    assert.deepEqual(await plugin.seen("cat ~/.netrc"), ["ask", "allow"])
  })
})
