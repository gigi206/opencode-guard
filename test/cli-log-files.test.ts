// `guard last` and `guard status` on a log that is not what it should be: previous copy held to the checks of the log,
// `status` reporting what `last` refuses. Fake logs and settings in throwaway directories; the command runs in process.
import "./tmp.ts"
import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { after, describe, it } from "node:test"
import { fileURLToPath } from "node:url"
import { main } from "../src/cli/main.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
const base = realpathSync(mkdtempSync(join(tmpdir(), "guard-logs-")))
after(() => rmSync(base, { recursive: true, force: true }))

const entry = (reason: string) => `2026-11-04T10:00:00.000Z INFO shell → ask (local, rule test): ${reason}\n`

function world(options: Record<string, unknown> = {}) {
  const root = mkdtempSync(join(base, "w-"))
  const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "app")]
  for (const dir of [globalDir, systemDir, home, project, join(data, "opencode", "log")]) mkdirSync(dir, { recursive: true })
  writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options }] }))
  const env: Record<string, string | undefined> = { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data, TZ: "UTC" }
  const run = async (args: string[], environment = env) => {
    const [out, err]: string[][] = [[], []]
    const code = await main(args, { env: environment, cwd: project, systemDir, out: (line) => out!.push(line), err: (line) => err!.push(line) })
    return { code, out: out!.join("\n"), err: err!.join("\n") }
  }
  const decoy = join(root, "decoy")
  writeFileSync(decoy, entry("decoy reason"))
  return { root, log: join(data, "opencode", "log", "guard.log"), decoy, run, env, globalDir }
}

describe("guard last: the previous copy of the log", () => {
  it("LF-1: a link is not followed", async () => {
    const w = world()
    writeFileSync(w.log, entry("current"))
    symlinkSync(w.decoy, `${w.log}.1`)
    assert.doesNotMatch((await w.run(["last"])).out, /decoy reason/)
  })
  it("LF-2: a link is not followed from a logFile either", async () => {
    const custom = join(mkdtempSync(join(base, "logs-")), "my.log")
    const w = world({ logFile: custom })
    writeFileSync(custom, entry("current"))
    symlinkSync(w.decoy, `${custom}.1`)
    assert.doesNotMatch((await w.run(["last"])).out, /decoy reason/)
  })
  it("LF-3: a FIFO fails nothing and blocks nothing", async () => {
    const w = world()
    writeFileSync(w.log, entry("current"))
    execFileSync("mkfifo", [`${w.log}.1`])
    assert.equal((await w.run(["last"])).code, 0)
  })
  it("LF-4: with a FIFO, the current file is still shown", async () => {
    const w = world()
    writeFileSync(w.log, entry("current"))
    execFileSync("mkfifo", [`${w.log}.1`])
    assert.match((await w.run(["last"])).out, /shell: current/)
  })
  it("LF-5: a directory fails nothing", async () => {
    const w = world()
    writeFileSync(w.log, entry("current"))
    mkdirSync(`${w.log}.1`)
    assert.equal((await w.run(["last"])).code, 0)
  })
  it("witness: LF-6: a regular copy is read, before the current file", async () => {
    const w = world()
    writeFileSync(w.log, entry("current"))
    writeFileSync(`${w.log}.1`, entry("older"))
    assert.match((await w.run(["last"])).out, /shell: older\n.*shell: current/)
  })
  it("witness: LF-7: the copy of a logFile is read too", async () => {
    const custom = join(mkdtempSync(join(base, "logs-")), "my.log")
    const w = world({ logFile: custom })
    writeFileSync(custom, entry("current"))
    writeFileSync(`${custom}.1`, entry("older"))
    assert.match((await w.run(["last"])).out, /shell: older/)
  })
  it("witness: LF-8: under a data directory reached through a link, the copy of the default log is read, as the log is", async () => {
    const w = world()
    writeFileSync(w.log, entry("current"))
    writeFileSync(`${w.log}.1`, entry("older"))
    const link = join(w.root, "linked-data")
    symlinkSync(w.env.XDG_DATA_HOME!, link)
    assert.match((await w.run(["last"], { ...w.env, XDG_DATA_HOME: link })).out, /shell: older/)
  })
  it("witness: LF-9: a refused copy does not bring back the current file twice", async () => {
    const custom = join(mkdtempSync(join(base, "logs-")), "my.log")
    const w = world({ logFile: custom })
    writeFileSync(custom, entry("current"))
    symlinkSync(w.decoy, `${custom}.1`)
    assert.equal((await w.run(["last"])).out.match(/shell: current/g)?.length, 1)
  })
})

describe("guard last: the current log", () => {
  it("LF-10: a link is not followed: refused, as the plugin refuses to write through it", async () => {
    const w = world()
    symlinkSync(w.decoy, w.log)
    assert.equal((await w.run(["last"])).code, 1)
  })
  it("witness: LF-11: not a regular file: still an error", async () => {
    const w = world()
    mkdirSync(w.log)
    assert.equal((await w.run(["last"])).code, 1)
  })
  it("witness: LF-12: no HOME and no XDG_DATA_HOME: still an error", async () => {
    const w = world()
    assert.equal((await w.run(["last"], { OPENCODE_CONFIG_DIR: w.env.OPENCODE_CONFIG_DIR, TZ: "UTC" })).code, 1)
  })
})

describe("guard status: exit code 0 whatever the state", () => {
  const unknown = { OPENCODE_CONFIG_DIR: undefined as string | undefined, TZ: "UTC" }
  it("LF-13: log file unknown: code 0", async () => {
    const w = world()
    assert.equal((await w.run(["status", "--offline"], { ...unknown, OPENCODE_CONFIG_DIR: w.globalDir })).code, 0)
  })
  it("LF-14: log file unknown: an unknown state, with the reason", async () => {
    const w = world()
    assert.match((await w.run(["status", "--offline"], { ...unknown, OPENCODE_CONFIG_DIR: w.globalDir })).out, /^log: state unknown: the plugin's log file is unknown/m)
  })
  it("LF-15: log file unknown, model asked: code 0", async () => {
    const w = world()
    assert.equal((await w.run(["status"], { ...unknown, OPENCODE_CONFIG_DIR: w.globalDir })).code, 0)
  })
  it("LF-16: not a regular file: code 0", async () => {
    const w = world()
    mkdirSync(w.log)
    assert.equal((await w.run(["status", "--offline"])).code, 0)
  })
  it("LF-17: not a regular file: an unknown state, then the model's row", async () => {
    const w = world()
    mkdirSync(w.log)
    assert.match((await w.run(["status", "--offline"])).out, /^log: state unknown: .*is not a regular file\nmodel: not asked/m)
  })
  it("LF-18: a link: an unknown state", async () => {
    const w = world()
    symlinkSync(w.decoy, w.log)
    assert.match((await w.run(["status", "--offline"])).out, /^log: state unknown: /m)
  })
  it("LF-19: unreadable: code 0", { skip: process.getuid?.() === 0 }, async () => {
    const w = world()
    writeFileSync(w.log, entry("current"))
    chmodSync(w.log, 0)
    assert.equal((await w.run(["status", "--offline"])).code, 0)
  })
  it("witness: LF-20: a usage error stays a usage error", async () => {
    assert.equal((await world().run(["status", "--now"])).code, 2)
  })
})
