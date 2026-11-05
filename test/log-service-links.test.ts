// Symbolic links around the log file and OpenCode's service files, in temporary directories: a configured log that
// falls back to the default one, and a service file that keeps its masking through a link and says so.
import "./tmp.ts"
import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, it } from "node:test"
import { checkedLogFile, setupGuard } from "../src/index.ts"
import { serviceSecretSource } from "../src/secrets/opencode-service.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

const PASSWORD = "fake-service-password-0123"
const temp = () => realpathSync(mkdtempSync(join(tmpdir(), "guard-links-")))
function check(file: string, fallback: string) {
  const warnings: string[] = []
  return { file: checkedLogFile(file, fallback, undefined, [], warnings, "/"), warnings }
}

describe("logFile", () => {
  it("LS-1: a linked parent falls back to the default log, with a warning", () => {
    const root = temp()
    mkdirSync(join(root, "real"))
    symlinkSync(join(root, "real"), join(root, "link"))
    const fallback = join(root, "default.log")
    for (const file of [join(root, "link", "guard.log"), join(root, "link", "new", "dir", "guard.log")]) {
      const seen = check(file, fallback)
      assert.equal(seen.file, fallback)
      assert.deepEqual(seen.warnings, ["logFile refused (its path goes through a symbolic link): logging to the default log file"])
    }
  })
  it("LS-2: a dangling link in the path is refused", () => {
    const root = temp()
    symlinkSync(join(root, "absent"), join(root, "link"))
    assert.equal(check(join(root, "link", "guard.log"), join(root, "default.log")).file, join(root, "default.log"))
  })
  it("LS-3: a final link, a directory and a named pipe are refused", () => {
    const root = temp()
    const fallback = join(root, "default.log")
    writeFileSync(join(root, "target"), "")
    symlinkSync(join(root, "target"), join(root, "final.log"))
    mkdirSync(join(root, "dir.log"))
    execFileSync("mkfifo", [join(root, "pipe.log")])
    assert.match(check(join(root, "final.log"), fallback).warnings.join(), /it is a symbolic link/)
    assert.match(check(join(root, "dir.log"), fallback).warnings.join(), /it is not a regular file/)
    assert.equal(check(join(root, "pipe.log"), fallback).file, fallback)
  })
  it("LS-4: the plugin keeps logging, in the default log, and writes nothing through the link", async () => {
    const root = temp()
    const [target, data] = [join(root, "target"), join(root, "data")]
    mkdirSync(target)
    symlinkSync(target, join(root, "link"))
    const fake = fakeContext({ logFile: join(root, "link", "guard.log") })
    await setupGuard(fake.ctx, { XDG_DATA_HOME: data, HOME: root })
    assert.equal(existsSync(join(target, "guard.log")), false)
    assert.match(readFileSync(join(data, "opencode", "log", "guard.log"), "utf8"), /WARN logFile refused \(its path goes through a symbolic link\)/)
  })
  it("witness: LS-5: a plain path, existing or not, and the default path are kept", () => {
    const root = temp()
    writeFileSync(join(root, "old.log"), "")
    for (const file of [join(root, "old.log"), join(root, "new", "guard.log")]) assert.deepEqual(check(file, join(root, "default.log")), { file, warnings: [] })
    symlinkSync(root, join(root, "link"))
    const fallback = join(root, "link", "default.log")
    assert.deepEqual(check(fallback, fallback), { file: fallback, warnings: [] })
  })
})

describe("service files", () => {
  const setup = () => {
    const root = temp()
    const outside = join(root, "outside.json")
    const dir = join(root, "opencode")
    mkdirSync(dir)
    writeFileSync(outside, JSON.stringify({ password: PASSWORD }))
    return { outside, dir, file: join(dir, "service.json") }
  }
  it("LS-6: a link does not lose the masking: read through it, and said once, without the value", async () => {
    const { outside, dir, file } = setup()
    symlinkSync(outside, file)
    const lines: string[] = []
    const source = serviceSecretSource([dir], (line) => lines.push(line))
    assert.deepEqual(source().map((item) => item.value), [PASSWORD])
    await Promise.resolve()
    source()
    assert.deepEqual(lines, [`service file ${file} is a symbolic link: read through it, its password and remote route stay redacted`])
  })
  it("LS-6b: a link that cannot give its values says they stay in clear, without blocking", () => {
    const { dir, file } = setup()
    symlinkSync(join(dir, "absent"), file)
    execFileSync("mkfifo", [join(dir, "pipe")])
    symlinkSync(join(dir, "pipe"), join(dir, "service-beta.json"))
    const lines: string[] = []
    assert.deepEqual(serviceSecretSource([dir], (line) => lines.push(line))(), [])
    assert.equal(lines.length, 2)
    assert.ok(lines.every((line) => /not read \(it is a symbolic link .*\): its password and remote route are NOT redacted/.test(line)))
  })
  it("LS-7: a named pipe and a directory are reported, without blocking", () => {
    const { dir, file } = setup()
    execFileSync("mkfifo", [file])
    mkdirSync(join(dir, "service-beta.json"))
    const lines: string[] = []
    serviceSecretSource([dir], (line) => lines.push(line))()
    assert.equal(lines.length, 2)
    assert.ok(lines.every((line) => line.includes("it is not a regular file")))
  })
  it("LS-8: a value seen before stays masked when the file becomes a dangling link", async () => {
    const { outside, dir, file } = setup()
    writeFileSync(file, JSON.stringify({ password: PASSWORD }))
    const lines: string[] = []
    const redactor = createRedactor({ runtimeSecrets: serviceSecretSource([dir], (line) => lines.push(line)) })
    assert.ok(!redactor.redactString(`x ${PASSWORD} y`).value.includes(PASSWORD))
    await Promise.resolve()
    unlinkSync(file)
    symlinkSync(`${outside}.absent`, file)
    assert.ok(!redactor.redactString(`x ${PASSWORD} y`).value.includes(PASSWORD))
    assert.equal(lines.length, 1)
  })
  it("LS-9: back to a regular file, it is read again; a new link is reported again", async () => {
    const { outside, dir, file } = setup()
    symlinkSync(outside, file)
    const lines: string[] = []
    const source = serviceSecretSource([dir], (line) => lines.push(line))
    source()
    await Promise.resolve()
    unlinkSync(file)
    writeFileSync(file, JSON.stringify({ password: "fake-other-password-4567" }))
    assert.ok(source().some((item) => item.value === "fake-other-password-4567"))
    await Promise.resolve()
    unlinkSync(file)
    symlinkSync(outside, file)
    source()
    assert.equal(lines.length, 2)
  })
  it("LS-12: a linked file that breaks then is reported as not redacted", async () => {
    const { outside, dir, file } = setup()
    symlinkSync(outside, file)
    const lines: string[] = []
    const source = serviceSecretSource([dir], (line) => lines.push(line))
    source()
    await Promise.resolve()
    unlinkSync(file)
    symlinkSync(`${outside}.absent`, file)
    source()
    assert.equal(lines.length, 2)
    assert.match(lines[0]!, /read through it/)
    assert.match(lines[1]!, /NOT redacted/)
  })
  it("LS-13: the same link restored, then broken again, is reported again", async () => {
    const { outside, dir, file } = setup()
    symlinkSync(outside, file)
    const lines: string[] = []
    const source = serviceSecretSource([dir], (line) => lines.push(line))
    const swap = async (target: string) => {
      source()
      await Promise.resolve()
      unlinkSync(file)
      symlinkSync(target, file)
    }
    await swap(`${outside}.absent`)
    await swap(outside)
    await swap(`${outside}.absent`)
    source()
    assert.equal(lines.filter((line) => /NOT redacted/.test(line)).length, 2)
  })
  for (const [name, why, spoil] of [
    ["more than 1 MiB", /larger than 1 MiB/, (file: string) => writeFileSync(file, `{"password":"${PASSWORD}","pad":"${"x".repeat(1 << 20)}"}`)],
    ["invalid JSON", /not valid JSON/, (file: string) => writeFileSync(file, `{"password":"${PASSWORD}"`)],
    ...(process.getuid?.() === 0
      ? []
      : ([
          [
            "no read permission",
            /could not be read: EACCES/,
            (file: string) => {
              writeFileSync(file, JSON.stringify({ password: PASSWORD }))
              chmodSync(file, 0)
            },
          ],
        ] as const)),
  ] as ReadonlyArray<readonly [string, RegExp, (file: string) => void]>) {
    it(`LS-14: ${name}: a warning, once, without a value, and again after a good read`, async () => {
      const { dir, file } = setup()
      spoil(file)
      const lines: string[] = []
      const source = serviceSecretSource([dir], (line) => lines.push(line))
      assert.deepEqual(source(), [])
      await Promise.resolve()
      source()
      assert.equal(lines.length, 1)
      assert.match(lines[0]!, why)
      assert.match(lines[0]!, /NOT redacted/)
      assert.ok(!lines[0]!.includes(PASSWORD))
      await Promise.resolve()
      unlinkSync(file)
      writeFileSync(file, JSON.stringify({ password: PASSWORD }))
      assert.deepEqual(source().map((item) => item.value), [PASSWORD])
      await Promise.resolve()
      unlinkSync(file)
      spoil(file)
      source()
      assert.equal(lines.length, 2)
    })
  }
  it("LS-10: at startup, the log says it, in a plugin that loads", async () => {
    const root = temp()
    const home = join(root, "home")
    mkdirSync(join(home, ".config", "opencode"), { recursive: true })
    writeFileSync(join(root, "outside.json"), JSON.stringify({ password: PASSWORD }))
    symlinkSync(join(root, "outside.json"), join(home, ".config", "opencode", "service.json"))
    const logFile = join(root, "guard.log")
    await setupGuard(fakeContext({ logFile }).ctx, { HOME: home })
    const log = readFileSync(logFile, "utf8")
    assert.match(log, /WARN service file .*service\.json is a symbolic link: read through it/)
    assert.ok(!log.includes(PASSWORD))
  })
  it("LS-11: a warning that appears while running reaches the log", async () => {
    const root = temp()
    const home = join(root, "home")
    const dir = join(home, ".config", "opencode")
    mkdirSync(dir, { recursive: true })
    const logFile = join(root, "guard.log")
    const fake = fakeContext({ logFile })
    await setupGuard(fake.ctx, { HOME: home })
    writeFileSync(join(root, "outside.json"), JSON.stringify({ password: PASSWORD }))
    symlinkSync(join(root, "outside.json"), join(dir, "service.json"))
    await new Promise((done) => setImmediate(done))
    await fake.trigger("tool.execute.after", { sessionID: "ses_1", agent: "build", id: "call_1", tool: "bash", status: "completed", result: { output: "hello" } })
    assert.match(readFileSync(logFile, "utf8"), /service\.json is a symbolic link/)
  })
  it("witness: LS-12: a regular file is read, without a notice", () => {
    const { dir, file } = setup()
    writeFileSync(file, JSON.stringify({ password: PASSWORD }))
    const lines: string[] = []
    assert.deepEqual(serviceSecretSource([dir], (line) => lines.push(line))().map((item) => item.value), [PASSWORD])
    assert.deepEqual(lines, [])
  })
})
