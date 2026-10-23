import "./tmp.ts"
import assert from "node:assert/strict"
import { lstatSync, mkdirSync, mkdtempSync, realpathSync, symlinkSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import { registerGate } from "../src/hooks/gate.ts"
import { createRealPath, MAX_LOOKUPS, type LinkIo } from "../src/real-path.ts"
import { protectedWriteKind } from "../src/rules/sensitive-paths.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

/**
 * Fake plugin directory, working directory with links to it (absolute, relative, to a subdirectory), to a
 * fake `~/.ssh` and to an arbitrary directory, plus a link loop.
 */
function workspace() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-links-")))
  const plugin = join(root, "plugin")
  const work = join(root, "work")
  mkdirSync(join(plugin, "src"), { recursive: true })
  mkdirSync(join(work, "deep"), { recursive: true })
  mkdirSync(join(root, "home/.ssh"), { recursive: true })
  symlinkSync(plugin, join(work, "abs"))
  symlinkSync("../plugin", join(work, "rel"))
  symlinkSync(join(plugin, "src"), join(work, "deep/viasrc"))
  symlinkSync(join(root, "home/.ssh"), join(work, "cles"))
  symlinkSync(join(root, "home"), join(work, "elsewhere"))
  symlinkSync(join(work, "loop"), join(work, "loop"))
  return { root, plugin, work }
}

/** Spy input/output: no links, every component exists. */
function plainIo() {
  const calls = { lstat: 0 }
  const io: LinkIo = {
    lstat: () => {
      calls.lstat++
      return { isSymbolicLink: () => false }
    },
    readlink: () => {
      throw new Error("not a link")
    },
  }
  return { io, calls }
}

describe("batch 24: link resolution, component by component", () => {
  it("absolute and relative links, `..` after a link (kernel semantics), files to create", () => {
    const { plugin, work } = workspace()
    const real = createRealPath()
    assert.deepEqual(real(join(work, "abs/src/x.ts")), [join(plugin, "src/x.ts")])
    assert.deepEqual(real(join(work, "rel/x")), [join(plugin, "x")])
    // The kernel walks up from the link target (plugin/src), not from the link's directory.
    assert.deepEqual(real(`${join(work, "deep/viasrc")}/../index.ts`), [join(plugin, "index.ts")])
    assert.deepEqual(real(join(work, "abs/nouveau/dir/f")), [join(plugin, "nouveau/dir/f")])
    assert.deepEqual(real(join(work, "deep/f")), [join(work, "deep/f")])
    assert.deepEqual(real("/"), ["/"])
  })

  it("unknown: link loop, relative or too-long path", () => {
    const { work } = workspace()
    const real = createRealPath()
    assert.equal(real(join(work, "loop/f")), undefined)
    assert.equal(real("relatif/f"), undefined)
    assert.equal(real(`/${"x".repeat(5000)}`), undefined)
  })

  it("/proc/self: caller and server directories for cwd, root for root, unknown otherwise", () => {
    const { plugin, work } = workspace()
    const real = (directories: string[]) => createRealPath({ directories, processDirectory: work })
    assert.deepEqual(real([join(work, "abs")])("/proc/self/cwd/f"), [join(plugin, "f"), join(work, "f")])
    assert.deepEqual(real([join(work, "abs")])("/proc/thread-self/cwd/src"), [join(plugin, "src"), join(work, "src")])
    // Server (edit, write, patch tools) launched from the protected directory.
    assert.deepEqual(createRealPath({ directories: [work], processDirectory: join(work, "abs") })("/proc/self/cwd/f"), [join(work, "f"), join(plugin, "f")])
    // Roundabout forms: empty component, `.`, `task/<n>/`, `..` that leaves /proc/self then comes back.
    const forms = ["/proc/self//cwd/f", "/proc/self/./cwd/f", "/proc/self/task/123/cwd/f", "/proc/self/task/123/../123/cwd/f", "/proc/thread-self/../../cwd/f", "/proc/self/../self/cwd/f"]
    for (const path of forms) assert.deepEqual(real([join(work, "abs")])(path), [join(plugin, "f"), join(work, "f")], path)
    assert.deepEqual(real([])(`/proc/self/root${join(work, "abs/f")}`), [join(plugin, "f")])
    assert.equal(real([work])("/proc/self/fd/1"), undefined)
    assert.equal(real([work])("/proc/self/task"), undefined)
    // Descriptors under /dev: link to /proc/self/fd, so unknown too.
    if (lstatSync("/dev/fd", { throwIfNoEntry: false })?.isSymbolicLink()) assert.equal(real([work])("/dev/fd/1"), undefined)
  })

  it("lookup cap per call, memoized results", () => {
    const { io, calls } = plainIo()
    const real = createRealPath({ io })
    assert.equal(real(`/${Array.from({ length: MAX_LOOKUPS + 10 }, () => "d").join("/")}`), undefined)
    assert.equal(calls.lstat, MAX_LOOKUPS)
    const fresh = plainIo()
    const memo = createRealPath({ io: fresh.io })
    memo("/a/b")
    memo("/a/b")
    assert.equal(fresh.calls.lstat, 2)
  })
})

describe("batch 24: protected writes through a link", () => {
  it("plugin directory: absolute path, relative from the caller's directories, `..` after a link", () => {
    const { plugin, work } = workspace()
    const context = { protectedDirs: [plugin], cwd: work }
    assert.equal(protectedWriteKind(join(work, "abs/src/x.ts"), undefined, context), undefined)
    assert.equal(protectedWriteKind(join(work, "abs/src/x.ts"), undefined, { ...context, realPaths: createRealPath() }), "opencode")
    assert.equal(protectedWriteKind("rel/x", undefined, { ...context, realPaths: createRealPath() }), "opencode")
    assert.equal(protectedWriteKind("rel/x", undefined, { protectedDirs: [plugin], cwd: "/nowhere", cwds: ["/nowhere", work], realPaths: createRealPath() }), "opencode")
    // Raw form (shell, kernel): plugin/index.ts; normalized form: work/deep/index.ts.
    assert.equal(protectedWriteKind("deep/viasrc/../index.ts", undefined, { ...context, realPaths: createRealPath() }), "opencode")
    // Normalized form only (OpenCode tools): work/abs/f; raw form: home/../abs/f, absent.
    assert.equal(protectedWriteKind("elsewhere/../abs/f", undefined, { ...context, realPaths: createRealPath() }), "opencode")
    assert.equal(protectedWriteKind("deep/f", undefined, { ...context, realPaths: createRealPath() }), undefined)
  })

  it("other locations: a link to a `.ssh` has kind system", () => {
    const { plugin, work } = workspace()
    assert.equal(protectedWriteKind("cles/authorized_keys", undefined, { protectedDirs: [plugin], cwd: work }), undefined)
    assert.equal(protectedWriteKind("cles/authorized_keys", undefined, { protectedDirs: [plugin], cwd: work, realPaths: createRealPath() }), "system")
  })

  it("never any relaxation: unknown or harmless real path leave the lexical kind", () => {
    const { plugin } = workspace()
    const unknown = () => undefined
    const harmless = () => ["/tmp/harmless"]
    for (const realPaths of [unknown, harmless]) {
      assert.equal(protectedWriteKind(join(plugin, "index.ts"), undefined, { protectedDirs: [plugin], realPaths }), "opencode")
      assert.equal(protectedWriteKind("/etc/hosts", undefined, { protectedDirs: [plugin], realPaths }), "system")
      assert.equal(protectedWriteKind("~/.config/opencode/x.json", "/home/u", { protectedDirs: [plugin], realPaths }), "opencode")
    }
    // Cap exhausted: a path protected in the lexical sense remains so.
    const { io } = plainIo()
    const exhausted = createRealPath({ io })
    exhausted(`/${Array.from({ length: MAX_LOOKUPS + 1 }, () => "d").join("/")}`)
    assert.equal(protectedWriteKind(join(plugin, "index.ts"), undefined, { protectedDirs: [plugin], realPaths: exhausted }), "opencode")
  })

  it("real form of the plugin directory in protected directories (plugin loaded through a link)", () => {
    const { plugin, work } = workspace()
    assert.equal(protectedWriteKind(join(plugin, "x"), undefined, { protectedDirs: [join(work, "abs"), plugin] }), "opencode")
  })
})

describe("batch 24: decider and subcommands, depending on the option", () => {
  it("edit, write, patch and shell tools; launch directory; executed script", async () => {
    const { plugin, work } = workspace()
    const { config } = parseConfig({})
    const linked = createDecider({ config, redactor: createRedactor(), protectedDirs: [plugin], resolveLinks: true })
    const lexical = createDecider({ config, redactor: createRedactor(), protectedDirs: [plugin] })
    const calls = [
      { tool: "edit", input: { path: join(work, "abs/src/x.ts"), oldString: "a", newString: "b" }, directory: work },
      { tool: "write", input: { path: "rel/x", content: "a" }, directory: work },
      { tool: "patch", input: { patchText: "*** Begin Patch\n*** Add File: rel/neuf.ts\n+a\n*** End Patch" }, directory: work },
      { tool: "shell", input: { command: "echo a > rel/notes.txt" }, directory: work },
      { tool: "shell", input: { command: "echo a > rel/notes.txt" }, directory: "/nowhere", cwds: [work] },
    ]
    for (const call of calls) {
      const found = await linked.decide(call)
      assert.equal(found.rule, "self-protection", call.tool)
      assert.equal(found.verdict, "ask", call.tool)
      assert.notEqual((await lexical.decide(call)).rule, "self-protection", call.tool)
    }
    const script = { path: "./s.sh", content: "echo a > rel/notes.txt\n", shell: true, forModel: false }
    const viaScript = await linked.decide({ tool: "shell", input: { command: "bash ./s.sh" }, directory: work, scripts: [script] })
    assert.equal(viaScript.rule, "self-protection")
  })

  it("write tool via /proc/self/cwd: server directory, where the plugin is imported", async () => {
    const { plugin, work } = workspace()
    const { config } = parseConfig({})
    const linked = createDecider({ config, redactor: createRedactor(), protectedDirs: [plugin], resolveLinks: true })
    const previous = process.cwd()
    process.chdir(plugin)
    try {
      const found = await linked.decide({ tool: "write", input: { path: "/proc/self/cwd/index.ts", content: "a" }, directory: work })
      assert.equal(found.rule, "self-protection")
    } finally {
      process.chdir(previous)
    }
  })

  it("permission.evaluate: subcommand that writes through a link", async () => {
    const { plugin, work } = workspace()
    const { config } = parseConfig({})
    const log = { debug() {}, info() {}, warn() {}, error() {} }
    const evaluate = async (resolveLinks: boolean) => {
      const fake = fakeContext()
      ;(fake.ctx.location as { directory: string }).directory = work
      const decider = createDecider({ config, redactor: createRedactor(), protectedDirs: [plugin] })
      await registerGate(fake.ctx, { decider, redactor: createRedactor(), log, protectedDirs: [plugin], resolveLinks })
      const event = { sessionID: "ses_1", action: "shell", resources: ["echo a > rel/notes.txt"], effect: "allow", message: undefined, source: { type: "tool", messageID: "msg_1", id: "call_1" } }
      return fake.trigger("permission.evaluate", event)
    }
    assert.equal((await evaluate(true)).effect, "ask")
    assert.equal((await evaluate(false)).effect, "allow")
  })
})
