import assert from "node:assert/strict"
import { posix } from "node:path"
import { describe, it } from "node:test"
import { fileURLToPath } from "node:url"
import { parseConfig } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import { registerGate } from "../src/hooks/gate.ts"
import { createRealPath, MAX_LOOKUPS, type LinkIo } from "../src/real-path.ts"
import { protectedWriteKind } from "../src/rules/sensitive-paths.ts"
import { shellFinding } from "../src/rules/shell.ts"
import { argumentPaths, toolFinding } from "../src/rules/tools.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

// Batch 35: each write target is also classified under the form OpenCode writes it in. Categories C1 to C7 and families
// 1 to 10 of phase 1 (`dev/plans/audit36/phase1-report.md`, table 3.3): one test per missed or downgraded pair and
// per entry point (rule for the edit, write, patch tools; path argument of an MCP tool; write target of the
// shell for C1 to C6).

const HOME = "/home/test"
const PROJECT = `${HOME}/project`
const PLUGIN = `${HOME}/plugin_opencode`
const redactor = createRedactor()
const context = (cwd: string) => ({ redactor, home: HOME, cwd, protectedDirs: [PLUGIN] })

/** OpenCode 2.0.31 resolution (`resolvePath` from `core/src/file-access.ts`), copied here: only `~` and `~/` expanded. */
const openCodeForm = (cwd: string, raw: string) =>
  posix.resolve(cwd, raw === "~" ? HOME : raw.startsWith("~/") ? posix.join(HOME, raw.slice(2)) : raw)

type Rule = "self-protection" | "protected-write"
/** Phase 1 location families: 1 to 5 in self-protection, 6 to 10 plain protected locations. */
const FAMILIES: Record<number, { readonly label: string; readonly rule: Rule }> = {
  1: { label: "OpenCode configuration file names", rule: "self-protection" },
  2: { label: "OpenCode system configuration directory", rule: "self-protection" },
  3: { label: "OpenCode home directory configuration", rule: "self-protection" },
  4: { label: "OpenCode project configuration", rule: "self-protection" },
  5: { label: "plugin directory", rule: "self-protection" },
  6: { label: "shell startup files", rule: "protected-write" },
  7: { label: "system configuration directory", rule: "protected-write" },
  8: { label: "SSH keys directory", rule: "protected-write" },
  9: { label: "git hooks", rule: "protected-write" },
  10: { label: "user autostart and services", rule: "protected-write" },
}

interface Case {
  readonly category: string
  readonly family: number
  /** Variant (downgraded, first part of the segment). */
  readonly note?: string
  /** Session directory. */
  readonly cwd: string
  readonly path: string
  /** File that OpenCode writes (and, without a link, the kernel). */
  readonly target: string
}

const CONFIG = `${HOME}/.config/opencode/plugins/x.ts`
const SYSTEM_CONFIG = "/etc/opencode/plugins/x.ts"
const CRON = "/etc/cron.d/job"
const HOOK = `${PROJECT}/.git/hooks/pre-commit`

/** Missed (M) or downgraded (D) pairs from table 3.3, for C1 to C6. */
const CASES: readonly Case[] = [
  { category: "C1", family: 2, cwd: PROJECT, path: "//etc/opencode/plugins/x.ts", target: SYSTEM_CONFIG },
  { category: "C1", family: 2, note: "downgraded", cwd: PROJECT, path: "/etc//opencode/plugins/x.ts", target: SYSTEM_CONFIG },
  { category: "C1", family: 3, cwd: PROJECT, path: `${HOME}/.config//opencode/plugins/x.ts`, target: CONFIG },
  { category: "C1", family: 7, cwd: PROJECT, path: "//etc/cron.d/job", target: CRON },
  { category: "C1", family: 9, cwd: PROJECT, path: ".git//hooks/pre-commit", target: HOOK },
  { category: "C1", family: 10, cwd: PROJECT, path: `${HOME}/.config//autostart/x.desktop`, target: `${HOME}/.config/autostart/x.desktop` },
  { category: "C2", family: 2, cwd: PROJECT, path: "/./etc/opencode/plugins/x.ts", target: SYSTEM_CONFIG },
  { category: "C2", family: 2, note: "downgraded", cwd: PROJECT, path: "/etc/./opencode/plugins/x.ts", target: SYSTEM_CONFIG },
  { category: "C2", family: 3, cwd: PROJECT, path: "~/.config/./opencode/plugins/x.ts", target: CONFIG },
  { category: "C2", family: 7, cwd: PROJECT, path: "/./etc/cron.d/job", target: CRON },
  { category: "C2", family: 9, cwd: PROJECT, path: ".git/./hooks/pre-commit", target: HOOK },
  { category: "C2", family: 10, cwd: PROJECT, path: `${HOME}/.config/./systemd/user/x.service`, target: `${HOME}/.config/systemd/user/x.service` },
  { category: "C3", family: 2, cwd: PROJECT, path: "/tmp/../etc/opencode/plugins/x.ts", target: SYSTEM_CONFIG },
  { category: "C3", family: 2, note: "downgraded", cwd: PROJECT, path: "/etc/x/../opencode/plugins/x.ts", target: SYSTEM_CONFIG },
  { category: "C3", family: 3, cwd: PROJECT, path: `${HOME}/.config/x/../opencode/plugins/x.ts`, target: CONFIG },
  { category: "C3", family: 7, cwd: PROJECT, path: "/tmp/../etc/cron.d/job", target: CRON },
  { category: "C3", family: 9, cwd: PROJECT, path: ".git/x/../hooks/pre-commit", target: HOOK },
  { category: "C3", family: 10, cwd: PROJECT, path: "~/.config/x/../autostart/x.desktop", target: `${HOME}/.config/autostart/x.desktop` },
  { category: "C4", family: 1, cwd: PROJECT, path: "opencode.json/.", target: `${PROJECT}/opencode.json` },
  { category: "C4", family: 6, cwd: PROJECT, path: "~/.bashrc/x/..", target: `${HOME}/.bashrc` },
  { category: "C5", family: 2, cwd: PROJECT, path: "../../../etc/opencode/plugins/x.ts", target: SYSTEM_CONFIG },
  { category: "C5", family: 7, cwd: PROJECT, path: "../../../etc/cron.d/job", target: CRON },
  { category: "C6", family: 2, cwd: "/etc/opencode", path: "plugins/x.ts", target: SYSTEM_CONFIG },
  { category: "C6", family: 3, cwd: `${HOME}/.config/opencode`, path: "plugins/x.ts", target: CONFIG },
  { category: "C6", family: 4, cwd: `${PROJECT}/.opencode`, path: "plugins/x.ts", target: `${PROJECT}/.opencode/plugins/x.ts` },
  { category: "C6", family: 7, cwd: "/etc", path: "cron.d/job", target: CRON },
  { category: "C6", family: 8, cwd: `${HOME}/.ssh`, path: "authorized_keys", target: `${HOME}/.ssh/authorized_keys` },
  { category: "C6", family: 9, note: "first part of the segment", cwd: `${PROJECT}/.git`, path: "hooks/pre-commit", target: HOOK },
  { category: "C6", family: 10, note: "first part of the segment", cwd: `${HOME}/.config`, path: "systemd/user/x.service", target: `${HOME}/.config/systemd/user/x.service` },
]

const patchOf = (path: string) => ["*** Begin Patch", `*** Add File: ${path}`, "+x", "*** End Patch"].join("\n")

/** Entry points: name of the rule found, or `none`. */
const ENTRIES = {
  write: (cwd: string, path: string) => toolFinding("write", { path, content: "x" }, context(cwd))?.rule ?? "none",
  edit: (cwd: string, path: string) => toolFinding("edit", { path, oldString: "a", newString: "b" }, context(cwd))?.rule ?? "none",
  patch: (cwd: string, path: string) => toolFinding("patch", { patchText: patchOf(path) }, context(cwd))?.rule ?? "none",
  mcp: (cwd: string, path: string) => toolFinding("tool_x", { filePath: path }, context(cwd))?.rule ?? "none",
  shell: (cwd: string, path: string) => shellFinding(`echo x > ${path}`, context(cwd))?.rule ?? "none",
} as const

const title = (item: Case | { category: string; family: number; note?: string }) =>
  `${item.category} × family ${item.family} (${FAMILIES[item.family]!.label}${item.note ? `, ${item.note}` : ""})`

describe("batch 35: C1 to C6, resolved form classified by all families", () => {
  for (const item of CASES) {
    for (const [entry, find] of Object.entries(ENTRIES)) {
      it(`${title(item)} : ${entry}`, () => {
        // Construction: OpenCode (patch reading: whitespace trimmed) and, without a link, the kernel write the witness file.
        assert.equal(openCodeForm(item.cwd, entry === "patch" ? item.path.trim() : item.path), item.target)
        assert.equal(find(item.cwd, item.path), FAMILIES[item.family]!.rule)
      })
    }
  }

  it("C1 × file: URL of an MCP argument (doubled slashes kept by the path conversion)", () => {
    const url = `file://${HOME}/.config//opencode/plugins/x.ts`
    assert.equal(posix.normalize(fileURLToPath(url)), CONFIG)
    assert.equal(toolFinding("chrome-devtools-mcp_navigate_page", { pageId: 1, type: "url", url }, context(PROJECT))?.rule, "self-protection")
  })
})

/** C7: leading/trailing whitespace or quotes that the plugin removed and OpenCode keeps (`patch`: quotes only). */
const C7 = [
  { category: "C7a", family: 5, cwd: PROJECT, blank: " /../../plugin_opencode/index.ts", quote: '"/../../plugin_opencode/index.ts' },
  { category: "C7b", family: 5, cwd: PROJECT, blank: "../plugin_opencode/.. ", quote: '../plugin_opencode/.."' },
] as const

describe("batch 35: C7, exact form of the edit, write and patch tools", () => {
  for (const item of C7) {
    const variants = [
      ["write", "whitespace", item.blank],
      ["write", "quote", item.quote],
      ["edit", "whitespace", item.blank],
      ["edit", "quote", item.quote],
      ["patch", "quote", item.quote],
    ] as const
    for (const [entry, variant, path] of variants) {
      it(`${title(item)}: ${entry}, ${variant}`, () => {
        assert.ok(openCodeForm(item.cwd, entry === "patch" ? path.trim() : path).startsWith(`${PLUGIN}/`))
        assert.equal(ENTRIES[entry](item.cwd, path), "self-protection")
      })
    }
  }

  it("exact form subject to link resolution: name ending in a quote or whitespace, link to the configuration", () => {
    for (const [tool, path] of [["write", 'notes.txt"'], ["write", "notes.txt "], ["edit", 'notes.txt"'], ["patch", 'notes.txt"']] as const) {
      const exact = openCodeForm(PROJECT, path)
      // Only the exact form, not stripped of its quote or whitespace, leads to the configuration through a link.
      const realPaths = (absolute: string) => (absolute === exact ? [`${HOME}/.config/opencode/opencode.json`] : [posix.resolve(absolute)])
      const input = tool === "patch" ? { patchText: patchOf(path) } : tool === "edit" ? { path, oldString: "a", newString: "b" } : { path, content: "x" }
      assert.equal(toolFinding(tool, input, { ...context(PROJECT), realPaths })?.rule, "self-protection", `${tool} ${JSON.stringify(path)}`)
      assert.equal(toolFinding(tool, input, context(PROJECT))?.rule, undefined, `${tool} ${JSON.stringify(path)} without a link`)
    }
  })
})

describe("batch 35: severity, explicit maximum of kinds", () => {
  it("downgraded case: written form in a plain protected location, resolved form in self-protection", () => {
    assert.equal(protectedWriteKind("/etc//opencode/plugins/x.ts", HOME, context(PROJECT)), "opencode")
    // Local rule switch turned off: self-protection stays active.
    const off = { dangerousCommands: false, sensitiveFiles: false }
    assert.equal(toolFinding("write", { path: "/etc//opencode/plugins/x.ts", content: "x" }, { ...context(PROJECT), active: off })?.rule, "self-protection")
    assert.equal(shellFinding("echo x > /etc/./opencode/plugins/x.ts", { ...context(PROJECT), active: off })?.rule, "self-protection")
  })

  it("reverse direction: written form in self-protection, resolved form in a plain protected location", () => {
    assert.equal(openCodeForm(PROJECT, "~/.config/opencode/../../.bashrc"), `${HOME}/.bashrc`)
    assert.equal(protectedWriteKind("~/.config/opencode/../../.bashrc", HOME, context(PROJECT)), "opencode")
    assert.equal(toolFinding("write", { path: "~/.config/opencode/../../.bashrc", content: "x" }, context(PROJECT))?.rule, "self-protection")
  })

  it("real path in self-protection after a form resolved to a plain protected location", () => {
    const realPaths = (absolute: string) => (posix.resolve(absolute) === "/etc/cron.d/job" ? [`${PLUGIN}/index.ts`] : undefined)
    assert.equal(protectedWriteKind("//etc/cron.d/job", HOME, { ...context(PROJECT), realPaths }), "opencode")
  })
})

/** Fake I/O: no link, every component exists. */
const plainIo: LinkIo = { lstat: () => ({ isSymbolicLink: () => false }), readlink: () => "" }
/** Every component is a link to itself: loop. */
const loopIo: LinkIo = { lstat: () => ({ isSymbolicLink: () => true }), readlink: (path) => path }

describe("batch 35: resolved form kept when real paths are unknown", () => {
  const missed = `${HOME}/.config//opencode/plugins/x.ts`
  it("predicate that returns unknown", () => {
    const unknown = () => undefined
    assert.equal(protectedWriteKind(missed, HOME, { ...context(PROJECT), realPaths: unknown }), "opencode")
    assert.equal(protectedWriteKind("plugins/x.ts", HOME, { ...context(`${HOME}/.config/opencode`), realPaths: unknown }), "opencode")
    assert.equal(toolFinding("write", { path: missed, content: "x" }, { ...context(PROJECT), realPaths: unknown })?.rule, "self-protection")
  })
  it("lookup cap exhausted", () => {
    const deep = `${HOME}/.config//opencode/${"d/".repeat(MAX_LOOKUPS + 10)}f`
    const realPaths = createRealPath({ io: plainIo, directories: [PROJECT] })
    assert.equal(realPaths(posix.resolve(deep)), undefined)
    assert.equal(protectedWriteKind(deep, HOME, { ...context(PROJECT), realPaths }), "opencode")
  })
  it("link loop", () => {
    const realPaths = createRealPath({ io: loopIo, directories: [PROJECT] })
    assert.equal(realPaths(posix.resolve(missed)), undefined)
    assert.equal(protectedWriteKind(missed, HOME, { ...context(PROJECT), realPaths }), "opencode")
    assert.equal(shellFinding(`echo x > ${missed}`, { ...context(PROJECT), realPaths: createRealPath({ io: loopIo, directories: [PROJECT] }) })?.rule, "self-protection")
  })
})

describe("batch 35: Plan agent plans directory, same verdict as before", () => {
  it("absolute path, relative from the home directory, tilde, patch: self-protection", () => {
    const plan = `${HOME}/.opencode/plan/etape.md`
    assert.equal(ENTRIES.write(PROJECT, plan), "self-protection")
    assert.equal(ENTRIES.write(HOME, ".opencode/plan/etape.md"), "self-protection")
    assert.equal(ENTRIES.edit(PROJECT, "~/.opencode/plan/etape.md"), "self-protection")
    assert.equal(ENTRIES.patch(PROJECT, "~/.opencode/plan/etape.md"), "self-protection")
    assert.equal(toolFinding("write", { path: plan, content: "x" }, context(PROJECT))?.verdict, "ask")
  })
})

describe("batch 35: cost on long paths and many possible directories", () => {
  const timed = (label: string, run: () => unknown) => {
    const start = performance.now()
    const result = run()
    const elapsed = performance.now() - start
    assert.ok(elapsed < 1000, `${label} : ${elapsed.toFixed(0)} ms`)
    return result
  }
  /** Link-free I/O that counts lookups. */
  const countingIo = () => {
    const calls = { lstat: 0 }
    const io: LinkIo = {
      lstat: () => {
        calls.lstat++
        return { isSymbolicLink: () => false }
      },
      readlink: () => "",
    }
    return { io, calls }
  }

  it("long path protected under its resolved form, 300 directories: each case in under a second", () => {
    const long = `${"a/./b/../".repeat(400)}.config//opencode/x`
    const cwds = Array.from({ length: 300 }, (_, index) => `${HOME}/${"dir/".repeat(40)}${index}`)
    timed("classification, 300 directories", () => protectedWriteKind(long, HOME, { ...context(PROJECT), cwds }))
    timed("classification, 300 directories, real paths", () =>
      protectedWriteKind(long, HOME, { ...context(PROJECT), cwds, realPaths: createRealPath({ io: plainIo, directories: cwds }) }),
    )
    timed("shell, 300 directories", () => shellFinding(`cp a ${long} && echo x > ${long}/y`, { ...context(PROJECT), cwds }))
    timed("write", () => toolFinding("write", { path: `${long} `, content: "x" }, { ...context(PROJECT), realPaths: createRealPath({ io: plainIo }) }))
    const headers = Array.from({ length: 300 }, (_, index) => `*** Add File: ${long}/${index}"`).join("\n")
    timed("patch, 300 headers", () => toolFinding("patch", { patchText: `*** Begin Patch\n${headers}\n*** End Patch` }, context(PROJECT)))
  })

  it("long path with no protected form: link resolution traversed to the end, then to the cap", () => {
    // 150 detours: 300 named components in the raw form, 150 in the resolved form, under 4,096 characters.
    const long = `${"d/./e/../".repeat(150)}f`
    const single = countingIo()
    const kind = timed("classification, one directory, link-free real paths", () =>
      protectedWriteKind(long, HOME, { ...context(PROJECT), realPaths: createRealPath({ io: single.io, directories: [PROJECT] }) }),
    )
    assert.equal(kind, undefined)
    assert.ok(single.calls.lstat > 400, `${single.calls.lstat} lookups`)
    const write = countingIo()
    assert.equal(
      timed("write, link-free real paths", () => toolFinding("write", { path: `${long} `, content: "x" }, { ...context(PROJECT), realPaths: createRealPath({ io: write.io }) })),
      undefined,
    )
    assert.ok(write.calls.lstat > 400, `${write.calls.lstat} lookups`)
    const cwds = Array.from({ length: 300 }, (_, index) => `${HOME}/${"dir/".repeat(40)}${index}`)
    const many = countingIo()
    assert.equal(
      timed("classification, 300 directories, link-free real paths", () =>
        protectedWriteKind(long, HOME, { ...context(PROJECT), cwds, realPaths: createRealPath({ io: many.io, directories: cwds }) }),
      ),
      undefined,
    )
    assert.equal(many.calls.lstat, MAX_LOOKUPS)
  })

  it("shell command with 120 targets and 120 possible directories, without then with real paths", () => {
    const command = Array.from({ length: 120 }, (_, index) => `echo x > sub/dir/f${index}`).join("; ")
    const cwds = Array.from({ length: 120 }, (_, index) => `${HOME}/${"dir/".repeat(20)}${index}`)
    assert.equal(timed("shell, 120 × 120", () => shellFinding(command, { ...context(PROJECT), cwds })), undefined)
    const io = countingIo()
    assert.equal(
      timed("shell, 120 × 120, link-free real paths", () =>
        shellFinding(command, { ...context(PROJECT), cwds, realPaths: createRealPath({ io: io.io, directories: cwds }) }),
      ),
      undefined,
    )
    // Link resolution traversed up to the cap, which the predicate shares across all targets.
    assert.equal(io.calls.lstat, MAX_LOOKUPS)
  })
})

const silent = { debug() {}, info() {}, warn() {}, error() {} }

describe("batch 35, re-review: resolved form from a possible directory that is not the first (shell)", () => {
  it("shell rule: relative target protected only from the second possible directory", () => {
    const configuration = { ...context(PROJECT), cwds: [PROJECT, `${HOME}/.config`] }
    assert.equal(openCodeForm(`${HOME}/.config`, "opencode/plugins/x.ts"), CONFIG)
    assert.equal(shellFinding("echo x > opencode/plugins/x.ts", configuration)?.rule, "self-protection")
    assert.equal(shellFinding("echo x > hooks/pre-commit", { ...context(PROJECT), cwds: [PROJECT, `${PROJECT}/.git`] })?.rule, "protected-write")
  })

  async function gate() {
    const { config } = parseConfig({})
    const decider = createDecider({ config, redactor, home: HOME, protectedDirs: [PLUGIN] })
    const fake = fakeContext()
    Object.assign(fake.ctx, { location: { directory: PROJECT } })
    await registerGate(fake.ctx, { decider, redactor, home: HOME, protectedDirs: [PLUGIN], log: silent })
    let calls = 0
    const shell = async (command: string) => {
      const id = `call_${++calls}`
      const asserts = fake.asserts.length
      await fake.trigger("tool.execute.before", { agent: "build", messageID: "msg_1", sessionID: "ses_1", id, tool: "shell", input: { command } })
      return { id, asked: fake.asserts.length > asserts ? String(fake.asserts.at(-1)!.metadata?.reason) : undefined }
    }
    const evaluate = async (id: string, resources: string[]) => {
      const event = { sessionID: "ses_1", action: "shell", resources, effect: "allow", message: undefined as string | undefined, source: { type: "tool", messageID: "msg_1", id } }
      await fake.trigger("permission.evaluate", event)
      return event
    }
    return { shell, evaluate }
  }

  it("shell call: `cd` followed by a `;`, possible directories computed by the plugin (session then `cd` target)", async () => {
    const t = await gate()
    assert.match(String((await t.shell("cd ~/.config; echo x > opencode/plugins/x.ts")).asked), /self-protection/)
  })

  it("subcommands checked at authorization: possible directories of the call, the protected one second", async () => {
    const t = await gate()
    const call = await t.shell("cd ~/.config; true")
    assert.equal(call.asked, undefined)
    const event = await t.evaluate(call.id, ["echo x > opencode/plugins/x.ts"])
    assert.equal(event.effect, "ask")
    assert.match(String(event.message), /OpenCode's configuration/)
    // Witness: unknown call, session directory only.
    assert.equal((await t.evaluate("call_inconnu", ["echo x > opencode/plugins/x.ts"])).effect, "allow")
  })
})

/** C6 combined with C7a: session in the protected location, first component made of whitespace or a quote. */
const C6_C7A = [
  { family: 2, cwd: "/etc/opencode", blank: " /plugins/x.ts", quote: '"/plugins/x.ts', location: "/etc/opencode/" },
  { family: 3, cwd: `${HOME}/.config/opencode`, blank: " /plugins/x.ts", quote: '"/plugins/x.ts', location: `${HOME}/.config/opencode/` },
  { family: 9, cwd: `${PROJECT}/.git/hooks`, blank: " /pre-commit", quote: "'/pre-commit", location: `${PROJECT}/.git/hooks/` },
] as const

describe("batch 35, re-review: C6 combined with C7a, exact form classified by all families", () => {
  for (const item of C6_C7A) {
    const variants = [
      ["write", "whitespace", item.blank],
      ["write", "quote", item.quote],
      ["edit", "whitespace", item.blank],
      ["edit", "quote", item.quote],
      ["patch", "quote", item.quote],
    ] as const
    for (const [entry, variant, path] of variants) {
      it(`C6 + C7a × family ${item.family} (${FAMILIES[item.family]!.label}): ${entry}, ${variant}`, () => {
        assert.ok(openCodeForm(item.cwd, entry === "patch" ? path.trim() : path).startsWith(item.location))
        assert.equal(ENTRIES[entry](item.cwd, path), FAMILIES[item.family]!.rule)
      })
    }
  }
})

describe("batch 35, re-review: C7b with tilde, exact form with the tilde expanded", () => {
  const variants = [
    ["write", "whitespace", "~/plugin_opencode/.. "],
    ["write", "quote", '~/plugin_opencode/.."'],
    ["edit", "whitespace", "~/plugin_opencode/.. "],
    ["edit", "quote", '~/plugin_opencode/.."'],
    ["patch", "quote", '~/plugin_opencode/.."'],
  ] as const
  for (const [entry, variant, path] of variants) {
    it(`C7b × family 5 (plugin directory), tilde: ${entry}, ${variant}`, () => {
      assert.ok(openCodeForm(PROJECT, entry === "patch" ? path.trim() : path).startsWith(`${PLUGIN}/`))
      assert.equal(ENTRIES[entry](PROJECT, path), "self-protection")
    })
  }
})

describe("batch 35, re-review: multiple paths in one call, strictest finding", () => {
  const STARTUP = "~/.bashrc"
  const OWN_CONFIG = "~/.config/opencode/opencode.jsonc"
  const off = { dangerousCommands: false, sensitiveFiles: false }
  it("patch: self-protection reported regardless of the target's position", () => {
    for (const targets of [[STARTUP, OWN_CONFIG], [OWN_CONFIG, STARTUP]]) {
      const patchText = ["*** Begin Patch", ...targets.flatMap((target) => [`*** Add File: ${target}`, "+x"]), "*** End Patch"].join("\n")
      const found = toolFinding("patch", { patchText }, context(PROJECT))
      assert.equal(found?.rule, "self-protection", targets.join(" then "))
      assert.equal(found?.verdict, "ask")
      assert.equal(toolFinding("patch", { patchText }, { ...context(PROJECT), active: off })?.rule, "self-protection")
    }
  })
  it("path arguments of an MCP tool: self-protection reported regardless of the argument's position", () => {
    for (const filePaths of [[STARTUP, OWN_CONFIG], [OWN_CONFIG, STARTUP]]) {
      const found = toolFinding("tool_x", { filePaths }, context(PROJECT))
      assert.equal(found?.rule, "self-protection", filePaths.join(" then "))
      assert.equal(found?.verdict, "ask")
    }
    // Distinct keys, one under a path key, the other by its form.
    for (const input of [{ filePath: STARTUP, other: OWN_CONFIG }, { filePath: OWN_CONFIG, other: STARTUP }])
      assert.equal(toolFinding("tool_x", input, context(PROJECT))?.rule, "self-protection", JSON.stringify(input))
  })
  it("MCP arguments: a credentials file placed before a protected location keeps its place (previous finding)", () => {
    // Harmless path, then credentials file, then protected locations: the location finding does not move up
    // to the place of a path that does not have one.
    // The walk reads an object's keys starting from the last: order checked first.
    const input = { sourcePath: "~/.aws/credentials", filePath: "docs/notes.md", more: STARTUP, other: OWN_CONFIG }
    assert.deepEqual(argumentPaths(input), ["docs/notes.md", "~/.aws/credentials", OWN_CONFIG, STARTUP])
    const found = toolFinding("tool_x", input, context(PROJECT))
    assert.equal(found?.rule, "secret-file-read")
    assert.equal(found?.verdict, "ask")
    // Credentials files cut off: the strictest protected location.
    assert.equal(toolFinding("tool_x", input, { ...context(PROJECT), active: { dangerousCommands: true, sensitiveFiles: false } })?.rule, "self-protection")
  })
})
