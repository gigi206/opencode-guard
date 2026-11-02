// Lot 48 step H, ported: the user's rules in the global guard.json, read with the same checks as the `rules` option,
// added to them and re-read with the file in every reader of the rules (tool calls of every kind, `permission.evaluate`
// sub-commands, scripts run, `guard test`); kept while the file is present but cannot be used; `guard rules add|remove`;
// the fixes of review RH. Each case runs the plugin as OpenCode does (`setupGuard`, configuration directories of the
// test, test clock) or the command line in process; nothing is launched, text is judged. Only existing exports are
// imported at the top, so that the deployed code fails on assertions, not on loading.
import "./tmp.ts"
import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { setupGuard } from "../src/index.ts"
import { fakeContext } from "./fake-ctx.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>

/** A marker no built-in rule knows, and the user's deny rule on it for every tool. */
const MARK = "zq-forbidden-op"
const DENY_MARK = { id: "no-mark", pattern: MARK, verdict: "deny", reason: "marked operation", tools: "*" }
/** Shell only (the script written holds it): a deny rule on another marker. */
const SCRIPT_MARK = "zq-script-op"
const DENY_SCRIPT = { id: "no-script-mark", pattern: SCRIPT_MARK, verdict: "deny" }

interface Setup {
  readonly options?: Json
  readonly global?: Json
  readonly globalGuard?: Json | string
  readonly projectGuard?: Json
}

/** Plugin set up as OpenCode does: configuration directories, session directory `<root>/work/app`, test clock. */
async function guard(setup: Setup = {}) {
  const root = mkdtempSync(join(tmpdir(), "guard-rul-"))
  const [globalDir, systemDir, project] = [join(root, "global"), join(root, "system"), join(root, "work", "app")]
  for (const dir of [globalDir, systemDir, join(project, ".opencode")]) mkdirSync(dir, { recursive: true })
  const globalFile = join(globalDir, "guard.json")
  const write = (file: string, content: Json | string | undefined) => {
    if (content !== undefined) writeFileSync(file, typeof content === "string" ? content : JSON.stringify(content).replaceAll("<ROOT>", root))
  }
  if (setup.global) write(join(globalDir, "opencode.json"), { plugins: [{ package: PLUGIN_DIR, options: setup.global }] })
  write(globalFile, setup.globalGuard)
  write(join(project, ".opencode", "guard.json"), setup.projectGuard)
  const logFile = join(root, "guard.log")
  const fake = fakeContext({ logFile, ...(setup.options ?? {}) })
  ;(fake.ctx.location as { directory: string }).directory = project
  let now = 1_000_000
  await (setupGuard as (...args: unknown[]) => Promise<void>)(fake.ctx, {}, systemDir, globalDir, { now: () => now, intervalMs: 2000 })
  let call = 0
  /** Verdict of a call in `execute.before`: deny (blocked), ask (a confirmation was requested) or allow. */
  const verdict = async (tool: string, input: Json, sessionID = "ses_1") => {
    const before = fake.asserts.length
    try {
      await fake.trigger("tool.execute.before", { sessionID, agent: "build", messageID: "msg_0", id: `call_${++call}`, tool, input })
    } catch (error) {
      if (/Blocked/.test(String(error))) return "deny"
      throw error
    }
    return fake.asserts.length > before ? "ask" : "allow"
  }
  return {
    ...fake,
    root,
    project,
    globalFile,
    log: () => readFileSync(logFile, "utf8"),
    write,
    /** Next check of the guard.json files is due. */
    tick: () => (now += 2000),
    verdict,
    shell: (command: string) => verdict("shell", { command }),
    /** Effect left by `permission.evaluate` on a shell sub-command (a call `execute.before` did not see). */
    evaluate: async (command: string) => {
      const event = { sessionID: "ses_1", agent: "build", action: "shell", resources: [command], effect: "allow", message: undefined, source: { type: "tool", messageID: "msg_0", id: `other_${++call}` } }
      await fake.trigger("permission.evaluate", event)
      return event.effect
    },
    /** A script written by the agent in this session (tracked), then the verdict of running it. */
    script: async (name: string, content: string) => {
      const input = { path: name, content }
      const event = { sessionID: "ses_1", agent: "build", messageID: "msg_w", id: `w_${++call}`, tool: "write", input }
      await fake.trigger("tool.execute.before", event)
      writeFileSync(join(project, name), content)
      await fake.trigger("tool.execute.after", { ...event, status: "completed", result: { content: "ok" } })
      return verdict("shell", { command: `bash ${name}` })
    },
  }
}
type Plugin = Awaited<ReturnType<typeof guard>>

/** The rule's verdict in each reader: shell call, sub-command, script run, another tool, CodeMode code. */
async function readers(plugin: Plugin, round: number) {
  return {
    shell: await plugin.shell(`echo ${MARK}`),
    evaluate: await plugin.evaluate(`echo ${MARK}`),
    script: await plugin.script(`run${round}.sh`, `echo ${SCRIPT_MARK}\n`),
    read: await plugin.verdict("read", { path: `notes/${MARK}.txt` }),
    execute: await plugin.verdict("execute", { code: `await tools.read({ path: "${MARK}" })` }),
  }
}

describe("lot 48 step H: rules in the global guard.json", () => {
  it("RUL-1: a deny rule added after startup by a re-read applies in every reader; removed by a re-read, it no longer does", async () => {
    const plugin = await guard({ globalGuard: {} })
    assert.deepEqual(await readers(plugin, 0), { shell: "allow", evaluate: "allow", script: "allow", read: "allow", execute: "allow" })
    plugin.write(plugin.globalFile, { rules: [DENY_MARK, DENY_SCRIPT] })
    plugin.tick()
    // A script's finding is at most an ask (it may hold branches that are not run).
    assert.deepEqual(await readers(plugin, 1), { shell: "deny", evaluate: "deny", script: "ask", read: "deny", execute: "deny" })
    plugin.write(plugin.globalFile, { rules: [] })
    plugin.tick()
    assert.deepEqual(await readers(plugin, 2), { shell: "allow", evaluate: "allow", script: "allow", read: "allow", execute: "allow" })
    // Present at startup, then the file removed: the rule goes with it.
    const started = await guard({ globalGuard: { rules: [DENY_MARK] } })
    assert.equal(await started.shell(`echo ${MARK}`), "deny")
    rmSync(started.globalFile)
    started.tick()
    assert.equal(await started.shell(`echo ${MARK}`), "allow")
  })

  it("RUL-2: rules anywhere else than the top level of the global guard.json are ignored with a warning", async () => {
    const warning = /rules ignored: your rules count only in the plugin options and at the top level of the global guard\.json/
    const project = await guard({ projectGuard: { rules: [DENY_MARK] }, globalGuard: { trustedProjects: ["<ROOT>/work/app"] } })
    assert.equal(await project.shell(`echo ${MARK}`), "allow")
    assert.match(project.log(), new RegExp(`WARN project guard\\.json \\([^)]*\\): ${warning.source}`))
    const sections = await guard({ globalGuard: { agents: { build: { rules: [DENY_MARK] } }, projects: { "<ROOT>/work/app": { rules: [DENY_MARK] } } } })
    assert.equal(await sections.shell(`echo ${MARK}`), "allow")
    assert.match(sections.log(), new RegExp(`WARN global guard\\.json, agents\\.build: ${warning.source}`))
    assert.match(sections.log(), new RegExp(`WARN global guard\\.json, projects\\["[^"]+"\\]: ${warning.source}`))
  })

  it("RUL-3: the options' rules and the global guard.json's add up; a shared identifier is reported and both apply", async () => {
    const plugin = await guard({ options: { rules: [{ id: "shared", pattern: "zq-asked-op", verdict: "ask" }] }, globalGuard: { rules: [{ ...DENY_MARK, id: "shared" }, { pattern: "zq-plain", verdict: "ask" }] } })
    assert.equal(await plugin.shell("echo zq-asked-op"), "ask")
    assert.equal(await plugin.shell(`echo ${MARK}`), "deny")
    assert.match(plugin.log(), /WARN global guard\.json: rules: "shared" is also the identifier of a rule of the plugin options: both rules apply/)
    // A rule without an identifier gets the file's own default, never one of the options' (`custom-<index>`).
    assert.equal(await plugin.shell("echo zq-plain"), "ask")
    assert.equal(plugin.asserts.at(-1)?.metadata?.rule, "guard-json-1")
    assert.doesNotMatch(plugin.log(), /"custom-1" is also/)
  })

  it("RUL-4: the global guard.json made invalid after startup: its rules read last still deny, logged at the error level", async () => {
    const plugin = await guard({ globalGuard: { rules: [DENY_MARK] } })
    plugin.write(plugin.globalFile, "{ not json")
    plugin.tick()
    assert.equal(await plugin.shell(`echo ${MARK}`), "deny")
    assert.equal(await plugin.evaluate(`echo ${MARK}`), "deny")
    assert.match(plugin.log(), /ERROR global guard\.json ignored: it is not valid JSON; the rule read from it last stays in force until it is valid again/)
    // Still invalid, changed again: still kept; valid again: its content counts.
    plugin.write(plugin.globalFile, "{ still not json")
    plugin.tick()
    assert.equal(await plugin.shell(`echo ${MARK}`), "deny")
    plugin.write(plugin.globalFile, {})
    plugin.tick()
    assert.equal(await plugin.shell(`echo ${MARK}`), "allow")
    // Invalid at startup: nothing to keep, a warning as before.
    const broken = await guard({ globalGuard: "{ not json" })
    assert.equal(await broken.shell(`echo ${MARK}`), "allow")
    assert.match(broken.log(), /WARN global guard\.json ignored: it is not valid JSON/)
  })

  it("RUL-5: ruleOverrides naming a rule of the global guard.json is ignored with the warning of an option's rule", async () => {
    const warning = 'ruleOverrides["mine"] ignored: it names one of your rules (set its verdict in rules)'
    const plugin = await guard({ globalGuard: { rules: [{ ...DENY_MARK, id: "mine" }], ruleOverrides: { mine: "off" } } })
    assert.ok(plugin.log().includes(`WARN global guard.json: ${warning}`), plugin.log())
    assert.equal(await plugin.shell(`echo ${MARK}`), "deny")
    // A rule of the guard.json under a built-in identifier: a setting of that identifier read from the global
    // configuration is ignored too (it would apply to the user's rule).
    const relax = { ruleOverrides: { "git-reset-hard": "off" } }
    const builtin = await guard({ global: relax, options: relax, globalGuard: { rules: [{ ...DENY_MARK, id: "git-reset-hard" }] } })
    assert.equal(await builtin.shell("git reset --hard"), "ask")
    assert.equal(await builtin.shell(`echo ${MARK}`), "deny")
    assert.match(builtin.log(), /WARN ruleOverrides\.git-reset-hard ignored: it names one of your rules \(set its verdict in rules\)/)
  })

  it("RUL-14: control: the same deny rule given in the rules option at startup also gives an ask in a script run", async () => {
    // A script's finding is at most an ask by design (`scriptFinding`): the reader of RUL-1 behaves as for the option.
    const plugin = await guard({ options: { rules: [DENY_SCRIPT] } })
    assert.equal(await plugin.script("run.sh", `echo ${SCRIPT_MARK}\n`), "ask")
    assert.equal(await plugin.shell(`echo ${SCRIPT_MARK}`), "deny")
  })

  it("RUL-6: the settings of a call cannot be resolved: the rules in force still apply, not only the startup ones", async () => {
    const { registerGate } = await import("../src/hooks/gate.ts")
    const { createDecider } = await import("../src/decide.ts")
    const { createRedactor } = await import("../src/secrets/redact.ts")
    const { parseConfig } = await import("../src/config.ts")
    const { config } = parseConfig({})
    const redactor = createRedactor()
    const decider = createDecider({ config, redactor })
    const fake = fakeContext()
    const rules = [{ id: "no-mark", verdict: "deny" as const, reason: "marked operation", pattern: new RegExp(MARK), tools: ["*"] }]
    const scopes = {
      resolve: () => {
        throw new Error("simulated internal error")
      },
      sectioned: () => false,
      tracking: () => false,
      refresh() {},
      rules: () => rules,
    }
    await registerGate(fake.ctx, { decider, redactor, rules: config.rules, scopes, log: { debug() {}, info() {}, warn() {}, error() {} } } as Parameters<typeof registerGate>[1])
    const event = { sessionID: "ses_1", agent: "build", messageID: "msg_0", id: "call_1", tool: "shell", input: { command: `echo ${MARK}` } }
    await assert.rejects(fake.trigger("tool.execute.before", event), /Blocked/)
  })
})

type Main = (argv: readonly string[], io: unknown) => number

/** Configuration directories and the command line run in process on them (imported here: loading never fails the test). */
async function cli(setup: { readonly global?: Json; readonly globalGuard?: Json } = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-rulcli-")))
  const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "app")]
  for (const dir of [globalDir, systemDir, home, data, project]) mkdirSync(dir, { recursive: true })
  if (setup.global) writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: setup.global }] }))
  const guardFile = join(globalDir, "guard.json")
  if (setup.globalGuard) writeFileSync(guardFile, JSON.stringify(setup.globalGuard))
  const { main } = (await import(new URL("../src/cli/main.ts", import.meta.url).href)) as { main: Main }
  return {
    root,
    globalDir,
    systemDir,
    project,
    guardFile,
    text: () => (existsSync(guardFile) ? readFileSync(guardFile, "utf8") : undefined),
    read: () => JSON.parse(readFileSync(guardFile, "utf8")) as Json,
    run: (args: readonly string[], terminal?: { width: number; color: boolean }) => {
      const out: string[] = []
      const err: string[] = []
      const io = { env: { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }, cwd: project, systemDir, out: (line: string) => out.push(line), err: (line: string) => err.push(line) }
      const code = main(args, { ...io, ...(terminal ? { terminal } : {}) })
      return { code, out: out.join("\n"), err: err.join("\n"), lines: out }
    },
  }
}

/** Verdict of a shell call by the plugin set up on the command line's directories. */
async function plugged(w: Awaited<ReturnType<typeof cli>>, command: string) {
  const fake = fakeContext({ logFile: join(w.root, "plugin.log") })
  ;(fake.ctx.location as { directory: string }).directory = w.project
  await (setupGuard as (...args: unknown[]) => Promise<void>)(fake.ctx, {}, w.systemDir, w.globalDir, { now: () => 1_000_000, intervalMs: 2000 })
  const before = fake.asserts.length
  try {
    await fake.trigger("tool.execute.before", { sessionID: "ses_1", agent: "build", messageID: "msg_0", id: "call_1", tool: "shell", input: { command } })
  } catch (error) {
    if (/Blocked/.test(String(error))) return "deny"
    throw error
  }
  return fake.asserts.length > before ? "ask" : "allow"
}

describe("lot 48 step H: guard rules add|remove", () => {
  it("RUL-7: add writes the rule in the global guard.json, the plugin applies it, rules lists it under its source", async () => {
    const w = await cli({ global: { rules: [{ id: "from-options", pattern: "zq-option", verdict: "ask" }] }, globalGuard: { trustedProjects: ["/nowhere"] } })
    const r = w.run(["rules", "add", "no-mark", "--pattern", `--${MARK}`, "--verdict", "deny", "--reason", "marked operation"])
    assert.equal(r.code, 0, r.err)
    assert.equal(r.out, `rule no-mark (deny) added to rules in ${w.guardFile}`)
    assert.deepEqual(w.read(), { trustedProjects: ["/nowhere"], rules: [{ id: "no-mark", pattern: `--${MARK}`, verdict: "deny", reason: "marked operation" }] })
    assert.equal(await plugged(w, `echo --${MARK}`), "deny")
    const more = w.run(["rules", "add", "reads", "--pattern=zq-read", "--verdict=ask", "--tools", "read, glob", "--flags", "i"])
    assert.equal(more.code, 0, more.err)
    assert.deepEqual((w.read().rules as Json[])[1], { id: "reads", pattern: "zq-read", verdict: "ask", tools: ["read", "glob"], flags: "i" })
    const listed = w.run(["rules", "--custom"])
    assert.equal(listed.code, 0, listed.err)
    const at = listed.lines.indexOf(`Your rules (rules of the global guard.json ${w.guardFile}):`)
    assert.ok(at > 0, listed.out)
    assert.equal(listed.lines[0], "Your rules (rules option of the global configuration):")
    assert.match(listed.lines[1]!, /^ {2}from-options +ask /)
    assert.match(listed.lines[at + 1]!, /^ {2}no-mark +deny +shell +marked operation /)
    assert.match(listed.lines[at + 2]!, /^ {2}reads +ask +read,glob +custom rule 1 of the global guard\.json +\/zq-read\/i$/)
    const pretty = w.run(["rules", "--custom"], { width: 80, color: false })
    assert.ok(pretty.lines.some((line) => line.startsWith("  From the global guard.json") && line.includes(w.guardFile)), pretty.out)
  })

  it("RUL-8: refused, nothing written: verdict, pattern, built-in or reserved identifier, identifier used by either source", async () => {
    const w = await cli({ global: { rules: [{ id: "from-options", pattern: "zq-option", verdict: "ask" }] }, globalGuard: { rules: [{ id: "from-file", pattern: "zq-file", verdict: "ask" }] } })
    const before = w.text()
    const cases: Array<[string[], RegExp]> = [
      [["rules", "add", "x", "--pattern", "zq", "--verdict", "block"], /the verdict must be "ask" or "deny"/],
      [["rules", "add", "x", "--pattern", "zq-(", "--verdict", "deny"], /the pattern of x is not a valid regular expression$/],
      [["rules", "add", "x", "--pattern", "zq", "--verdict", "deny", "--flags", "q"], /the pattern of x is not a valid regular expression with these flags/],
      [["rules", "add", "eval", "--pattern", "zq", "--verdict", "deny"], /eval is the identifier of a built-in rule/],
      [["rules", "add", "placeholder", "--pattern", "zq", "--verdict", "deny"], /placeholder is the identifier of a built-in rule/],
      [["rules", "add", "internal-error", "--pattern", "zq", "--verdict", "deny"], /internal-error is reserved/],
      [["rules", "add", "from-options", "--pattern", "zq", "--verdict", "deny"], /a rule from-options already exists in the rules option of the global configuration/],
      [["rules", "add", "from-file", "--pattern", "zq", "--verdict", "deny"], new RegExp(`a rule from-file already exists in rules of ${w.guardFile.replaceAll(".", "\\.")}`)],
    ]
    for (const [args, message] of cases) {
      const r = w.run(args)
      assert.equal(r.code, 1, args.join(" "))
      assert.match(r.err, /^guard: refused, nothing written: /)
      assert.match(r.err, message)
      assert.ok(!r.err.includes("zq-("), "never the pattern")
      assert.equal(w.text(), before)
    }
    // Usage errors (code 2), nothing written.
    for (const args of [["rules", "add", "x", "--verdict", "deny"], ["rules", "add", "x", "--pattern", "zq"], ["rules", "remove", "x", "--pattern", "zq"], ["rules", "add", "x", "--pattern", "zq", "--verdict", "deny", "--custom"], ["rules", "add", "x", "--pattern", "zq", "--verdict", "deny", "--tools", ","], ["rules", "--verdict", "deny"]]) {
      assert.equal(w.run(args).code, 2, args.join(" "))
      assert.equal(w.text(), before)
    }
  })

  it("RUL-9: remove: from the file only (the last one removes the list); a rule of the rules option is never removed", async () => {
    const w = await cli({ global: { rules: [{ id: "from-options", pattern: "zq-option", verdict: "ask" }] }, globalGuard: { localAsks: "ask", rules: [{ id: "a", pattern: "zq-a", verdict: "deny" }, { id: "b", pattern: "zq-b", verdict: "ask" }] } })
    const first = w.run(["rules", "remove", "a"])
    assert.equal(first.code, 0, first.err)
    assert.equal(first.out, `rule a removed from rules in ${w.guardFile}`)
    assert.deepEqual(w.read(), { localAsks: "ask", rules: [{ id: "b", pattern: "zq-b", verdict: "ask" }] })
    assert.equal(w.run(["rules", "remove", "b"]).code, 0)
    assert.deepEqual(w.read(), { localAsks: "ask" })
    const absent = w.run(["rules", "remove", "b"])
    assert.equal(absent.code, 0)
    assert.equal(absent.out, `rule b is not in rules of ${w.guardFile}: nothing changed`)
    const before = w.text()
    const option = w.run(["rules", "remove", "from-options"])
    assert.equal(option.code, 1)
    assert.equal(option.err, "guard: rule from-options is defined only in the rules option of the global configuration (opencode.json), which guard never writes: nothing removed")
    assert.equal(w.text(), before)
  })

  it("RUL-10: a pattern holding a secret never appears in what the command prints", async () => {
    const fake = `ghp_${"a1B2".repeat(9)}`
    const w = await cli({ global: { rules: [{ id: "taken", pattern: "zq-taken", verdict: "ask" }] } })
    const runs = [
      w.run(["rules", "add", "token", "--pattern", fake, "--verdict", "deny"]),
      w.run(["rules", "add", "taken", "--pattern", fake, "--verdict", "deny"]),
      w.run(["rules", "add", "broken", "--pattern", `${fake}(`, "--verdict", "deny"]),
      w.run(["rules"]),
      w.run(["rules", "--custom"], { width: 80, color: true }),
      w.run(["rules", "remove", "token"]),
    ]
    assert.deepEqual(runs.map((r) => r.code), [0, 1, 1, 0, 0, 0])
    for (const r of runs) assert.ok(!`${r.out}\n${r.err}`.includes(fake), `${r.out}\n${r.err}`)
    assert.ok(runs[3]!.out.includes("[[GUARD_REDACTED:"), "listed, redacted")
  })
})

/** bash present: the completion script is run by it (as in `cli-completion.test.ts`). */
const bash = () => {
  try {
    execFileSync("bash", ["-c", "true"])
    return true
  } catch {
    return false
  }
}

describe("lot 48 step H, ported: the readers of the new base", () => {
  it("PH-1: guard test applies the rules of the global guard.json, like the plugin; an unusable file is said", async () => {
    const w = await cli({ global: {}, globalGuard: { rules: [DENY_MARK] } })
    const { testCall } = (await import(new URL("../src/cli/test.ts", import.meta.url).href)) as {
      testCall: (io: unknown, request: unknown) => Promise<{ verdict: string; rule?: string; notes: readonly string[] }>
    }
    const io = { env: { HOME: join(w.root, "home"), OPENCODE_CONFIG_DIR: w.globalDir, XDG_DATA_HOME: join(w.root, "data") }, cwd: w.project, systemDir: w.systemDir, out: () => {}, err: () => {} }
    const shell = await testCall(io, { tool: "shell", input: { command: `echo ${MARK}` }, model: false })
    const read = await testCall(io, { tool: "read", input: { path: `notes/${MARK}.txt` }, model: false })
    assert.deepEqual([shell.verdict, shell.rule, read.verdict, read.rule], ["deny", "no-mark", "deny", "no-mark"])
    assert.equal(await plugged(w, `echo ${MARK}`), "deny")
    writeFileSync(w.guardFile, "{ not json")
    const broken = await testCall(io, { tool: "shell", input: { command: `echo ${MARK}` }, model: false })
    assert.match(broken.notes.join("\n"), /the global guard\.json is ignored \(it is not valid JSON\): a running plugin keeps the rules it read from it last, not seen here/)
  })

  it("PH-2: a shell request without a tool call (scheduled task): an ask of a rule of the global guard.json is denied", async () => {
    const plugin = await guard({ globalGuard: {} })
    const unattended = async () => {
      // `source` given as absent: the fake context otherwise adds a tool call's.
      const event: Json = { sessionID: "ses_1", agent: "build", action: "shell", resources: ["echo zq-asked-op"], effect: "allow", message: undefined, source: undefined }
      await plugin.trigger("permission.evaluate", event)
      return event.effect
    }
    assert.equal(await unattended(), "allow")
    plugin.write(plugin.globalFile, { rules: [{ id: "asked", pattern: "zq-asked-op", verdict: "ask" }] })
    plugin.tick()
    assert.equal(await unattended(), "deny")
  })

  it("PH-3: completion of rules add and remove: the words, the options of add, the verdicts, free values", { skip: !bash() && "bash not installed" }, async () => {
    const { completionScript } = (await import(new URL("../src/cli/completion.ts", import.meta.url).href)) as { completionScript: (shell: string) => string }
    const complete = (...line: string[]) => {
      const words = ["guard", ...line]
      const script = `${completionScript("bash")}\nCOMP_WORDS=(${words.map((word) => `'${word}'`).join(" ")}); COMP_CWORD=${words.length - 1}\n_guard; printf '%s\\n' "\${COMPREPLY[@]}"`
      return execFileSync("bash", ["--norc", "--noprofile", "-c", script], { encoding: "utf8", env: { PATH: process.env.PATH ?? "/usr/bin:/bin" } }).split("\n").filter(Boolean)
    }
    assert.deepEqual(complete("rules", "ad"), ["add"])
    assert.deepEqual(complete("rules", "rem"), ["remove"])
    assert.deepEqual(complete("rules", "add", "mine", ""), ["--pattern", "--verdict", "--reason", "--tools", "--flags"])
    assert.deepEqual(complete("rules", "add", "mine", "--verdict", ""), ["ask", "deny"])
    for (const option of ["--pattern", "--reason", "--tools", "--flags"]) assert.deepEqual(complete("rules", "add", "mine", option, ""), [], option)
    assert.deepEqual(complete("rules", "remove", ""), [])
  })

  it("PH-4: rules add and remove write the top level only (--agent, --project: usage errors); help lists them", async () => {
    const w = await cli({ globalGuard: { rules: [{ id: "a", pattern: "zq-a", verdict: "deny" }] } })
    const before = w.text()
    for (const args of [
      ["rules", "add", "x", "--pattern", "zq", "--verdict", "deny", "--agent", "build"],
      ["rules", "add", "x", "--pattern", "zq", "--verdict", "deny", "--project"],
      ["rules", "remove", "a", "--agent", "build"],
    ]) {
      const r = w.run(args)
      assert.equal(r.code, 2, args.join(" "))
      assert.match(r.err, /^guard: rules (add|remove) writes the top level of the global guard\.json only \(no --agent or --project\)/)
      assert.equal(w.text(), before)
    }
    const help = w.run(["help"]).out
    const change = help.indexOf("Change (in the global guard.json only):")
    for (const usage of ["rules add <id>", "--pattern <regex>", "--verdict ask|deny", "--reason <text>", "--tools <tools>|*", "--flags <flags>", "rules remove <id>"])
      assert.ok(change > 0 && help.indexOf(`  ${usage}`, change) > change, usage)
  })
})

describe("lot 48 step H, ported: fixes of review RH", () => {
  it("CRC-19 (RH-3): a valid file whose rules became unusable by an edit: the deny rule read last stays, logged as an error", async () => {
    const edits: Record<string, Json> = { "not a list": { rules: DENY_MARK }, "invalid pattern": { rules: [{ ...DENY_MARK, pattern: `${MARK}(` }] } }
    const seen: Record<string, string> = {}
    for (const [name, edited] of Object.entries(edits)) {
      const plugin = await guard({ globalGuard: { rules: [DENY_MARK] } })
      plugin.write(plugin.globalFile, edited)
      plugin.tick()
      seen[name] = `${await plugin.shell(`echo ${MARK}`)}, ${/ERROR global guard\.json/.test(plugin.log()) ? "error" : "no error"}`
    }
    assert.deepEqual(seen, { "not a list": "deny, error", "invalid pattern": "deny, error" })
  })

  it("CRC-26: guard rules: the note about the option's list comes right after that list, before the global guard.json's", async () => {
    const w = await cli({ global: { rules: [{ id: "opt-rule", pattern: "zq-opt", verdict: "deny" }] }, globalGuard: { rules: [{ id: "file-rule", pattern: "zq-file", verdict: "ask" }] } })
    const lines = w.run(["rules", "--custom"]).lines
    const note = lines.findIndex((line) => line.startsWith("  Not shown: a project's opencode.json"))
    const file = lines.findIndex((line) => line.startsWith("Your rules (rules of the global guard.json"))
    assert.ok(note > 0 && file > note && lines[note - 1]!.includes("opt-rule"), lines.join("\n"))
  })

  it("CRC-24: a rule's value already written where the plugin sets it aside: its warning is said with nothing changed", async () => {
    const w = await cli({ globalGuard: { ruleOverrides: { "guard-cli": "model", "self-protection": "model", eval: "deny" } } })
    const user = w.run(["rules", "model", "guard-cli"])
    assert.match(user.out, /nothing changed/)
    assert.match(user.out, /but the plugin ignores it there: global guard\.json: ruleOverrides\.guard-cli "model" ignored/)
    const always = w.run(["rules", "model", "self-protection"])
    assert.match(always.out, /but the plugin ignores it there: ruleOverrides\.self-protection "model" ignored: this rule is always active/)
    // Witness: a value in force there says nothing more.
    const held = w.run(["rules", "deny", "eval"])
    assert.match(held.out, /nothing changed/)
    assert.doesNotMatch(held.out, /ignores it/)
  })

  it("CRC-25: removing a rule written under a built-in identifier says the ruleOverrides of that rule applies again", async () => {
    const w = await cli({ globalGuard: { ruleOverrides: { eval: "off" }, rules: [{ id: "eval", pattern: "zq-eval", verdict: "deny" }] } })
    const r = w.run(["rules", "remove", "eval"])
    assert.equal(r.code, 0, r.err)
    assert.match(r.out, /ruleOverrides\.eval "off" \(global guard\.json\) applies again to the built-in rule eval/)
  })
})

/** Runs `body`, then removes what it may have set on the prototype of every object (the defect of RH-7, in `p0/`). */
const unpolluted = async (keys: readonly string[], body: () => Promise<void>) => {
  try {
    await body()
  } finally {
    for (const key of keys) delete (Object.prototype as Record<string, unknown>)[key]
  }
}

// Last: in the deployed code, these cases may set keys on the prototype of every object while they run.
describe("lot 48 step H, ported: names that reach the prototype (RH-7)", () => {
  it("CRC-20 (RH-7): a rule's setting for an agent named __proto__ is refused, never a success with nothing written", () =>
    unpolluted(["ruleOverrides"], async () => {
      const w = await cli({ globalGuard: {} })
      const r = w.run(["rules", "deny", "git-reset-hard", "--agent", "__proto__"])
      const data = w.read()
      const written = Object.hasOwn(data, "agents") && Object.hasOwn(data.agents as Json, "__proto__")
      assert.ok(r.code !== 0 || written, `${r.code} ${r.out.replace(/ of \/.*/, "")} ${w.text()?.replace(/\s+/g, " ")}`)
    }))

  it("CRC-23: __proto__, constructor and prototype refused as agent or rule names; another inherited name works as an own key", () =>
    unpolluted(["scripts", "ruleOverrides", "rules"], async () => {
      const w = await cli({ globalGuard: {} })
      for (const args of [
        ["set", "scripts", "false", "--agent", "constructor"],
        ["rules", "deny", "git-reset-hard", "--agent", "prototype"],
        ["rules", "add", "__proto__", "--pattern", "zq-x", "--verdict", "deny"],
      ]) {
        const r = w.run(args)
        assert.equal(r.code !== 0 && /it would reach every object's prototype/.test(r.err), true, `${args.join(" ")}: ${r.code} ${r.err}`)
      }
      assert.deepEqual(w.read(), {})
      const r = w.run(["rules", "deny", "git-reset-hard", "--agent", "toString"])
      assert.equal(r.code, 0, r.err)
      assert.deepEqual(w.read(), { agents: { toString: { ruleOverrides: { "git-reset-hard": "deny" } } } })
    }))
})
