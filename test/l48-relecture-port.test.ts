// Lot 48, review of steps H and C ported to the current base: the points of contact the porters' tests may miss (a shell
// request without a tool call, the prompt's text, the command line of the exceptions, the policy after the merge, the
// re-read of the settings, the default settings, the base's redactionOff). Fake files and configuration directories only;
// the plugin is set up as OpenCode does (test clock, test home), the command line runs in process. Only existing exports
// are imported at the top, so that the base fails on assertions, not on loading.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { after, describe, it } from "node:test"
import { parseConfig, resolveVersion, type GuardFile } from "../src/config.ts"
import { setupGuard } from "../src/index.ts"
import { shellFinding } from "../src/rules/shell.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

type Json = Record<string, unknown>
type Main = (argv: readonly string[], io: unknown) => number | Promise<number>
const RULE = "secret-file-read"
const MINUTE = 60_000

const roots: string[] = []
after(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true })
})

/**
 * Configuration directories, a fake home holding a fake `.netrc`, a project (git repository) holding a fake `.env`, a fake
 * `.pgpass` elsewhere; the command line in process, and the plugin set up with a moving clock and the fake home.
 */
async function world(globalGuard?: Json) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-rp-")))
  roots.push(root)
  const [globalDir, systemDir, home, data, project, secrets] = [join(root, "g"), join(root, "s"), join(root, "h"), join(root, "d"), join(root, "w", "app"), join(root, "k")]
  for (const dir of [globalDir, systemDir, home, data, join(project, ".git"), join(project, ".opencode"), secrets]) mkdirSync(dir, { recursive: true })
  const [env, pgpass, netrc] = [join(project, ".env"), join(secrets, ".pgpass"), join(home, ".netrc")]
  writeFileSync(env, "API_KEY=dummy\n")
  writeFileSync(pgpass, "host:5432:db:user:dummy\n")
  writeFileSync(netrc, "machine example.org login me password dummy\n")
  const guardFile = join(globalDir, "guard.json")
  const save = (file: string, content: Json) => writeFileSync(file, JSON.stringify(content))
  if (globalGuard) save(guardFile, globalGuard)
  const { main } = (await import(new URL("../src/cli/main.ts", import.meta.url).href)) as { main: Main }
  return {
    root,
    globalDir,
    home,
    project,
    env,
    pgpass,
    netrc,
    guardFile,
    save,
    read: () => JSON.parse(readFileSync(guardFile, "utf8")) as Json,
    run: async (args: readonly string[]) => {
      const out: string[] = []
      const err: string[] = []
      const io = { env: { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }, cwd: project, systemDir, out: (line: string) => out.push(line), err: (line: string) => err.push(line) }
      const code = await main(args, io)
      return { code, out: out.join("\n"), err: err.join("\n") }
    },
    plugin: async (options: Json = {}) => {
      const logFile = join(root, "guard.log")
      const fake = fakeContext({ logFile, ...options })
      ;(fake.ctx.location as { directory: string }).directory = project
      let now = 1_000_000
      await (setupGuard as (...args: unknown[]) => Promise<void>)(fake.ctx, {}, systemDir, globalDir, { now: () => now, intervalMs: 2000 }, home)
      let call = 0
      let last = ""
      return {
        fake,
        /** Verdict of a shell call in `execute.before`: deny (blocked), refused (confirmation not granted), ask or allow. */
        shell: async (command: string, sessionID = "ses_1") => {
          const before = fake.asserts.length
          last = `call_${++call}`
          try {
            await fake.trigger("tool.execute.before", { sessionID, agent: "build", messageID: "msg_0", id: last, tool: "shell", input: { command } })
          } catch (error) {
            return /Blocked|unattended/i.test(String(error)) ? "deny" : "refused"
          }
          return fake.asserts.length > before ? "ask" : "allow"
        },
        /** The identifier of the last shell call. */
        lastId: () => last,
        /** `permission.evaluate` of shell sub-commands: a tool call's source (`id`, a new one by default), or none. */
        evaluate: async (commands: string[], source: string | null = `other_${++call}`) => {
          const event: Json = { sessionID: "ses_1", agent: "build", action: "shell", resources: commands, effect: "allow", message: undefined }
          event.source = source === null ? undefined : { type: "tool", messageID: "msg_0", id: source }
          await fake.trigger("permission.evaluate", event)
          return event.effect as string
        },
        /** Moves the clock (a guard.json check is due after 2 s). */
        tick: (ms = 2000) => (now += ms),
        log: () => readFileSync(logFile, "utf8"),
      }
    },
  }
}

describe("review of H and C ported", () => {
  it("RP-1: a shell request without a tool call: exception, memory and a rule of the global guard.json added after startup, together: denied", async () => {
    const w = await world({ rememberConfirmations: 10, exceptions: { [RULE]: [] } })
    w.save(w.guardFile, { rememberConfirmations: 10, exceptions: { [RULE]: [w.env] } })
    const plugin = await w.plugin()
    plugin.tick()
    // With a tool call: the exception lifts, the memory remembers a confirmed set.
    assert.equal(await plugin.evaluate([`cat ${w.env}`]), "allow")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "ask")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "allow")
    // A rule of the global guard.json added after startup, beside the exception and the memory.
    w.save(w.guardFile, { rememberConfirmations: 10, exceptions: { [RULE]: [w.env] }, rules: [{ id: "asked", pattern: "zq-asked", verdict: "ask" }] })
    plugin.tick()
    for (const command of [`cat ${w.env}`, `cat ${w.pgpass}`, "echo zq-asked", `cat ${w.env} zq-asked`]) assert.equal(await plugin.evaluate([command], null), "deny", command)
    // With a tool call: the exception never lifts another rule's ask on the same command.
    assert.equal(await plugin.shell(`cat ${w.env} zq-asked`), "ask")
    assert.equal(plugin.fake.asserts.at(-1)?.metadata?.rule, "asked")
    // A deny rule of the file on the excepted file: denied.
    w.save(w.guardFile, { rememberConfirmations: 10, exceptions: { [RULE]: [w.env] }, rules: [{ id: "no-env", pattern: "\\.env\\b", verdict: "deny" }] })
    plugin.tick()
    assert.equal(await plugin.shell(`cat ${w.env}`), "deny")
  })

  it("RP-2: default settings, the prompt's action: each file at most once, never cut; the full reason in the request and the log", async () => {
    const w = await world()
    const plugin = await w.plugin()
    const files = [w.netrc, join(w.home, ".pgpass"), join(w.home, ".git-credentials"), join(w.home, ".ssh", "id_rsa"), w.env]
    const commands = [
      "cat ~/.netrc",
      `wc -l ~/.netrc ${w.env}`,
      // Five files: three named, then how many more; home forms kept by the reason, absolute ones shown by the call.
      `wc -l ~/.netrc ~/.pgpass ~/.git-credentials ~/.ssh/id_rsa ${w.env}`,
      `head -c 10 ~/.netrc ${"x".repeat(150)}`,
    ]
    for (const command of commands) {
      const before = plugin.fake.asserts.length
      assert.equal(await plugin.shell(command), "ask", command)
      const posed = plugin.fake.asserts[before]!
      const reason = String(posed.metadata?.reason ?? "")
      assert.match(reason, /^access to a credential file \(/, command)
      for (const file of files) {
        const count = posed.action.split(file).length - 1
        assert.ok(count <= 1, `${command}: ${file} ${count} times in ${posed.action}`)
        // Never cut in the reason (the call may be cut, as before): no part of the path, past the shared root, then the ellipsis.
        const shown = posed.action.split(" · ")[1] ?? ""
        for (let size = w.root.length + 3; size < file.length; size++) assert.ok(!shown.includes(`${file.slice(0, size)}…`), `${command}: ${file} cut in ${posed.action}`)
      }
    }
    // The full reason: in the request's metadata and the log.
    const five = String(plugin.fake.asserts.at(-2)?.metadata?.reason)
    assert.equal(five, `access to a credential file (${w.netrc}, ${join(w.home, ".pgpass")}, ${join(w.home, ".git-credentials")} and 2 more)`)
    assert.ok(plugin.log().includes(five))
  })

  it("RP-3: rules off secret-file-read without --path turns the whole rule off; --path adds one file; reset --path removes only that file", async () => {
    const w = await world({})
    const whole = await w.run(["rules", "off", RULE])
    assert.equal(whole.code, 0, whole.err)
    assert.match(whole.out, /the whole rule secret-file-read is off there, for every file/)
    w.save(w.guardFile, {})
    const one = await w.run(["rules", "off", RULE, "--path", w.env])
    assert.equal(one.code, 0, one.err)
    assert.match(one.out, /added to exceptions\.secret-file-read/)
    assert.doesNotMatch(one.out, /whole rule/)
    assert.deepEqual(w.read(), { exceptions: { [RULE]: [w.env] } })
    w.save(w.guardFile, { ruleOverrides: { [RULE]: "off" }, exceptions: { [RULE]: [w.env, w.pgpass] } })
    assert.equal((await w.run(["rules", "reset", RULE, "--path", w.env])).code, 0)
    assert.deepEqual(w.read(), { ruleOverrides: { [RULE]: "off" }, exceptions: { [RULE]: [w.pgpass] } })
    assert.equal((await w.run(["rules", "reset", RULE])).code, 0)
    assert.deepEqual(w.read(), { exceptions: { [RULE]: [w.pgpass] } })
    assert.equal((await w.run(["rules", "reset", RULE, "--path", w.pgpass])).code, 0)
    assert.deepEqual(w.read(), {})
  })

  it("RP-4: exception and memory lift asks only: a deny setting, self-protection, a refused confirmation, the unattended mode", async () => {
    const denied = await world({ ruleOverrides: { [RULE]: "deny" }, exceptions: { [RULE]: [] }, rememberConfirmations: 10 })
    denied.save(denied.guardFile, { ruleOverrides: { [RULE]: "deny" }, exceptions: { [RULE]: [denied.env] }, rememberConfirmations: 10 })
    const strict = await denied.plugin()
    assert.equal(await strict.shell(`cat ${denied.env}`), "deny")
    // Self-protection beside a lifted read: still asked.
    const w = await world({ exceptions: { [RULE]: [] }, rememberConfirmations: 10 })
    w.save(w.guardFile, { exceptions: { [RULE]: [w.env] }, rememberConfirmations: 10 })
    const plugin = await w.plugin()
    assert.equal(await plugin.shell(`cat ${w.env}`), "allow")
    assert.equal(await plugin.shell(`cat ${w.env} && guard rules off rm`), "ask")
    assert.equal(await plugin.shell(`cat ${w.env} > ${w.guardFile}`), "ask")
    // Memory only after a confirmation granted.
    plugin.fake.onAssert(async () => {
      throw new Error("rejected")
    })
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "refused")
    plugin.fake.onAssert(async () => {})
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "ask")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "allow")
    // Unattended mode: nothing confirmed, nothing remembered.
    const auto = await w.plugin({ askAs: "deny" })
    assert.equal(await auto.shell(`cat ${w.pgpass}`), "deny")
    assert.equal(await auto.shell(`cat ${w.pgpass}`), "deny")
  })

  it("RP-5: re-read of the settings: an exception added then removed, a delay removed; agents section, untrusted project and non-absolute paths ignored", async () => {
    const w = await world({})
    const plugin = await w.plugin()
    assert.equal(await plugin.shell(`cat ${w.env}`), "ask")
    w.save(w.guardFile, { exceptions: { [RULE]: [w.env] }, rememberConfirmations: 10 })
    plugin.tick()
    assert.equal(await plugin.shell(`cat ${w.env}`), "allow")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "ask")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "allow")
    w.save(w.guardFile, {})
    plugin.tick()
    assert.equal(await plugin.shell(`cat ${w.env}`), "ask")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "ask")
    // Ignored with a warning: an agents section, a relative path, a home form; a home form never matches an absolute exception.
    w.save(w.guardFile, { agents: { build: { exceptions: { [RULE]: [w.env] } } }, exceptions: { [RULE]: [".env", "~/.netrc", w.netrc] } })
    plugin.tick()
    assert.equal(await plugin.shell(`cat ${w.env}`), "ask")
    assert.equal(await plugin.shell("cat ~/.netrc"), "ask")
    assert.equal(await plugin.shell(`cat ${w.netrc}`), "allow")
    const log = plugin.log()
    assert.match(log, /exceptions ignored: an agents section does not accept it/)
    assert.match(log, /exceptions\.secret-file-read\[0\] ignored: an absolute path is expected/)
    assert.match(log, /exceptions\.secret-file-read\[1\] ignored: an absolute path is expected/)
    // A project's guard.json: not trusted, ignored; trusted, applied.
    w.save(join(w.project, ".opencode", "guard.json"), { exceptions: { [RULE]: [w.pgpass] } })
    w.save(w.guardFile, {})
    plugin.tick()
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "ask")
    w.save(w.guardFile, { trustedProjects: [w.project] })
    plugin.tick()
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "allow")
  })

  it("RP-6: memory: the whole delay up to 60 min, strict end; sibling sub-commands of the same call only; none without a tool call", async () => {
    const w = await world({ rememberConfirmations: 60 })
    const plugin = await w.plugin()
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "ask")
    plugin.tick(59 * MINUTE)
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "allow")
    plugin.tick(MINUTE)
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "ask")
    // A set of two files, then the same command lifted by the memory: its sub-commands name part of the set.
    assert.equal(await plugin.shell(`cat ${w.env} ${w.pgpass}`), "ask")
    assert.equal(await plugin.shell(`cat ${w.env} ${w.pgpass}`), "allow")
    const id = plugin.lastId()
    assert.equal(await plugin.evaluate([`cat ${w.env}`, `cat ${w.pgpass}`], id), "allow")
    // Another call (a part of the set is not the set), and no tool call: asked, then denied.
    assert.equal(await plugin.evaluate([`cat ${w.env}`]), "ask")
    assert.equal(await plugin.evaluate([`cat ${w.env}`], null), "deny")
  })

  it("RP-7: default settings: no real path of an existing file looked up, no content read after the first file recognized by its name", () => {
    const calls = { existing: 0, contents: [] as string[] }
    const ctx = {
      redactor: createRedactor(),
      home: "/home/test",
      cwd: "/home/test/p",
      cwds: ["/home/test/p"],
      realPaths: (absolute: string, existing = false) => (existing && calls.existing++, [absolute]),
      credentialContent: (path: string) => (calls.contents.push(path), false),
    } as unknown as Parameters<typeof shellFinding>[1]
    const found = shellFinding("cat /home/test/p/notes /home/test/p/.env /home/test/p/more /home/test/p/other", ctx)
    assert.equal(found?.rule, RULE)
    assert.equal(calls.existing, 0)
    assert.deepEqual(calls.contents, ["cat", "/home/test/p/notes"])
  })

  it("RP-8: redactionOff of the global guard.json only (a trusted project's ignored); a global file become unusable: redactionOff dropped, its rules kept", () => {
    const project = "/srv/rp/app"
    const global: GuardFile = { label: "global guard.json", global: true, data: { redactionOff: ["twilio_key"], trustedProjects: [project], rules: [{ id: "zq", pattern: "zq-op", verdict: "deny" }] } }
    const local: GuardFile = { label: `${project}/.opencode/guard.json`, global: false, dir: project, data: { redactionOff: ["github_pat"] } }
    const inputs = { files: [global, local], project, realPath: (path: string) => path, regularFile: () => true }
    const { config } = parseConfig({}, {}, () => [], inputs)
    const first = resolveVersion(config.layers!, inputs.files)
    assert.deepEqual(first.redactionOff, ["twilio_key"])
    assert.ok(first.warnings.some((line) => line.includes("redactionOff ignored")), first.warnings.join("\n"))
    const broken = resolveVersion(config.layers!, [{ label: "global guard.json", global: true, reason: "invalid JSON" }, local], first)
    assert.equal(broken.redactionOff, undefined)
    assert.deepEqual(broken.rules.map((rule) => rule.id), ["zq"])
    assert.equal(broken.errors?.length, 1)
  })

  it("RP-9: command line: set|unset rememberConfirmations, --path with another rule, setting or --agent, rules --explain, test", async () => {
    const w = await world({})
    for (const value of ["0", "61", "abc", "1.5"]) assert.equal((await w.run(["set", "rememberConfirmations", value])).code, 1, value)
    assert.deepEqual(w.read(), {})
    assert.equal((await w.run(["set", "rememberConfirmations", "30"])).code, 0)
    assert.deepEqual(w.read(), { rememberConfirmations: 30 })
    for (const args of [
      ["set", "rememberConfirmations", "30", "--agent", "build"],
      ["unset", "rememberConfirmations", "--agent", "build"],
      ["rules", "ask", RULE, "--path", w.env],
      ["rules", "deny", RULE, "--path", w.env],
      ["rules", "off", "rm", "--path", w.env],
      ["rules", "reset", "rm", "--path", w.env],
      ["rules", "off", RULE, "--path", w.env, "--agent", "build"],
    ])
      assert.equal((await w.run(args)).code, 2, args.join(" "))
    assert.deepEqual(w.read(), { rememberConfirmations: 30 })
    const explained = await w.run(["rules", "--explain", RULE])
    assert.match(explained.out, /exceptions/)
    assert.match(explained.out, /rememberConfirmations/)
    assert.equal((await w.run(["rules", "off", RULE, "--path", w.env])).code, 0)
    const tested = await w.run(["test", "--", `cat ${w.env}`])
    assert.match(tested.out, /lifted by an exception/)
    const asked = await w.run(["test", "--", `cat ${w.pgpass}`])
    assert.match(asked.out, /rememberConfirmations \(30 min\) does not apply here/)
  })

  it("RP-10: a script written in the session that only reads the excepted file, run by bash: the read of the script's text", async () => {
    const w = await world({ exceptions: { [RULE]: [] } })
    w.save(w.guardFile, { exceptions: { [RULE]: [w.env] } })
    const plugin = await w.plugin()
    const input = { path: "run.sh", content: `cat ${w.env}\n` }
    const event = { sessionID: "ses_1", agent: "build", messageID: "msg_w", id: "w_1", tool: "write", input }
    await plugin.fake.trigger("tool.execute.before", event)
    writeFileSync(join(w.project, "run.sh"), input.content)
    await plugin.fake.trigger("tool.execute.after", { ...event, status: "completed", result: { content: "ok" } })
    // bash is not one of the readers of the list: the same read through bash -c asks.
    assert.equal(await plugin.shell(`bash -c 'cat ${w.env}'`), "ask")
    assert.equal(await plugin.shell("bash run.sh"), "ask")
  })

  it("RP-11: the same script run with its output redirected to a file or piped to a program out of the list: asked, as the direct read", async () => {
    const w = await world({ exceptions: { [RULE]: [] } })
    w.save(w.guardFile, { exceptions: { [RULE]: [w.env] } })
    const plugin = await w.plugin()
    const input = { path: "run.sh", content: `cat ${w.env}\n` }
    const event = { sessionID: "ses_1", agent: "build", messageID: "msg_w", id: "w_1", tool: "write", input }
    await plugin.fake.trigger("tool.execute.before", event)
    writeFileSync(join(w.project, "run.sh"), input.content)
    await plugin.fake.trigger("tool.execute.after", { ...event, status: "completed", result: { content: "ok" } })
    // Witnesses: the direct read lifted alone, asked with a redirection to a file or a pipe to sort.
    assert.equal(await plugin.shell(`cat ${w.env}`), "allow")
    assert.equal(await plugin.shell(`cat ${w.env} > copy.txt`), "ask")
    assert.equal(await plugin.shell(`cat ${w.env} | sort`), "ask")
    assert.equal(await plugin.shell("bash run.sh > copy.txt"), "ask")
    assert.equal(await plugin.shell("bash run.sh | sort"), "ask")
  })
})
