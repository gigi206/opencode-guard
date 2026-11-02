// Lot 48, fixes after the review of the port: an exception or the memory never lifts an ask in a script written in the
// session nor in a call made by CodeMode code, and no confirmation coming from there is remembered; each other context
// keeps what step C planned; `rules off secret-file-read --path` says when the exception has no effect. Fake files and
// configuration directories only; the plugin is set up as OpenCode does (test clock, test home), the command line runs in
// process. Only existing exports are imported at the top, so that the base fails on assertions, not on loading.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { after, describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import { setupGuard } from "../src/index.ts"
import { rulePolicy } from "../src/rules/features.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

type Json = Record<string, unknown>
type Main = (argv: readonly string[], io: unknown) => number | Promise<number>
const RULE = "secret-file-read"

const roots: string[] = []
after(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true })
})

/** Configuration directories, a fake home, a project (git repository) holding a fake `.env`, a fake `.pgpass` elsewhere. */
async function world() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-cp-")))
  roots.push(root)
  const [globalDir, systemDir, home, data, project, secrets] = [join(root, "g"), join(root, "s"), join(root, "h"), join(root, "d"), join(root, "w", "app"), join(root, "k")]
  for (const dir of [globalDir, systemDir, home, data, join(project, ".git"), join(project, ".opencode"), secrets]) mkdirSync(dir, { recursive: true })
  const [env, pgpass] = [join(project, ".env"), join(secrets, ".pgpass")]
  writeFileSync(env, "API_KEY=dummy\n")
  writeFileSync(pgpass, "host:5432:db:user:dummy\n")
  const guardFile = join(globalDir, "guard.json")
  const save = (content: Json) => writeFileSync(guardFile, JSON.stringify(content))
  const { main } = (await import(new URL("../src/cli/main.ts", import.meta.url).href)) as { main: Main }
  return {
    home,
    project,
    env,
    pgpass,
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
      const fake = fakeContext({ logFile: join(root, "guard.log"), ...options })
      ;(fake.ctx.location as { directory: string }).directory = project
      const now = 1_000_000
      await (setupGuard as (...args: unknown[]) => Promise<void>)(fake.ctx, {}, systemDir, globalDir, { now: () => now, intervalMs: 2000 }, home)
      let count = 0
      /** Verdict of a call in `execute.before`: deny (blocked), refused (confirmation not granted), ask or allow. */
      const call = async (tool: string, input: Json, id = `call_${++count}`) => {
        const before = fake.asserts.length
        try {
          await fake.trigger("tool.execute.before", { sessionID: "ses_1", agent: "build", messageID: "msg_0", id, tool, input })
        } catch (error) {
          return /Blocked|unattended/i.test(String(error)) ? "deny" : "refused"
        }
        return fake.asserts.length > before ? "ask" : "allow"
      }
      return {
        fake,
        call,
        shell: (command: string, id?: string) => call("shell", { command }, id),
        done: (tool: string, input: Json, id: string) =>
          fake.trigger("tool.execute.after", { sessionID: "ses_1", agent: "build", messageID: "msg_0", id, tool, input, status: "completed", result: { content: "ok" } }),
        /** `permission.evaluate` of shell sub-commands: a tool call's source, or none (`null`). */
        evaluate: async (commands: string[], source: string | null) => {
          const event: Json = { sessionID: "ses_1", agent: "build", action: "shell", resources: commands, effect: "allow", message: undefined }
          event.source = source === null ? undefined : { type: "tool", messageID: "msg_0", id: source }
          await fake.trigger("permission.evaluate", event)
          return event.effect as string
        },
        /** A script written in full by the agent in the session (tracked), at `run.sh` in the project. */
        script: async (content: string) => {
          const input = { path: "run.sh", content }
          await call("write", input, "w_1")
          writeFileSync(join(project, "run.sh"), content)
          await fake.trigger("tool.execute.after", { sessionID: "ses_1", agent: "build", messageID: "msg_w", id: "w_1", tool: "write", input, status: "completed", result: { content: "ok" } })
        },
      }
    },
  }
}

/** A world whose global guard.json excepts the fake `.env` and remembers confirmations for 10 minutes, or only one of them. */
async function waived(only?: "exceptions" | "memory") {
  const w = await world()
  w.save({ ...(only === "memory" ? {} : { exceptions: { [RULE]: [w.env] } }), ...(only === "exceptions" ? {} : { rememberConfirmations: 10 }) })
  return { w, plugin: await w.plugin() }
}

describe("no exception or memory in a script or in CodeMode code", () => {
  it("CP-1: a direct shell command: the exception and the memory lift (witness)", async () => {
    const { w, plugin } = await waived()
    assert.equal(await plugin.shell(`cat ${w.env}`), "allow")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "ask")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "allow")
  })

  it("CP-2: shell sub-commands of the same call: lifted; without a tool call: denied (witness)", async () => {
    const { w, plugin } = await waived()
    assert.equal(await plugin.evaluate([`cat ${w.env}`], "other_1"), "allow")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "ask")
    assert.equal(await plugin.evaluate([`cat ${w.pgpass}`], "other_2"), "allow")
    assert.equal(await plugin.evaluate([`cat ${w.env}`], null), "deny")
    assert.equal(await plugin.evaluate([`cat ${w.pgpass}`], null), "deny")
  })

  it("CP-3: read, glob, grep and MCP tools called directly: the exception lifts (witness)", async () => {
    const { w, plugin } = await waived()
    assert.equal(await plugin.call("read", { path: w.env }), "allow")
    assert.equal(await plugin.call("grep", { pattern: "KEY", path: w.env }), "allow")
    assert.equal(await plugin.call("glob", { pattern: "*", path: w.env }), "allow")
    assert.equal(await plugin.call("files_read", { path: w.env }), "allow")
    assert.equal(await plugin.call("read", { path: w.pgpass }), "ask")
  })

  it("CP-4: guard test applies the exception and leaves the memory out (witness)", async () => {
    const w = await world()
    w.save({ exceptions: { [RULE]: [w.env] }, rememberConfirmations: 10 })
    assert.match((await w.run(["test", "--", `cat ${w.env}`])).out, /lifted by an exception/)
    assert.match((await w.run(["test", "--", `cat ${w.pgpass}`])).out, /rememberConfirmations \(10 min\) does not apply here/)
  })

  it("CP-5: a script written in the session reads the excepted file: asked, piped, redirected or alone", async () => {
    const { w, plugin } = await waived()
    await plugin.script(`cat ${w.env}\n`)
    assert.equal(await plugin.shell(`cat ${w.env}`), "allow")
    for (const command of ["bash run.sh", "bash run.sh | sort", "bash run.sh > copy.txt", "sh ./run.sh"]) assert.equal(await plugin.shell(command), "ask", command)
  })

  it("CP-6: a file confirmed and remembered for a direct read: a script that reads it still asks", async () => {
    const { w, plugin } = await waived()
    await plugin.script(`cat ${w.pgpass}\n`)
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "ask")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "allow")
    assert.equal(await plugin.shell("bash run.sh"), "ask")
  })

  it("CP-7: a script's ask confirmed: nothing remembered, the direct read still asks (witness)", async () => {
    const { w, plugin } = await waived()
    await plugin.script(`cat ${w.pgpass}\n`)
    assert.equal(await plugin.shell("bash run.sh"), "ask")
    assert.equal(await plugin.shell(`cat ${w.pgpass} && bash run.sh`), "ask")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "ask")
  })

  it("CP-8: a script judged without a directory: no exception either", async () => {
    const w = await world()
    const { config } = parseConfig({})
    const policy = rulePolicy(config.features, new Map(), { exceptions: new Map([[RULE, new Set([w.env])]]) })
    const decider = createDecider({ config: { ...config, policy }, redactor: createRedactor(), home: w.home, resolveLinks: true })
    const script = { path: "run.sh", content: `cat ${w.env}\n`, shell: true, forModel: false }
    // Witness: the same read as a command is lifted without a directory.
    assert.equal((await decider.decide({ tool: "shell", input: { command: `cat ${w.env}` } })).verdict, "allow")
    const ran = await decider.decide({ tool: "shell", input: { command: "bash run.sh" }, scripts: [script] })
    assert.equal(`${ran.verdict}/${ran.rule}`, `ask/${RULE}`)
  })

  it("CP-9: CodeMode code that names the excepted file: no credential file rule on the code itself (witness)", async () => {
    const { w, plugin } = await waived()
    assert.equal(await plugin.call("execute", { code: `return "${w.env}"` }, "x_0"), "allow")
  })

  it("CP-10: calls made by CodeMode code (same identifier): the exception does not lift, until the code ends", async () => {
    const { w, plugin } = await waived("exceptions")
    assert.equal(await plugin.call("execute", { code: "return 1" }, "x_1"), "allow")
    assert.equal(await plugin.call("read", { path: w.env }, "x_1"), "ask")
    await plugin.done("read", { path: w.env }, "x_1")
    // An internal call refused does not end the code: the next ones still ask.
    plugin.fake.onAssert(async () => {
      throw new Error("rejected")
    })
    assert.equal(await plugin.call("read", { path: w.env }, "x_1"), "refused")
    plugin.fake.onAssert(async () => {})
    assert.equal(await plugin.shell(`cat ${w.env}`, "x_1"), "ask")
    assert.equal(await plugin.call("files_read", { path: w.env }, "x_1"), "ask")
    await plugin.done("execute", { code: "return 1" }, "x_1")
    // The code ended: a call with the same identifier is a direct call again.
    assert.equal(await plugin.call("read", { path: w.env }, "x_1"), "allow")
  })

  it("CP-11: a set remembered by a direct confirmation: a call made by CodeMode code still asks", async () => {
    const { w, plugin } = await waived("memory")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "ask")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "allow")
    assert.equal(await plugin.call("execute", { code: "return 1" }, "x_2"), "allow")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`, "x_2"), "ask")
  })

  it("CP-12: a confirmation given to a call made by CodeMode code: not remembered for a direct read", async () => {
    const { w, plugin } = await waived("memory")
    assert.equal(await plugin.call("execute", { code: "return 1" }, "x_3"), "allow")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`, "x_3"), "ask")
    await plugin.done("shell", { command: `cat ${w.pgpass}` }, "x_3")
    await plugin.done("execute", { code: "return 1" }, "x_3")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "ask")
  })

  it("CP-13: shell sub-commands of a call made by CodeMode code: the exception does not lift", async () => {
    const { w, plugin } = await waived("exceptions")
    assert.equal(await plugin.call("execute", { code: "return 1" }, "x_4"), "allow")
    assert.equal(await plugin.evaluate([`cat ${w.env}`], "x_4"), "ask")
    // Witness: another call's sub-commands are lifted.
    assert.equal(await plugin.evaluate([`cat ${w.env}`], "other_3"), "allow")
  })

  it("CP-14: shell sub-commands of a call made by CodeMode code: a remembered set does not lift", async () => {
    const { w, plugin } = await waived("memory")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "ask")
    assert.equal(await plugin.call("execute", { code: "return 1" }, "x_5"), "allow")
    assert.equal(await plugin.evaluate([`cat ${w.pgpass}`], "x_5"), "ask")
  })
})

describe("rules off secret-file-read --path where the rule is off or denies", () => {
  it("CP-15: a line says the exception has no effect there; exit code 0; none otherwise", async () => {
    const w = await world()
    for (const word of ["off", "deny"]) {
      w.save({ ruleOverrides: { [RULE]: word } })
      const added = await w.run(["rules", "off", RULE, "--path", w.env])
      assert.equal(added.code, 0, added.err)
      assert.match(added.out, /added to exceptions\.secret-file-read/)
      assert.match(added.out, new RegExp(`the exception has no effect there while ruleOverrides\\.${RULE} is "${word}"`))
      assert.deepEqual(w.read(), { ruleOverrides: { [RULE]: word }, exceptions: { [RULE]: [w.env] } })
    }
    // In a project: the setting of its section counts.
    w.save({ projects: { [w.project]: { ruleOverrides: { [RULE]: "deny" } } } })
    const project = await w.run(["rules", "off", RULE, "--path", w.env, "--project"])
    assert.equal(project.code, 0, project.err)
    assert.match(project.out, /the exception has no effect there while ruleOverrides\.secret-file-read is "deny"/)
    // The group off.
    w.save({ sensitiveFiles: false })
    assert.match((await w.run(["rules", "off", RULE, "--path", w.env])).out, /the exception has no effect there while secret-file-read does not apply/)
    // Witnesses: the rule asks there, or "ask" is set: no such line.
    for (const content of [{}, { ruleOverrides: { [RULE]: "ask" } }]) {
      w.save(content)
      const plain = await w.run(["rules", "off", RULE, "--path", w.env])
      assert.equal(plain.code, 0, plain.err)
      assert.doesNotMatch(plain.out, /no effect/)
    }
  })
})
