// Lot 48, step C on the current base: its points of contact with the base (a shell request without a tool call, the two
// closed lists of readers, the confirmation prompt's text, the redaction of outputs) and the command line of the
// exceptions and of the memory of confirmations (rules off|reset --path, set|unset rememberConfirmations, show,
// rules --explain, test, help, completion). Fake files and configuration directories only; the command line runs in
// process, bash only for the completion. Only existing exports are imported at the top, so that the base fails on
// assertions, not on loading.
import "./tmp.ts"
import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { after, describe, it } from "node:test"
import { guardAction } from "../src/hooks/gate.ts"
import { setupGuard } from "../src/index.ts"
import { onlyReads } from "../src/rules/shell.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"
import { FAKE } from "./fixtures.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>
type Main = (argv: readonly string[], io: unknown) => number | Promise<number>
const RULE = "secret-file-read"

const roots: string[] = []
after(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true })
})

/**
 * Configuration directories, a fake home, a project (git repository) holding a fake `.env`, a fake `.pgpass` elsewhere,
 * the command line run in process on them, and the plugin set up as OpenCode does with the project as session directory.
 */
async function world() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-portc-")))
  roots.push(root)
  const [globalDir, systemDir, home, data, project, secrets] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "work", "app"), join(root, "secrets")]
  for (const dir of [globalDir, systemDir, home, data, join(project, ".git"), join(project, ".opencode"), secrets]) mkdirSync(dir, { recursive: true })
  const [env, pgpass] = [join(project, ".env"), join(secrets, ".pgpass")]
  writeFileSync(env, "API_KEY=dummy\n")
  writeFileSync(pgpass, "host:5432:db:user:dummy\n")
  const { main } = (await import(new URL("../src/cli/main.ts", import.meta.url).href)) as { main: Main }
  const guardFile = join(globalDir, "guard.json")
  return {
    root,
    project,
    secrets,
    env,
    pgpass,
    guardFile,
    read: () => JSON.parse(readFileSync(guardFile, "utf8")) as Json,
    run: async (args: readonly string[], terminal?: { width: number; color: boolean }) => {
      const out: string[] = []
      const err: string[] = []
      const io = { env: { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }, cwd: project, systemDir, out: (line: string) => out.push(line), err: (line: string) => err.push(line) }
      const code = await main(args, { ...io, ...(terminal ? { terminal } : {}) })
      return { code, out: out.join("\n"), err: err.join("\n"), lines: out }
    },
    plugin: async () => {
      const logFile = join(root, "guard.log")
      const fake = fakeContext({ logFile })
      ;(fake.ctx.location as { directory: string }).directory = project
      await (setupGuard as (...args: unknown[]) => Promise<void>)(fake.ctx, {}, systemDir, globalDir, { now: () => 1_000_000, intervalMs: 2000 }, home)
      let call = 0
      return {
        fake,
        /** Verdict of a shell call in `execute.before` (an ask is confirmed): ask or allow. */
        shell: async (command: string) => {
          const before = fake.asserts.length
          await fake.trigger("tool.execute.before", { sessionID: "ses_1", agent: "build", messageID: "msg_0", id: `call_${++call}`, tool: "shell", input: { command } })
          return fake.asserts.length > before ? "ask" : "allow"
        },
        /** `permission.evaluate` of shell sub-commands: a tool call's source `execute.before` did not see, or none. */
        evaluate: async (commands: string[], toolless = false) => {
          const event: Json = { sessionID: "ses_1", agent: "build", action: "shell", resources: commands, effect: "allow", message: undefined }
          event.source = toolless ? undefined : { type: "tool", messageID: "msg_0", id: `other_${++call}` }
          await fake.trigger("permission.evaluate", event)
          return event as { effect: string; message?: string }
        },
        log: () => readFileSync(logFile, "utf8"),
      }
    },
  }
}

describe("points of contact with the base", () => {
  it("PC-1: a shell request without a tool call: neither an exception nor the memory lifts its ask, which is denied", async () => {
    const w = await world()
    writeFileSync(w.guardFile, JSON.stringify({ rememberConfirmations: 10, exceptions: { [RULE]: [w.env] } }))
    const plugin = await w.plugin()
    // With a tool call's source: the excepted file is lifted; a set confirmed in the session is remembered.
    assert.equal((await plugin.evaluate([`cat ${w.env}`])).effect, "allow")
    assert.equal(await plugin.shell(`cat ${w.pgpass}`), "ask")
    assert.equal((await plugin.evaluate([`cat ${w.pgpass}`])).effect, "allow")
    // The shell condition of a scheduled task, run by OpenCode itself: denied for each file, under the rule.
    for (const file of [w.env, w.pgpass]) {
      const event = await plugin.evaluate([`cat ${file}`], true)
      assert.equal(event.effect, "deny", file)
      assert.match(event.message ?? "", /^\[guard\] Blocked \(rule secret-file-read\): access to a credential file/, file)
    }
    assert.equal((plugin.log().match(/shell without a tool call → deny \(not run by a tool call, rule secret-file-read\)/g) ?? []).length, 2)
  })

  it("PC-2: the readers of the exceptions and those of guard-cli (onlyReads) stay two lists: cut for the first, diff for the second", async () => {
    const w = await world()
    writeFileSync(w.guardFile, JSON.stringify({ exceptions: { [RULE]: [w.env] } }))
    const plugin = await w.plugin()
    assert.equal(await plugin.shell(`head -1 ${w.env} | cut -c1-3`), "allow")
    // `diff` is not one of the exceptions' readers (an option passes its output to another program).
    assert.equal(await plugin.shell(`diff ${w.env} ${w.env}`), "ask")
    // guard-cli: its own list, unchanged (`diff` reads, `cut` is not in it).
    assert.equal(onlyReads("diff bin/guard bin/guard.old"), true)
    assert.equal(onlyReads("cut -c1-3 bin/guard"), false)
  })

  it("PC-3: default settings, the prompt's action: a file the call shows whole is named once, by the call (witness: as before)", async () => {
    const w = await world()
    const plugin = await w.plugin()
    const redactor = createRedactor()
    // The base's text: the rule's reason without files, then the call (as long as the action allows).
    const asBefore = async (command: string) => {
      const before = plugin.fake.asserts.length
      assert.equal(await plugin.shell(command), "ask", command)
      const posed = plugin.fake.asserts[before]!
      assert.equal(posed.action, guardAction(redactor, "access to a credential file", RULE, posed.resources[0]), command)
    }
    // Absolute, relative, more than three files.
    await asBefore(`cat ${w.env}`)
    await asBefore("cat .env")
    const four = [w.env, w.pgpass, join(w.secrets, ".netrc"), join(w.secrets, "id_rsa")]
    for (const file of four.slice(2)) writeFileSync(file, "dummy\n")
    await asBefore(`wc -l ${four.join(" ")}`)
    // Another reason under the rule's name (one of your rules, a check stopped by a limit), a tool's path: as before.
    const action = (reason: string, call: string) => guardAction(redactor, reason, RULE, call)
    assert.equal(action("keys stay here (/srv/app/.env)", "shell: cat /srv/app/.env"), "guard · secret-file-read: keys stay here (/srv/app/.env) · shell: cat /srv/app/.env")
    assert.equal(action("access to a file that could not be checked for a private key (/srv/k)", "shell: cat /srv/k"), "guard · secret-file-read: access to a file that could not be checked for a private key (/srv/k) · shell: cat /srv/k")
    const deep = `/srv/${"d/".repeat(30)}**/.env`
    assert.equal(action(`access to a credential file (${deep})`, "glob: /srv"), `guard · secret-file-read: access to a credential file (/srv/${"d/".repeat(27)}… · glob: /srv`)
  })

  it("PC-4: default settings: a file written in another form keeps its absolute path in the prompt's reason, once and whole", async () => {
    const redactor = createRedactor()
    const action = (reason: string, call: string) => guardAction(redactor, reason, RULE, call)
    // The reason of the rule now names the files: each one the call shows whole is left to the call.
    assert.equal(action("access to a credential file (/srv/app/.env)", "shell: cat /srv/app/.env"), "guard · secret-file-read: access to a credential file · shell: cat /srv/app/.env")
    assert.equal(action("access to a credential file (/a/.env, /h/.pgpass and 1 more)", "shell: cat /a/.env ~/.pgpass ~/.netrc"), "guard · secret-file-read: access to a credential file (/h/.pgpass and 1 more) · shell: cat /a/.env ~/.pgpass ~/.netrc")
    assert.equal(action("access to a credential file (/srv/app/.env)", "shell: cat /srv/app/./.env"), "guard · secret-file-read: access to a credential file (/srv/app/.env) · shell: cat /srv/app/./.env")
    // Too long for both: the reason without its files rather than a path cut.
    const long = `shell: cat /srv/app/./.env # ${"x".repeat(30)}`
    assert.equal(action("access to a credential file (/srv/app/.env)", long), `guard · secret-file-read: access to a credential file · ${long}`)
    // In the plugin: the reason (request's metadata, log) names the file; the action shows its absolute path at most once, whole.
    const w = await world()
    const plugin = await w.plugin()
    const dotted = w.env.replace("/app/", "/app/./")
    assert.equal(await plugin.shell(`cat ${dotted}`), "ask")
    const posed = plugin.fake.asserts.at(-1)!
    assert.equal(posed.metadata?.reason, `access to a credential file (${w.env})`)
    assert.equal(posed.action, guardAction(redactor, `access to a credential file (${w.env})`, RULE, posed.resources[0]))
    assert.ok(posed.action.split(w.env).length <= 2 && (posed.action.includes(`(${w.env})`) || !posed.action.includes("credential file (")), posed.action)
    assert.ok(plugin.log().includes(`shell → ask (local, rule secret-file-read): access to a credential file (${w.env})`), plugin.log())
  })

  it("PC-5: an exception and the memory do not stop the redaction of what the read prints (witness)", async () => {
    const w = await world()
    writeFileSync(w.env, `GITHUB_TOKEN=${FAKE.github}\n`)
    writeFileSync(w.guardFile, JSON.stringify({ rememberConfirmations: 10, exceptions: { [RULE]: [w.env] } }))
    const plugin = await w.plugin()
    await plugin.shell(`cat ${w.env}`)
    const event = await plugin.fake.trigger("tool.execute.after", { sessionID: "ses_1", agent: "build", messageID: "msg_0", id: "call_1", tool: "shell", input: { command: `cat ${w.env}` }, status: "completed", result: { output: `GITHUB_TOKEN=${FAKE.github}\n`, content: [{ type: "text", text: `GITHUB_TOKEN=${FAKE.github}\n` }] } })
    const printed = JSON.stringify((event as { result: unknown }).result)
    assert.ok(!printed.includes(FAKE.github), printed)
  })
})

describe("command line", () => {
  it("PC-6: rules off secret-file-read without --path says the whole rule is off; with --path, one file; another rule, nothing more", async () => {
    const w = await world()
    const whole = await w.run(["rules", "off", RULE])
    assert.equal(whole.code, 0, whole.err)
    assert.deepEqual(w.read(), { ruleOverrides: { [RULE]: "off" } })
    assert.equal(whole.lines[1], `the whole rule ${RULE} is off there, for every file (one file only: guard rules off ${RULE} --path <file>)`)
    assert.equal((await w.run(["rules", "reset", RULE])).code, 0)
    const one = await w.run(["rules", "off", RULE, "--path", w.env])
    assert.equal(one.out, `${w.env} added to exceptions.${RULE} in the top level of ${w.guardFile}`)
    assert.deepEqual(w.read(), { exceptions: { [RULE]: [w.env] } })
    assert.equal((await w.run(["rules", "off", "eval"])).lines.length, 1)
  })

  it("PC-7: set and unset rememberConfirmations: whole minutes from 1 to 60, top level or --project, never --agent", async () => {
    const w = await world()
    const set = await w.run(["set", "rememberConfirmations", "5"])
    assert.equal(set.code, 0, set.err)
    assert.equal(set.out, `rememberConfirmations set to 5 in the top level of ${w.guardFile}`)
    assert.deepEqual(w.read(), { rememberConfirmations: 5 })
    assert.match((await w.run(["show"])).out, /^ {2}rememberConfirmations\s+5 min\s+global guard\.json$/m)
    for (const value of ["0", "61", "5m", "-1"]) {
      const r = await w.run(["set", "rememberConfirmations", value])
      assert.equal(r.code, value === "-1" ? 2 : 1, value)
      assert.deepEqual(w.read(), { rememberConfirmations: 5 }, value)
    }
    const agent = await w.run(["set", "rememberConfirmations", "5", "--agent", "build"])
    assert.equal(agent.code, 2)
    assert.ok(agent.err.startsWith("guard: rememberConfirmations does not go with --agent"), agent.err)
    assert.equal((await w.run(["unset", "rememberConfirmations", "--agent", "build"])).code, 2)
    assert.equal((await w.run(["set", "rememberConfirmations", "30", "--project"])).code, 0)
    assert.deepEqual(w.read(), { rememberConfirmations: 5, projects: { [w.project]: { rememberConfirmations: 30 } } })
    const unset = await w.run(["unset", "rememberConfirmations"])
    assert.equal(unset.lines[0], `rememberConfirmations removed from the top level of ${w.guardFile}`)
    assert.deepEqual(w.read(), { projects: { [w.project]: { rememberConfirmations: 30 } } })
  })

  it("PC-8: rules --explain secret-file-read names exceptions and rememberConfirmations, in the same seven lines; another rule does not", async () => {
    const w = await world()
    const r = await w.run(["rules", "--explain", RULE])
    assert.equal(r.code, 0)
    assert.equal(r.lines.length, 7)
    for (const word of ["exceptions.secret-file-read", "guard rules off secret-file-read --path <file>", "rememberConfirmations", "neither ever lifts a denial"]) assert.ok(r.lines[6]!.includes(word), word)
    assert.ok(!(await w.run(["rules", "--explain", "eval"])).out.includes("exceptions"))
  })

  it("PC-9: guard test applies the exceptions and says the memory of confirmations does not apply outside a session", async () => {
    const w = await world()
    writeFileSync(w.guardFile, JSON.stringify({ rememberConfirmations: 5, exceptions: { [RULE]: [w.env] } }))
    const lifted = await w.run(["test", "--", "cat", w.env])
    assert.equal(lifted.code, 0, lifted.err)
    assert.ok(lifted.lines.includes("verdict: allow"), lifted.out)
    assert.ok(lifted.lines.includes(`note: ${RULE} lifted by an exception: ${w.env}`), lifted.out)
    const asked = await w.run(["test", "--", "cat", w.pgpass])
    assert.ok(asked.lines.includes("verdict: ask"), asked.out)
    assert.ok(asked.lines.includes("note: rememberConfirmations (5 min) does not apply here: it remembers a confirmation within a session only"), asked.out)
  })

  it("PC-10: guard show in a terminal: rememberConfirmations on and each exception carry the relaxes mark in its color", async () => {
    const w = await world()
    writeFileSync(w.guardFile, JSON.stringify({ rememberConfirmations: 5, exceptions: { [RULE]: [w.env] } }))
    const MARK = "\x1b[33mrelaxes\x1b[39m"
    const { lines } = await w.run(["show"], { width: 100, color: true })
    assert.ok(lines.some((line) => line.includes("rememberConfirmations") && line.includes(MARK)), lines.join("\n"))
    assert.ok(lines.some((line) => line.includes(RULE) && line.includes(MARK) && line.includes(w.env)), lines.join("\n"))
    writeFileSync(w.guardFile, "{}")
    const off = (await w.run(["show"], { width: 100, color: true })).lines
    assert.ok(off.some((line) => line.includes("rememberConfirmations") && !line.includes("relaxes")), off.join("\n"))
  })

  it("PC-11: help and completion know --path and rememberConfirmations", { skip: !bash() && "bash not installed" }, async () => {
    const w = await world()
    const help = (await w.run(["help"])).out
    for (const word of ["--path <file>", "rules off|reset secret-file-read only", "rememberConfirmations (minutes, 1 to 60)", "never with --path or rememberConfirmations"]) assert.ok(help.includes(word), word)
    const { completionScript } = (await import(new URL("../src/cli/completion.ts", import.meta.url).href)) as { completionScript: (shell: string) => string }
    const complete = (...line: string[]) => {
      const words = ["guard", ...line]
      const script = `${completionScript("bash")}\nCOMP_WORDS=(${words.map((word) => `'${word}'`).join(" ")}); COMP_CWORD=${words.length - 1}\n_guard; printf '%s\\n' "\${COMPREPLY[@]}"`
      return execFileSync("bash", ["--norc", "--noprofile", "-c", script], { encoding: "utf8", env: { PATH: process.env.PATH ?? "/usr/bin:/bin" } }).split("\n").filter(Boolean)
    }
    assert.deepEqual(complete("rules", "off", RULE, "--pa"), ["--path"])
    assert.deepEqual(complete("rules", "reset", RULE, "--pa"), ["--path"])
    assert.deepEqual(complete("rules", "ask", RULE, "--pa"), [])
    assert.deepEqual(complete("rules", "off", "eval", "--pa"), [])
    assert.deepEqual(complete("set", "rem"), ["rememberConfirmations"])
    assert.deepEqual(complete("set", "rememberConfirmations", ""), [])
    assert.deepEqual(complete("unset", "rem"), ["rememberConfirmations"])
  })
})

function bash(): boolean {
  try {
    execFileSync("bash", ["-c", "true"])
    return true
  } catch {
    return false
  }
}
