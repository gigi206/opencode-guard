// Lot 48 step C, command line: `guard rules off|reset <rule> --path <file> [--project [<dir>]]` writes or removes a file's
// exception (its real path) in the global guard.json, refused unless the plugin's resolution retains it; `guard show`
// lists the exceptions in force and the delay of `rememberConfirmations`, with their origin, every line redacted. Each
// command runs in process on configuration directories and fake files of the test. The command line is imported inside
// each test, so that the code without `--path` fails on assertions, not on loading.
import "./tmp.ts"
import assert from "node:assert/strict"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { setupGuard } from "../src/index.ts"
import { fakeContext } from "./fake-ctx.ts"
import { FAKE } from "./fixtures.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>
type Main = (argv: readonly string[], io: unknown) => number
const RULE = "secret-file-read"

/**
 * Configuration directories, a project (git repository) holding a fake `.env`, fake credential files elsewhere, a link to
 * one of them in the project, a directory whose name the rule knows, and the command line run in process on them.
 */
async function world() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-excli-")))
  const [globalDir, systemDir, home, data, project, secrets] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "work", "app"), join(root, "secrets")]
  for (const dir of [globalDir, systemDir, home, data, join(project, ".git"), join(project, "sub"), join(secrets, "keys.pem")]) mkdirSync(dir, { recursive: true })
  const [env, pgpass, link] = [join(project, ".env"), join(secrets, ".pgpass"), join(project, "linked.pgpass")]
  writeFileSync(env, "API_KEY=dummy\n")
  writeFileSync(pgpass, "host:5432:db:user:dummy\n")
  symlinkSync(pgpass, link)
  const { main } = (await import(new URL("../src/cli/main.ts", import.meta.url).href)) as { main: Main }
  const guardFile = join(globalDir, "guard.json")
  return {
    root,
    globalDir,
    systemDir,
    project,
    secrets,
    env,
    pgpass,
    link,
    keys: join(secrets, "keys.pem"),
    guardFile,
    read: () => JSON.parse(readFileSync(guardFile, "utf8")) as Json,
    /** The global configuration declares the plugin with these options. */
    declare: (options: Json) => writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options }] })),
    run: (args: readonly string[], cwd = project, terminal?: { width: number; color: boolean }) => {
      const out: string[] = []
      const err: string[] = []
      const io = { env: { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }, cwd, systemDir, out: (line: string) => out.push(line), err: (line: string) => err.push(line) }
      const code = main(args, { ...io, ...(terminal ? { terminal } : {}) })
      return { code, out: out.join("\n"), err: err.join("\n"), lines: out }
    },
  }
}
type World = Awaited<ReturnType<typeof world>>

/** Verdict of a shell call by the plugin set up as OpenCode does on the world's directories (session directory: its project). */
async function verdict(w: World, command: string) {
  const fake = fakeContext({ logFile: join(w.root, "plugin.log") })
  ;(fake.ctx.location as { directory: string }).directory = w.project
  await (setupGuard as (...args: unknown[]) => Promise<void>)(fake.ctx, {}, w.systemDir, w.globalDir, { now: () => 1_000_000, intervalMs: 2000 })
  const before = fake.asserts.length
  await fake.trigger("tool.execute.before", { sessionID: "ses_1", agent: "build", messageID: "msg_0", id: "call_1", tool: "shell", input: { command } })
  return fake.asserts.length > before ? "ask" : "allow"
}

describe("guard rules off --path", () => {
  it("EXCLI-1: top level: the real path is written and the plugin lifts the ask; already listed: nothing changed", async () => {
    const w = await world()
    assert.equal(await verdict(w, `cat ${w.env}`), "ask")
    const r = w.run(["rules", "off", RULE, "--path", w.env])
    assert.equal(r.code, 0, r.err)
    assert.equal(r.out, `${w.env} added to exceptions.${RULE} in the top level of ${w.guardFile}`)
    assert.deepEqual(w.read(), { exceptions: { [RULE]: [w.env] } })
    assert.equal(await verdict(w, `cat ${w.env}`), "allow")
    // Already listed, by its path or a relative form: nothing changed.
    const again = w.run(["rules", "off", RULE, "--path", "./.env"])
    assert.equal(again.code, 0)
    assert.match(again.out, /: nothing changed$/)
    assert.deepEqual(w.read(), { exceptions: { [RULE]: [w.env] } })
  })

  it("EXCLI-2: --project (default and given) with a relative path from the current directory; other keys kept", async () => {
    const w = await world()
    writeFileSync(w.guardFile, JSON.stringify({ keep: true, projects: { [w.project]: { ruleOverrides: { eval: "deny" } } } }))
    // A `..` component is refused, nothing written.
    const dotted = w.run(["rules", "off", RULE, "--path", "../.env", "--project"], join(w.project, "sub"))
    assert.equal(dotted.code !== 0 && /has a "\.\." component/.test(dotted.err), true, dotted.err)
    const r = w.run(["rules", "off", RULE, "--path", ".env", "--project"], w.project)
    assert.equal(r.code, 0, r.err)
    assert.equal(r.out, `${w.env} added to exceptions.${RULE} in projects[${JSON.stringify(w.project)}] of ${w.guardFile}`)
    assert.deepEqual(w.read(), { keep: true, projects: { [w.project]: { ruleOverrides: { eval: "deny" }, exceptions: { [RULE]: [w.env] } } } })
    assert.equal(w.run(["rules", "off", RULE, "--path", w.pgpass, "--project", w.project], w.root).code, 0)
    assert.deepEqual((w.read().projects as Json)[w.project], { ruleOverrides: { eval: "deny" }, exceptions: { [RULE]: [w.env, w.pgpass] } })
    assert.equal(await verdict(w, `cat ${w.env} ${w.pgpass}`), "allow")
  })

  it("EXCLI-3: a symbolic link: its real path is written and the message says so", async () => {
    const w = await world()
    const r = w.run(["rules", "off", RULE, "--path", "linked.pgpass"])
    assert.equal(r.code, 0, r.err)
    assert.equal(r.out, `${w.pgpass} added to exceptions.${RULE} in the top level of ${w.guardFile} (the real path of ${w.link})`)
    assert.deepEqual(w.read(), { exceptions: { [RULE]: [w.pgpass] } })
  })

  it("EXCLI-4: refused, nothing written: missing file, directory, a rule that accepts no exception", async () => {
    const w = await world()
    writeFileSync(w.guardFile, '{"keep": true}\n')
    for (const [args, reason] of [
      [["rules", "off", RULE, "--path", "missing.env"], `${join(w.project, "missing.env")} does not exist`],
      [["rules", "off", RULE, "--path", w.keys], `${w.keys} is not a regular file`],
    ] as const) {
      const r = w.run(args)
      assert.equal(r.code, 1, args.join(" "))
      assert.ok(r.err.includes("refused, nothing written") && r.err.includes(reason), r.err)
      assert.equal(readFileSync(w.guardFile, "utf8"), '{"keep": true}\n')
    }
    // Another rule: a usage error (the plugin accepts no exception for it), nothing written.
    for (const args of [["rules", "off", "guard-cli", "--path", w.env], ["rules", "off", "rm", "--path", w.env, "--project"], ["rules", "reset", "rm", "--path", w.env]]) {
      const r = w.run(args)
      assert.equal(r.code, 2, args.join(" "))
      assert.ok(r.err.startsWith("guard: --path goes with secret-file-read only: no other rule accepts exceptions"), r.err)
      assert.equal(readFileSync(w.guardFile, "utf8"), '{"keep": true}\n')
    }
  })
})

describe("guard rules reset --path", () => {
  it("EXCLI-5: the last path removed takes its list and emptied objects with it; another path stays", async () => {
    const w = await world()
    writeFileSync(w.guardFile, JSON.stringify({ keep: true, exceptions: { [RULE]: [w.env, w.pgpass] }, projects: { [w.project]: { exceptions: { [RULE]: [w.pgpass] } } } }))
    const top = w.run(["rules", "reset", RULE, "--path", "linked.pgpass"])
    assert.equal(top.code, 0, top.err)
    assert.equal(top.lines[0], `${w.pgpass} removed from exceptions.${RULE} in the top level of ${w.guardFile}`)
    // Still excepted for the current directory, by the project section.
    assert.equal(top.lines[1], `${w.pgpass} is still excepted for ${RULE} in ${w.project}, by global guard.json, projects[${JSON.stringify(w.project)}]`)
    assert.equal(w.run(["rules", "reset", RULE, "--path", w.pgpass, "--project"]).code, 0)
    assert.deepEqual(w.read(), { keep: true, exceptions: { [RULE]: [w.env] } })
    assert.equal(w.run(["rules", "reset", RULE, "--path", ".env"]).code, 0)
    assert.deepEqual(w.read(), { keep: true })
    const none = w.run(["rules", "reset", RULE, "--path", ".env"])
    assert.equal(none.code, 0)
    assert.equal(none.out, `${w.env} is not in exceptions.${RULE} in the top level of ${w.guardFile}: nothing changed`)
  })

  it("EXCLI-6: a file that no longer exists is removed by its absolute path; another source that still lists it is named", async () => {
    const w = await world()
    const gone = join(w.project, "gone.env")
    writeFileSync(gone, "dummy\n")
    assert.equal(w.run(["rules", "off", RULE, "--path", gone]).code, 0)
    rmSync(gone)
    const r = w.run(["rules", "reset", RULE, "--path", "gone.env"])
    assert.equal(r.code, 0, r.err)
    assert.equal(r.out, `${gone} removed from exceptions.${RULE} in the top level of ${w.guardFile}`)
    assert.deepEqual(w.read(), {})
    w.declare({ exceptions: { [RULE]: [w.pgpass] } })
    assert.equal(w.run(["rules", "off", RULE, "--path", w.pgpass]).code, 0)
    const still = w.run(["rules", "reset", RULE, "--path", w.pgpass])
    assert.equal(still.lines[1], `${w.pgpass} is still excepted for ${RULE} in ${w.project}, by global configuration`)
  })
})

describe("guard --path: usage errors", () => {
  it("EXCLI-7: --path with another word than off or reset, with --agent, without a file", async () => {
    const w = await world()
    for (const [args, message] of [
      [["rules", "ask", RULE, "--path", ".env"], "--path goes with rules off or rules reset only, not with ask"],
      [["rules", "deny", RULE, "--path=.env"], "--path goes with rules off or rules reset only, not with deny"],
      [["rules", "off", RULE, "--path", ".env", "--agent", "build"], "--path does not go with --agent: an agents section accepts no exception"],
      [["rules", "reset", RULE, "--agent", "build", "--path", ".env"], "--path does not go with --agent"],
      [["rules", "off", RULE, "--path"], "--path needs a file"],
      [["rules", "off", RULE, "--path", "--project"], "--path needs a file"],
    ] as const) {
      const r = w.run(args)
      assert.equal(r.code, 2, args.join(" "))
      assert.ok(r.err.startsWith(`guard: ${message}`), r.err)
    }
    assert.ok(!existsSync(w.guardFile))
  })
})

describe("guard show: exceptions and the memory of confirmations", () => {
  it("EXCLI-8: plain output: the delay and its origin among the settings, then each exception with its source and section", async () => {
    const w = await world()
    const plain = w.run(["show"])
    assert.match(plain.out, /^ {2}rememberConfirmations\s+off\s+default$/m)
    assert.match(plain.out, /^Exceptions in force: none$/m)
    w.declare({ rememberConfirmations: 10, exceptions: { [RULE]: [w.pgpass] } })
    writeFileSync(w.guardFile, JSON.stringify({ exceptions: { [RULE]: [w.link] }, projects: { [w.project]: { exceptions: { [RULE]: [w.env] } } } }))
    const shown = w.run(["show"])
    assert.equal(shown.code, 0)
    assert.match(shown.out, /^ {2}rememberConfirmations\s+10 min\s+global configuration$/m)
    const block = shown.lines.slice(shown.lines.indexOf("Exceptions in force:") + 1)
    assert.match(block[0]!, new RegExp(`^ {2}${RULE} {2}${w.pgpass} +global guard\\.json$`))
    assert.match(block[1]!, new RegExp(`^ {2}${RULE} {2}${w.env} +global guard\\.json, projects\\[`))
    // Another directory: the project section no longer applies.
    assert.ok(!w.run(["show"], w.root).out.includes(w.env))
  })

  it("EXCLI-9: terminal: a block of its own, the relaxes mark, the origin under the path; the delay marked when on", async () => {
    const w = await world()
    writeFileSync(w.guardFile, JSON.stringify({ rememberConfirmations: 5, exceptions: { [RULE]: [w.env] } }))
    const { code, lines } = w.run(["show"], w.project, { width: 80, color: false })
    assert.equal(code, 0)
    assert.ok(lines.some((line) => /^ {4}rememberConfirmations +5 min +relaxes +global guard\.json$/.test(line)))
    const at = lines.indexOf("  Exceptions in force")
    assert.ok(at > 0, "a heading")
    assert.match(lines[at + 1]!, new RegExp(`^ {4}${RULE} {2}relaxes {2}${w.env}$`))
    assert.equal(lines[at + 2], `${" ".repeat(4 + RULE.length + 2 + 7 + 2)}global guard.json`)
    // In color: the legend explains the mark even when only an exception relaxes.
    writeFileSync(w.guardFile, JSON.stringify({ exceptions: { [RULE]: [w.env] } }))
    const colored = w.run(["show"], w.project, { width: 80, color: true }).lines
    assert.ok(colored.some((line) => line.includes("relaxes\x1b[39m\x1b[2m: the setting relaxes a protection")))
    const none = await world()
    const empty = none.run(["show"], none.project, { width: 80, color: false }).lines
    assert.equal(empty[empty.indexOf("  Exceptions in force") + 1], "    none")
  })

  it("EXCLI-10: a fake secret in a file name is redacted in what rules off --path and show print", async () => {
    const w = await world()
    const file = join(w.secrets, `${FAKE.github}.pem`)
    writeFileSync(file, "dummy\n")
    const added = w.run(["rules", "off", RULE, "--path", file])
    assert.equal(added.code, 0, added.err)
    assert.ok(added.out.includes("added to exceptions") && !added.out.includes(FAKE.github), added.out)
    assert.deepEqual(w.read(), { exceptions: { [RULE]: [file] } })
    for (const terminal of [undefined, { width: 80, color: false }, { width: 80, color: true }]) {
      const shown = w.run(["show"], w.project, terminal).out
      assert.ok(shown.includes(w.secrets) && !shown.includes(FAKE.github), shown)
    }
  })
})
