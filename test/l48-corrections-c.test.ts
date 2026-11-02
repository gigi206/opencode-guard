// Lot 48, fixes of review RC. An exception (or the memory) for one credential file must never lift the read of another
// one: a word with a `..` component, a relative or a home-relative path never gives a target (the `HOME` of a command is
// the session's); a target is retained only when every other part of the command is a program of a closed list that
// neither writes, launches nor runs code. (The fixes of review RH are tested with the global guard.json's rules.) Fake
// files only, nothing launched. Only existing exports are imported at the top, so that the base fails on assertions, not
// on loading.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { after, describe, it } from "node:test"
import { parseConfig, resolveVersion } from "../src/config.ts"
import { createCredentialContent } from "../src/credential-content.ts"
import { setupGuard } from "../src/index.ts"
import { createRealPath } from "../src/real-path.ts"
import { shellFinding } from "../src/rules/shell.ts"
import { toolFinding } from "../src/rules/tools.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>
const RULE = "secret-file-read"

const roots: string[] = []
after(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true })
})

/**
 * `<root>/work/app/.env` (the excepted file), `<root>/secrets/.env` (another one), the link `app/lnk` to
 * `<root>/secrets/deep` (so `app/lnk/../.env` is `secrets/.env` for the kernel), the link `work/cur` to `app` (a path
 * through a link a command could replace), a sourced file that changes directory, and a fake home with its own `.netrc`.
 */
function files() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-crc-")))
  roots.push(root)
  const app = join(root, "work", "app")
  const secrets = join(root, "secrets")
  const home = join(root, "home")
  for (const dir of [app, join(secrets, "deep"), home]) mkdirSync(dir, { recursive: true })
  const env = join(app, ".env")
  const other = join(secrets, ".env")
  for (const file of [env, other]) writeFileSync(file, "NAME=dummy\n")
  for (const dir of [home, secrets]) writeFileSync(join(dir, ".netrc"), "machine example.invalid\n")
  symlinkSync(join(secrets, "deep"), join(app, "lnk"))
  const cur = join(root, "work", "cur")
  symlinkSync(app, cur)
  writeFileSync(join(app, "setup.sh"), `cd ${secrets}\n`)
  return { root, app, secrets, home, env, other, cur, netrc: join(home, ".netrc") }
}

/** Rule context of a shell command run in `dir` (proven directory), with the resolvers of a call. */
function context(dir: string, home: string, active?: Json) {
  return {
    redactor: createRedactor(),
    home,
    cwd: dir,
    cwds: [dir],
    credentialContent: createCredentialContent({ directories: [dir], home }),
    realPaths: createRealPath({ directories: [dir] }),
    ...(active ? { active: { dangerousCommands: true, sensitiveFiles: true, ...active } } : {}),
  } as Parameters<typeof shellFinding>[1]
}
const excepting = (...paths: string[]) => ({ exceptions: new Map([[RULE, new Set(paths)]]) })

/** Plugin set up as OpenCode does (session directory `<root>/work/app`), global options = effective options. */
async function guard(options: Json, fs = files()) {
  const { root, app } = fs
  const [globalDir, systemDir] = [join(root, "global"), join(root, "system")]
  for (const dir of [globalDir, systemDir, join(app, ".opencode")]) mkdirSync(dir, { recursive: true })
  writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options }] }))
  const logFile = join(root, "guard.log")
  const fake = fakeContext({ logFile, ...options })
  ;(fake.ctx.location as { directory: string }).directory = app
  fake.agents.set("plan", { mode: "primary", permissions: [] })
  await (setupGuard as (...args: unknown[]) => Promise<void>)(fake.ctx, {}, systemDir, globalDir, { now: () => 1_000_000, intervalMs: 2000 })
  let call = 0
  /** Verdict of a tool call in `execute.before`: deny, ask (a confirmation was requested) or allow. */
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
    ...fs,
    shell: (command: string, sessionID?: string) => verdict("shell", { command }, sessionID),
    read: (path: string, sessionID?: string) => verdict("read", { path }, sessionID),
    tool: (tool: string, input: Json) => verdict(tool, input),
    /** Effect left by `permission.evaluate` on the shell sub-commands of a call `execute.before` did not see. */
    evaluate: async (commands: string[]) => {
      const event = { sessionID: "ses_1", agent: "build", action: "shell", resources: commands, effect: "allow", message: undefined, source: { type: "tool", messageID: "msg_0", id: `other_${++call}` } }
      await fake.trigger("permission.evaluate", event)
      return event.effect
    },
    log: () => readFileSync(logFile, "utf8"),
  }
}

type Main = (args: readonly string[], io: Json) => number

/** The command line run in process on a fake global configuration directory (`globalGuard`: its guard.json). */
async function cli(setup: { readonly global?: Json; readonly globalGuard?: Json } = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-crccli-")))
  roots.push(root)
  const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "app")]
  for (const dir of [globalDir, systemDir, home, data, project]) mkdirSync(dir, { recursive: true })
  if (setup.global) writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: setup.global }] }))
  const guardFile = join(globalDir, "guard.json")
  if (setup.globalGuard) writeFileSync(guardFile, JSON.stringify(setup.globalGuard))
  const { main } = (await import(new URL("../src/cli/main.ts", import.meta.url).href)) as { main: Main }
  return {
    root,
    project,
    guardFile,
    read: () => JSON.parse(readFileSync(guardFile, "utf8")) as Json,
    run: (args: readonly string[], cwd = project) => {
      const out: string[] = []
      const err: string[] = []
      const io = { env: { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }, cwd, systemDir, out: (line: string) => out.push(line), err: (line: string) => err.push(line) }
      const code = main(args, io)
      return { code, out: out.join("\n"), err: err.join("\n") }
    },
  }
}

describe("fixes of review RC: the target is the file the shell opens (tests RC-1 to RC-6)", () => {
  it("CRC-1: a `..` after a link names another file for the kernel: the ask stays despite the exception", () => {
    const fs = files()
    const ctx = context(fs.app, fs.home, excepting(fs.env))
    // Witness: the excepted file itself is lifted.
    assert.equal(shellFinding(`cat ${fs.env}`, ctx), undefined)
    for (const command of [`cat ${fs.app}/lnk/../.env`, "cat ./lnk/../.env"]) assert.equal(shellFinding(command, ctx)?.rule, RULE, command)
  })

  it("CRC-2: with the default settings, the reason of a `..` after a link names the path as written", () => {
    const fs = files()
    const finding = shellFinding(`cat ${fs.app}/lnk/../.env`, context(fs.app, fs.home))
    assert.equal(finding?.rule, RULE)
    assert.equal(finding?.reason, `access to a credential file (${fs.app}/lnk/../.env)`)
  })

  it("CRC-3: a directory change the plugin does not see (command word rebuilt by the shell): the ask stays", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    // Witness (absolute path: a relative one is never a target): the excepted file is lifted through the real plugin.
    assert.equal(await plugin.shell(`cat ${fs.env}`), "allow")
    assert.equal(await plugin.shell(`c''d ${fs.secrets} && cat ./.env`), "ask")
  })

  it("CRC-4: a directory change made by a sourced file: the ask stays", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    assert.equal(await plugin.shell(`cat ${fs.env}`), "allow")
    assert.equal(await plugin.shell(". ./setup.sh && cat ./.env"), "ask")
  })

  it("CRC-5: `HOME` changed in a way the plugin does not see: the ask on a home-relative file stays", () => {
    const fs = files()
    const ctx = context(fs.app, fs.home, excepting(fs.netrc))
    // Witness: the excepted file, by its absolute path, is lifted.
    assert.equal(shellFinding(`cat ${fs.netrc}`, ctx), undefined)
    assert.equal(shellFinding(`export H''OME=${fs.secrets} && cat ~/.netrc`, ctx)?.rule, RULE)
  })

  it("CRC-5b: the excepted file named home-relative, nothing changing `HOME`: the ask stays (the session's `HOME` is unseen)", () => {
    const fs = files()
    assert.equal(shellFinding("cat ~/.netrc", context(fs.app, fs.home, excepting(fs.netrc)))?.rule, RULE)
  })

  it("CRC-6: an exception written with a `..` after a link does not except the lexical file", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [`${fs.app}/lnk/../.env`] } }, fs)
    // The kernel's file for that path is `secrets/.env`: the project's own `.env` was never named.
    assert.equal(await plugin.shell(`cat ${fs.env}`), "ask")
  })
})

describe("fixes of review RC: every other part of the command only reads (point 4)", () => {
  it("CRC-7: a part before the read replaces a link or swaps directories on the excepted file's path: the ask stays", async () => {
    const fs = files()
    const ctx = context(fs.app, fs.home, excepting(fs.env))
    // Witness: the excepted file, also through the link, is lifted.
    assert.equal(shellFinding(`cat ${fs.cur}/.env`, ctx), undefined)
    const swaps = [`ln -sfn ${fs.secrets} ${fs.cur} && cat ${fs.cur}/.env`, `mv ${fs.app} ${fs.root}/old && mv ${fs.secrets} ${fs.app} && cat ${fs.env}`]
    for (const command of swaps) assert.equal(shellFinding(command, ctx)?.rule, RULE, command)
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    for (const command of swaps) assert.equal(await plugin.shell(command), "ask", command)
  })

  it("CRC-8: the same with the memory of confirmations: the remembered set is not lifted after such a part", async () => {
    const fs = files()
    const plugin = await guard({ rememberConfirmations: 10 }, fs)
    assert.equal(await plugin.shell(`cat ${fs.cur}/.env`), "ask")
    assert.equal(await plugin.shell(`cat ${fs.cur}/.env`), "allow")
    assert.equal(await plugin.shell(`ln -sfn ${fs.secrets} ${fs.cur} && cat ${fs.cur}/.env`), "ask")
    assert.equal(await plugin.shell(`mv ${fs.app} ${fs.root}/old; mv ${fs.secrets} ${fs.app}; cat ${fs.cur}/.env`), "ask")
  })

  it("CRC-9: the excepted file read, then filtered by programs of the closed list: lifted (witness)", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    const reads = [
      `cat ${fs.env} | grep NAME`,
      `head -1 ${fs.env} | cut -c1-4 | wc -c`,
      `cat ${fs.env} 2>/dev/null`,
      `cat ${fs.env} 2>&1 | tail -1`,
      `(cat ${fs.env}); echo done`,
      `grep -c NAME ${fs.env} && echo found`,
      `grep $(whoami) ${fs.env}`,
    ]
    for (const command of reads) assert.equal(await plugin.shell(command), "allow", command)
  })

  it("CRC-10: an assignment or a redirection to a file in another part, or in the part that reads: the ask stays", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    const commands = [`X=1; cat ${fs.env}`, `cat ${fs.env}; echo x > ${fs.root}/out`, `cat ${fs.env} > ${fs.root}/copy.txt`, `cat ${fs.env} | sort`, `export X=1 && cat ${fs.env}`]
    for (const command of commands) assert.equal(await plugin.shell(command), "ask", command)
  })

  it("CRC-11: a substitution among the arguments of the part that reads, with an absolute path: the ask stays", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    assert.equal(await plugin.shell(`cat $(ln -sfn ${fs.secrets} ${fs.cur}) ${fs.cur}/.env`), "ask")
    assert.equal(await plugin.shell(`cat ${fs.cur}/.env <(ln -sfn ${fs.secrets} ${fs.cur})`), "ask")
  })

  it("CRC-12: the part that reads launches another program or writes, with an absolute path: the ask stays", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    const commands = [
      `timeout 5 cat ${fs.env}`,
      `env cat ${fs.env}`,
      `xargs cat ${fs.env}`,
      `git diff --no-index ${fs.env} /dev/null`,
      `sed -n p ${fs.env}`,
      `${fs.app}/setup.sh ${fs.env}`,
      `cp ${fs.env} ${fs.root}/bak`,
      `coproc cat ${fs.env}`,
      `- cat ${fs.env}`,
    ]
    for (const command of commands) assert.equal(await plugin.shell(command), "ask", command)
  })

  it("CRC-13: permission.evaluate: another sub-command of the call replaces a link: the ask stays (witness: only reads)", async () => {
    const fs = files()
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    assert.equal(await plugin.evaluate([`cat ${fs.env}`, "grep NAME"]), "allow")
    // A sibling that reads the same file with a program of the closed list counts as a part that reads, as in execute.before.
    assert.equal(await plugin.evaluate([`cat ${fs.env}`, `head -1 ${fs.env}`]), "allow")
    // With a program outside the list, even one that launches nothing: the ask stays.
    assert.equal(await plugin.evaluate([`cat ${fs.env}`, `strings ${fs.env}`]), "ask")
    assert.equal(await plugin.evaluate([`ln -sfn ${fs.secrets} ${fs.cur}`, `cat ${fs.cur}/.env`]), "ask")
  })
})

describe("fixes of review RC: home-relative, relative and `..` words (points 1 to 3, 5)", () => {
  it("CRC-14: `HOME` may change (word in a view without quotes or backslashes, `$`, braces, pattern, sourced file): the ask stays", () => {
    const fs = files()
    const ctx = context(fs.app, fs.home, excepting(fs.netrc))
    // Witness: the excepted file, by its absolute path, then filtered, is lifted.
    assert.equal(shellFinding(`cat ${fs.netrc} | grep machine`, ctx), undefined)
    const commands = ["echo H\\OME | cat ~/.netrc", "cat ~/.netrc $HOME/notes", "echo {a,b} && cat ~/.netrc", "ls HOM? | cat ~/.netrc", ". ./setup.sh && cat ~/.netrc"]
    for (const command of commands) assert.equal(shellFinding(command, ctx)?.rule, RULE, command)
  })

  it("CRC-14b: the same file named home-relative, then filtered, nothing changing `HOME`: the ask stays", () => {
    const fs = files()
    assert.equal(shellFinding("cat ~/.netrc | grep machine", context(fs.app, fs.home, excepting(fs.netrc)))?.rule, RULE)
  })

  it("CRC-15: a relative path never gives a target (shell, read tool, memory)", async () => {
    const fs = files()
    assert.equal(shellFinding("cat ./.env", context(fs.app, fs.home, excepting(fs.env)))?.rule, RULE)
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    assert.equal(await plugin.shell("cat ./.env"), "ask")
    assert.equal(await plugin.read("./.env"), "ask")
    const memory = await guard({ rememberConfirmations: 10 }, fs)
    assert.equal(await memory.shell("cat ./.env"), "ask")
    assert.equal(await memory.shell("cat ./.env"), "ask")
    assert.equal(await memory.read("./.env"), "ask")
    assert.equal(await memory.read("./.env"), "ask")
  })

  it("CRC-16: a `..` component never gives a target, even without a link (shell, read tool, MCP tool)", async () => {
    const fs = files()
    const dotted = `${fs.app}/../app/.env`
    assert.equal(shellFinding(`cat ${dotted}`, context(fs.app, fs.home, excepting(fs.env)))?.rule, RULE)
    const plugin = await guard({ exceptions: { [RULE]: [fs.env] } }, fs)
    assert.equal(await plugin.shell(`cat ${dotted}`), "ask")
    assert.equal(await plugin.read(dotted), "ask")
    assert.equal(await plugin.tool("files_read", { path: dotted }), "ask")
    // Witness: the same file without `..` is lifted for the three.
    assert.equal(await plugin.read(fs.env), "allow")
    assert.equal(await plugin.tool("files_read", { path: fs.env }), "allow")
  })

  it("CRC-17: with the default settings, a relative word is named as written in the reason", () => {
    const fs = files()
    const ctx = context(fs.app, fs.home)
    assert.equal(shellFinding("cat ./.env", ctx)?.reason, "access to a credential file (./.env)")
    assert.equal(shellFinding(`cat .env ${fs.other}`, ctx)?.reason, `access to a credential file (.env, ${fs.other})`)
    assert.equal(shellFinding("cat ~/.netrc", ctx)?.reason, `access to a credential file (${fs.netrc})`)
  })
})

describe("fixes of review RC: `..` in the configuration and the command line (point 6)", () => {
  it("CRC-18: an exception with a `..` component is ignored with a warning; guard rules off --path refuses it", async () => {
    const fs = files()
    const dotted = `${fs.app}/../app/.env`
    const plugin = await guard({ exceptions: { [RULE]: [dotted] } }, fs)
    assert.equal(await plugin.shell(`cat ${fs.env}`), "ask")
    assert.ok(plugin.log().includes(`WARN exceptions.${RULE}[0] ignored: ${JSON.stringify(dotted)} has a ".." component`), plugin.log())
    const w = await cli({ globalGuard: {} })
    writeFileSync(join(w.project, ".env"), "NAME=dummy\n")
    const r = w.run(["rules", "off", RULE, "--path", `${w.project}/../app/.env`])
    assert.equal(r.code !== 0 && /has a "\.\." component/.test(r.err), true, `${r.code} ${r.out} ${r.err}`)
    assert.deepEqual(w.read(), {})
  })
})

describe("fixes of review RC: paths of sources that cannot be retained, regular file check injected (point 9)", () => {
  const declared = (global: Json) => () => [{ label: "global", options: global }, { label: "system", reason: "it is missing or unreadable" }]

  it("CRC-21: an untrusted project guard.json and undeclared effective options: their paths are never resolved", () => {
    const fs = files()
    const asked: string[] = []
    const realPath = (path: string) => {
      asked.push(path)
      try {
        return realpathSync(path)
      } catch {
        return undefined
      }
    }
    const projectFile = join(fs.root, "chosen", "project.env")
    const optionFile = join(fs.root, "chosen", "option.env")
    const projectGuard = { label: `project guard.json (${fs.app})`, global: false, dir: fs.app, data: { exceptions: { [RULE]: [projectFile] } } }
    const options = { exceptions: { [RULE]: [optionFile, fs.env] } }
    const inputs = { files: [projectGuard], project: fs.app, realPath, regularFile: () => true }
    const { config, warnings } = parseConfig(options, {}, declared({ exceptions: { [RULE]: [fs.env] } }) as never, inputs as never)
    const version = resolveVersion(config.layers!, [projectGuard])
    assert.deepEqual(asked.filter((path) => path === projectFile || path === optionFile), [])
    assert.ok(version.warnings.some((line) => line.includes(`exceptions.${RULE} ${JSON.stringify(projectFile)} ignored: its directory is not trusted`)), version.warnings.join("\n"))
    assert.ok(warnings.some((line) => line.startsWith(`exceptions.${RULE} ${JSON.stringify(optionFile)} ignored: a relaxation counts only if`)), warnings.join("\n"))
    // Witness: the path the global configuration lists as written is resolved and retained.
    assert.ok(asked.includes(fs.env))
    assert.equal(version.base.policy.exceptions?.get(RULE)?.has(fs.env), true)
  })

  it("CRC-22: the regular file check is injected with the path resolution (the configuration reads no file itself)", () => {
    const missing = "/nonexistent-crc-22/.env"
    const options = { exceptions: { [RULE]: [missing] } }
    const parse = (regularFile?: () => boolean) =>
      parseConfig(options, {}, declared(options) as never, { files: [], realPath: (path: string) => path, ...(regularFile ? { regularFile } : {}) } as never)
    assert.equal(parse(() => true).config.policy.exceptions?.get(RULE)?.has(missing), true)
    assert.ok(parse(() => false).warnings.some((line) => line.includes(`${JSON.stringify(missing)} is not a regular file`)))
    assert.ok(parse().warnings.some((line) => line.includes(`${JSON.stringify(missing)} could not be checked`)))
    assert.doesNotMatch(readFileSync(new URL("../src/config.ts", import.meta.url), "utf8"), /from "node:fs"/)
  })
})

describe("fixes of review RC: effective options in a trusted project, bounded cost", () => {
  it("CRC-27: an exception only in the effective options of a project trusted at startup is still lifted (witness)", async () => {
    const fs = files()
    const [globalDir, systemDir] = [join(fs.root, "global"), join(fs.root, "system")]
    for (const dir of [globalDir, systemDir, join(fs.app, ".opencode")]) mkdirSync(dir, { recursive: true })
    writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: { trustedProjects: [join(fs.root, "work")] } }] }))
    const fake = fakeContext({ logFile: join(fs.root, "guard.log"), trustedProjects: [join(fs.root, "work")], exceptions: { [RULE]: [fs.env] } })
    ;(fake.ctx.location as { directory: string }).directory = fs.app
    await (setupGuard as (...args: unknown[]) => Promise<void>)(fake.ctx, {}, systemDir, globalDir, { now: () => 1_000_000, intervalMs: 2000 })
    await fake.trigger("tool.execute.before", { sessionID: "ses_1", agent: "build", messageID: "msg_0", id: "call_1", tool: "shell", input: { command: `cat ${fs.env}` } })
    assert.equal(fake.asserts.length, 0)
  })

  it("CRC-28: many substitutions or target words: no target, at a bounded cost (Node only)", () => {
    const fs = files()
    const ctx = context(fs.app, fs.home, excepting(fs.env))
    const started = performance.now()
    assert.equal(shellFinding(`cat ${fs.env} ${"$(true) ".repeat(4000)}`, ctx)?.rule, RULE)
    assert.equal(shellFinding(`cat ${`${fs.env} `.repeat(400)}`, ctx)?.rule, RULE)
    assert.ok(performance.now() - started < 3000, `${performance.now() - started} ms`)
    // Witness below the limits: lifted.
    assert.equal(shellFinding(`cat ${fs.env} ${"$(true) ".repeat(8)}`, ctx), undefined)
  })
})
