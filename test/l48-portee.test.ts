// Lot 48 step B3: settings by agent and by project. guard.json files (global, and in each `.opencode` OpenCode reads),
// `agents` sections (main agent recorded at the prompt, subagent), `projects` sections and `trustedProjects` (global
// sources only). Two layers: a project's settings always harden; they relax only for a trusted project. Each case runs
// the plugin as OpenCode does (`setupGuard`, configuration directories of the test); nothing is launched, text is judged.
// Only existing exports are imported, so that the deployed code fails on assertions, not on loading.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { setupGuard } from "../src/index.ts"
import { fakeContext } from "./fake-ctx.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>

interface Setup {
  /** Plugin options received (effective configuration). */
  readonly options?: Json
  /** Plugin options of the global opencode.json (absent: no file). */
  readonly global?: Json
  readonly globalGuard?: Json | string
  /** guard.json of the project's `.opencode`, and of its parent's. */
  readonly projectGuard?: Json | string
  readonly parentGuard?: Json
}

/** Plugin set up as OpenCode does: configuration directories, session directory `<ROOT>/work/app`, test clock. */
async function guard(setup: Setup = {}) {
  const root = mkdtempSync(join(tmpdir(), "guard-prt-"))
  const rooted = (content: Json | string) => (typeof content === "string" ? content : JSON.stringify(content)).replaceAll("<ROOT>", root)
  const [globalDir, systemDir, project] = [join(root, "global"), join(root, "system"), join(root, "work", "app")]
  for (const dir of [globalDir, systemDir, join(project, ".opencode"), join(root, "work", ".opencode")]) mkdirSync(dir, { recursive: true })
  const write = (file: string, content: Json | string | undefined) => {
    if (content !== undefined) writeFileSync(file, rooted(content))
  }
  if (setup.global) write(join(globalDir, "opencode.json"), { plugins: [{ package: PLUGIN_DIR, options: setup.global }] })
  write(join(globalDir, "guard.json"), setup.globalGuard)
  write(join(project, ".opencode", "guard.json"), setup.projectGuard)
  write(join(root, "work", ".opencode", "guard.json"), setup.parentGuard)
  const logFile = join(root, "guard.log")
  const fake = fakeContext({ logFile, ...(setup.options ? (JSON.parse(rooted(setup.options)) as Json) : {}) })
  ;(fake.ctx.location as { directory: string }).directory = project
  for (const [name, mode] of [["plan", "primary"], ["lax", "primary"], ["both", "all"], ["explore", "subagent"], ["reviewer", "subagent"], ["quick", "subagent"]])
    fake.agents.set(name!, { mode: mode!, permissions: [] })
  // Child sessions: OpenCode's subagent tool creates them with `parentID`.
  const parents = new Map<string, string>()
  const session = fake.ctx.session as unknown as { get: (input: { sessionID: string }) => Promise<Json> }
  const plain = session.get
  session.get = async (input) => ({ ...(await plain(input)), ...(parents.has(input.sessionID) ? { parentID: parents.get(input.sessionID) } : {}) })
  let now = 1_000_000
  await (setupGuard as (...args: unknown[]) => Promise<void>)(fake.ctx, {}, systemDir, globalDir, { now: () => now, intervalMs: 2000 })
  let call = 0
  return {
    ...fake,
    root,
    project,
    globalDir,
    log: () => readFileSync(logFile, "utf8"),
    write,
    tick: (ms = 2000) => (now += ms),
    /** Prompt of the user (root session) or of the subagent tool (child session), with the session agent at that time. */
    prompt: async (sessionID: string, agent: string, parent?: string) => {
      fake.switchAgent(sessionID, agent)
      if (parent) parents.set(sessionID, parent)
      await fake.trigger("session.prompt", { sessionID, messageID: `msg_${++call}`, prompt: { text: "go" } })
    },
    /** Verdict of a shell call in `execute.before`: deny (blocked), ask (a confirmation was requested) or allow. */
    verdict: async (command: string, sessionID = "ses_1", agent = "build") => {
      const before = fake.asserts.length
      try {
        await fake.trigger("tool.execute.before", { sessionID, agent, messageID: "msg_0", id: `call_${++call}`, tool: "shell", input: { command } })
      } catch (error) {
        if (/Blocked/.test(String(error))) return "deny"
        throw error
      }
      return fake.asserts.length > before ? "ask" : "allow"
    },
    /** Effect left by `permission.evaluate` on the shell sub-commands of a call. */
    evaluate: async (command: string, sessionID: string, agent: string) => {
      const event = { sessionID, agent, action: "shell", resources: [command], effect: "allow", message: undefined, source: { type: "tool", messageID: "msg_0", id: `other_${++call}` } }
      await fake.trigger("permission.evaluate", event)
      return event.effect
    },
  }
}

const off = (rule: string) => ({ ruleOverrides: { [rule]: "off" } })

describe("lot 48 step B3: guard.json files", () => {
  it("PRT-1: the global guard.json is read at startup; its relaxations apply; start line with sources and trust", async () => {
    const plugin = await guard({ globalGuard: off("git-reset-hard") })
    assert.equal(await plugin.verdict("git reset --hard"), "allow")
    assert.equal(await plugin.verdict("git clean -fdx"), "ask")
    assert.match(plugin.log(), /INFO settings by agent and by project \(guard\.json: global guard\.json; agent sections: none; project sections: none; this project: not trusted\)/)
  })

  it("PRT-2: re-read when it changes, at most once per interval (never a read per call); info line", async () => {
    const plugin = await guard({ globalGuard: {} })
    const file = join(plugin.globalDir, "guard.json")
    assert.equal(await plugin.verdict("git reset --hard"), "ask")
    plugin.write(file, off("git-reset-hard"))
    plugin.tick(1999)
    assert.equal(await plugin.verdict("git reset --hard"), "ask") // not checked yet: no read on this call
    plugin.tick(1)
    assert.equal(await plugin.verdict("git reset --hard"), "allow")
    assert.match(plugin.log(), /INFO guard\.json re-read \(guard\.json: global guard\.json; /)
    plugin.write(file, { ruleOverrides: { "git-reset-hard": "deny" } })
    plugin.tick()
    assert.equal(await plugin.verdict("git reset --hard"), "deny")
    // Present at startup, then removed: neither its deny nor its relaxation stays.
    rmSync(file)
    plugin.tick()
    assert.equal(await plugin.verdict("git reset --hard"), "ask")
    const relaxed = await guard({ globalGuard: off("git-reset-hard") })
    assert.equal(await relaxed.verdict("git reset --hard"), "allow")
    rmSync(join(relaxed.globalDir, "guard.json"))
    relaxed.tick()
    assert.equal(await relaxed.verdict("git reset --hard"), "ask")
    assert.match(relaxed.log(), /INFO guard\.json re-read \(guard\.json: none; agent sections: none; project sections: none; this project: not trusted\)/)
    // Created while running (absent at startup), then removed: back to the startup settings.
    const late = await guard()
    assert.equal(await late.verdict("git reset --hard"), "ask")
    late.write(join(late.globalDir, "guard.json"), off("git-reset-hard"))
    late.tick()
    assert.equal(await late.verdict("git reset --hard"), "allow")
    rmSync(join(late.globalDir, "guard.json"))
    late.tick()
    assert.equal(await late.verdict("git reset --hard"), "ask")
    assert.match(late.log(), /INFO guard\.json re-read \(guard\.json: none; startup settings\)/)
    // Tool calls never read a session.
    assert.equal(late.lookups.session, 0)
  })

  it("PRT-3: invalid, symbolic link, too large, not an object: ignored as a whole without its content; unknown keys and other options warned", async () => {
    const marker = "MARKER-not-to-be-logged"
    for (const [content, reason] of [
      [`{"ruleOverrides": {"git-reset-hard": "off"}, "${marker}": `, "it is not valid JSON"],
      [`["${marker}"]`, "it is not a JSON object"],
      [JSON.stringify({ ...off("git-reset-hard"), pad: `${marker}${"x".repeat(70_000)}` }), "it is larger than 65536 bytes"],
    ] as const) {
      const plugin = await guard({ globalGuard: content })
      assert.equal(await plugin.verdict("git reset --hard"), "ask", reason)
      assert.ok(plugin.log().includes(`WARN global guard.json ignored: ${reason}`), plugin.log())
      assert.ok(!plugin.log().includes(marker))
    }
    const linked = await guard()
    const target = join(linked.root, "elsewhere.json")
    writeFileSync(target, JSON.stringify(off("git-reset-hard")))
    symlinkSync(target, join(linked.project, ".opencode", "guard.json"))
    symlinkSync(target, join(linked.globalDir, "guard.json"))
    linked.tick()
    assert.equal(await linked.verdict("git reset --hard"), "ask")
    assert.match(linked.log(), /WARN global guard\.json ignored: it is a symbolic link/)
    assert.ok(linked.log().includes(`WARN project guard.json (${join(linked.project, ".opencode", "guard.json")}) ignored: it is a symbolic link`))
    const keys = await guard({ globalGuard: { ruleOverride: { "git-reset-hard": "off" }, askAs: "deny", ...off("git-clean") } })
    assert.equal(await keys.verdict("git reset --hard"), "ask") // askAs not taken: no unattended denial
    assert.equal(await keys.verdict("git clean -fdx"), "allow")
    assert.match(keys.log(), /WARN global guard\.json: unknown option ruleOverride, ignored/)
    assert.match(keys.log(), /WARN global guard\.json: askAs ignored: only the plugin options in opencode\.json accept it/)
  })

  it("PRT-4: two layers: a project not listed hardens over a global relaxation, its relaxations are dropped; listed or \"*\": kept", async () => {
    const global = { ruleOverrides: { "git-reset-hard": "off", "git-clean": "off", "rm-critical": "off" } }
    const project = { ruleOverrides: { "git-reset-hard": "deny", "rm-critical": "ask", "git-push-force": "off" } }
    const mixed = await guard({ globalGuard: global, projectGuard: project })
    assert.equal(await mixed.verdict("git reset --hard"), "deny") // project hardening
    assert.equal(await mixed.verdict("git clean -fdx"), "allow") // global relaxation
    assert.equal(await mixed.verdict("rm -rf ~"), "ask") // harder than the global "off"
    assert.equal(await mixed.verdict("git push --force"), "ask") // project relaxation dropped
    assert.ok(mixed.log().includes(`project guard.json (${join(mixed.project, ".opencode", "guard.json")}): ruleOverrides.git-push-force "off" ignored: its directory is not trusted`), mixed.log())
    for (const trustedProjects of [["<ROOT>/work"], "*"]) {
      const trusted = await guard({ globalGuard: { ...global, trustedProjects }, projectGuard: project })
      assert.equal(await trusted.verdict("git push --force"), "allow", JSON.stringify(trustedProjects))
      assert.equal(await trusted.verdict("git reset --hard"), "deny")
      assert.match(trusted.log(), /this project: trusted\)/)
    }
    // A project guard.json in a parent `.opencode` counts too (OpenCode reads every ancestor's): it always hardens; it
    // relaxes only if its own directory is trusted, not because the session directory is.
    const parent = await guard({ parentGuard: { ruleOverrides: { "git-clean": "deny" } } })
    assert.equal(await parent.verdict("git clean -fdx"), "deny")
    for (const [listed, expected] of [["<ROOT>/work/app", "ask"], ["<ROOT>/work", "allow"]] as const) {
      const above = await guard({ globalGuard: { trustedProjects: [listed] }, parentGuard: off("git-clean") })
      assert.equal(await above.verdict("git clean -fdx"), expected, listed)
      assert.match(above.log(), /this project: trusted\)/)
    }
    // Effective options that relax (a project opencode.json replacing the plugin options): kept for a trusted project,
    // otherwise dropped as before (the global file does not set them).
    const listed = await guard({ options: off("git-clean"), globalGuard: { trustedProjects: ["<ROOT>/work/app"] } })
    assert.equal(await listed.verdict("git clean -fdx"), "allow")
    const unlisted = await guard({ options: off("git-clean"), globalGuard: { trustedProjects: ["<ROOT>/other"] } })
    assert.equal(await unlisted.verdict("git clean -fdx"), "ask")
    assert.match(unlisted.log(), /WARN ruleOverrides\.git-clean "off" ignored: a relaxation counts only if the global or system configuration sets it too/)
  })

  it("PRT-5: projects sections of the global sources apply to the session directory and below, the closest one last", async () => {
    const plugin = await guard({
      globalGuard: { projects: { "<ROOT>/work": { ruleOverrides: { "git-clean": "off", "git-reset-hard": "off" } }, "<ROOT>/work/app": { ruleOverrides: { "git-reset-hard": "deny" } }, "<ROOT>/other": off("git-push-force") } },
    })
    assert.equal(await plugin.verdict("git clean -fdx"), "allow")
    assert.equal(await plugin.verdict("git reset --hard"), "deny")
    assert.equal(await plugin.verdict("git push --force"), "ask")
    assert.ok(plugin.log().includes(`project sections: ${join(plugin.root, "work")}, ${join(plugin.root, "work", "app")};`), plugin.log())
    // In the global opencode.json too.
    const declared = await guard({ global: { projects: { "<ROOT>/work": off("git-clean") } }, options: { projects: { "<ROOT>/work": off("git-clean") } } })
    assert.equal(await declared.verdict("git clean -fdx"), "allow")
  })

  it("PRT-6: trustedProjects or projects written by a project are ignored; trustedProjects added to the global guard.json counts at the next re-read", async () => {
    const own = await guard({ projectGuard: { trustedProjects: "*", projects: { "<ROOT>": off("git-clean") }, ...off("git-clean") } })
    assert.equal(await own.verdict("git clean -fdx"), "ask")
    assert.match(own.log(), /WARN project guard\.json \([^)]*\): trustedProjects ignored: it counts only in the global configuration/)
    assert.match(own.log(), /WARN project guard\.json \([^)]*\): projects ignored: it counts only in the global configuration/)
    // Injected through the effective options (a project opencode.json), absent from the global file.
    const injected = await guard({ options: { trustedProjects: "*", ...off("git-clean") } })
    assert.equal(await injected.verdict("git clean -fdx"), "ask")
    assert.match(injected.log(), /WARN trustedProjects ignored: it counts only in the global configuration/)
    // Step D writes trustedProjects into the global guard.json: no restart needed, in both directions.
    const later = await guard({ globalGuard: {}, projectGuard: off("git-clean") })
    assert.equal(await later.verdict("git clean -fdx"), "ask")
    later.write(join(later.globalDir, "guard.json"), { trustedProjects: ["<ROOT>/work/app"] })
    later.tick()
    assert.equal(await later.verdict("git clean -fdx"), "allow")
    later.write(join(later.globalDir, "guard.json"), { trustedProjects: [] })
    later.tick()
    assert.equal(await later.verdict("git clean -fdx"), "ask")
  })

  it("PRT-7: a switch set to false in a section or a guard.json of a project not listed is dropped; at the top of the options, as before", async () => {
    const plugin = await guard({ projectGuard: { dangerousCommands: false, profile: "credentials-only", agents: { build: { dangerousCommands: false } } } })
    await plugin.prompt("ses_1", "build")
    assert.equal(await plugin.verdict("git reset --hard"), "ask")
    assert.match(plugin.log(), /project guard\.json \([^)]*\): dangerousCommands false ignored: its directory is not trusted/)
    assert.match(plugin.log(), /project guard\.json \([^)]*\), agents\.build: dangerousCommands false ignored: its directory is not trusted/)
    const projectSection = await guard({ globalGuard: { projects: { "<ROOT>/work/app": { dangerousCommands: false } } } })
    assert.equal(await projectSection.verdict("git reset --hard"), "allow") // a global source may relax
    const options = await guard({ options: { dangerousCommands: false }, projectGuard: {} })
    assert.equal(await options.verdict("git reset --hard"), "allow")
  })
})

describe("lot 48 step B3: agent sections", () => {
  const sections = { agents: { reviewer: off("git-reset-hard"), build: { ruleOverrides: { "git-clean": "deny" } }, quick: { decisionModel: false } } }

  it("PRT-8: strict main agent: a subagent without a section stays strict, one with a relaxing section is relaxed", async () => {
    const plugin = await guard({ globalGuard: sections })
    await plugin.prompt("ses_root", "build")
    await plugin.prompt("ses_explore", "explore", "ses_root")
    await plugin.prompt("ses_review", "reviewer", "ses_root")
    assert.equal(await plugin.verdict("git reset --hard", "ses_root", "build"), "ask")
    assert.equal(await plugin.verdict("git reset --hard", "ses_explore", "explore"), "ask")
    assert.equal(await plugin.verdict("git reset --hard", "ses_review", "reviewer"), "allow")
    // The main agent's section reaches its subagents.
    assert.equal(await plugin.verdict("git clean -fdx", "ses_root", "build"), "deny")
    assert.equal(await plugin.verdict("git clean -fdx", "ses_explore", "explore"), "deny")
    // A subagent of a subagent: main agent of the root session.
    await plugin.prompt("ses_nested", "reviewer", "ses_explore")
    assert.equal(await plugin.verdict("git reset --hard", "ses_nested", "reviewer"), "allow")
    assert.equal(await plugin.verdict("git clean -fdx", "ses_nested", "reviewer"), "deny")
    // Same in permission.evaluate (shell sub-commands).
    assert.equal(await plugin.evaluate("git reset --hard", "ses_review", "reviewer"), "allow")
    assert.equal(await plugin.evaluate("git reset --hard", "ses_explore", "explore"), "ask")
    // Session lookups only at the prompt.
    assert.equal(plugin.lookups.session, 4)
    assert.match(plugin.log(), /agent sections: reviewer, build, quick;/)
  })

  it("PRT-9: plugin reloaded without a recorded prompt: never more lenient (only the hardenings of the calling agent's section)", async () => {
    const plugin = await guard({ globalGuard: { agents: { build: off("git-reset-hard"), reviewer: { ruleOverrides: { "git-push-force": "off", "git-clean": "deny" } } } } })
    assert.equal(await plugin.verdict("git reset --hard", "ses_1", "build"), "ask")
    assert.equal(await plugin.verdict("git push --force", "ses_2", "reviewer"), "ask")
    assert.equal(await plugin.verdict("git clean -fdx", "ses_2", "reviewer"), "deny")
    await plugin.prompt("ses_1", "build")
    assert.equal(await plugin.verdict("git reset --hard", "ses_1", "build"), "allow")
    // A main agent that is not primary (mode "all": the model can launch it) is never recorded.
    const both = await guard({ globalGuard: { agents: { both: off("git-reset-hard") } } })
    await both.prompt("ses_3", "both")
    assert.equal(await both.verdict("git reset --hard", "ses_3", "both"), "ask")
  })

  it("PRT-10: session unreadable at the prompt: main agent unknown, never more lenient", async () => {
    const plugin = await guard({ globalGuard: { agents: { build: off("git-reset-hard") } } })
    await plugin.prompt("ses_ok", "build")
    assert.equal(await plugin.verdict("git reset --hard", "ses_ok", "build"), "allow")
    plugin.failLookups(true)
    await plugin.prompt("ses_1", "build")
    plugin.failLookups(false)
    assert.equal(await plugin.verdict("git reset --hard", "ses_1", "build"), "ask")
    assert.match(plugin.log(), /ERROR agent sections: session lookup failed/)
  })

  it("PRT-11: an agent switch made by the model mid-turn has no effect until the next prompt (its hardenings apply)", async () => {
    const plugin = await guard({ globalGuard: { agents: { lax: { ruleOverrides: { "git-reset-hard": "off", "git-clean": "deny" } } } } })
    await plugin.prompt("ses_1", "build")
    plugin.switchAgent("ses_1", "lax")
    assert.equal(await plugin.verdict("git reset --hard", "ses_1", "lax"), "ask")
    assert.equal(await plugin.verdict("git clean -fdx", "ses_1", "lax"), "deny")
    await plugin.prompt("ses_1", "lax")
    assert.equal(await plugin.verdict("git reset --hard", "ses_1", "lax"), "allow")
  })

  it("PRT-12: decisionModel in a section: off for one subagent, on for an agent when the top level turns it off", async () => {
    const decision = { baseURL: "http://127.0.0.1:9/v1", model: "m" }
    const plugin = await guard({ options: { decision }, globalGuard: sections })
    await plugin.prompt("ses_root", "build")
    await plugin.prompt("ses_quick", "quick", "ses_root")
    assert.equal(await plugin.verdict("ls", "ses_root", "build"), "ask") // model unreachable
    assert.equal(await plugin.verdict("ls", "ses_quick", "quick"), "allow")
    // The global file turns the model off (the effective options are its own); the main agent's section turns it on.
    const on = await guard({ global: { decision, decisionModel: false }, options: { decision, decisionModel: false }, globalGuard: { agents: { build: { decisionModel: true } } } })
    await on.prompt("ses_root", "build")
    assert.equal(await on.verdict("ls", "ses_root", "build"), "ask")
    assert.equal(await on.verdict("ls", "ses_other", "plan"), "allow")
  })

  it("PRT-16: scripts in a section: unchecked for that agent only; files written by any agent are tracked", async () => {
    const run = async (plugin: Awaited<ReturnType<typeof guard>>, sessionID: string, agent: string) => {
      const write = { sessionID, agent, messageID: "msg_w", id: `w_${sessionID}`, tool: "write", input: { path: "reset.sh", content: "git reset --hard\n" } }
      await plugin.trigger("tool.execute.before", write)
      writeFileSync(join(plugin.project, "reset.sh"), "git reset --hard\n")
      await plugin.trigger("tool.execute.after", { ...write, status: "completed", result: { content: "ok" } })
    }
    // Written and run under lax (scripts off), then run under build after the user's next prompt: tracked, checked.
    const plugin = await guard({ globalGuard: { agents: { lax: { scripts: false } } } })
    await plugin.prompt("ses_root", "lax")
    await run(plugin, "ses_root", "lax")
    assert.equal(await plugin.verdict("bash reset.sh", "ses_root", "lax"), "allow")
    await plugin.prompt("ses_root", "build")
    assert.equal(await plugin.verdict("bash reset.sh", "ses_root", "build"), "ask")
    // Off at the top level (global file), on for the main agent: tracked, and checked for it only.
    const on = await guard({ global: { scripts: false }, options: { scripts: false }, globalGuard: { agents: { build: { scripts: true } } } })
    await on.prompt("ses_root", "build")
    await run(on, "ses_root", "build")
    assert.equal(await on.verdict("bash reset.sh", "ses_root", "build"), "ask")
    await on.prompt("ses_root", "plan")
    assert.equal(await on.verdict("bash reset.sh", "ses_root", "plan"), "allow")
  })

  it("PRT-13: a project section (not trusted) hardens but does not relax; trusted, it relaxes", async () => {
    const project = { agents: { reviewer: { ruleOverrides: { "git-reset-hard": "off", "git-clean": "deny" } } } }
    for (const trusted of [false, true]) {
      const plugin = await guard({ projectGuard: project, ...(trusted ? { globalGuard: { trustedProjects: ["<ROOT>/work/app"] } } : {}) })
      await plugin.prompt("ses_root", "build")
      await plugin.prompt("ses_review", "reviewer", "ses_root")
      assert.equal(await plugin.verdict("git reset --hard", "ses_review", "reviewer"), trusted ? "allow" : "ask")
      assert.equal(await plugin.verdict("git clean -fdx", "ses_review", "reviewer"), "deny")
    }
  })
})

describe("lot 48 step B3: nothing changes without these settings", () => {
  it("PRT-14 (guard): no guard.json, no agents, projects or trustedProjects: no start line, no session read by the prompt hook", async () => {
    const plugin = await guard({ options: { redactPrompt: false } })
    assert.equal(plugin.hooks.get("session.prompt")?.length, 1)
    assert.ok(!plugin.log().includes("settings by agent and by project"))
    assert.equal(await plugin.verdict("git reset --hard"), "ask")
    assert.equal(plugin.lookups.session, 0)
  })

  it("PRT-15: documentation of guard.json, layers, agents and projects", () => {
    const text = readFileSync(join(PLUGIN_DIR, "docs", "configuration.md"), "utf8")
    for (const needle of ["## Settings by agent and by project (`guard.json`)", '"trustedProjects"', '"projects"', '"agents"', "trusted project", "The model chooses which subagent it launches"])
      assert.ok(text.includes(needle), needle)
  })
})
