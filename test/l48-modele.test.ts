// Lot 48 step B2: letting the decision model decide some local asks. `localAsks: "model"` (every built-in rule without a
// setting), `"model"` in `ruleOverrides` (one rule), `selfProtectionByModel` (the always-active group too): such an ask is
// marked `modelDecides` where it is built, and the model's verdict is followed only if it judged the input in full. A
// deny, then an ask the user confirms, then an ask left to the model, at every combination point. Nothing is launched:
// text is judged, and the model is a function. Only existing exports are imported, so that the deployed code fails on
// assertions, not on loading.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createDecider, type ExecutedScript } from "../src/decide.ts"
import * as gate from "../src/hooks/gate.ts"
import { setupGuard } from "../src/index.ts"
import type { ActiveRules } from "../src/rules/features.ts"
import { toolFinding } from "../src/rules/tools.ts"
import { LIMIT_REACHED, mostSevere, type Finding } from "../src/rules/types.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
const ctx = { redactor: createRedactor(), home: "/home/test", cwd: "/home/test/app", protectedDirs: ["/opt/guard"] }
const DECISION = { baseURL: "http://127.0.0.1:9/v1", model: "m" }
const SELF_WRITE = "echo '{}' > ~/.config/opencode/opencode.json"

/** Plugin entries as re-read from the global and system configurations: the global one declares `options`. */
const declaredBy = (options: Record<string, unknown>) => () => [{ label: "global", options }, { label: "system", reason: "it is missing or unreadable" }]
const configOf = (options: Record<string, unknown>, declared?: () => unknown[]) => parseConfig(options, {}, declared as Parameters<typeof parseConfig>[2])
/** Settings declared in the global configuration too (relaxations retained). */
const relaxed = (options: Record<string, unknown>) => configOf(options, declaredBy(options))
const policyOf = (options: Record<string, unknown>) => (relaxed(options).config as { policy?: ActiveRules }).policy
const shell = (command: string, active?: ActiveRules, extra: Record<string, unknown> = {}) => toolFinding("shell", { command }, { ...ctx, active, ...extra })
const marked = (finding?: Finding) => Boolean(finding && (finding.dataOnly || finding.modelDecides !== undefined))
const brief = (finding?: Finding) => finding && [finding.verdict, finding.rule, marked(finding)]

/** Model answers: low risk (allow), medium (ask), high (deny); a failing model. */
const answer = (score: number) => async () => ({ answers: { risk: { score }, destructive: { noul: 0.01 }, exfiltration: { noul: 0.01 }, credentials: { noul: 0.01 }, privilege_persistence: { noul: 0.01 } } })
const ALLOW = answer(0.1)
const ASK = answer(2)
const DENY = answer(2.9)
const DOWN = async () => {
  throw new Error("connection refused")
}

/** Counts the model calls. */
function counted(model: () => Promise<unknown>) {
  const calls = { count: 0 }
  return { calls, model: async () => (calls.count++, model()) }
}

async function decide(options: Record<string, unknown>, tool: string, input: unknown, model?: () => Promise<unknown>, scripts?: ExecutedScript[]) {
  const { config } = relaxed({ decision: DECISION, ...options })
  const decider = createDecider({ config, redactor: createRedactor(), home: "/home/test", ...(model ? { model: model as never } : {}) })
  return decider.decide({ tool, input, directory: "/home/test/app", ...(scripts ? { scripts } : {}) })
}
const decideShell = (options: Record<string, unknown>, command: string, model?: () => Promise<unknown>, scripts?: ExecutedScript[]) => decide(options, "shell", { command }, model, scripts)

/** Gate with a real decider and an injected model (no connection), as `setupGuard` builds it. */
async function gateWith(options: Record<string, unknown>, model?: () => Promise<unknown>, deps: Record<string, unknown> = {}) {
  const { config } = relaxed({ decision: DECISION, ...options })
  const fake = fakeContext()
  const lines: string[] = []
  const log = { debug() {}, info: (line: string) => lines.push(line), warn() {}, error() {} }
  const redactor = createRedactor()
  const decider = createDecider({ config, redactor, home: "/home/test", ...(model ? { model: model as never } : {}) })
  await gate.registerGate(fake.ctx, { decider, redactor, log, home: "/home/test", rules: config.rules, active: (config as { policy?: ActiveRules }).policy, ...deps })
  const before = (command: string, id = "call_9") => fake.trigger("tool.execute.before", { sessionID: "ses_1", agent: "build", messageID: "msg_1", id, tool: "shell", input: { command } })
  const evaluate = (resources: string[], id: string | null = "call_9") =>
    fake.trigger("permission.evaluate", {
      sessionID: "ses_1",
      action: "shell",
      resources,
      effect: "allow",
      message: undefined as string | undefined,
      ...(id === null ? {} : { source: { type: "tool", messageID: "msg_1", id } }),
    })
  return { fake, lines, before, evaluate }
}

/** Global and system configuration directories of the test: the global file declares `global` for this plugin. */
function configDirs(global?: Record<string, unknown>) {
  const root = mkdtempSync(join(tmpdir(), "guard-mod-"))
  const [globalDir, systemDir] = [join(root, "global"), join(root, "system")]
  mkdirSync(globalDir)
  mkdirSync(systemDir)
  if (global) writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: global }] }))
  return { globalDir, systemDir }
}

async function startLog(options: Record<string, unknown>, global?: Record<string, unknown>) {
  const logFile = join(mkdtempSync(join(tmpdir(), "guard-mod-log-")), "guard.log")
  const fake = fakeContext({ logFile, ...options })
  const { globalDir, systemDir } = configDirs(global)
  await setupGuard(fake.ctx, {}, systemDir, globalDir)
  return readFileSync(logFile, "utf8")
}

describe("lot 48 step B2: combination order (default settings)", () => {
  it("MOD-1: a deny, then an ask the user confirms, then an ask the model can decide", () => {
    const data: Finding = { verdict: "ask", rule: "privilege", reason: "x", dataOnly: true }
    const left: Finding = { verdict: "ask", rule: "codemode-fetch", reason: "y", modelDecides: "z" }
    const user: Finding = { verdict: "ask", rule: "git-reset-hard", reason: "w" }
    assert.equal(mostSevere([data, user])?.rule, "git-reset-hard")
    assert.equal(mostSevere([left, undefined, user])?.rule, "git-reset-hard")
    assert.equal(mostSevere([data, left])?.rule, "privilege")
    assert.equal(mostSevere([data, user, { verdict: "deny", rule: "mkfs", reason: "v" }])?.rule, "mkfs")
  })
  it("MOD-1b: the same through the decider: a user rule's ask in another reading of the command is not decided by the model", async () => {
    // The view without a leading assignment and the command word read literally: a user rule anchored on `cat` asks there,
    // while the whole command is an ask from heredoc data only. The model allows: the user's rule still asks.
    const rules = [{ id: "user-cat", verdict: "ask", reason: "user rule", pattern: "^cat\\b" }]
    for (const command of ["A=1 cat > n.md <<'EOF'\nsudo ls\nEOF", "\"cat\" > n.md <<'EOF'\nsudo ls\nEOF"]) {
      const decision = await decideShell({ rules }, command, ALLOW)
      assert.deepEqual([decision.verdict, decision.rule], ["ask", "user-cat"], command)
    }
    // Without the user rule: still decided by the model (heredoc data only).
    assert.equal((await decideShell({}, "A=1 cat > n.md <<'EOF'\nsudo ls\nEOF", ALLOW)).verdict, "allow")
  })
})

describe("lot 48 step B2: options and precedence", () => {
  it("MOD-2: localAsks model → the model's verdict on a local ask judged in full; otherwise the ask remains", async () => {
    const options = { localAsks: "model" }
    const allowed = await decideShell(options, "sudo ls", ALLOW)
    assert.deepEqual([allowed.verdict, allowed.rule, allowed.source], ["allow", "privilege", "model"])
    assert.match(allowed.reason, /^privilege escalation, left to the decision model by localAsks, decided by m: /)
    assert.deepEqual([(await decideShell(options, "sudo ls", ASK)).verdict, (await decideShell(options, "sudo ls", DENY)).verdict], ["ask", "deny"])
    // Unreachable model, truncated input, model disabled: the ask remains.
    const down = await decideShell(options, "sudo ls", DOWN)
    assert.deepEqual([down.verdict, down.rule, down.source], ["ask", "privilege", "model-error"])
    const long = await decideShell({ ...options, maxStateChars: 200 }, `sudo ls ${"a".repeat(400)}`, ALLOW)
    assert.deepEqual([long.verdict, long.rule], ["ask", "privilege"])
    assert.match(long.reason, /the input was too long for the decision model to decide$/)
    const disabled = await decideShell(options, "sudo ls")
    assert.deepEqual([disabled.verdict, disabled.rule, disabled.source], ["ask", "privilege", "local"])
    // The same input in a script run by the command: never decided by the model alone.
    const script: ExecutedScript = { path: "run.sh", content: "sudo ls\n", shell: true, forModel: true }
    assert.equal((await decideShell(options, "bash run.sh", ALLOW, [script])).verdict, "ask")
  })
  it("MOD-3: model on one rule; another rule's ask in the same command still asks; a setting on the rule wins over localAsks", async () => {
    const one = { ruleOverrides: { privilege: "model" } }
    assert.equal((await decideShell(one, "sudo ls", ALLOW)).verdict, "allow")
    assert.equal((await decideShell(one, "git reset --hard", ALLOW)).verdict, "ask")
    for (const command of ["sudo ls; git reset --hard", "git reset --hard; sudo ls"]) {
      const decision = await decideShell(one, command, ALLOW)
      assert.deepEqual([decision.verdict, decision.rule], ["ask", "git-reset-hard"], command)
      assert.deepEqual(brief(shell(command, policyOf(one))), ["ask", "git-reset-hard", false], command)
    }
    const asked = { localAsks: "model", ruleOverrides: { "git-reset-hard": "ask" } }
    assert.deepEqual([(await decideShell(asked, "git reset --hard", ALLOW)).verdict, (await decideShell(asked, "sudo ls; git reset --hard", ALLOW)).rule], ["ask", "git-reset-hard"])
    assert.equal((await decideShell({ localAsks: "model", ruleOverrides: { privilege: "deny" } }, "sudo ls", ALLOW)).verdict, "deny")
    // A deny stays a deny: "model" only reaches a rule's asks.
    const denied = await decideShell({ localAsks: "model", ruleOverrides: { "rm-critical": "model" } }, "rm -rf ~", ALLOW)
    assert.deepEqual([denied.verdict, denied.rule], ["deny", "rm-critical"])
    // "model" turns a rule on in a disabled group, like "ask" and "deny".
    assert.deepEqual(brief(shell("sudo ls", policyOf({ dangerousCommands: false, ruleOverrides: { privilege: "model" } }))), ["ask", "privilege", true])
  })
  it("MOD-3b: several paths of one patch: an ask the user confirms is not replaced by self-protection left to the model", async () => {
    const options = { localAsks: "model", selfProtectionByModel: true, ruleOverrides: { "protected-write": "ask" } }
    const patchText = ["*** Begin Patch", "*** Update File: /home/test/.bashrc", "@@", "-x", "+y", "*** Update File: /home/test/.config/opencode/opencode.json", "@@", "-x", "+y", "*** End Patch"].join("\n")
    assert.deepEqual(brief(toolFinding("patch", { patchText }, { ...ctx, active: policyOf(options) })), ["ask", "self-protection", false])
    const decision = await decide(options, "patch", { patchText }, ALLOW)
    assert.deepEqual([decision.verdict, decision.rule], ["ask", "self-protection"])
  })
  it("MOD-4b: an ask born from an unfinished check comes before an ask left to the model, in either order", async () => {
    const options = { localAsks: "model", selfProtectionByModel: true }
    for (const [command, rule] of [
      ["sudo ls; a$(echo b) x", "nested-opencode"],
      ["a$(echo b) x; sudo ls", "nested-opencode"],
      ['sudo ls; dd if=x of="$OUT"', "dd-device"],
      ['dd if=x of="$OUT"; sudo ls', "dd-device"],
    ]) {
      const decision = await decideShell(options, command, ALLOW)
      assert.deepEqual([decision.verdict, decision.rule], ["ask", rule], command)
    }
  })
  it("MOD-4 (guard): never left to the model: limits, values known only at run time, denials found inside data, user rules, internal errors, read tools", async () => {
    const active = policyOf({ localAsks: "model", selfProtectionByModel: true })
    for (const command of [
      "a$(echo b) x",
      "opencode $X run",
      "dd if=a of=../../../dev/sda",
      'dd if=x of="$OUT"',
      "cat > notes.md <<'EOF'\nmkfs.ext4 /dev/sdb1\nEOF",
      `python3 -c "${"x=1;".repeat(17000)}"`,
    ])
      assert.equal(marked(shell(command, active)), false, command.slice(0, 40))
    assert.deepEqual(brief(shell("cat foo.bin", active, { credentialContent: () => LIMIT_REACHED })), ["ask", "secret-file-read", false])
    assert.deepEqual(brief(shell("echo x > /home/test/app/link/f", active, { realPaths: () => LIMIT_REACHED })), ["ask", "self-protection", false])
    assert.equal(marked(toolFinding("read", { path: "/home/test/app/foo.bin" }, { ...ctx, active, credentialContent: () => LIMIT_REACHED })), false)
    assert.equal(marked(toolFinding("write", { path: "/home/test/app/link/f", content: "x" }, { ...ctx, active, realPaths: () => LIMIT_REACHED })), false)
    const options = { localAsks: "model", selfProtectionByModel: true }
    const custom = await decideShell({ ...options, rules: [{ id: "no-deploy", verdict: "ask", reason: "deploy", pattern: "deploy" }] }, "deploy now", ALLOW)
    assert.deepEqual([custom.verdict, custom.rule], ["ask", "no-deploy"])
    const throwing = [{ id: "boom", verdict: "ask", reason: "x", pattern: "(a+)+$", tools: ["webfetch"] }]
    const { config } = relaxed({ decision: DECISION, ...options, rules: throwing })
    const broken = { ...config, rules: [{ ...config.rules[0]!, pattern: { test: () => { throw new Error("broken") } } as unknown as RegExp }] }
    const internal = await createDecider({ config: broken, redactor: createRedactor(), model: ALLOW as never }).decide({ tool: "webfetch", input: { url: "https://x.invalid" }, directory: "/home/test/app" })
    assert.deepEqual([internal.verdict, internal.rule], ["ask", "internal-error"])
    // Read-only tools: the model is never consulted, the ask remains.
    const reads = counted(ALLOW)
    const read = await decide(options, "read", { path: "/home/test/app/.env" }, reads.model)
    assert.deepEqual([read.verdict, read.rule, reads.calls.count], ["ask", "secret-file-read", 0])
  })
  it("MOD-5: always-active rules: only with selfProtectionByModel; the placeholder still denies", async () => {
    assert.deepEqual([(await decideShell({ localAsks: "model" }, SELF_WRITE, ALLOW)).verdict, (await decideShell({ localAsks: "model", selfProtectionByModel: true }, SELF_WRITE, ALLOW)).verdict], ["ask", "ask"])
    const ignored = relaxed({ ruleOverrides: { "self-protection": "model" } })
    assert.ok(ignored.warnings.includes('ruleOverrides.self-protection "model" ignored: this rule is always active ("model" needs selfProtectionByModel)'), ignored.warnings.join("\n"))
    assert.deepEqual(brief(shell(SELF_WRITE, (ignored.config as { policy?: ActiveRules }).policy)), ["ask", "self-protection", false])
    const one = { selfProtectionByModel: true, ruleOverrides: { "self-protection": "model" } }
    assert.deepEqual(brief(shell(SELF_WRITE, policyOf(one))), ["ask", "self-protection", false])
    assert.deepEqual(brief(shell("echo [[GUARD_REDACTED:openai]] > a.txt", policyOf({ ...one, localAsks: "model" }))), ["deny", "placeholder", false])
  })
  it("MOD-6: localAsks model, model on a rule and selfProtectionByModel count only if the global configuration sets them too", () => {
    const project = configOf({ localAsks: "Model", selfProtectionByModel: "true", ruleOverrides: { privilege: "model" } }, declaredBy({}))
    for (const line of [
      'localAsks "model" ignored: a relaxation counts only if the global or system configuration sets it too (global configuration: it does not set this value; system configuration: it is missing or unreadable)',
      "selfProtectionByModel ignored: a relaxation counts only if the global or system configuration sets it too (global configuration: it does not set this value; system configuration: it is missing or unreadable)",
      'ruleOverrides.privilege "model" ignored: a relaxation counts only if the global or system configuration sets it too (global configuration: it does not set this value; system configuration: it is missing or unreadable)',
    ])
      assert.ok(project.warnings.includes(line), `${line}\n${project.warnings.join("\n")}`)
    assert.deepEqual(brief(shell("sudo ls", (project.config as { policy?: ActiveRules }).policy)), ["ask", "privilege", false])
    const global = configOf({ localAsks: "model", selfProtectionByModel: true, ruleOverrides: { privilege: "model" } }, declaredBy({ localAsks: "MODEL", selfProtectionByModel: "1", ruleOverrides: { privilege: "Model" } }))
    assert.deepEqual(global.warnings, [])
    assert.deepEqual(brief(shell(SELF_WRITE, (global.config as { policy?: ActiveRules }).policy)), ["ask", "self-protection", false])
    const invalid = relaxed({ localAsks: "always" })
    assert.ok(invalid.warnings.includes('invalid value for localAsks ("always"), using "ask"'), invalid.warnings.join("\n"))
  })
})

describe("lot 48 step B2: execute.before then permission.evaluate", () => {
  it("MOD-7: allowed by the model in execute.before → the same sub-command asks are not posed again; anything else still is", async () => {
    const options = { ruleOverrides: { privilege: "model" } }
    const allowed = await gateWith(options, ALLOW)
    await allowed.before("sudo ls")
    assert.equal(allowed.fake.asserts.length, 0)
    assert.ok(allowed.lines.some((line) => /^shell → allow \(model, rule privilege\): privilege escalation, left to the decision model by ruleOverrides, decided by m: /.test(line)), allowed.lines.join("\n"))
    assert.equal((await allowed.evaluate(["sudo ls"])).effect, "allow")
    // Another rule's ask (not left to the model), a sub-command's deny, another call, no source: they remain.
    assert.equal((await allowed.evaluate(["sudo ls", "git reset --hard"])).effect, "ask")
    assert.equal((await allowed.evaluate(["sudo ls", "rm -rf ~"])).effect, "deny")
    assert.equal((await allowed.evaluate(["sudo ls"], "call_other")).effect, "ask")
    assert.equal((await allowed.evaluate(["sudo ls"], null)).effect, "ask")
    // The mark ends with the call.
    await allowed.fake.trigger("tool.execute.after", { sessionID: "ses_1", agent: "build", messageID: "msg_1", id: "call_9", tool: "shell", input: { command: "sudo ls" }, status: "completed" })
    assert.equal((await allowed.evaluate(["sudo ls"])).effect, "ask")
    // Unreachable model, truncated input: execute.before asks; confirmed, evaluate does not ask again.
    for (const [model, extra] of [[DOWN, {}], [ALLOW, { maxStateChars: 200 }]] as const) {
      const kept = await gateWith({ ...options, ...extra }, model)
      await kept.before(`sudo ls ${"a".repeat(400)}`)
      assert.equal(kept.fake.asserts.length, 1)
      assert.equal((await kept.evaluate(["sudo ls"])).effect, "allow")
    }
    // A model that asks: the user is asked, as without the setting.
    const asking = await gateWith(options, ASK)
    await asking.before("sudo ls")
    assert.equal(asking.fake.asserts.length, 1)
    // A rule set to deny with "model" elsewhere: denied in execute.before.
    const denied = await gateWith({ ruleOverrides: { privilege: "model", "git-reset-hard": "deny" } }, ALLOW)
    await assert.rejects(denied.before("sudo ls; git reset --hard"), /Blocked \(rule git-reset-hard\)/)
    // In execute.before too: another rule's ask remains, a denying rule set to "model" still denies.
    const other = await gateWith(options, ALLOW)
    await other.before("sudo ls; git reset --hard")
    assert.equal(other.fake.asserts.length, 1)
    const critical = await gateWith({ ruleOverrides: { "rm-critical": "model" } }, ALLOW)
    await assert.rejects(critical.before("rm -rf ~"), /Blocked \(rule rm-critical\)/)
  })
  it("MOD-7c: unattended mode: decided by the model, the call runs; left with the user, it is denied as before", async () => {
    const options = { ruleOverrides: { privilege: "model" } }
    const allowed = await gateWith(options, ALLOW, { askAs: "deny" })
    await allowed.before("sudo ls")
    assert.equal(allowed.fake.asserts.length, 0)
    const down = await gateWith(options, DOWN, { askAs: "deny" })
    await assert.rejects(down.before("sudo ls"), /^Error: \[guard\] Blocked \(rule privilege\): confirmation required, but unattended mode/)
  })
  it("MOD-7b: self-protection in execute.before, without then with selfProtectionByModel", async () => {
    const without = await gateWith({ localAsks: "model" }, ALLOW)
    await without.before(SELF_WRITE)
    assert.equal(without.fake.asserts.length, 1)
    const withIt = await gateWith({ localAsks: "model", selfProtectionByModel: true }, ALLOW)
    await withIt.before(SELF_WRITE)
    assert.equal(withIt.fake.asserts.length, 1)
    assert.equal((await withIt.evaluate([SELF_WRITE])).effect, "allow")
  })
})

describe("lot 48 step B2: startup and documentation", () => {
  it("MOD-8: start line and warning when the decision model is disabled (credentials-only profile included)", async () => {
    const options = { localAsks: "model", ruleOverrides: { privilege: "model" } }
    const off = await startLog(options, options)
    assert.ok(off.includes('WARN localAsks "model", ruleOverrides.privilege "model" retained but the decision model is disabled: these asks stay with you'), off)
    assert.match(off, /INFO active \(.*; rule overrides: privilege model; local asks: model/)
    const profile = { profile: "credentials-only", localAsks: "model" }
    assert.ok((await startLog({ ...profile, decision: DECISION }, profile)).includes('WARN localAsks "model" retained but the decision model is disabled'))
    const alone = { selfProtectionByModel: true, decision: DECISION }
    assert.ok((await startLog(alone, alone)).includes('WARN selfProtectionByModel has no effect without localAsks "model" or an always-active rule set to "model"'))
  })
  it("MOD-9: the documentation describes the settings and when the model has the last word", () => {
    const configuration = readFileSync(new URL("../docs/configuration.md", import.meta.url), "utf8")
    for (const text of ["`localAsks`", "`selfProtectionByModel`", '`"model"`']) assert.ok(configuration.includes(text), text)
    const model = readFileSync(new URL("../docs/decision-model.md", import.meta.url), "utf8")
    assert.ok(model.includes("localAsks"))
    assert.ok(!model.includes("It never changes the verdict:"))
  })
})
