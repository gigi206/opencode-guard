import "./tmp.ts"
// Lot 47, placeholder rule in the examination of an executed script: the rule (write) does not apply to an execution and
// is discarded before the findings are combined, so it never takes the place of a finding of another rule on the content
// of the script. The command itself keeps the deny. Each proof asserts the correct behavior; the guards give the same
// verdict before and after. Fake values; nothing is run: the rules are evaluated on text.
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createDecider, scriptFinding } from "../src/decide.ts"
import { shellFinding } from "../src/rules/shell.ts"
import { toolFinding } from "../src/rules/tools.ts"
import { createRedactor } from "../src/secrets/redact.ts"

const ctx = { redactor: createRedactor(), home: "/home/test" }
const OFF = { ...ctx, active: { dangerousCommands: false, sensitiveFiles: false } }
const show = (f: ReturnType<typeof shellFinding>) => (f ? `${f.verdict}/${f.rule}${f.dataOnly || f.modelDecides !== undefined ? " marked" : ""}` : "none")
/** Finding of an executed script read by a shell (content judged by the shell rules). */
const script = (content: string, context: typeof ctx = ctx) => show(scriptFinding({ path: "s.sh", content, shell: true, forModel: true }, context))
const PLACEHOLDER = "[[GUARD_REDACTED:fake]]"
/** The same placeholder encoded in base64 (written by the placeholder rule as a deny too). */
const ENCODED = Buffer.from(PLACEHOLDER).toString("base64")
const answer = {
  answers: {
    risk: { type: "score", score: 0.2, confidence: 0.9 },
    destructive: { type: "noul", noul: 0.01 },
    exfiltration: { type: "noul", noul: 0.01 },
    credentials: { type: "noul", noul: 0.01 },
    privilege_persistence: { type: "noul", noul: 0.01 },
  },
}

describe("lot 47 placeholder rule in scripts: discarded before the findings are combined", () => {
  it("F3H-1", () => {
    // Guards true on both sides: the ask of the script alone; a script with only a placeholder gives nothing.
    assert.equal(script("git reset --hard\n"), "ask/git-reset-hard")
    assert.equal(script(`echo ${PLACEHOLDER}\n`), "none")
    // Proof: a placeholder in the script does not take the place of the ask of another rule.
    assert.equal(script(`echo ${PLACEHOLDER}\ngit reset --hard\n`), "ask/git-reset-hard")
  })
  it("F3H-2", () => {
    // Guards true on both sides: the encoded placeholder denies a command and gives nothing in a script.
    assert.equal(show(shellFinding(`echo ${ENCODED}`, ctx)), "deny/placeholder")
    assert.equal(script(`echo ${ENCODED}\n`), "none")
    // Proof: the encoded form does not take the place of the ask either.
    assert.equal(script(`echo ${ENCODED}\ngit reset --hard\n`), "ask/git-reset-hard")
  })
  it("F3H-3", async () => {
    const { config } = parseConfig({ decision: { baseURL: "https://nox.invalid/v1", model: "nox-4b" } })
    const decider = createDecider({ config, redactor: createRedactor(), model: async () => answer })
    const run = (command: string, content: string) => decider.decide({ tool: "shell", input: { command }, scripts: [{ path: "f.sh", content, shell: true, forModel: true }] })
    // Guards true on both sides: the command with a placeholder is denied; a script with only a placeholder is left to
    // the model, which allows.
    assert.equal((await run(`echo ${PLACEHOLDER}; bash f.sh`, "git reset --hard\n")).verdict, "deny")
    assert.equal((await run("bash f.sh", `echo ${PLACEHOLDER}\n`)).verdict, "allow")
    // Proof: the ask of the script is kept even though the model allows.
    const decision = await run("bash f.sh", `echo ${PLACEHOLDER}\ngit reset --hard\n`)
    assert.equal(decision.verdict, "ask")
    assert.equal(decision.rule, "git-reset-hard")
  })
  it("F3H-4", () => {
    // Guards true on both sides: the command itself keeps the deny of the placeholder rule, in clear or encoded, through
    // the shell rules and the tool rules, switches off included (always-active rule); a write keeps it too.
    for (const context of [ctx, OFF]) {
      assert.equal(show(shellFinding(`echo ${PLACEHOLDER}\ngit reset --hard`, context)), "deny/placeholder")
      assert.equal(show(toolFinding("shell", { command: `echo ${PLACEHOLDER}` }, context)), "deny/placeholder")
      assert.equal(show(toolFinding("shell", { command: `echo ${ENCODED}` }, context)), "deny/placeholder")
      assert.equal(show(toolFinding("write", { path: "a.env", content: `KEY=${PLACEHOLDER}` }, context)), "deny/placeholder")
    }
    // Switches off: the ask of the script is disabled, the placeholder still gives nothing in a script.
    assert.equal(script(`echo ${PLACEHOLDER}\ngit reset --hard\n`, OFF), "none")
  })
})
