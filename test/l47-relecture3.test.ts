import "./tmp.ts"
// Lot 47 review after step 3g: a finding added by a reading of 3d to 3g must never make a consumer lose a finding of
// step 3b (before 3d). Each proof asserts the behavior of step 3b. Fake values; nothing is run: the rules are evaluated
// on text.
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { scriptFinding } from "../src/decide.ts"
import { shellFinding } from "../src/rules/shell.ts"
import { createRedactor } from "../src/secrets/redact.ts"

const ctx = { redactor: createRedactor(), home: "/home/test" }
const show = (f: ReturnType<typeof shellFinding>) => (f ? `${f.verdict}/${f.rule}${f.dataOnly || f.modelDecides !== undefined ? " marked" : ""}` : "none")
/** Finding of an executed script read by a shell (content judged by the shell rules). */
const script = (content: string) => show(scriptFinding({ path: "s.sh", content, shell: true, forModel: true }, ctx))

describe("lot 47 review after 3g: added findings never make a consumer lose a previous one", () => {
  it("RL3-1", () => {
    // Guards true on both sides: an ask of the script is kept; the placeholder rule denies the write of a placeholder.
    assert.equal(script("git reset --hard\n"), "ask/git-reset-hard")
    assert.equal(show(shellFinding("echo [[GUARD_REDACTED:fake]]", ctx)), "deny/placeholder")
    // Proof: a placeholder that exists only once the continued lines are joined must not take the place of the ask of
    // the script (the placeholder rule does not apply to an execution and is discarded by `scriptFinding`).
    assert.equal(script("echo [[GUARD_RE\\\nDACTED:fake]]\ngit reset --hard\n"), "ask/git-reset-hard")
  })
})
