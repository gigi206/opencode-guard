import "./tmp.ts"
// Lot 47 targeted review: readings added by steps 3d and 3e must add to the previous reading, never take its place.
// Each proof asserts the behavior of step 3b (before 3d), which the lot must keep. Fake values; nothing is run: the
// rules are evaluated on text.
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { scriptRuns, shellFinding } from "../src/rules/shell.ts"
import { createRedactor } from "../src/secrets/redact.ts"

const ctx = { redactor: createRedactor(), home: "/home/test" }
/** Finding with its mark: an ask that the decision model may decide is weaker than an ask without a mark. */
const marked = (command: string) => {
  const f = shellFinding(command, ctx)
  return f ? `${f.verdict}${f.dataOnly || f.modelDecides !== undefined ? " marked" : ""}` : "none"
}
const runs = (command: string) => scriptRuns(command).map((run) => `${run.kind}:${run.path}`)

describe("lot 47 targeted review: added readings never take the place of previous ones", () => {
  it("RL2-1", () => {
    // Guards true on both sides: a program fixed at run time gives an ask without a mark; a word found only in heredoc
    // data gives a marked ask.
    assert.equal(marked("a$(b) y"), "ask")
    assert.equal(marked("cat <<'EOF'\ngit reset --hard\nEOF"), "ask marked")
    // Proof: the quoted heredoc ends at its fourth line, then the program fixed at run time and the continued line
    // run (checked with bash and dash); the joined view must not turn the ask without a mark into a marked one.
    assert.equal(marked("cat <<\\\n'EOF'\nx \\\nEOF\na$(b) y\ngit \\\n reset --hard\nEOF"), "ask")
  })

  it("RL2-2", () => {
    // Guards true on both sides: the redirected input is examined, below the limit and without a grouped option.
    assert.ok(runs("sh -eo pipefail x.sh; bash < y.sh").includes("shell:y.sh"))
    assert.ok(runs("bash a.sh; bash b.sh; bash c.sh; bash < y.sh").includes("shell:y.sh"))
    // Proof: at the limit of 4, a file of the reading added for grouped options does not take the place of the
    // redirected input of a later segment.
    assert.ok(runs("bash a.sh; bash b.sh; sh -eo pipefail x.sh; bash < y.sh").includes("shell:y.sh"))
  })
})
