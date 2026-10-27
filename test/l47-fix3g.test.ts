import "./tmp.ts"
// Lot 47, fixes after the targeted review: the asks added by the view with the continued lines joined (reading not
// stable, internal error) are compared by strength with the findings of the original view, so an ask that the model may
// decide never masks them. Each proof asserts the correct behavior; the guards give the same verdict before and after.
// Fake values; nothing is run: the rules are evaluated on text.
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { shellFinding } from "../src/rules/shell.ts"
import { createRedactor } from "../src/secrets/redact.ts"

const ctx = { redactor: createRedactor(), home: "/home/test" }
/** Finding with its mark: an ask that the decision model may decide is weaker than an ask without a mark. */
const marked = (command: string, context: object = ctx) => {
  const f = shellFinding(command, context as typeof ctx)
  return f ? `${f.verdict}/${f.rule}${f.dataOnly || f.modelDecides !== undefined ? " marked" : ""}` : "none"
}
/** A word found only in heredoc data: a marked ask. */
const data = "cat <<'D'\ngit reset --hard\nD\n"

describe("lot 47 targeted review fixes: added asks compared by strength", () => {
  it("F3G-1", () => {
    // Heredocs whose delimiter is cut by a line continuation: one joining is not enough for two of them.
    const unstable = "cat <<E\\\nOF\nEOF\n".repeat(2) + "E\n"
    // Guards true on both sides: the heredoc data alone, the reading not stable alone.
    assert.equal(marked(data), "ask/git-reset-hard marked")
    assert.equal(marked(unstable), "ask/nested-opencode")
    // Proof: the ask of a reading not stable is not masked by a marked ask of the original view.
    const finding = shellFinding(data + unstable, ctx)
    assert.equal(marked(data + unstable), "ask/nested-opencode")
    assert.match(finding!.reason, /continues joined/)
  })

  it("F3G-2", () => {
    // Internal error (injected) on a word that exists only once the continued lines are joined.
    const command = `${data}cat /tmp/ab\\\ncd`
    const failing = {
      ...ctx,
      credentialContent: (token: string) => {
        if (token.includes("abcd")) throw new Error("injected failure")
        return false
      },
    }
    // Guard true on both sides: without the failure, the marked ask of the heredoc data.
    assert.equal(marked(command), "ask/git-reset-hard marked")
    // Proof: the prudent ask of the error of the joined view is not masked by a marked ask of the original view.
    const finding = shellFinding(command, failing)
    assert.equal(marked(command, failing), "ask/nested-opencode")
    assert.match(finding!.reason, /internal error/)
  })
})
