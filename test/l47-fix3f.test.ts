import "./tmp.ts"
// Lot 47, fixes after the review: the view with the continued lines joined is judged once (a reading that a new joining
// would still change gives an ask), and its internal error never removes a finding; exact reasons for a quoted awk
// string and a path too long to check. Each proof asserts the correct behavior; the guards give the same verdict before
// and after. Fake values and I/O; nothing is run: the rules are evaluated on text.
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { createRealPath, type LinkIo } from "../src/real-path.ts"
import { shellFinding } from "../src/rules/shell.ts"
import { toolFinding } from "../src/rules/tools.ts"
import { createRedactor } from "../src/secrets/redact.ts"

const ctx = { redactor: createRedactor(), home: "/home/test" }
const shown = (f: { verdict: string; rule: string } | undefined) => (f ? `${f.verdict}/${f.rule}` : "none")
const found = (command: string, context: object = ctx) => shown(shellFinding(command, context as typeof ctx))

describe("lot 47 review fixes: joined view and exact reasons", () => {
  it("F3F-1", () => {
    // Heredocs whose delimiter is cut by a line continuation: one joining is enough for one of them, not for two.
    const heredocs = (n: number) => "cat <<E\\\nOF\nEOF\n".repeat(n) + "E\n"
    // Guards true on both sides: one such heredoc, heredocs without a continuation, a deny after the heredocs.
    assert.equal(found(heredocs(1)), "none")
    assert.equal(found("cat <<EOF\nx\nEOF\n".repeat(3)), "none")
    assert.equal(found(`${heredocs(3)}rm -rf /`), "deny/rm-critical")
    // Proof: a joined view that a new joining would still change gives an ask, never nothing.
    for (const n of [2, 3, 40]) {
      const finding = shellFinding(heredocs(n), ctx)
      assert.equal(shown(finding), "ask/nested-opencode", String(n))
      assert.match(finding!.reason, /continues joined/)
    }
  })

  it("F3F-2", () => {
    // Internal error (injected) on a word that exists only once the continued lines are joined, with no other finding.
    const command = "cat /tmp/ab\\\ncd"
    const failing = {
      ...ctx,
      credentialContent: (token: string) => {
        if (token.includes("abcd")) throw new Error("injected failure")
        return false
      },
    }
    // Guard true on both sides: without the failure.
    assert.equal(found(command), "none")
    // Proof: the error of the joined view adds the prudent ask, never nothing.
    const finding = shellFinding(command, failing)
    assert.equal(shown(finding), "ask/nested-opencode")
    assert.match(finding!.reason, /internal error/)
  })

  it("F3F-3", () => {
    // Guards true on both sides: a dynamic awk program keeps its reason; a short path is not checked against a limit.
    const dynamic = shellFinding("awk '{system($0)}' f", ctx)
    assert.equal(shown(dynamic), "ask/awk-dynamic-exec")
    assert.match(dynamic!.reason, /executing non-literal text/)
    const io: LinkIo = { lstat: () => ({ isSymbolicLink: () => false }), readlink: () => "" }
    const linked = { ...ctx, cwd: "/home/test/project", cwds: ["/home/test/project"], realPaths: createRealPath({ io, directories: ["/home/test/project"], processDirectory: "/home/test/project" }) }
    assert.equal(shown(toolFinding("write", { path: "/home/test/project/f", content: "x" }, linked)), "none")
    // Proof: a quoted awk string too long to read, and a path too long to check: same rule, same verdict, exact reason.
    const awk = shellFinding(`awk '${"x".repeat(70000)}' f`, ctx)
    assert.equal(shown(awk), "ask/awk-dynamic-exec")
    assert.match(awk!.reason, /quoted string longer than the plugin checks/)
    const write = toolFinding("write", { path: `/${"x".repeat(5000)}`, content: "x" }, linked)
    assert.equal(shown(write), "ask/self-protection")
    assert.match(write!.reason, /or the path is too long to check/)
  })
})
