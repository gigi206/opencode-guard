import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { summarize } from "../src/hooks/gate.ts"
import { hiddenHeaders, patchTargets, readPatch, type PatchSection } from "../src/patch.ts"
import { toolFinding } from "../src/rules/tools.ts"
import { createRedactor } from "../src/secrets/redact.ts"

// Named invisible characters (no escapes in the strings of this file).
const LS = String.fromCharCode(0x2028)
const PS = String.fromCharCode(0x2029)
const NEL = String.fromCharCode(0x85)
const NBSP = String.fromCharCode(0xa0)
const BOM = String.fromCharCode(0xfeff)
const patch = (...lines: string[]) => ["*** Begin Patch", ...lines, "*** End Patch"].join("\n")
const sections = (text: string): readonly PatchSection[] | undefined => {
  const reading = readPatch(text)
  return reading.accepted ? reading.sections : undefined
}
const accepted = (text: string) => readPatch(text).accepted

describe("batch 34: broad reading of patch headers", () => {
  it("any line starting with a marker once its whitespace is trimmed, wherever it is; path without its whitespace; deduplicated", () => {
    const text = [
      "before the envelope",
      "*** Add File: a.ts",
      `  *** Update File: ${LS}b.ts${NBSP}`,
      "@@",
      " *** Delete File: c.ts",
      "\t*** Move to: d.ts",
      "+*** Add File: not-a-header.ts",
      "*** Add File: a.ts",
      "*** Add File: ",
      "*** Add File:\te.ts",
      "*** add file: f.ts",
    ].join("\n")
    assert.deepEqual(patchTargets(text), ["a.ts", "b.ts", "c.ts", "d.ts"])
  })
  it("separators: only the newline splits a line; complete path, U+0085 kept; pieces only on request", () => {
    const text = `*** Add File: a\rb${LS}c\nnotes${PS}*** Delete File: ~/.bashrc\n*** Add File: x${NEL}`
    assert.deepEqual(patchTargets(text), [`a\rb${LS}c`, `x${NEL}`])
    assert.deepEqual(patchTargets(text, { pieces: true }), [`a\rb${LS}c`, `x${NEL}`, "a", "~/.bashrc"])
  })
  it("hidden headers: only lines without a complete path, split at other line endings", () => {
    const text = [`*** Add File: a\rb`, `+x${LS}*** Delete File: c`, " ctx\r *** Move to: d", "notes\r*** Add File: c", "+y"].join("\n")
    assert.deepEqual(hiddenHeaders(text), ["c", "d"])
    assert.deepEqual(hiddenHeaders(patch("*** Add File: a", "+x")), [])
  })
  it("contains the exact reading (headers and destinations)", () => {
    const text = `cat <<'EOF'\n${patch(` *** Add File: ${BOM}n.sh`, "+x", "\t*** Delete File: d.sh", "*** Update File: u.sh", "*** Move to: v.sh", "@@", "-a", "+b")}\nEOF`
    const exact = sections(text)
    assert.ok(exact)
    const broad = new Set(patchTargets(text))
    for (const section of exact) {
      assert.ok(broad.has(section.path), section.path)
      if (section.type === "update" && section.moveTo) assert.ok(broad.has(section.moveTo))
    }
  })
})

describe("batch 34: exact reading, OpenCode 2.0.31 grammar", () => {
  it("envelope: whitespace of the whole text trimmed (byte order mark included), markers alone on their line, indented or not", () => {
    assert.ok(accepted(`${BOM}  \n${patch("*** Delete File: a")}\n\n`))
    assert.ok(accepted(`  *** Begin Patch\n*** Delete File: a\n\t*** End Patch  `))
    for (const text of [
      `x\n${patch("*** Delete File: a")}`,
      `${patch("*** Delete File: a")}\nx`,
      patch("*** Delete File: a", "*** End Patch", "*** Delete File: b"),
      patch(),
      "*** Begin Patch",
      `*** Begin Patch${LS}*** Delete File: a${LS}*** End Patch`,
      "*** begin patch\n*** Delete File: a\n*** End Patch",
    ])
      assert.equal(accepted(text), false, JSON.stringify(text))
  })
  it("environment id: tolerated right after the start, value non-empty", () => {
    assert.ok(accepted(patch(" *** Environment ID: e1", "*** Delete File: a")))
    assert.equal(accepted(patch("*** Environment ID:  ", "*** Delete File: a")), false)
    assert.equal(accepted(patch("*** Delete File: a", "*** Environment ID: e1")), false)
    // Two id lines in a row: the second is no longer right after the start (rejection confirmed by the oracle).
    assert.equal(accepted(patch("*** Environment ID: e1", "*** Environment ID: e2", "*** Delete File: a")), false)
  })
  it("inline document: optional command, label in matching or non-matching quotes, empty lines absorbed after the opening", () => {
    const inner = patch("*** Delete File: a")
    for (const text of [`<<EOF\n${inner}\nEOF`, `cat <<'P_1'\n\n  \n${inner}\nP_1  `, `cat\t <<"EOF"\n${inner}\nEOF`])
      assert.deepEqual(sections(text), [{ type: "delete", path: "a" }], JSON.stringify(text))
    for (const text of [
      `<<EOF\n${inner}\n\nEOF`, // empty line before the closing: stays in the text
      `<<'EOF"\n${inner}\nEOF`,
      `<<-EOF\n${inner}\nEOF`,
      `echo x; cat <<EOF\n${inner}\nEOF`,
      `<<EOF\n${inner}\nEOFX`,
      `<<EOF\n${inner}`,
    ])
      assert.equal(accepted(text), false, JSON.stringify(text))
  })
  it("line endings: split on the newline only, a trailing carriage return removed per line", () => {
    assert.deepEqual(sections("*** Begin Patch\r\n*** Add File: a\r\n+x\r\n+y\r\r\n*** End Patch\r\n"), [{ type: "add", path: "a", content: "x\ny\r\n" }])
    assert.deepEqual(sections(patch("*** Update File: a\r", "@@\r", "\r", "-x\r", "+y\r")), [{ type: "update", path: "a", added: ["y"] }])
    assert.deepEqual(sections(patch(`*** Add File: a${LS}+x`)), [{ type: "add", path: `a${LS}+x`, content: "" }])
  })
  it("path: JavaScript whitespace trimmed at both ends (Unicode separators included), nothing else; U+0085 kept", () => {
    assert.deepEqual(sections(patch(`*** Delete File: ${LS}\r ${BOM}'a b'${NBSP}${PS}`)), [{ type: "delete", path: "'a b'" }])
    assert.deepEqual(sections(patch(`*** Delete File: ~/x${NEL}`)), [{ type: "delete", path: `~/x${NEL}` }])
  })
  it("indented header accepted at section level: after the start, after an add, after a delete", () => {
    assert.deepEqual(
      sections(patch(`${LS}*** Add File: a`, "+x", `\t*** Delete File: b`, `${NBSP}*** Update File: c`, "@@", "-x", "+y")),
      [
        { type: "add", path: "a", content: "x\n" },
        { type: "delete", path: "b" },
        { type: "update", path: "c", added: ["y"] },
      ],
    )
  })
  it("in an update body: header indented by one space = context line; other indentation, or after an end of file = rejection", () => {
    assert.deepEqual(sections(patch("*** Update File: a", "@@", " *** Delete File: b", " *** End Patch", "-x", "+y")), [{ type: "update", path: "a", added: ["y"] }])
    assert.equal(accepted(patch("*** Update File: a", "@@", "\t*** Delete File: b", "-x", "+y")), false)
    assert.equal(accepted(patch("*** Update File: a", "@@", "-x", "+y", "*** End of File", " *** Delete File: b")), false)
    // End of file then empty line, then unindented boundary: accepted.
    assert.deepEqual(sections(patch("*** Update File: a", "-x", "*** End of File", "", "*** Delete File: b")), [
      { type: "update", path: "a", added: [] },
      { type: "delete", path: "b" },
    ])
  })
  it("move line: unindented, right after the header (end-of-file lines excepted), only one, destination non-empty", () => {
    assert.deepEqual(sections(patch("*** Update File: a", "*** End of File", "*** Move to:  b ", "@@", "-x", "+y")), [{ type: "update", path: "a", moveTo: "b", added: ["y"] }])
    // Indented by one space: context line, in-place change.
    assert.deepEqual(sections(patch("*** Update File: a", " *** Move to: b", "-x", "+y")), [{ type: "update", path: "a", added: ["y"] }])
    for (const text of [
      patch("*** Update File: a", "\t*** Move to: b", "-x", "+y"),
      patch("*** Update File: a", "@@", "-x", "*** Move to: b", "+y"),
      patch("*** Update File: a", "*** Move to: b", "*** Move to: c", "-x", "+y"),
      patch("*** Update File: a", "*** Move to:", "-x", "+y"),
      patch("*** Update File: a", "*** Move to: \t", "-x", "+y"),
      patch("*** Delete File: a", "*** Move to: b"),
    ])
      assert.equal(accepted(text), false, JSON.stringify(text))
  })
  it("whole-patch rejection: tab after the colon, empty line in an add, body after a delete, empty update, stray line", () => {
    for (const text of [
      patch("*** Add File:\ta", "+x"),
      patch("*** Add File: a", "+x", "", "*** Delete File: b"),
      patch("*** Add File: a", " x"),
      patch("*** Delete File: a", ""),
      patch("*** Delete File: a", "+x"),
      patch("*** Update File: a"),
      patch("*** Update File: a", "@@"),
      patch("*** Update File: a", "@@", "@@ ctx", "-x"),
      patch("*** Update File: a", "-x", "*** End of File", "*** End of File"),
      patch("*** Delete File: a", "junk"),
      patch("*** Delete File: a", ""),
    ])
      assert.equal(accepted(text), false, JSON.stringify(text))
  })
  it("content of an add: what OpenCode writes (joined lines, final newline added unless content is empty or already terminated)", () => {
    assert.deepEqual(sections(patch("*** Add File: a", "+x", "+", "*** Add File: b", "*** Add File: c", "+", "+")), [
      { type: "add", path: "a", content: "x\n" },
      { type: "add", path: "b", content: "" },
      { type: "add", path: "c", content: "\n" },
    ])
    assert.deepEqual(sections(patch("*** Add File: a", `+${BOM}x`, "+*** Delete File: b")), [{ type: "add", path: "a", content: `${BOM}x\n*** Delete File: b\n` }])
  })
})

describe("batch 34: linear cost of readings (1 MiB patch, unfavorable lines)", () => {
  const MIB = 1024 * 1024
  let big = ""
  for (let index = 0; big.length < MIB; index++) big += `*** Add File: src/dir-${index}/file-${index}.ts\n+export const value${index} = ${index}\n`
  const cases: Record<string, string> = {
    "1 MiB patch": `*** Begin Patch\n${big}*** End Patch`,
    "very long line without a newline": `*** Add File: ${"a".repeat(MIB)}`,
    "line full of whitespace": `${" ".repeat(MIB)}*** Add File: x`,
    "Unicode separators": LS.repeat(MIB),
    "carriage returns": "\r".repeat(MIB),
    "headers after a separator": "x\r*** Add File: a".repeat(MIB / 16),
    "inline document without closing": `<<EOF${"\n".repeat(MIB)}x`,
    "empty lines": "\n".repeat(MIB),
    "huge update": `*** Begin Patch\n*** Update File: a\n${"+x\n".repeat(MIB / 3)}*** End Patch`,
  }
  const ctx = { redactor: createRedactor(), home: "/home/test", cwd: "/home/test/project", protectedDirs: ["/home/test/project/guard"] }
  for (const [name, text] of Object.entries(cases))
    it(`${name}: each reading, the rule and the summary in under a second`, () => {
      for (const [what, run] of [
        ["broad reading", () => patchTargets(text, { pieces: true })],
        ["exact reading", () => readPatch(text)],
        ["rule", () => toolFinding("patch", { patchText: text }, ctx)],
        ["summary", () => summarize("patch", { patchText: text })],
      ] as const) {
        const start = performance.now()
        run()
        const elapsed = performance.now() - start
        assert.ok(elapsed < 1000, `${what} : ${elapsed.toFixed(0)} ms`)
      }
    })
})
