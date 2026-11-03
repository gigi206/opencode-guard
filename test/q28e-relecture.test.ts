// Review of Q28e: the URLs of an artifact page's `action`, `formaction` and `ping` attributes judged against the
// standard URL parser (`URL` of Node) from view addresses of any depth (any segment names, those the server decodes
// included), both schemes. Text is judged, nothing runs.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { toolFinding } from "../src/rules/tools.ts"
import type { Finding } from "../src/rules/types.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fastEnough } from "./budget.ts"

const options = { redactor: createRedactor(), home: "/home/test", cwd: "/home/test/work/app" } as never
const brief = (finding?: Finding) => (finding ? `${finding.verdict}:${finding.rule}` : "none")
const verdict = (files: Record<string, string>, tool = "opencode_artifact_create") =>
  brief(toolFinding(tool, tool === "opencode_artifact_create" ? { title: "API", files } : { id: "art_1", files }, options))
const ASK = "ask:opencode-server-api"
const carriers = (url: string) => [
  `<a href="/d" ping="${url}">d</a>`,
  `<a href="/d" ping="/s ${url} /t">d</a>`,
  `<form method="post" action="${url}"></form>`,
  `<button formaction="${url}">x</button>`,
]
/** URLs the browser reads from each carrier: a `ping` list split on ASCII whitespace, a form URL whole. */
const urlsOf = (carrier: number, url: string) =>
  carrier < 2 ? (carrier === 0 ? url : `/s ${url} /t`).split(/[\t\n\f\r ]+/).filter(Boolean) : [url]

/** Oracle: a protected route as the whole path (the router's segments, independent of the plugin's expression). */
const ROUTE = /^\/api\/(?:session\/[^/']+\/(?:agent|command|prompt|permission)|experimental\/voice\/session\/[^/']+\/instructions)(?:$|\/)/
/** Segment names of a view address: any, those the server decodes (`%2F`, `%5C`) included. */
const NAMES = ["a", "%2F", "%5C", "", "x.y", "%2e%2f", "%C3%A9"]

function generator(seed: number) {
  let state = seed
  const next = (n: number) => {
    state = (Math.imul(state, 1103515245) + 12345) & 0x7fffffff
    return state % n
  }
  return { next, pick: <T,>(items: readonly T[]) => items[next(items.length)]! }
}

/** Does the browser send `url` to a protected route from some view address of depth 0 to 10, under http or https? */
function reaches(url: string, pick: <T>(items: readonly T[]) => T): boolean {
  for (const scheme of ["http:", "https:"])
    for (let depth = 0; depth <= 10; depth++) {
      let page = `${scheme}//127.0.0.1:4096/api/experimental/artifacts/art_Q/view/`
      for (let i = 0; i < depth; i++) page += `${pick(NAMES)}/`
      try {
        const resolved = new URL(url, `${page}p.html`)
        if ((resolved.protocol === "http:" || resolved.protocol === "https:") && ROUTE.test(resolved.pathname)) return true
      } catch {}
    }
  return false
}

const DOTS = ["..", ".", "%2e", "%2E", ".%2e", "%2E.", "%2e%2E", "%2E%2E", "..."]
const WORDS = ["x", "", "api", "experimental", "session", "voice", "ses_1", "prompt", "agent", "command", "permission", "instructions", "artifacts", "view", "%2f", "%5c", "a b", "x\ty", "x\ny", "\x0b", "{id}"]
const SEPARATORS = ["/", "/", "\\", "\\", "//", "/\t", "\\\n"]
const PREFIXES = ["", "", "", "", " ", "\x01", "\t", "\n ", "http:", "https:", "HTTP:", "hTtPs:", "h\ttp:", "/", "\\", "//h", "\\\\h", "http://h", "https:\\\\h", "./", "%2e/", "\\.\\"]
const SUFFIXES = ["", "", "?q", "#f", "?a/../b", " ", "\x1f", "\n", "/", "\x0c"]
const TAILS = ["session/ses_1/prompt", "session/ses_1/agent", "session/x/command", "session/x/permission/r/reply", "voice/session/x/instructions", "experimental/voice/session/x/instructions", "api/session/ses_1/prompt", "api/experimental/voice/session/v/instructions"]

function draw({ next, pick }: ReturnType<typeof generator>): string {
  const parts: string[] = []
  if (next(2)) {
    for (let k = next(9); k > 0; k--) parts.push(next(3) ? ".." : pick(DOTS))
    if (next(3) === 0) parts.push(pick(WORDS), pick(["..", "%2e%2e", ".%2E"]))
    parts.push(...pick(TAILS).split("/"))
    if (next(4) === 0) parts.splice(next(parts.length + 1), 0, pick([...DOTS, ...WORDS]))
  } else for (let n = next(13); n > 0; n--) parts.push(next(2) ? pick(DOTS) : pick(WORDS))
  return pick(PREFIXES) + parts.map((part, i) => (i ? pick(SEPARATORS) : "") + part).join("") + pick(SUFFIXES)
}

const KEYS = ["p.html", "index.html", "a/b/c.html", "d1/d2/d3/d4/d5/d6/p.html", "\ud800.html", "x/p.svg"]

describe("Q28e review: attribute URLs against the standard URL parser at any served depth", () => {
  it("Q28e-R1: random URLs that reach a route from some depth (http or https) ask in every carrier", () => {
    const random = generator(2026)
    let reached = 0
    const missed: string[] = []
    for (let i = 0; i < 15_000; i++) {
      const url = draw(random)
      const key = random.pick(KEYS)
      carriers(url).forEach((body, carrier) => {
        if (!urlsOf(carrier, url).some((one) => reaches(one, random.pick))) return
        reached++
        if (verdict({ [key]: body }) !== ASK && missed.length < 10) missed.push(JSON.stringify([key, carrier, url]))
      })
    }
    assert.ok(reached > 1_000, String(reached))
    assert.deepEqual(missed, [])
  })

  it("Q28e-R2: the forms Q28-c5 recognizes still ask (raw route, `..` runs, the key's depth, `\\`, `http:` relative)", () => {
    const forms: [string, string][] = [
      ["p.html", "/api/session/ses_1/prompt"],
      ["p.html", "http://evil.example/api/session/ses_1/agent"],
      ["p.html", "../../../../session/ses_1/command"],
      ["p.html", "../../../voice/session/v/instructions"],
      ["a/b/c.html", "..\\..\\..\\..\\..\\..\\session\\ses_1\\prompt"],
      ["a/b/c.html", "%2e%2e/.%2E/%2E./%2E%2e/../../session/ses_1/permission"],
      ["p.html", "\\api\\session\\ses_1\\prompt"],
      ["p.html", "http:..\\..\\..\\..\\session\\ses_1\\prompt"],
      ["p.html", "\\\\h\\api\\session\\ses_1\\agent"],
      ["x/p.svg", " \x01..\\..\\..\\..\\..\\session\\ses_1\\prompt\x1f "],
    ]
    for (const [key, url] of forms)
      for (const tool of ["opencode_artifact_create", "opencode_artifact_update"])
        assert.deepEqual(carriers(url).map((body) => verdict({ [key]: body }, tool)), Array(4).fill(ASK), `${key} ${url}`)
  })

  it("Q28e-R3 (control): a documentation page asks nothing outside a template the browser sends, nor a URL no depth sends", () => {
    const quiet = [
      `<pre>POST ..\\..\\..\\..\\session\\{id}\\prompt</pre><p>/api/session/ses_1/prompt</p>`,
      `<a href="..\\..\\..\\..\\session\\x\\prompt">GET</a><img src="\\api\\session\\x\\prompt">`,
      `<form method="post" action="..\\..\\..\\session\\x\\prompt"></form>`,
      `<form method="post" action="..%2f..%2f..%2f..%2fsession/x/prompt"></form>`,
      `<form method="post" action="%252e%252e/%252e%252e/%252e%252e/%252e%252e/session/x/prompt"></form>`,
      `<form method="post" action="..\\..\\..\\..\\Session\\x\\prompt"></form>`,
      `<form method="post" action="mailto:..\\..\\..\\..\\session\\x\\prompt"></form>`,
    ]
    for (const body of quiet) assert.equal(verdict({ "index.html": body }), "none", body)
    for (const body of quiet.slice(0, 2)) assert.equal(verdict({ "docs/api.md": body }), "none", body)
    // A template in a form URL: the browser sends it (`/api/session/%7Bid%7D/prompt`), as the documentation says.
    assert.equal(verdict({ "docs/api.html": `<form method="post" action="..\\..\\..\\..\\session\\{id}\\prompt"></form>` }), ASK)
  })

  it("Q28e-R4: cost is linear in the artifact's size, on a long key and many URLs (minimum of three runs)", () => {
    const key = `${"k/".repeat(10_000)}p.html`
    const bodies = (n: number) => [
      `<a ping="${"..\\..\\..\\..\\..\\session\\x\\prompt ".repeat(n)}">`,
      `<form action="${"a\\..\\%2E%2e\\".repeat(n)}session\\x\\prompt">`,
      `<form action="..\\..\\..\\..\\..\\${"seg\\".repeat(n)}">`,
      `<a ping="${"\x01 \t".repeat(n)}">`,
      `<form action="http:${"h".repeat(4 * n)}">`,
    ]
    const time = (body: string) => {
      const runs: number[] = []
      for (let i = 0; i < 3; i++) {
        const start = performance.now()
        verdict({ [key]: body })
        runs.push(performance.now() - start)
      }
      return Math.min(...runs)
    }
    const small = bodies(25_000).map(time)
    const large = bodies(100_000).map(time)
    large.forEach((elapsed, i) => {
      assert.ok(fastEnough(elapsed, 1_500), `${Math.round(elapsed)} ms for form ${i}`)
      assert.ok(fastEnough(elapsed, 8 * small[i]! + 30), `form ${i}: ${Math.round(small[i]!)} ms then ${Math.round(elapsed)} ms for 4 times the size`)
    })
  })

  it("Q28e-R5: no exception leaves the check (lone surrogates, `%zz`, brackets, NUL, odd hosts and ports)", () => {
    const random = generator(99)
    const junk = ["\ud800", "\udfff", "%zz", "%", "[", "]", "@", "\0", ":", "//[::1", "http://[", "https://%zz", "http://h:99999999", "\\\\", "..", "%2e", "　", " ", "#", "?", "javascript:", "http:", "x"]
    for (let i = 0; i < 5_000; i++) {
      let url = ""
      for (let n = random.next(12); n > 0; n--) url += random.pick(junk) + random.pick(["", "/", "\\", " "])
      const key = random.pick(["p.html", "\ud800/p.html", "a/b/c.html"])
      for (const body of carriers(url))
        for (const tool of ["opencode_artifact_create", "opencode_artifact_update"])
          assert.doesNotThrow(() => verdict({ [key]: body }, tool), JSON.stringify(url))
    }
  })
})
