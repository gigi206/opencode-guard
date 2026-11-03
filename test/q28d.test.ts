// The URLs of an artifact page's `action`, `formaction` and `ping` attributes resolved as the browser resolves them: by the
// standard URL parser against the address the page is served at, so a `\` reads as `/` and `..` climbs from the page's
// directory. In addition to the existing checks, never instead of them. Text is judged, nothing runs.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { toolFinding } from "../src/rules/tools.ts"
import type { Finding } from "../src/rules/types.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fastEnough } from "./budget.ts"

const HOME = "/home/test"
const PROJECT = `${HOME}/work/app`
const brief = (finding?: Finding) => (finding ? `${finding.verdict}:${finding.rule}${finding.modelDecides ? " (model)" : ""}` : "none")
const page = (files: Record<string, string>, tool = "opencode_artifact_create") =>
  brief(
    toolFinding(tool, tool === "opencode_artifact_create" ? { title: "API", files } : { id: "art_1", files }, {
      redactor: createRedactor(),
      home: HOME,
      cwd: PROJECT,
    } as never),
  )

const ASK = "ask:opencode-server-api"
const html = (body: string) => `<!doctype html><html><head><title>API</title></head><body>${body}</body></html>`
/** The same URL in each attribute sent with `POST`: alone, then as one URL of a `ping` list. */
const carriers = (url: string) => [
  html(`<a href="/docs" ping="${url}">docs</a>`),
  html(`<a href="/docs" ping="/stats ${url}\t/visits">docs</a>`),
  html(`<form method="post" action="${url}"><button>x</button></form>`),
  html(`<form method="post"><button formaction="${url}">x</button></form>`),
]
const verdicts = (key: string, url: string, tool?: string) => carriers(url).map((body) => page({ [key]: body }, tool))
const back = (count: number, separator: string) => `..${separator}`.repeat(count)

describe("Q28d: attribute URLs resolved by the standard URL parser", () => {
  it("Q28d-1: absolute routes written with backslashes, alone or mixed with slashes, on any host, ask", () => {
    const urls = [
      "\\api\\session\\ses_1\\prompt",
      "/api\\session\\ses_1\\prompt",
      "\\api/session\\ses_1/agent",
      "/api/session\\ses_1\\command",
      "\\api\\session\\ses_1\\permission",
      "\\api\\experimental\\voice\\session\\ses_1\\instructions",
      "http://127.0.0.1:4096\\api\\session\\ses_1\\prompt",
      "http:\\\\localhost:4096\\api\\session\\ses_1\\prompt",
      "\\\\evil.example\\api\\session\\ses_1\\prompt",
      " \\api\\session\\ses_1\\prompt ",
    ]
    for (const url of urls)
      for (const tool of ["opencode_artifact_create", "opencode_artifact_update"])
        for (const key of ["index.html", "a/b/c.html"]) assert.deepEqual(verdicts(key, url, tool), Array(4).fill(ASK), JSON.stringify({ url, key, tool }))
  })

  it("Q28d-2: relative routes with backslashes climb from the page's directory, root or deep page", () => {
    // From `view/index.html`, four `..` reach `/api/`; from `view/a/b/c.html`, six; more stop at the root.
    const cases: Array<[string, string]> = [
      ["index.html", `${back(4, "\\")}session\\ses_1\\prompt`],
      ["index.html", `${back(3, "\\")}voice\\session\\ses_1\\instructions`],
      ["index.html", `..\\../..\\../session/ses_1\\prompt`],
      ["index.html", `.\\${back(4, "\\")}session\\ses_1\\agent`],
      ["index.html", `${back(10, "\\")}api\\session\\ses_1\\prompt`],
      ["index.html", `..\\x\\..\\${back(3, "\\")}session\\ses_1\\command`],
      ["a/b/c.html", `${back(6, "\\")}session\\ses_1\\prompt`],
      ["a/b/c.html", `../..\\../..\\${back(2, "/")}session\\ses_1\\permission`],
      ["a/b/c.html", `${back(10, "\\")}api\\session\\ses_1\\prompt`],
      ["a\\b\\c.html", `${back(6, "\\")}session\\ses_1\\prompt`],
      ["./a/b/c.html", `${back(6, "\\")}session\\ses_1\\prompt`],
    ]
    for (const [key, url] of cases) assert.deepEqual(verdicts(key, url), Array(4).fill(ASK), JSON.stringify({ key, url }))
  })

  it("Q28d-3 (control): URLs that the browser resolves elsewhere ask nothing", () => {
    const cases: Array<[string, string]> = [
      // Relative without `..`, or too few `..`: a file of the artifact or another path of the server.
      ["index.html", "api\\session\\ses_1\\prompt"],
      ["index.html", "api/session/ses_1/prompt"],
      ["index.html", "session\\ses_1\\prompt"],
      ["index.html", `${back(3, "\\")}session\\ses_1\\prompt`],
      // Another route, a known read, a route without its last segment.
      ["index.html", "\\api\\session\\ses_1\\message"],
      ["index.html", "\\api\\session\\ses_1\\prompts"],
      ["index.html", "\\api\\session\\ses_1"],
      ["index.html", "\\docs\\api\\session\\ses_1\\prompt"],
      // Other schemes.
      ["index.html", "mailto:\\api\\session\\ses_1\\prompt"],
      ["index.html", "foo:\\api\\session\\ses_1\\prompt"],
    ]
    for (const [key, url] of cases) assert.deepEqual(verdicts(key, url), Array(4).fill("none"), JSON.stringify({ key, url }))
    // The page can be served shallower than its key (`view/a%2Fb%2Fc.html` at depth 0, `view/a/b%2Fc.html` at depth 1),
    // where four or five `..` reach the route (Q28 review R4).
    for (const n of [4, 5]) assert.deepEqual(verdicts("a/b/c.html", `${back(n, "\\")}session\\ses_1\\prompt`), Array(4).fill(ASK), String(n))
    // Attributes loaded with `GET`, and a page's text, ask nothing.
    const others = [
      html(`<a href="\\api\\session\\ses_1\\prompt">route</a><img src="..\\..\\..\\..\\session\\ses_1\\prompt">`),
      html(`<p>POST \\api\\session\\ses_1\\prompt</p><a href="/docs" title="..\\..\\..\\..\\session\\ses_1\\prompt">docs</a>`),
    ]
    for (const body of others) assert.equal(page({ "index.html": body }), "none", body)
  })

  it("Q28d-4 (documented limits): JavaScript `\\\\`, HTML entities and `<base>` are not resolved", () => {
    const limits = [
      html(`<script>fetch("\\\\api\\\\session\\\\ses_1\\\\prompt", { method: "POST" })</script>`),
      html(`<a href="/docs" ping="&#92;api&#92;session&#92;ses_1&#92;prompt">docs</a>`),
      html(`<base href="/api/session/ses_1/"><form method="post" action="prompt"><button>x</button></form>`),
    ]
    for (const body of limits) assert.equal(page({ "index.html": body }), "none", body)
    assert.equal(page({ "app.js": `fetch("\\\\api\\\\session\\\\ses_1\\\\prompt", { method: "POST" })` }), "none")
  })

  it("Q28d-5 (non-regression): forms recognized before still ask, whatever the page's depth", () => {
    const urls = [
      "/api/session/ses_1/prompt",
      "http://localhost:4096/api/session/ses_1/agent",
      "../../../../session/ses_1/prompt",
      "../../session/ses_1/prompt",
      "../../../../../../../session/ses_1/command",
      "../voice/session/ses_1/instructions",
      "/api/session/ses_1/pro\nmpt",
    ]
    for (const url of urls) for (const key of ["index.html", "a/b/c.html"]) assert.deepEqual(verdicts(key, url), Array(4).fill(ASK), JSON.stringify({ url, key }))
    // Inline code and attribute code are not resolved but still examined.
    assert.equal(page({ "index.html": html(`<script>fetch("/api/session/ses_1/prompt", { method: "POST" })</script>`) }), ASK)
    assert.equal(page({ "index.html": html(`<button onclick="fetch('../../../../session/ses_1/prompt', { method: 'POST' })">x</button>`) }), ASK)
    // A name the URL parser cannot write (lone surrogate): the existing checks still apply.
    assert.equal(page({ "\ud800.html": html(`<form method="post" action="/api/session/ses_1/prompt"></form>`) }), ASK)
    assert.equal(page({ "\ud800.html": html(`<form method="post" action="\\api\\session\\ses_1\\prompt"></form>`) }), ASK) // read against a fixed base, so a name the URL parser cannot write no longer matters
  })

  it("Q28d-6: cost of many attribute URLs at doubled sizes (Node only)", () => {
    const shapes: Array<(n: number) => string> = [
      (n) => html(`<a href="/docs" ping="${"..\\x ".repeat(n / 5)}">`),
      (n) => html(`<a href="/docs" ping="${"..\\".repeat(n / 3)}session\\ses_1\\prompx">`),
      (n) => html(`<form ${'action="\\api\\session\\x\\promp" '.repeat(n / 34)}>`),
      (n) => html(`<a href="/docs" ping="http://${"a".repeat(n)}\\api">`),
      (n) => html(`<a href="/docs" ping="${"\\".repeat(n)}">`),
    ]
    const fastest = (body: string) => {
      let best = Infinity
      for (let i = 0; i < 3; i++) {
        const start = performance.now()
        page({ "a/b/index.html": body })
        best = Math.min(best, performance.now() - start)
      }
      return best
    }
    for (const [index, make] of shapes.entries()) {
      const small = fastest(make(100_000))
      const large = fastest(make(200_000))
      assert.ok(large <= 3 * small + 20, `shape ${index}: ${small.toFixed(1)} ms -> ${large.toFixed(1)} ms`)
      assert.ok(fastEnough(large, 1500), `shape ${index}: ${large.toFixed(1)} ms`)
    }
  })
})
