// Review of Q28b (artifact files typed as served, stable positions, URLs read as the browser reads them): the type of a
// file compared with the server's own reading (`normalizePath` of OpenCode 2.2.5, then `lookup` of `mime-types`) on many
// keys, positions after every code point, tabs and line breaks (including the `ping` list, split on blanks before the
// URLs are read), a page that documents the API, and the cost of the new paths. Text is judged, nothing runs.
import "./tmp.ts"
import assert from "node:assert/strict"
import { createRequire } from "node:module"
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
const ROUTE = "/api/session/ses_1/prompt"
const html = (body: string) => `<!doctype html><html><head><title>API</title></head><body>${body}</body></html>`
const post = (url: string) => `fetch(${JSON.stringify(url)}, { method: "POST", body: "{}" })`

// `mime-types` 3.0.2 as installed with the plugin's dependencies (the version of OpenCode 2.2.5's service).
const { lookup } = createRequire(import.meta.url)("mime-types") as { lookup: (path: string) => string | false }
// JavaScript MIME type essences (WHATWG MIME Sniffing): what a `<script src>` runs under `nosniff`.
const JS_TYPES = new Set(["application/ecmascript", "application/javascript", "application/x-ecmascript", "application/x-javascript", "text/ecmascript", "text/javascript", "text/jscript", "text/livescript", "text/x-ecmascript", "text/x-javascript"])

/** `normalizePath` of `packages/core/src/artifact.ts` (OpenCode 2.2.5): undefined when the server refuses the key. */
function stored(raw: string): string | undefined {
  const trimmed = raw.replaceAll("\\", "/").replace(/^(?:\.\/)+/u, "").replace(/^\/+/u, "")
  if (!trimmed || trimmed.includes("\0")) return undefined
  const segments = trimmed.split("/")
  return segments.some((part) => !part || part === "." || part === "..") ? undefined : segments.join("/")
}

describe("Q28b review: type as served, positions, tabs and line breaks, cost", () => {
  it("Q28bR-1: a key accepted by the server is read whole exactly when the server serves it as JavaScript", () => {
    const pieces = ["js", "JS", "mjs", "ecma", "cjs", "md", ".", "/", "\\", "./", "a", " ", "\t", "..", "İ", "K", "é"]
    const keys: string[] = []
    const build = (prefix: string, depth: number) => {
      if (depth > 0) keys.push(prefix)
      if (depth < 3) for (const piece of pieces) build(prefix + piece, depth + 1)
    }
    build("", 0)
    let accepted = 0
    const wrong: string[] = []
    for (const key of keys) {
      const clean = stored(key)
      if (clean === undefined) continue
      accepted++
      const served = JS_TYPES.has(String(lookup(clean)))
      const asked = page({ "index.html": "<p>x</p>", [key]: post(ROUTE) }) === ASK
      if (served !== asked) wrong.push(`${JSON.stringify(key)}: served ${served}, asked ${asked}`)
    }
    assert.ok(accepted > 3000, `${accepted} keys`)
    assert.deepEqual(wrong, [])
  })

  it("Q28bR-2: no code point before the code shifts the positions (each one, by blocks)", () => {
    const missed: string[] = []
    for (let start = 0; start <= 0x10ffff; start += 0x1000) {
      let prefix = ""
      for (let point = start; point < start + 0x1000 && point <= 0x10ffff; point++) {
        if (point >= 0xd800 && point <= 0xdfff) continue
        const c = String.fromCodePoint(point)
        if (!/[<>"'&]/.test(c)) prefix += c
      }
      for (const body of [`${prefix}<script>${post(ROUTE)}</script>`, `<title>${prefix}</title><b onclick='${post(ROUTE)}'>x</b>`])
        if (page({ "index.html": body }) !== ASK) missed.push(start.toString(16))
    }
    assert.deepEqual(missed, [])
  })

  it("Q28bR-3: a ping list split by a tab or a line break still pings the route (blanks separate its URLs)", () => {
    // `ping` is a set of URLs separated by ASCII whitespace: `/api/session/ses_1/prompt` and `x` are two URLs here.
    for (const blank of ["\t", "\n", "\r\n", "\r"])
      assert.equal(page({ "index.html": html(`<a href="/docs" ping="${ROUTE}${blank}x">x</a>`) }), ASK, JSON.stringify(blank))
  })

  it("Q28bR-4 (control): a page that documents the API, with tabs and line breaks in its attributes, asks nothing", () => {
    const forms = [
      html(`<a href="https://example.com/docs\n#prompt">${ROUTE}</a>`),
      html(`<a\n  href="#prompt"\n  title="POST ${ROUTE}">prompt</a>`),
      html(`<pre><code>curl -X POST \\\n\thttp://localhost:4096${ROUTE}</code></pre>`),
      html(`<form action="/search"\n method="get"><input name="q" value="${ROUTE}"></form>`),
      html(`<a href="/docs" ping="/stats\n/visits">${ROUTE}</a>`),
      html(`<img src="data:image/png;base64,\niVBORw0KGgo=" alt="${ROUTE}">`),
      // Any `data:` URL is examined whole, as in Q28 (both trees): the one expected ask.
      html(`<iframe src="data:text/plain,\t${ROUTE}"></iframe>`),
    ]
    assert.deepEqual(forms.map((body) => page({ "index.html": body })), Array(forms.length).fill("none").fill(ASK, 6))
  })

  it("Q28bR-5: cost of the new paths at doubled sizes (Node only)", () => {
    const shapes: Array<(n: number) => Record<string, string>> = [
      (n) => ({ [`${"./".repeat(n)}js`]: "x" }),
      (n) => ({ [`${"/".repeat(n)}js`]: "x", [`${"\\".repeat(n)}mjs`]: "x" }),
      (n) => ({ [`${"a.".repeat(n / 2)}ecma`]: "x" }),
      (n) => ({ "index.html": `<a ${'href="java\tscript:x" '.repeat(n / 10)}>` }),
      (n) => ({ "index.html": `<a ping="${"\t\n".repeat(n)}">` }),
      (n) => ({ "index.html": `<form action="${"/api/session/\t".repeat(n / 8)}">` }),
      (n) => ({ "index.html": `${"İ".repeat(n)}<script>x</script>` }),
      (n) => ({ "index.html": `<A ${"ONCLICK=X ".repeat(n / 5)}>` }),
    ]
    const fastest = (files: Record<string, string>) => {
      let best = Infinity
      for (let i = 0; i < 3; i++) {
        const start = performance.now()
        page(files)
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
