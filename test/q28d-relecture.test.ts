// Review of Q28d: the URLs of `action`, `formaction` and `ping` judged against the standard URL parser (the browser's)
// on values drawn at random, the new confirmations of a documentation page, cost and exceptions. Text is judged,
// nothing runs.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { toolFinding } from "../src/rules/tools.ts"
import type { Finding } from "../src/rules/types.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fastEnough } from "./budget.ts"

const brief = (finding?: Finding) => (finding ? `${finding.verdict}:${finding.rule}` : "none")
const verdict = (files: Record<string, string>, tool = "opencode_artifact_create") =>
  brief(
    toolFinding(tool, tool === "opencode_artifact_create" ? { title: "API", files } : { id: "art_1", files }, {
      redactor: createRedactor(),
      home: "/home/test",
      cwd: "/home/test/work/app",
    } as never),
  )
const ASK = "ask:opencode-server-api"

/** Seeded generator: the same draws on every run. */
function generator(seed: number) {
  let state = seed
  const next = (n: number) => {
    state = (state * 1103515245 + 12345) & 0x7fffffff
    return state % n
  }
  return { next, pick: <T>(items: readonly T[]) => items[next(items.length)]! }
}

/** Oracle: a protected route as the whole path the server routes (written independently of the plugin's expression). */
const ROUTE = /^\/api\/(?:session\/[^/]+\/(?:agent|command|prompt|permission)|experimental\/voice\/session\/[^/]+\/instructions)(?:$|[/?#])/

/** Address OpenCode v2.2.5 serves a key at: `encodeURIComponent` per segment, under any host and id. */
const naturalAddress = (key: string) =>
  `http://example.test:9/api/experimental/artifacts/art_Q/view/${key.replaceAll("\\", "/").split("/").map(encodeURIComponent).join("/")}`

/** The browser's request for these URLs from that address: does one of them reach a protected route? */
function browserReaches(urls: string[], address: string): boolean {
  return urls.some((url) => {
    try {
      const resolved = new URL(url, address)
      return (resolved.protocol === "http:" || resolved.protocol === "https:") && ROUTE.test(resolved.pathname)
    } catch {
      return false
    }
  })
}

/** Server side of OpenCode v2.2.5 (`extractViewSubpath` then the trim of `normalizePath`): the key a view address reads. */
function servedKey(address: string): string {
  const path = new URL(address).pathname.slice("/api/experimental/artifacts/art_Q/view/".length)
  return decodeURIComponent(path).replaceAll("\\", "/").replace(/^(?:\.\/)+/u, "").replace(/^\/+/u, "")
}

function randomCase(random: ReturnType<typeof generator>) {
  const { next, pick } = random
  const sep = () => pick(["/", "\\", "/", "\\", "\t/", "\n\\"])
  const depth = next(5)
  const key = [...Array.from({ length: depth }, (_, i) => `${pick(["a", "b c", "%", "?q", "#h", "d"])}${i}`), "p.html"].join(pick(["/", "\\"]))
  const id = pick(["ses_1", "x", "{id}", "<id>", ":id", "%7Bid%7D", "a b", "...", "%2e%2e"])
  const route = pick([
    ["session", id, pick(["prompt", "agent", "command", "permission", "prompts", "messages"])],
    ["experimental", "voice", "session", id, "instructions"],
    ["session"],
    ["docs", "x"],
  ])
  let url = route.map((part) => part + sep()).join("").slice(0, -1)
  const form = pick(["absolute", "relative", "dots", "host", "scheme"])
  if (form === "absolute") url = `${sep()}api${sep()}${url}`
  else if (form === "relative") url = `api${sep()}${url}`
  else if (form === "dots")
    url = `${Array.from({ length: next(depth + 7) }, () => pick(["..", "..", ".", "x\\..", "%2e%2e"]) + sep()).join("")}${pick([`api${sep()}`, `experimental${sep()}`, ""])}${url}`
  else if (form === "host") url = `${pick(["http://h", "https:\\\\h", "\\\\h", "//127.0.0.1:4096", "http:h"])}${sep()}api${sep()}${url}`
  else url = `${pick(["mailto:", "foo:", "javascript:void ", "data:,"])}/api/${url}`
  url = `${pick(["", " ", "\t"])}${url}${pick(["", "?a=1", "#f", " "])}`
  const attribute = pick(["ping", "action", "formaction", "list"])
  const body =
    attribute === "ping"
      ? `<a href=/ ping="${url}">x</a>`
      : attribute === "list"
        ? `<a ping="/s ${url.trim()} /t">x</a>`
        : attribute === "action"
          ? `<form action="${url}"></form>`
          : `<button formaction="${url}">`
  const urls =
    attribute === "ping" ? url.split(/[\t\n\f\r ]+/).filter(Boolean) : attribute === "list" ? `/s ${url.trim()} /t`.split(/[\t\n\f\r ]+/).filter(Boolean) : [url]
  return { key, url, body, urls }
}

describe("Q28d review: attribute URLs against the standard URL parser", () => {
  it("R1: every random action/formaction/ping URL that reaches a protected route from its page's address asks", () => {
    const random = generator(20261103)
    let reached = 0
    const missed: unknown[] = []
    for (let i = 0; i < 20_000; i++) {
      const { key, url, body, urls } = randomCase(random)
      if (!browserReaches(urls, naturalAddress(key))) continue
      reached++
      for (const tool of ["opencode_artifact_create", "opencode_artifact_update"])
        if (verdict({ [key]: body }, tool) !== ASK) missed.push({ key, url, tool })
    }
    assert.ok(reached > 500, `too few reaching cases drawn: ${reached}`)
    assert.deepEqual(missed.slice(0, 5), [], `${missed.length} missed out of ${reached}`)
  })

  it("R2: forms recognized before Q28d (slashes, `..` at any depth, any host, tab in the route) still ask", () => {
    const urls = [
      "/api/session/ses_1/prompt",
      "http://localhost:4096/api/session/ses_1/agent",
      "../../../../session/ses_1/command",
      "../../../voice/session/ses_1/instructions",
      "../../../../../../../../api/session/ses_1/permission",
      "/api/session/ses_1/pro\tmpt",
      "/api/session/<id>/prompt",
      "/api/session/:id/prompt",
    ]
    for (const url of urls)
      for (const key of ["index.html", "a/b/c.html", "a\\b\\c\\d\\e.svg"])
        for (const body of [`<a ping="${url}">x</a>`, `<form action="${url}"></form>`, `<button formaction="${url}">`])
          assert.equal(verdict({ [key]: body }), ASK, JSON.stringify({ url, key, body }))
  })

  it("R3: new confirmations on a documentation page are templates in POST attributes only (text, code, href, Markdown ask nothing)", () => {
    // Observed: the parser encodes `{`, `}`, `"`, so `/api/session/{id}/prompt` in an `action` or `ping` now asks (the
    // browser does send `POST /api/session/%7Bid%7D/prompt`). Everything else stays as before.
    const templates = ["{id}", "{sessionID}", "${id}", "{{id}}"]
    for (const id of templates)
      for (const word of ["prompt", "agent"]) {
        const route = `/api/session/${id}/${word}`
        assert.equal(verdict({ "index.html": `<form action="${route}"></form>` }), ASK, route)
        assert.equal(verdict({ "index.html": `<a ping="http://localhost:4096${route}">x</a>` }), ASK, route)
        assert.equal(verdict({ "index.html": `<p>POST ${route}</p><pre><code>curl -X POST ${route}</code></pre>` }), "none", route)
        assert.equal(verdict({ "index.html": `<a href="${route}">doc</a>` }), "none", route)
        assert.equal(verdict({ "api.md": `POST ${route}` }), "none", route)
      }
    assert.equal(verdict({ "index.html": `<form action='/api/session/" + id + "/prompt'></form>` }), ASK)
    // A relative route without `..` stays a file of the artifact.
    assert.equal(verdict({ "index.html": `<form action="api/session/{id}/prompt"></form>` }), "none")
  })

  it("R4: the same file served at another depth (`%2F` in its view address) reaches the route through `..\\` and asks", () => {
    // OpenCode v2.2.5 decodes the view subpath (`decodeURIComponent`) before `normalizePath`: `a%2Fb%2Fc.html` serves the
    // key `a/b/c.html` from the view directory, `%2F/%2F/c.html` serves `c.html` two levels down. A page that links or
    // frames that address (an `href` or `src`, loaded with `GET`) makes the browser resolve from that depth.
    const view = "http://127.0.0.1:4096/api/experimental/artifacts/art_Q/view/"
    const cases: Array<[string, string, string]> = [
      ["a/b/c.html", "a%2Fb%2Fc.html", "..\\..\\..\\..\\session\\x\\prompt"],
      ["c.html", "%2F/%2F/c.html", "..\\..\\..\\..\\..\\..\\session\\x\\prompt"],
    ]
    for (const [key, address, url] of cases) {
      assert.equal(servedKey(view + address), key)
      assert.ok(browserReaches([url], view + address))
      assert.equal(verdict({ [key]: `<a href="/d" ping="${url}">d</a>` }), ASK, JSON.stringify({ key, address, url }))
    }
  })

  it("R5: cost stays linear with a long file name and many ping URLs", () => {
    // Each URL is resolved against the page's address, whose length is that of the key: URLs × key length.
    const key = `${"a/".repeat(2000)}x.html`
    const time = (count: number) => {
      const start = performance.now()
      verdict({ [key]: `<a ping="${"b ".repeat(count)}">x</a>` })
      return performance.now() - start
    }
    time(1000)
    const elapsed = Math.min(time(100_000), time(100_000), time(100_000))
    assert.ok(fastEnough(elapsed, 300), `${Math.round(elapsed)} ms for a 4 kB key and 100 000 ping URLs`)
  })

  it("R6: long URLs and many attributes on a short key stay linear", () => {
    const cases = [
      `<a ping="${"..\\".repeat(100_000)}api\\session\\s\\prompt">x</a>`,
      `<a ping="\\api\\x">x</a>`.repeat(20_000),
      `<form action="${"x\\".repeat(100_000)}"></form>`,
      `<a ping="${"\t".repeat(100_000)}">x</a>`,
    ]
    for (const body of cases) {
      const start = performance.now()
      verdict({ "a/b/index.html": body })
      const elapsed = performance.now() - start
      assert.ok(fastEnough(elapsed, 500), `${Math.round(elapsed)} ms`)
    }
  })

  it("R7: no exception escapes on random malformed URLs and names", () => {
    const random = generator(7)
    const alphabet = ["\\", "/", ".", "..", ":", "%", "%zz", "\ud800", "\udfff", "\0", " ", "\t", "\n", "?", "#", "[", "]", "@", "http:", "//", "a", "{", "　", "ẞ"]
    const draw = (n: number) => Array.from({ length: n }, () => random.pick(alphabet)).join("")
    for (let i = 0; i < 5_000; i++) {
      const key = `${draw(random.next(6))}${random.pick(["x.html", "x.svg", "", "x"])}`
      const url = draw(random.next(20))
      for (const body of [`<a ping="${url}">`, `<form action=${url}>`, `<button formaction='${url}'>`])
        assert.doesNotThrow(() => verdict({ [key]: body }), JSON.stringify({ key, url }))
    }
  })
})
