// Review of Q28c: each URL of a `ping` list read as the browser reads it (split on ASCII whitespace, then the WHATWG URL
// parser, here Node's `URL`, against the page's address), nothing recognized before lost, other attributes unchanged,
// linear cost. Text is judged, nothing runs.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { SERVER_API_ROUTE } from "../src/rules/shell.ts"
import { toolFinding } from "../src/rules/tools.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fastEnough } from "./budget.ts"

const context = { redactor: createRedactor(), home: "/home/test", cwd: "/home/test/work/app" } as never
const verdict = (body: string) => toolFinding("opencode_artifact_create", { title: "API", files: { "index.html": body } }, context)?.verdict ?? "none"
const link = (ping: string, quote = '"') => `<a href="/docs" ping=${quote}${ping}${quote}>docs</a>`
const BASE = "http://127.0.0.1:4096/api/experimental/artifacts/art_1/view/index.html"
const PATH = /^\/api\/(?:session\/[^/]+\/(?:agent|command|prompt|permission)|experimental\/voice\/session\/[^/]+\/instructions)$/
/** What the browser sends a `POST` to: one of the protected routes. */
const browserCalls = (list: string) =>
  list.split(/[\t\n\f\r ]+/).some((url) => url !== "" && PATH.test(new URL(url, BASE).pathname))

let seed = 7
const random = (n: number) => {
  seed ^= seed << 13
  seed >>>= 0
  seed ^= seed >>> 17
  seed ^= seed << 5
  seed >>>= 0
  return seed % n
}
const pick = <T>(items: readonly T[]) => items[random(items.length)]!
const BENIGN = ["/stats", "x", "a?b", "/docs#f", "../", "./y", "/api/session/s/message", "/api/session/s", "s/prompt", "prompt"]
const ROUTES = [
  "/api/session/s/prompt",
  "/api/session/ses_1/agent",
  "http://127.0.0.1:4096/api/session/s/command",
  "//127.0.0.1/api/session/s/permission",
  "../../../../session/s/prompt",
  "../../../../experimental/voice/session/s/instructions",
  "/api/experimental/voice/session/v/instructions",
]
// C0 controls around a URL: stripped by the URL parser at both ends, never separators.
const BEFORE = ["", "", "\x01", "\x0b", "\x00"]
const AFTER = ["", "", "?q=1", "#f", "\x01", "\x0b"]
const SEPARATORS = ["\t", "\n", "\f", "\r", " ", "\r\n", " \t", "\n\n\f"]
const list = () => {
  const urls = Array.from({ length: 1 + random(4) }, () => (random(3) === 0 ? pick(BEFORE) + pick(ROUTES) + pick(AFTER) : pick(BENIGN)))
  return (random(2) ? pick(SEPARATORS) : "") + urls.map((url, index) => (index ? pick(SEPARATORS) : "") + url).join("") + (random(2) ? pick(SEPARATORS) : "")
}

describe("Q28c review: the ping list of an artifact page", () => {
  it("Q28cR-1: every list whose URLs, read by the browser, reach a protected route asks (6 000 random lists)", () => {
    let reached = 0
    for (let i = 0; i < 6000; i++) {
      const ping = list()
      if (!browserCalls(ping)) continue
      reached++
      assert.equal(verdict(link(ping, random(2) ? '"' : "'")), "ask", JSON.stringify(ping))
    }
    assert.ok(reached > 2000, `${reached} lists reach a route`)
  })

  it("Q28cR-2: what the whole list without tabs and line breaks recognized still asks (6 000 random lists)", () => {
    let recognized = 0
    for (let i = 0; i < 6000; i++) {
      const ping = list()
      if (!SERVER_API_ROUTE.test(ping.replace(/[\t\n\r]/g, ""))) continue
      recognized++
      assert.equal(verdict(link(ping)), "ask", JSON.stringify(ping))
    }
    assert.ok(recognized > 1000, `${recognized} lists recognized`)
  })

  it("Q28cR-3: other attributes keep their verdicts (same expectations before and after Q28c)", () => {
    const route = "/api/session/s/prompt"
    const cases: Array<[string, string]> = [
      [`<form method="post" action="/x\n${route}"></form>`, "ask"],
      [`<form method="post" action="${route}\nx"></form>`, "none"],
      [`<form method="post" action="${route} x"></form>`, "ask"],
      [`<button formaction="\t${route}\f">x</button>`, "ask"],
      [`<button formaction="${route}\tx">x</button>`, "none"],
      [`<a href="/x ${route}" data-ping="/x\n${route}" xping="${route}">x</a>`, "none"],
      [`<a pingx="/x\t${route}\tb">x</a>`, "none"],
      [`<a href="java\nscript:fetch('${route}')">x</a>`, "ask"],
      [`<img src="data:text/html,${route}">`, "ask"],
      [`<b onclick="fetch('/x\t${route}')">x</b>`, "ask"],
      [`<iframe srcdoc="${route}"></iframe>`, "ask"],
      [`<p title="ping=${route}">${route}</p>`, "none"],
    ]
    for (const [body, expected] of cases) assert.equal(verdict(body), expected, JSON.stringify(body))
  })

  it("Q28cR-4: cost of long lists and long runs of blanks at doubled sizes (Node only)", () => {
    const shapes: Array<(n: number) => string> = [
      (n) => link("/api/session/s ".repeat(n / 15)),
      (n) => link(`${" ".repeat(n / 2)}${"\t\n".repeat(n / 4)}`),
      (n) => link("../ ".repeat(n / 4)),
      (n) => link(`/api/session/${"x".repeat(n)}`),
      (n) => link("\x01\x0b".repeat(n / 2)),
      (n) => `<a ${"ping='/a b' ".repeat(n / 12)}>`,
      (n) => link(`${"a\f".repeat(n / 2)}`, ""),
    ]
    const fastest = (body: string) => {
      let best = Infinity
      for (let i = 0; i < 3; i++) {
        const start = performance.now()
        verdict(body)
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
