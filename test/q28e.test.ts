// The URLs of an artifact page's `action`, `formaction` and `ping` attributes read once as the standard URL parser reads
// them, then judged at any depth: OpenCode v2.2.5 decodes the view subpath before reading the key, so the agent chooses
// the depth at which the browser sees a page (`view/a%2Fb%2Fc.html` serves `a/b/c.html` from `view/`). Each reaching
// case is checked against the standard URL parser from an address the server really serves the key at. Text is
// judged, nothing runs.
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
/** The same URL in each attribute sent with `POST`: alone, then as one URL of a `ping` list. */
const carriers = (url: string) => [
  `<a href="/d" ping="${url}">d</a>`,
  `<a href="/d" ping="/s ${url} /t">d</a>`,
  `<form method="post" action="${url}"></form>`,
  `<button formaction="${url}">x</button>`,
]
const verdicts = (key: string, url: string) => carriers(url).map((body) => verdict({ [key]: body }))

const VIEW = "http://127.0.0.1:4096/api/experimental/artifacts/art_Q/view/"
/** Oracle: a protected route as the whole path the server routes (written independently of the plugin's expression). */
const ROUTE = /^\/api\/(?:session\/[^/]+\/(?:agent|command|prompt|permission)|experimental\/voice\/session\/[^/]+\/instructions)(?:$|[/?#])/

/** An address the server serves `key` at, `depth` directories below `view/` (`%2F` segments, then the encoded key). */
const address = (key: string, depth: number) => `${VIEW}${"%2F/".repeat(depth)}${encodeURIComponent(key)}`

/** Server side of OpenCode v2.2.5 (`extractViewSubpath` then the trim of `normalizePath`): the key a view address reads. */
const servedKey = (at: string) =>
  decodeURIComponent(new URL(at).pathname.slice(new URL(VIEW).pathname.length)).replaceAll("\\", "/").replace(/^(?:\.\/)+/u, "").replace(/^\/+/u, "")

/** The browser's request for `url` from that address: does it reach a protected route? */
function reaches(url: string, at: string): boolean {
  try {
    const resolved = new URL(url, at)
    return (resolved.protocol === "http:" || resolved.protocol === "https:") && ROUTE.test(resolved.pathname)
  } catch {
    return false
  }
}

/** Seeded generator: the same draws on every run. */
function generator(seed: number) {
  let state = seed
  const next = (n: number) => {
    state = (Math.imul(state, 1103515245) + 12345) & 0x7fffffff
    return state % n
  }
  return { next, pick: <T>(items: readonly T[]) => items[next(items.length)]! }
}

describe("Q28e: attribute URLs read once by the URL parser, judged at any depth", () => {
  it("Q28e-1: a route reached from another depth than the key's asks (`\\`, `%2e` in any case, `.` segments, controls)", () => {
    // [key, depth of the address, URL]: the address serves the key (checked), and the browser reaches the route from it.
    const cases: Array<[string, number, string]> = [
      ["a/b/c.html", 0, "..\\..\\..\\..\\session\\x\\prompt"],
      ["c.html", 2, "..\\..\\..\\..\\..\\..\\session\\x\\prompt"],
      ["a/b/c/d/e.html", 0, "..\\..\\..\\voice\\session\\x\\instructions"],
      ["a/b/c.html", 0, "%2e%2e/%2E%2E/.%2e/%2E./session/x/agent"],
      ["a/b/c.html", 0, "%2e%2E\\..\\.%2E\\%2e.\\session\\x\\command"],
      ["a/b/c.html", 0, ".\\..\\%2e\\..\\.\\..\\%2E\\..\\session\\.\\x\\%2e\\permission"],
      ["a/b/c.html", 0, "..\\..\\..\\..\\session\\x\\y\\..\\prompt"],
      ["a/b/c.html", 0, "..\\..\\..\\..\\session\\x\\y\\%2E%2e\\prompt"],
      ["a/b/c.html", 0, "z\\..\\..\\..\\..\\..\\session\\x\\prompt"],
      ["a/b/c.html", 0, "\x01\x1f ..\\..\\..\\..\\session\\x\\prompt\x1f "],
      ["a/b/c.html", 0, "..\\..\\..\\..\\..\\api\\session\\x\\prompt?q=1#f"],
      ["a/b/c.html", 0, "http:..\\..\\..\\..\\session\\x\\prompt"],
      ["a/b/c.html", 0, "HTTP:%2e%2e/%2e%2e/%2e%2e/%2e%2e/session/x/prompt"],
      ["x/y.svg", 7, `${"..\\".repeat(12)}api\\session\\x\\prompt`],
      ["index.html", 3, "..\\..\\..\\..\\..\\..\\..\\session\\x\\prompt"],
    ]
    for (const [key, depth, url] of cases) {
      const at = address(key, depth)
      assert.equal(servedKey(at), key)
      assert.ok(reaches(url, at), JSON.stringify({ key, depth, url }))
      for (const tool of ["opencode_artifact_create", "opencode_artifact_update"])
        assert.deepEqual(carriers(url).map((body) => verdict({ [key]: body }, tool)), Array(4).fill(ASK), JSON.stringify({ key, depth, url, tool }))
    }
    // Tabs and line breaks inside a form's URL are removed (in a `ping` list, they separate its URLs).
    const broken = "..\\..\t\\..\n\\..\r\\session\\x\\pro\tmpt"
    assert.ok(reaches(broken, address("a/b/c.html", 0)))
    for (const body of [`<form action="${broken}"></form>`, `<button formaction="${broken}">x</button>`]) assert.equal(verdict({ "a/b/c.html": body }), ASK, body)
  })

  it("Q28e-2: absolute forms are read by the URL parser on a fixed address, whatever the key", () => {
    const urls = [
      "\\api\\.\\session\\x\\prompt",
      "/api/%2e/session/x/../x/agent",
      "/x/%2E%2E/api/session/x/command",
      "\\\\h\\api\\session\\x\\permission",
      "https:h\\api\\session\\x\\prompt",
      "http://127.0.0.1:4096/api/./experimental/voice/session/x/instructions",
    ]
    for (const url of urls)
      for (const key of ["\ud800.html", `${"a/".repeat(50)}p.html`, "index.html"]) {
        if (!key.includes("\ud800")) assert.ok(reaches(url, address(key, 0)), url)
        assert.deepEqual(verdicts(key, url), Array(4).fill(ASK), JSON.stringify({ url, key }))
      }
  })

  it("Q28e-3 (control): URLs that no address of the page sends to a route ask nothing", () => {
    // Every depth from `view/` (0) to 8 is tried with the standard URL parser: none reaches a route.
    const urls = [
      "..%2f..%2f..%2f..%2fsession%2fx%2fprompt",
      "..%5c..%5c..%5c..%5csession%5cx%5cprompt",
      "..\\..\\..\\session\\x\\prompt",
      "..\\..\\..\\..\\docs\\x",
      "..\\..\\..\\..\\session\\x\\prompt\\..",
      "%2e%2e%2e\\%2e%2e%2e\\%2e%2e%2e\\%2e%2e%2e\\session\\x\\prompt",
      "a%2eb\\..\\..\\..\\session\\x\\prompt",
      "api\\.\\session\\x\\prompt",
      "http:api\\session\\x\\prompt",
      "mailto:..\\..\\..\\..\\session\\x\\prompt",
      "foo:%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\session\\x\\prompt",
      "..\\..\\..\\..\\session\\x",
    ]
    for (const url of urls) {
      for (let depth = 0; depth <= 8; depth++) assert.ok(!reaches(url, address("index.html", depth)), JSON.stringify({ url, depth }))
      for (const key of ["index.html", "a/b/c.html"]) assert.deepEqual(verdicts(key, url), Array(4).fill("none"), JSON.stringify({ url, key }))
    }
    // Attributes loaded with `GET` and text are not read this way.
    assert.equal(verdict({ "a/b/c.html": `<a href="..\\..\\..\\..\\session\\x\\prompt">d</a><p>..\\..\\..\\..\\session\\x\\prompt</p>` }), "none")
  })

  it("Q28e-4: random URLs reaching a route from any served depth ask (forms of Q28-c5 included: the key's own depth)", () => {
    const random = generator(20261104)
    const { next, pick } = random
    const sep = () => pick(["/", "\\", "/", "\\", "\t/", "\n\\"])
    const dot = () => pick(["..", "..", "%2e%2e", ".%2E", "%2E.", ".", "%2e", "x\\..", "y/%2e%2e"])
    let reached = 0
    const missed: unknown[] = []
    for (let i = 0; i < 40_000; i++) {
      const keyDepth = next(5)
      const key = [...Array.from({ length: keyDepth }, (_, n) => `${pick(["a", "b c", "%", "d"])}${n}`), "p.html"].join("/")
      const depth = pick([keyDepth, next(keyDepth + 1), next(8)])
      const id = pick(["ses_1", "{id}", "%2e%2e", "a b", ":id"])
      const route = pick([
        ["session", id, pick(["prompt", "agent", "command", "permission", "prompts"])],
        ["experimental", "voice", "session", id, "instructions"],
        ["docs", "x"],
      ])
      const tail = route.map((part) => part + sep()).join("").slice(0, -1)
      const form = pick(["dots", "dots", "absolute", "scheme"])
      const climb = () => Array.from({ length: depth + pick([2, 3, 4, 5, 6, next(8)]) }, () => dot() + sep()).join("")
      let url =
        form === "dots"
          ? `${climb()}${pick([`api${sep()}`, `experimental${sep()}`, ""])}${tail}`
          : form === "absolute"
            ? `${pick(["/", "\\", "\\\\h\\", "//h/", "https:h/"])}api${sep()}${pick(["", `.${sep()}`, `%2e${sep()}`, `x${sep()}..${sep()}`])}${tail}`
            : `${pick(["http:", "HTTPS:"])}${climb()}${tail}`
      url = `${pick(["", " ", "\x01", "\t"])}${url}${pick(["", "?a=1", "#f", "\x1f"])}`
      const at = address(key, depth)
      const carrier = next(4)
      // The browser splits a `ping` list on ASCII whitespace before reading each URL.
      const urls = carrier < 2 ? (carrier === 0 ? url : `/s ${url} /t`).split(/[\t\n\f\r ]+/).filter(Boolean) : [url]
      if (!urls.some((one) => reaches(one, at))) continue
      reached++
      const body = carriers(url)[carrier]!
      if (verdict({ [key]: body }) !== ASK) missed.push({ key, depth, url, body })
    }
    assert.ok(reached > 500, `too few reaching cases drawn: ${reached}`)
    assert.deepEqual(missed.slice(0, 5), [], `${missed.length} missed out of ${reached}`)
  })

  it("Q28e-5: cost is linear in the artifact's size, whatever the key's length (Node only)", () => {
    const key = `${"a/".repeat(10_000)}x.html`
    const cases = [
      `<a ping="${"b ".repeat(100_000)}">x</a>`,
      `<a ping="${"..\\ ".repeat(50_000)}">x</a>`,
      `<form action="..\\${" ".repeat(100_000)}..\\session"></form>`,
      `<form action="${"x\\..\\".repeat(50_000)}${"..\\".repeat(5)}session\\x\\prompt"></form>`,
      `<form action="${"%2e%2E\\".repeat(50_000)}session\\x\\prompt"></form>`,
      `<form action="${"\x01".repeat(100_000)}a${"\x01".repeat(100_000)}"></form>`,
      `<button formaction="http:${"..\\".repeat(100_000)}">`,
    ]
    for (const body of cases) {
      const runs = [0, 1, 2].map(() => {
        const start = performance.now()
        verdict({ [key]: body })
        return performance.now() - start
      })
      const elapsed = Math.min(...runs)
      assert.ok(fastEnough(elapsed, 300), `${Math.round(elapsed)} ms for ${body.slice(0, 40)}`)
    }
  })
})
