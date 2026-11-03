// The `ping` list of an artifact page read as the browser reads it: split on ASCII whitespace (tab, line feed, form feed,
// carriage return, space) into its URLs, each one then read like any other URL. Forms (`action`, `formaction`) keep a
// single URL. Text is judged, nothing runs.
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
const ROUTE = "/api/session/ses_1/prompt"
const html = (body: string) => `<!doctype html><html><head><title>API</title></head><body>${body}</body></html>`
const link = (ping: string) => html(`<a href="/docs" ping="${ping}">docs</a>`)
const BLANKS = ["\t", "\n", "\f", "\r", " ", "\r\n", " \t\n "]

describe("Q28c: the ping list of an artifact page, split into its URLs", () => {
  it("Q28c-1: a route among several ping URLs, after and before each ASCII blank, asks", () => {
    // The next URL starts with a letter: once the blanks are removed from the whole list, the route would run into it.
    for (const blank of BLANKS)
      for (const ping of [`${ROUTE}${blank}stats`, `/stats${blank}${ROUTE}`, `/a${blank}${ROUTE}${blank}b`, `${blank}${ROUTE}${blank}x`])
        for (const tool of ["opencode_artifact_create", "opencode_artifact_update"])
          assert.equal(page({ "index.html": link(ping) }, tool), ASK, JSON.stringify({ ping, tool }))
  })

  it("Q28c-2: every protected route, relative with `..` or on any host, as one URL of a list, asks", () => {
    const routes = [
      "/api/session/ses_1/agent",
      "/api/session/ses_1/command",
      "/api/session/ses_1/permission",
      "/api/experimental/voice/session/ses_1/instructions",
      "http://127.0.0.1:4096/api/session/ses_1/prompt",
      "../../session/ses_1/prompt",
    ]
    for (const route of routes) for (const blank of ["\t", "\n"]) assert.equal(page({ "index.html": link(`/x${blank}${route}${blank}y`) }), ASK, route)
    // An unquoted value ends at the first blank (HTML): a single URL.
    assert.equal(page({ "index.html": html(`<a href=/docs ping=${ROUTE}>docs</a>`) }), ASK, "unquoted")
    assert.equal(page({ "index.html": html(`<area href="/docs" PING='/x\n${ROUTE}'>`) }), ASK, "area, single quotes")
  })

  it("Q28c-3 (kept): a route cut by a tab or a line break inside a ping list still asks, as in Q28b", () => {
    for (const blank of ["\t", "\n", "\r\n"]) assert.equal(page({ "index.html": link(`/api/session/ses_1/pro${blank}mpt`) }), ASK, JSON.stringify(blank))
  })

  it("Q28c-4 (control): other ping lists and single-URL forms ask nothing", () => {
    const forms = [
      link("/stats /visits\t/clicks\n/views"),
      link(`/stats\n${ROUTE.replace("prompt", "message")}`),
      link("/api/session/ses_1/ prompt"),
      html(`<a href="/docs" ping="/stats\t/visits">${ROUTE}</a>`),
      html(`<a href="/docs" title="ping ${ROUTE}">docs</a>`),
      // `action` and `formaction` hold one URL: a blank inside is removed, never a separator.
      html(`<form method="post" action="${ROUTE}\nx"><button>x</button></form>`),
      html(`<form method="post"><button formaction="${ROUTE}\tx">x</button></form>`),
    ]
    assert.deepEqual(forms.map((body) => page({ "index.html": body })), Array(forms.length).fill("none"))
  })

  it("Q28c-5: cost of long ping lists at doubled sizes (Node only)", () => {
    const shapes: Array<(n: number) => string> = [
      (n) => link("/a ".repeat(n / 3)),
      (n) => link(`${"/x\t".repeat(n / 3)}${ROUTE}`),
      (n) => link(" \t\n\f\r".repeat(n / 5)),
      (n) => link(`${"../".repeat(n / 6)}x ../`.repeat(2)),
      (n) => html(`<a ${'ping="/a\t/b" '.repeat(n / 14)}>`),
    ]
    const fastest = (body: string) => {
      let best = Infinity
      for (let i = 0; i < 3; i++) {
        const start = performance.now()
        page({ "index.html": body })
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
