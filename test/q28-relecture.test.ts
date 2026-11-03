// Review of Q28 (artifact pages that call the OpenCode server API): equality with the shell form on any host, false
// asks on a page that documents the API, files the server serves as JavaScript (`mime-types` 3.0.2 of OpenCode 2.2.5:
// a bare name is read as an extension), positions shifted by a lowercase that grows, the five settings through
// `decide`, the cost at doubled sizes, and the shell route expression unchanged. Text is judged, nothing runs.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import type { ActiveRules } from "../src/rules/features.ts"
import { toolFinding } from "../src/rules/tools.ts"
import type { Finding } from "../src/rules/types.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fastEnough } from "./budget.ts"

const HOME = "/home/test"
const PROJECT = `${HOME}/work/app`
const CREATE = "opencode_artifact_create"
const UPDATE = "opencode_artifact_update"
const brief = (finding?: Finding) => (finding ? `${finding.verdict}:${finding.rule}${finding.modelDecides ? " (model)" : ""}` : "none")
const check = (tool: string, input: unknown, active?: ActiveRules) =>
  brief(toolFinding(tool, input, { redactor: createRedactor(), home: HOME, cwd: PROJECT, active } as never))
const shell = (command: string, active?: ActiveRules) => check("shell", { command }, active)
const page = (files: Record<string, string>, active?: ActiveRules, tool = CREATE) =>
  check(tool, tool === CREATE ? { title: "API", files } : { id: "art_1", files }, active)

const on: ActiveRules = { dangerousCommands: true, sensitiveFiles: true }
const SETTINGS: ReadonlyArray<ActiveRules | undefined> = [
  undefined,
  { dangerousCommands: false, sensitiveFiles: false },
  { ...on, overrides: new Map([["opencode-server-api", "deny"]]) },
  { ...on, localAsksByModel: true, selfProtectionByModel: true },
  { ...on, selfProtectionByModel: true, overrides: new Map([["opencode-server-api", "model"]]) },
]
const ASK = "ask:opencode-server-api"
const EXPECTED = [ASK, ASK, "deny:opencode-server-api", ASK, ASK]

const ROUTE = "/api/session/ses_1/prompt"
const html = (body: string) => `<!doctype html><html><head><title>API</title></head><body>${body}</body></html>`
const post = (url: string) => `fetch(${JSON.stringify(url)}, { method: "POST", body: "{}" })`

describe("Q28 review", () => {
  it("Q28R-1: any host, like the shell rule (which asks on the route under any host, and on a mere mention)", () => {
    const actual: Record<string, string[]> = {}
    const expected: Record<string, string[]> = {}
    for (const host of ["evil.example", "10.0.0.5:4096", "[::1]:4096", "opencode.local:4096", "localhost:4096"]) {
      const url = `http://${host}${ROUTE}`
      expected[host] = SETTINGS.map((active) => shell(`curl ${url}`, active))
      assert.deepEqual(expected[host], EXPECTED, `shell ${host}`)
      assert.deepEqual(SETTINGS.map((active) => shell(`echo ${url}`, active)), EXPECTED, `shell mention ${host}`)
      for (const tool of [CREATE, UPDATE]) actual[`${tool} ${host}`] = SETTINGS.map((active) => page({ "index.html": html(`<script>${post(url)}</script>`) }, active, tool))
      for (const tool of [CREATE, UPDATE]) expected[`${tool} ${host}`] = expected[host]!
      delete expected[host]
    }
    assert.deepEqual(actual, expected)
    // Weaker than the shell on purpose: a URL loaded with GET (only known reads on these routes); the shell asks on it.
    assert.deepEqual(SETTINGS.map((active) => shell("curl http://localhost:4096/api/session/ses_1/permission", active)), EXPECTED)
    assert.equal(page({ "index.html": html(`<img src="http://localhost:4096/api/session/ses_1/permission">`) }), "none")
  })

  it("Q28R-2: a documentation page asks nothing in its common forms; route strings in code and inert blocks ask", () => {
    const common: Record<string, string>[] = [
      { "index.html": html(`<p>POST ${ROUTE} sends a prompt</p>`) },
      { "index.html": html(`<table><tr><td>POST</td><td>/api/session/:id/prompt</td></tr><tr><td>POST</td><td>/api/session/{sessionID}/agent</td></tr></table>`) },
      { "index.html": html(`<pre><code class="language-sh">curl -X POST http://localhost:4096${ROUTE} -d '{"text":"hi"}'</code></pre>`) },
      { "index.html": html(`<pre><code><span>fetch</span>(<span>"${ROUTE}"</span>, {method: "POST"})</code></pre>`) },
      { "README.md": "POST `" + ROUTE + "`\n```js\nfetch('" + ROUTE + "',{method:'POST'})\n```" },
      { "index.html": html(`<a href="#p" title="POST ${ROUTE}" data-route="${ROUTE}">prompt</a><img alt="${ROUTE}" src="x.png">`) },
      { "index.html": html(`<a href="http://localhost:4096${ROUTE}">${ROUTE}</a><!-- route: ${ROUTE} -->`) },
      { "index.html": html(`<pre id="c">curl -X POST ${ROUTE}</pre><script>b.onclick = () => navigator.clipboard.writeText(c.textContent)</script>`) },
      { "index.html": html(`<pre>&lt;script&gt;${post(ROUTE)}&lt;/script&gt;</pre>`) },
      { "index.html": html(`<script>const routes = [{ method: "POST", path: "/api/session/{sessionID}/prompt" }]</script>`) },
      { "routes.json": JSON.stringify([{ path: ROUTE }]) },
    ]
    for (const files of common) assert.equal(page(files), "none", JSON.stringify(files))
    // Code that runs but only holds the route in a string (no flow analysis, like the shell's `echo`).
    const inCode: Record<string, string>[] = [
      { "index.html": html(`<button onclick="navigator.clipboard.writeText('curl -X POST http://localhost:4096${ROUTE}')">Copy</button>`) },
      { "index.html": html(`<div id="t"></div><script>const routes = [{ method: "POST", path: "/api/session/:sessionID/prompt" }]; t.textContent = routes[0].path</script>`) },
      { "app.js": `document.body.textContent = "POST ${ROUTE} sends a prompt"` },
      { "app.js": `const sample = \`curl -X POST http://localhost:4096${ROUTE}\`` },
    ]
    // Blocks the browser never runs, read as markup by the prudent choice.
    const inert: Record<string, string>[] = [
      { "index.html": html(`<script type="application/json" id="d">{"path":"${ROUTE}"}</script>`) },
      { "index.html": html(`<script type="text/plain">${post(ROUTE)}</script>`) },
      { "index.html": html(`<template><script>${post(ROUTE)}</script></template>`) },
      { "index.html": html(`<xmp><script>${post(ROUTE)}</script></xmp>`) },
      { "index.html": html(`<textarea><script>${post(ROUTE)}</script></textarea>`) },
      { "index.html": html(`<!-- <script>${post(ROUTE)}</script> -->`) },
    ]
    assert.deepEqual([...inCode, ...inert].map((files) => page(files)), Array(10).fill(ASK))
  })

  it("Q28R-3 (defect): a root file named js, mjs or ecma (dot or not) is served as JavaScript and escapes", () => {
    // `lookup` of mime-types 3.0.2 reads `extname("x." + path)`: `js`, `.js` and `JS` at the root give text/javascript
    // (`lib/js` gives nothing: text/plain, not run). OpenCode strips a leading `./` or `/` of a key (`normalizePath`).
    const names = ["js", ".js", "JS", "mjs", ".mjs", "ecma", ".ecma", "./js", "/ecma"]
    const actual = names.map((name) => page({ "index.html": html(`<script src="${name.replace(/^\.?\//, "")}"></script>`), [name]: post(ROUTE) }))
    assert.deepEqual(actual, Array(names.length).fill(ASK))
  })

  it("Q28R-3b (control): files served as text, or not as JavaScript, ask nothing; a JavaScript file asks", () => {
    for (const name of ["lib/js", "lib/.js", "app.cjs", "app.jsx", "app.ts", "app.js.", "notes.txt", "data.json", "page.md"])
      assert.equal(page({ "index.html": html("<p>x</p>"), [name]: post(ROUTE) }), "none", name)
    for (const name of ["app.js", "APP.JS", "lib/main.mjs", "x.ecma"]) assert.equal(page({ "index.html": html("<p>x</p>"), [name]: post(ROUTE) }), ASK, name)
  })

  it("Q28R-4 (defect): a character whose lowercase is longer (U+0130) shifts the positions and hides the code", () => {
    const shifted = [
      { "index.html": "İ".repeat(10) + `<script>${post(ROUTE)}</script>` },
      { "index.html": `<title>${"İ".repeat(100)}</title><button onclick='${post(ROUTE)}'>x</button>` },
    ]
    assert.deepEqual(shifted.map((files) => page(files)), [ASK, ASK])
  })

  it("Q28R-5: a tab in the scheme is read like the browser; an entity in the scheme and JavaScript-escaped slashes stay documented limits", () => {
    // The tab is removed as the browser does; the entity and the escapes are encoded forms, listed with `%` and base64.
    const code = post(ROUTE).replaceAll('"', "'")
    const forms = [
      { "index.html": html(`<a href="java\tscript:${code}">x</a>`) },
      { "index.html": html(`<a href="&#106;avascript:${code}">x</a>`) },
      { "index.html": html(`<script>fetch("\\/api\\/session\\/ses_1\\/prompt", { method: "POST" })</script>`) },
    ]
    assert.deepEqual(forms.map((files) => page(files)), [ASK, "none", "none"])
  })

  it("Q28R-6: through decide, five settings, direct and CodeMode call: never left to the model, which neither lifts nor turns it into a denial", async () => {
    let calls = 0
    const allow = async () => {
      calls++
      return {
        answers: {
          risk: { type: "score", score: 0.05, confidence: 0.95 },
          destructive: { type: "noul", noul: 0.01 },
          exfiltration: { type: "noul", noul: 0.01 },
          credentials: { type: "noul", noul: 0.01 },
          privilege_persistence: { type: "noul", noul: 0.01 },
        },
      }
    }
    const settings: Record<string, unknown>[] = [
      {},
      { dangerousCommands: false, sensitiveFiles: false },
      { ruleOverrides: { "opencode-server-api": "deny" } },
      { localAsks: "model", selfProtectionByModel: true },
      { selfProtectionByModel: true, ruleOverrides: { "opencode-server-api": "model" } },
    ]
    const actual: string[] = []
    const consulted: Array<[number, number]> = []
    const denied: string[] = []
    const deny = async () => ({
      answers: {
        risk: { type: "score", score: 3, confidence: 0.99 },
        destructive: { type: "noul", noul: 0.99 },
        exfiltration: { type: "noul", noul: 0.99 },
        credentials: { type: "noul", noul: 0.99 },
        privilege_persistence: { type: "noul", noul: 0.99 },
      },
    })
    for (const setting of settings) {
      const { config } = parseConfig({ decision: { baseURL: "https://nox.invalid/v1", model: "nox-4b" }, ...setting })
      const decider = createDecider({ config, redactor: createRedactor(), model: allow as never })
      for (const [tool, input] of [
        [CREATE, { title: "API", files: { "index.html": html(`<script>${post(ROUTE)}</script>`) } }],
        [UPDATE, { id: "art_1", files: { "app.js": post(`../../../..${ROUTE.slice(4)}`) } }],
      ] as const)
        for (const fromCode of [false, true]) {
          const decided = await decider.decide({ tool, input, agent: "build", directory: PROJECT, ...(fromCode ? { fromCode } : {}) })
          actual.push(`${decided.verdict}:${decided.rule}`)
        }
      // The model is consulted as for the shell pair (it may deny, never lifts the ask): same calls, fresh deciders.
      const consult = async (tool: string, input: unknown, fromCode: boolean) => {
        calls = 0
        await createDecider({ config, redactor: createRedactor(), model: allow as never }).decide({ tool, input, agent: "build", directory: PROJECT, ...(fromCode ? { fromCode } : {}) })
        return calls
      }
      const paired = await consult("shell", { command: `opencode api POST ${ROUTE}` }, false)
      for (const fromCode of [false, true])
        consulted.push([await consult(CREATE, { title: "API", files: { "index.html": html(`<script>${post(ROUTE)}</script>`) } }, fromCode), paired])
      // A model that denies (witness: a page without route is denied) does not turn the ask into a denial either.
      const denier = createDecider({ config, redactor: createRedactor(), model: deny as never })
      const witness = await denier.decide({ tool: CREATE, input: { title: "API", files: { "index.html": html("<p>hello</p>") } }, agent: "build", directory: PROJECT })
      assert.equal(witness.verdict, "deny", "witness")
      for (const fromCode of [false, true]) {
        const decided = await createDecider({ config, redactor: createRedactor(), model: deny as never }).decide({
          tool: CREATE,
          input: { title: "API", files: { "index.html": html(`<script>${post(ROUTE)}</script>`) } },
          agent: "build",
          directory: PROJECT,
          ...(fromCode ? { fromCode } : {}),
        })
        denied.push(`${decided.verdict}:${decided.rule}`)
      }
    }
    assert.deepEqual(denied, EXPECTED.flatMap((verdict) => [verdict, verdict]))
    assert.deepEqual(actual, EXPECTED.flatMap((verdict) => Array(4).fill(verdict)))
    for (const [artifact, paired] of consulted) assert.equal(artifact, paired)
  })

  it("Q28R-7: the cost doubles at most about twice when the artifact doubles (Node only)", () => {
    const shapes: Array<(n: number) => Record<string, string>> = [
      (n) => ({ "index.html": `<p>${"word ".repeat(n)}</p>` }),
      (n) => ({ "index.html": "<a ".repeat(n) }),
      (n) => ({ "index.html": `<a b="x `.repeat(n) }),
      (n) => ({ "index.html": `<a ${"onclick=../ ".repeat(n)}>` }),
      (n) => ({ "index.html": "<script>../a</script>".repeat(n / 4) }),
      (n) => Object.fromEntries(Array.from({ length: n / 50 }, (_, i) => [`p${i}.html`, `<script>fetch("../x")</script>`])),
      (n) => ({ "app.js": "../session/a/".repeat(n / 3) }),
      (n) => ({ "index.html": "<".repeat(n * 2) }),
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

  it("Q28R-8: the exported route expression is the shell rule's former one; other tools unchanged", async () => {
    const shellModule = (await import("../src/rules/shell.ts")) as { SERVER_API_ROUTE?: RegExp }
    const former = /\/api\/(?:session\/[^\s"'\/{}]+\/(?:agent|command|prompt|permission)|experimental\/voice\/session\/[^\s"'\/{}]+\/instructions)\b/
    assert.equal(shellModule.SERVER_API_ROUTE?.source, former.source)
    assert.equal(shellModule.SERVER_API_ROUTE?.flags, former.flags)
    const files = { "index.html": html(`<script>${post(ROUTE)}</script>`) }
    for (const tool of ["artifact_create", "opencode_artifact_read", "opencode_artifact_delete", "write", "my_mcp_publish"])
      assert.notEqual(check(tool, { title: "API", id: "art_1", files, filePath: `${PROJECT}/a.html`, content: "x" }), ASK, tool)
  })
})
