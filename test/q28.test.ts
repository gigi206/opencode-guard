// Q28: the code of an artifact's pages (`opencode_artifact_create`, `opencode_artifact_update`) that calls a protected
// route of the OpenCode server API gets the confirmation of `opencode-server-api`, like the shell form (same routes,
// same verdict under every setting, never left to the model). Text, Markdown and known reads ask nothing. Text is
// judged, nothing runs.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import type { ActiveRules } from "../src/rules/features.ts"
import { toolFinding } from "../src/rules/tools.ts"
import type { Finding } from "../src/rules/types.ts"
import { createRedactor, placeholder } from "../src/secrets/redact.ts"
import { withinBudget } from "./budget.ts"

const HOME = "/home/test"
const PROJECT = `${HOME}/work/app`
const CREATE = "opencode_artifact_create"
const UPDATE = "opencode_artifact_update"
const brief = (finding?: Finding) => (finding ? `${finding.verdict}:${finding.rule}${finding.modelDecides ? " (model)" : ""}` : "none")
const check = (tool: string, input: unknown, active?: ActiveRules) =>
  brief(toolFinding(tool, input, { redactor: createRedactor(), home: HOME, cwd: PROJECT, active } as never))
const shell = (command: string, active?: ActiveRules) => check("shell", { command }, active)
const page = (files: Record<string, string>, tool = CREATE) =>
  check(tool, tool === CREATE ? { title: "Report", files } : { id: "art_1", files })

const on: ActiveRules = { dangerousCommands: true, sensitiveFiles: true }
const SETTINGS: ReadonlyArray<ActiveRules | undefined> = [
  undefined,
  { dangerousCommands: false, sensitiveFiles: false },
  { ...on, overrides: new Map([["opencode-server-api", "deny"]]) },
  { ...on, localAsksByModel: true, selfProtectionByModel: true },
  { ...on, selfProtectionByModel: true, overrides: new Map([["opencode-server-api", "model"]]) },
]
const EXPECTED = ["ask:opencode-server-api", "ask:opencode-server-api", "deny:opencode-server-api", "ask:opencode-server-api", "ask:opencode-server-api"]

const html = (body: string) => `<!doctype html><html><head><title>Report</title></head><body>${body}</body></html>`
const post = (url: string) => `fetch(${JSON.stringify(url)}, { method: "POST", body: "{}" })`

/** Recognized forms: files of the artifact, and the route the paired shell form calls. */
const FORMS: ReadonlyArray<readonly [string, Record<string, string>, string]> = [
  ["inline script, absolute path", { "index.html": html(`<script>${post("/api/session/ses_1/prompt")}</script>`) }, "/api/session/ses_1/prompt"],
  ["module script, absolute URL to localhost", { "index.html": html(`<script type="module">${post("http://localhost:4096/api/session/ses_1/agent")}</script>`) }, "/api/session/ses_1/agent"],
  ["event handler attribute", { "index.html": html(`<button onclick='${post("http://127.0.0.1:4096/api/session/ses_1/command")}'>Go</button>`) }, "/api/session/ses_1/command"],
  ["javascript: URL", { "index.html": html(`<a href="javascript:${post("/api/session/ses_1/permission/per_1/reply").replaceAll('"', "'")}">Reply</a>`) }, "/api/session/ses_1/permission/per_1/reply"],
  ["script file of the artifact", { "index.html": html(`<script src="app.js"></script>`), "app.js": post("/api/session/ses_1/prompt") }, "/api/session/ses_1/prompt"],
  ["module file of the artifact", { "index.html": html(`<script type="module" src="lib/main.mjs"></script>`), "lib/main.mjs": post("/api/session/ses_1/prompt") }, "/api/session/ses_1/prompt"],
  ["relative address up to /api/ from the view root", { "index.html": html(`<script>${post("../../../../session/ses_1/prompt")}</script>`) }, "/api/session/ses_1/prompt"],
  ["relative address from a deeper page", { "docs/a/page.html": html(`<script>${post("./../../../../../../session/ses_1/agent")}</script>`) }, "/api/session/ses_1/agent"],
  ["view path followed by ..", { "index.html": html(`<script>${post("/api/experimental/artifacts/art_1/view/../../../../session/ses_1/command")}</script>`) }, "/api/session/ses_1/command"],
  ["relative voice route", { "index.html": html(`<script>${post("../../../voice/session/ses_1/instructions")}</script>`) }, "/api/experimental/voice/session/ses_1/instructions"],
  ["form submitted with POST", { "index.html": html(`<form method="post" action="../../../../session/ses_1/prompt"><button>Send</button></form>`) }, "/api/session/ses_1/prompt"],
  ["link ping (POST)", { "index.html": html(`<a href="#top" ping="/api/session/ses_1/prompt">Top</a>`) }, "/api/session/ses_1/prompt"],
  ["SVG document script", { "chart.svg": `<svg xmlns="http://www.w3.org/2000/svg"><script><![CDATA[${post("/api/session/ses_1/prompt")}]]></script></svg>` }, "/api/session/ses_1/prompt"],
  ["script after a comment closed by <!-->", { "index.html": html(`<!--><script>${post("/api/session/ses_1/prompt")}</script><!-- -->`) }, "/api/session/ses_1/prompt"],
  ["script inside a comment (read as markup)", { "index.html": html(`<!-- <script>${post("/api/session/ses_1/prompt")}</script> -->`) }, "/api/session/ses_1/prompt"],
  ["script inside SVG style (foreign content)", { "index.html": html(`<svg><style><script>${post("/api/session/ses_1/prompt")}</script></style></svg>`) }, "/api/session/ses_1/prompt"],
  ["script inside textarea (read as markup)", { "index.html": html(`<textarea><script>${post("/api/session/ses_1/prompt")}</script></textarea>`) }, "/api/session/ses_1/prompt"],
  ["iframe srcdoc", { "index.html": html(`<iframe srcdoc="<script>${post("../../../../session/ses_1/prompt").replaceAll('"', "&quot;")}</script>"></iframe>`) }, "/api/session/ses_1/prompt"],
  ["data: script", { "index.html": html(`<script src="data:text/javascript,${post("http://127.0.0.1:4096/api/session/ses_1/prompt").replaceAll('"', "'")}"></script>`) }, "/api/session/ses_1/prompt"],
  ["data: document in a frame", { "index.html": html(`<iframe src='data:text/html,<script>${post("http://localhost:4096/api/session/ses_1/agent")}</script>'></iframe>`) }, "/api/session/ses_1/agent"],
  ["XHTML document handler", { "page.xhtml": `<html xmlns="http://www.w3.org/1999/xhtml"><body onload="${post("/api/session/ses_1/prompt").replaceAll('"', "&quot;")}"/></html>` }, "/api/session/ses_1/prompt"],
]

describe("Q28: artifact pages that call the OpenCode server API", () => {
  it("Q28-1: each recognized form asks like the shell form to the same route, under every setting", () => {
    // Every form at once: in the deployed code, the failure lists each one.
    const expected: Record<string, string[]> = {}
    const actual: Record<string, string[]> = {}
    for (const [what, files, route] of FORMS) {
      const paired = SETTINGS.map((active) => shell(`opencode api POST ${route}`, active))
      assert.deepEqual(paired, EXPECTED, `shell pair of ${what}`)
      for (const tool of [CREATE, UPDATE]) {
        const input = tool === CREATE ? { title: "Report", files } : { id: "art_1", files }
        expected[`${tool}: ${what}`] = paired
        actual[`${tool}: ${what}`] = SETTINGS.map((active) => check(tool, input, active))
      }
    }
    assert.deepEqual(actual, expected)
  })

  it("Q28-2 (control): text, <pre>/<code>, Markdown and plain text that document the API ask nothing", () => {
    const route = "/api/session/ses_1/prompt"
    const documented: Record<string, string>[] = [
      { "index.html": html(`<p>POST ${route} sends a prompt.</p><pre><code>${post(route).replaceAll('"', "&quot;")}</code></pre>`) },
      { "index.html": html(`<pre>&lt;script&gt;${post(route)}&lt;/script&gt;</pre>`) },
      { "index.html": html(`<p>See ../../../../session/ses_1/prompt</p><title>${route}</title>`) },
      { "index.md": `# API\n\n\`\`\`js\n<script>${post(route)}</script>\n\`\`\`\n<button onclick="${post(route)}">x</button>\n` },
      { "notes.txt": `<script>${post(route)}</script>`, "data.json": JSON.stringify({ code: post(route) }), "style.css": `a { background: url(${route}) }` },
    ]
    for (const files of documented) for (const tool of [CREATE, UPDATE]) assert.equal(page(files, tool), "none", JSON.stringify(files))
  })

  it("Q28-3 (control): known reads and GET-only resources ask nothing, as in the shell form", () => {
    assert.equal(shell("opencode api GET /api/session"), "none")
    const reads: Record<string, string>[] = [
      { "index.html": html(`<script>fetch("/api/session").then((r) => r.json()); fetch("../../../../session/ses_1/message")</script>`) },
      { "index.html": html(`<img src="/api/session/ses_1/permission"><iframe src="../../../../session/ses_1/permission/per_1"></iframe>`) },
      { "index.html": html(`<a href="/api/session/ses_1/prompt">route</a><link rel="prefetch" href="/api/session/ses_1/agent">`) },
      { "index.html": html(`<script>${post("session/ses_1/prompt")}</script>`) },
    ]
    for (const files of reads) assert.equal(page(files), "none", JSON.stringify(files))
  })

  it("Q28-4 (documented limits): a route built, encoded or from a variable is not recognized", () => {
    const limits = [
      `fetch(\`/api/session/\${id}/prompt\`, { method: "POST" })`,
      `fetch("/api/session/" + id + "/prompt", { method: "POST" })`,
      `fetch("/api/session/ses_1/%70rompt", { method: "POST" })`,
      `const route = "prompt"; fetch(base + route, { method: "POST" })`,
    ]
    for (const code of limits) assert.equal(page({ "index.html": html(`<script>${code}</script>`) }), "none", code)
  })

  it("Q28-5 (control): reading and deleting an artifact, and other tools, are unchanged", () => {
    const files = { "index.html": html(`<script>${post("/api/session/ses_1/prompt")}</script>`) }
    assert.equal(check("opencode_artifact_read", { id: "art_1" }), "none")
    assert.equal(check("opencode_artifact_delete", { id: "art_1" }), "none")
    assert.equal(check("opencode_artifact_read", { id: "art_1", files }), "none")
    assert.equal(check("my_mcp_publish", { title: "Report", files }), "none")
    assert.equal(page({ "index.html": html("<p>Hello</p>"), "app.js": "console.log(1)" }), "none")
    // Malformed inputs: nothing to examine (OpenCode refuses them).
    assert.equal(check(CREATE, { title: "Report", files: "index.html" }), "none")
    assert.equal(check(CREATE, { title: "Report", files: { "index.html": 42 } }), "none")
  })

  it("Q28-6: the other findings of the call hold (placeholder denial)", () => {
    const files = { "index.html": html(`<script>${post("/api/session/ses_1/prompt")}</script><p>key=${placeholder("openai_key")}</p>`) }
    assert.equal(page(files), "deny:placeholder")
  })

  it("Q28-7: a CodeMode internal call and a direct call ask; a model that allows does not lift it", async () => {
    const allow = async () => ({
      answers: {
        risk: { type: "score", score: 0.05, confidence: 0.95 },
        destructive: { type: "noul", noul: 0.01 },
        exfiltration: { type: "noul", noul: 0.01 },
        credentials: { type: "noul", noul: 0.01 },
        privilege_persistence: { type: "noul", noul: 0.01 },
      },
    })
    const calling = { title: "Report", files: { "index.html": html(`<script>${post("/api/session/ses_1/prompt")}</script>`) } }
    const plain = { title: "Report", files: { "index.html": html(`<p>${"/api/session/ses_1/prompt"}</p>`) } }
    for (const settings of [{}, { localAsks: "model", selfProtectionByModel: true }]) {
      const { config } = parseConfig({ decision: { baseURL: "https://nox.invalid/v1", model: "nox-4b" }, ...settings })
      const decider = createDecider({ config, redactor: createRedactor(), model: allow as never })
      for (const fromCode of [true, false]) {
        const asked = await decider.decide({ tool: CREATE, input: calling, agent: "build", directory: PROJECT, ...(fromCode ? { fromCode } : {}) })
        assert.equal(`${asked.verdict}:${asked.rule}`, "ask:opencode-server-api", JSON.stringify(settings))
        const judged = await decider.decide({ tool: CREATE, input: plain, agent: "build", directory: PROJECT, ...(fromCode ? { fromCode } : {}) })
        assert.equal(`${judged.verdict}:${judged.rule}`, "allow:undefined")
      }
    }
  })

  it("Q28-8: the cost stays linear on a large or malformed artifact (Node only)", () => {
    const route = post("/api/session/ses_1/prompt")
    const large: Record<string, string>[] = [
      { "index.html": html(`<p>${"text ".repeat(200_000)}</p><script>${route}</script>`) },
      { "index.html": "<a ".repeat(200_000) },
      { "index.html": `<a b="${"x".repeat(1_000_000)}` },
      { "index.html": `<script>${"./".repeat(300_000)}x` },
      { "app.js": "../".repeat(300_000) + "x/" + "./".repeat(300_000) },
      { "index.html": "<p onclick=".repeat(100_000) },
      { "index.html": `<iframe srcdoc="${"<p>../ ".repeat(200_000)}">` },
      { "index.html": `<a href="data:text/html,${"../.".repeat(200_000)}">` },
      { "index.html": "<!--".repeat(200_000) },
    ]
    const start = performance.now()
    assert.equal(page(large[0]!), "ask:opencode-server-api")
    for (const files of large.slice(1)) assert.equal(page(files), "none")
    assert.ok(withinBudget(start, 3000), `${Math.round(performance.now() - start)} ms`)
  })
})
