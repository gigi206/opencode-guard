// Fixes of the Q28 review (artifact pages that call the OpenCode server API): a file is typed as the server types it
// (key normalized as OpenCode stores it, then `lookup` of `mime-types` 3.0.2: a bare name at the root is an extension,
// any case), positions never shift (ASCII lowercase only), and a URL is read without its tabs and line breaks, as the
// browser reads it. Entities and `\/` stay documented limits. Text is judged, nothing runs.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { toolFinding } from "../src/rules/tools.ts"
import type { Finding } from "../src/rules/types.ts"
import { createRedactor } from "../src/secrets/redact.ts"

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
const single = post(ROUTE).replaceAll('"', "'")

describe("Q28b: artifact files typed as served, stable positions, URLs read as the browser reads them", () => {
  it("Q28b-1: a file the server serves as JavaScript is examined whole, whatever the form of its name", () => {
    // `lookup` reads `extname("x." + key)` after `normalizePath` (`\` to `/`, leading `./` then `/` removed).
    const names = ["js", ".js", "JS", "Js", "mjs", ".mjs", ".MJS", "ecma", ".ecma", "./js", "/ecma", ".//js", "./././JS", "//mjs", "lib\\app.js", "app.js", "APP.JS", "lib/main.mjs", "x.ecma"]
    for (const tool of ["opencode_artifact_create", "opencode_artifact_update"])
      for (const name of names) assert.equal(page({ "index.html": html(`<script src="js"></script>`), [name]: post(ROUTE) }, tool), ASK, `${tool} ${name}`)
  })

  it("Q28b-2 (control): a file the server does not serve as JavaScript is not read whole", () => {
    // `lib/js` and `lib/.js` have no extension for `lookup` (text/plain or binary), `app.js.` neither; not run.
    for (const name of ["lib/js", "lib/.js", "js.", "app.js.", "app.cjs", "app.jsx", "app.ts"])
      assert.equal(page({ "index.html": html("<p>x</p>"), [name]: post(ROUTE) }), "none", name)
  })

  it("Q28b-3: a bare text name at the root is served as text and skipped, like its dotted form", () => {
    // The server serves `md` as text/markdown, `json` as application/json, `txt` and `css` as text: never run.
    const content = `<script>${post(ROUTE)}</script>`
    for (const name of ["md", ".md", "MD", "./md", "json", "txt", "css", "page.md", "notes.txt"])
      assert.equal(page({ "index.html": html("<p>x</p>"), [name]: content }), "none", name)
    // Not typed by name (`README`, no known extension): read as a document, its script is examined.
    assert.equal(page({ "index.html": html("<p>x</p>"), README: content }), ASK)
  })

  it("Q28b-4: a character whose lowercase is longer (U+0130, the only one) never shifts the positions", () => {
    const I = "İ"
    const forms = [
      { "index.html": I.repeat(10) + `<script>${post(ROUTE)}</script>` },
      { "index.html": `<title>${I.repeat(100)}</title><button onclick='${post(ROUTE)}'>x</button>` },
      { "index.html": html(`<p title="${I.repeat(40)}" onclick='${post(ROUTE)}'>x</p>`) },
      { "index.html": html(`<p${I}${I}${I} onclick='${post(ROUTE)}'>x</p>`) },
      { "index.html": html(`<a href="#${I.repeat(30)}">x</a><a href="javascript:${single}">y</a>`) },
      { "index.html": `${I.repeat(500)}<SCRIPT>${post(ROUTE)}</SCRIPT>` },
    ]
    assert.deepEqual(forms.map((files) => page(files)), Array(forms.length).fill(ASK))
  })

  it("Q28b-5 (control): other non-ASCII characters around the code, same length or expanded only in uppercase", () => {
    // Kelvin sign, sigma, ohm sign, an astral letter (two units, lowercase two units), ß and the ligature ﬁ.
    for (const c of ["K", "Σ", "Ω", "\u{10400}", "ß", "ﬁ"]) {
      assert.equal(page({ "index.html": c.repeat(50) + `<script>${post(ROUTE)}</script>` }), ASK, c)
      assert.equal(page({ "index.html": `<title>${c.repeat(50)}</title><b onclick='${post(ROUTE)}'>x</b>` }), ASK, c)
      assert.equal(page({ "index.html": `<p>${c.repeat(50)} ${ROUTE}</p>` }), "none", c)
    }
    // A tag name is read in ASCII only: `<scrİpt>` is not a script for the browser.
    assert.equal(page({ "index.html": `<scrİpt>${post(ROUTE)}</scrİpt>` }), "none")
  })

  it("Q28b-6: a javascript: or data: URL split by tabs or line breaks, which the browser removes", () => {
    const forms = [
      html(`<a href="java\tscript:${single}">x</a>`),
      html(`<a href="java\nscript:${single}">x</a>`),
      html(`<a href="java\r\nscript:${single}">x</a>`),
      html(`<a href="j\ta\nv\ra\tscript:${single}">x</a>`),
      html(`<a href="javascript:fetch('/api/ses\tsion/ses_1/pro\nmpt', { method: 'POST' })">x</a>`),
      html(`<iframe src="da\nta:text/html,<script>${single}</script>"></iframe>`),
      html(`<form action="/api/session/ses_1/pro\tmpt" method="post"></form>`),
    ]
    assert.deepEqual(forms.map((body) => page({ "index.html": body })), Array(forms.length).fill(ASK))
    assert.equal(page({ "index.html": forms[0]! }, "opencode_artifact_update"), ASK)
  })

  it("Q28b-7 (control): blanks before the scheme, plain links, and tabs inside code kept as code", () => {
    assert.equal(page({ "index.html": html(`<a href="\tjavascript:${single}">x</a>`) }), ASK)
    assert.equal(page({ "index.html": html(`<a href="https://example.com/\tdocs">x</a><p>java\tscript: ${ROUTE}</p>`) }), "none")
    // In an `on…` attribute the value is code: a tab inside a string is part of the string, not the route.
    assert.equal(page({ "index.html": html(`<b onclick="fetch('/api/ses\tsion/ses_1/prompt', { method: 'POST' })">x</b>`) }), "none")
  })

  it("Q28b-8 (documented limits): HTML entities and JavaScript escapes are not decoded", () => {
    const forms = [
      html(`<a href="&#106;avascript:${single}">x</a>`),
      html(`<a href="java&#9;script:${single}">x</a>`),
      html(`<a href="javascript&colon;${single}">x</a>`),
      html(`<script>fetch("\\/api\\/session\\/ses_1\\/prompt", { method: "POST" })</script>`),
      html(`<script>fetch("\\u002fapi\\u002fsession\\u002fses_1\\u002fprompt", { method: "POST" })</script>`),
    ]
    assert.deepEqual(forms.map((body) => page({ "index.html": body })), Array(forms.length).fill("none"))
  })
})
