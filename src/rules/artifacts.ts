import { posix } from "node:path"
import { overridden, type ActiveRules } from "./features.ts"
import { SERVER_API_ROUTE } from "./shell.ts"
import type { Finding } from "./types.ts"

/**
 * OpenCode 2.2.5 tools that write an artifact's files (`packages/core/src/tool/plugin/artifact.ts`, `opencode`
 * namespace: the hooks see `opencode_<name>`, direct or CodeMode call). Its pages are served later by the local server
 * (`/api/experimental/artifacts/<id>/view/`, `sandbox allow-scripts`, `nosniff`), outside the tool hooks.
 */
const ARTIFACT_WRITE_TOOLS: ReadonlySet<string> = new Set(["opencode_artifact_create", "opencode_artifact_update"])

/** Extensions served as JavaScript (`mime-types`), run by a `<script src>` of a page: the whole file is code. */
const SCRIPT_EXTENSIONS: ReadonlySet<string> = new Set(["js", "mjs", "ecma"])

/**
 * Extensions served as text that the browser never runs (Markdown, plain text, tables, JSON, CSS). Any other file may be
 * a document (HTML, XHTML, SVG, any XML type): its executable parts are examined.
 */
const TEXT_EXTENSIONS: ReadonlySet<string> = new Set(["md", "markdown", "mdx", "mkd", "txt", "text", "log", "csv", "tsv", "json", "css"])

/** Attributes whose URL a page sends with a method other than `GET` (form submission, `ping` of a link: `POST`). */
const POST_ATTRIBUTES: ReadonlySet<string> = new Set(["action", "formaction", "ping"])

/** ASCII whitespace (HTML): what separates the URLs of a `ping` list. A URL read this way has no tab or line break left. */
const PING_SEPARATORS = /[\t\n\f\r ]+/

/**
 * Run of `.`/`..` segments with at least one `..`, at the start of a path or after a `/` (a relative address, resolved
 * against the page's directory under `/api/experimental/artifacts/<id>/view/`). Never starts inside a run: linear.
 */
const DOT_SEGMENTS = /(?<![\w.~%+-]|\.\/)(?:\.\/)*\.\.\/(?:\.{1,2}\/)*/g

/** A protected route as the whole path of a request, from its start (the server routes the whole path). */
const ROUTE_PATH = new RegExp(`^(?:${SERVER_API_ROUTE.source})`)

/** Key of a file as OpenCode stores it (`normalizePath`, `packages/core/src/artifact.ts`: `\` to `/`, leading `./` then `/` removed). */
function artifactKey(path: string): string {
  return path.replaceAll("\\", "/").replace(/^(?:\.\/)+/u, "").replace(/^\/+/u, "")
}

/**
 * Extension by which the server types a file: its key (`artifactKey`), then read as `lookup` of `mime-types` does
 * (`extname("x." + path)`, any case): a bare name at the root (`js`, `.js`) is an extension.
 */
function extension(path: string): string {
  return posix.extname(`x.${artifactKey(path)}`).toLowerCase().slice(1)
}

/**
 * Parents of `view/` (`/api/experimental/artifacts/<id>/view/`, any id), the shallowest directory the server serves a
 * file from: what a relative URL reaches when its `..` climb out of the page's directory.
 */
const VIEW_PARENTS = ["api", "experimental", "artifacts", "art", "view"]

/** A segment that the URL parser reads as `.` or `..`: dots, each written as is or as `%2e` (any case). */
const DOT_SEGMENT = /^(?:\.|%2e){1,2}$/i

/** URL without the C0 controls and spaces at its ends, as the URL parser reads it (a loop: linear on any blanks). */
function stripEnds(url: string): string {
  let start = 0
  let end = url.length
  while (start < end && url.charCodeAt(start) <= 0x20) start++
  while (end > start && url.charCodeAt(end - 1) <= 0x20) end--
  return url.slice(start, end)
}

/**
 * Path of an HTTP URL read by the standard URL parser: absolute, or from the root of a fixed address (`base`, any
 * host: only a path from the root or a host is read against it).
 */
function absolutePath(url: string, base?: string): string | undefined {
  try {
    const resolved = new URL(url, base)
    return resolved.protocol === "http:" || resolved.protocol === "https:" ? resolved.pathname : undefined
  } catch {
    return undefined
  }
}

/**
 * Paths that a path from the root or a relative path (`/` only) requests, whatever the depth its page is served at:
 * `.` segments dropped, a `..` after a segment of its own removes it, and each remaining leading `..` climbs one
 * directory, from any depth (the server decodes the view subpath before reading the key: `view/a%2Fb%2Fc.html` serves
 * `a/b/c.html` from `view/`, `view/%2F/c.html` serves `c.html` one level down). Linear in the URL alone.
 */
function pathsFrom(url: string): string[] {
  if (url.startsWith("/")) return [absolutePath(url, "http://127.0.0.1:4096/")].filter((path) => path !== undefined)
  const end = url.search(/[?#]/)
  const kept: string[] = []
  let climbs = 0
  for (const segment of (end === -1 ? url : url.slice(0, end)).split("/")) {
    const dots = DOT_SEGMENT.test(segment) ? segment.replace(/%2e/gi, ".") : ""
    if (dots === ".." && kept.length > 0) kept.pop()
    else if (dots === "..") climbs++
    else if (dots !== ".") kept.push(segment)
  }
  const paths: string[] = []
  // From `view/` up: three `..` reach `/api/experimental/`, four `/api/`, five or more the root (`/./`: never a host).
  for (let up = 3; up <= Math.min(climbs, VIEW_PARENTS.length); up++) {
    const path = absolutePath(`/./${[...VIEW_PARENTS.slice(0, VIEW_PARENTS.length - up), ...kept].join("/")}`, "http://127.0.0.1:4096/")
    if (path !== undefined) paths.push(path)
  }
  return paths
}

/**
 * Paths that a URL of `POST_ATTRIBUTES` may request, read as the standard URL parser reads it (C0 controls and spaces
 * at its ends and tabs and line breaks anywhere removed, `\` read as `/`, `.` and `..` segments, `%2e` as a dot in
 * them; `%2f` and `%5c` stay as they are), at any depth of its page and on any host. `http:` or `https:` followed by a
 * path is read both relative to the page (same scheme) and as an absolute URL (another scheme: `https:h/api/…`).
 */
function requestedPaths(value: string): string[] {
  const url = stripEnds(value).replace(/[\t\n\r]/g, "")
  const scheme = /^[a-z][a-z\d+.-]*:/i.exec(url)?.[0].toLowerCase()
  if (scheme === undefined) return pathsFrom(url.replaceAll("\\", "/"))
  if (scheme !== "http:" && scheme !== "https:") return []
  return [...pathsFrom(url.slice(scheme.length).replaceAll("\\", "/")), absolutePath(url)].filter((path) => path !== undefined)
}

/** ASCII letters only, as HTML reads tag and attribute names: the length never changes, positions stay valid. */
function asciiLower(text: string): string {
  return text.replace(/[A-Z]+/g, (letters) => letters.toLowerCase())
}

/** URL as the browser reads it: tabs and line breaks removed anywhere (WHATWG URL parser). Not a decoding. */
function urlValue(value: string): string {
  return value.replace(/[\t\n\r]/g, "")
}

/**
 * The code calls a protected route: written as is (any host), or relative with `..` up to `/api/` or
 * `/api/experimental/`, whatever the depth of the page that runs it (a script file runs in the page that loads it).
 */
function callsServerApi(code: string): boolean {
  if (SERVER_API_ROUTE.test(code)) return true
  if (!code.includes("../")) return false
  return ["/api/", "/api/experimental/"].some((prefix) => SERVER_API_ROUTE.test(code.replace(DOT_SEGMENTS, prefix)))
}

const NAME = /[^\s"'>\/=]+/y
const BLANKS = /[\s\/]*/y

/**
 * Parts of a document that the page runs or sends: `<script>` content, `on…` and `srcdoc` attribute values, `javascript:`
 * and `data:` URLs, and the URLs of `POST_ATTRIBUTES` (the whole `ping` list and each of its URLs). Text, `<pre>`/`<code>`
 * and other attributes (loaded with `GET`) are not. Comments and raw text elements are read as markup too: their end
 * differs between HTML, foreign content and XML, and a document may be any of them. One pass by position, quotes of
 * attribute values respected: linear. A URL of `POST_ATTRIBUTES` that the browser may resolve to a protected route
 * (`requestedPaths`) is returned as that route too, in addition.
 */
function executableParts(text: string): string[] {
  const lower = asciiLower(text)
  const parts: string[] = []
  let at = 0
  while ((at = lower.indexOf("<", at)) !== -1) {
    NAME.lastIndex = at + 1
    const tag = /[a-z]/.test(lower[at + 1] ?? "") ? NAME.exec(lower)?.[0] : undefined
    if (!tag) {
      at++
      continue
    }
    let position = at + 1 + tag.length
    while (position < text.length && text[position] !== ">") {
      BLANKS.lastIndex = position
      BLANKS.exec(text)
      position = BLANKS.lastIndex
      NAME.lastIndex = position
      const attribute = NAME.exec(lower)?.[0]
      if (!attribute) {
        if (text[position] === ">") break
        position++
        continue
      }
      position += attribute.length
      while (/\s/.test(text[position] ?? "")) position++
      if (text[position] !== "=") continue
      position++
      while (/\s/.test(text[position] ?? "")) position++
      const quote = text[position]
      let value: string
      if (quote === '"' || quote === "'") {
        const end = text.indexOf(quote, position + 1)
        value = text.slice(position + 1, end === -1 ? text.length : end)
        position = end === -1 ? text.length : end + 1
      } else {
        const start = position
        while (position < text.length && !/[\s>]/.test(text[position]!)) position++
        value = text.slice(start, position)
      }
      if ((attribute.startsWith("on") && attribute.length > 2) || attribute === "srcdoc") parts.push(value)
      else if (POST_ATTRIBUTES.has(attribute) || /^[\s\x00-\x1f]*(?:javascript|data):/i.test(urlValue(value))) {
        parts.push(urlValue(value))
        // `ping` is a list of URLs that the browser splits on ASCII whitespace before reading each one: each URL too.
        const urls = attribute === "ping" ? value.split(PING_SEPARATORS) : POST_ATTRIBUTES.has(attribute) ? [value] : []
        for (const url of urls) {
          if (!url) continue
          if (attribute === "ping") parts.push(url)
          for (const path of requestedPaths(url)) {
            const route = path.match(ROUTE_PATH)?.[0]
            if (route) parts.push(route)
          }
        }
      }
    }
    at = position + 1
    if (tag === "script") {
      const end = lower.indexOf("</script", at)
      parts.push(text.slice(at, end === -1 ? text.length : end))
      if (end === -1) break
      at = end
    }
  }
  return parts
}

/**
 * Artifact written with a page that calls the server API (rule `opencode-server-api`, same routes as the shell form):
 * once opened, the page runs outside the tool hooks. Ask, a denial only with its `deny` setting, never left to the model.
 */
export function artifactFinding(tool: string, input: unknown, active?: ActiveRules): Finding | undefined {
  if (!ARTIFACT_WRITE_TOOLS.has(tool) || input === null || typeof input !== "object") return undefined
  const files = (input as Record<string, unknown>).files
  if (files === null || typeof files !== "object") return undefined
  for (const [path, content] of Object.entries(files)) {
    if (typeof content !== "string") continue
    const kind = extension(path)
    if (TEXT_EXTENSIONS.has(kind)) continue
    const parts = SCRIPT_EXTENSIONS.has(kind) ? [content] : executableParts(content)
    if (parts.some(callsServerApi))
      return overridden(
        {
          verdict: "ask",
          rule: "opencode-server-api",
          reason: `artifact page code (${path}) that calls the OpenCode server API (switches the agent, sends a prompt or a command, replaces the instructions of a voice call, or answers a permission request): once the page is opened, it can bypass the guard`,
        },
        active,
      )
  }
  return undefined
}
