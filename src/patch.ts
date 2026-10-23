// Reading of the headers of an OpenCode `patch` tool patch, shared by the protected-locations rule, the
// confirmation summary, and script tracking. OpenCode 2.0.31 grammar (`packages/util/src/patch.ts`, `parse`
// function, verified by running it on random texts: `dev/tools/patch-reader-diff.ts`).
// Two reads, both in linear time:
// - broad (`patchTargets`): any path a header can designate, wherever the line is;
// - exact (`readPatch`): what OpenCode accepts and writes, section by section.

/** Whitespace trimmed as OpenCode does: JavaScript's `trim` (Unicode spaces, byte order mark, line endings). */
const trim = (text: string) => text.trim()
const trimEnd = (text: string) => text.trimEnd()

const BEGIN = "*** Begin Patch"
const END = "*** End Patch"
const ENVIRONMENT = "*** Environment ID:"
const END_OF_FILE = "*** End of File"
const ADD = "*** Add File: "
const UPDATE = "*** Update File: "
const DELETE = "*** Delete File: "
const MOVE = "*** Move to: "
/** The four file markers, mandatory space included. */
const MARKERS = [ADD, UPDATE, DELETE, MOVE]
/**
 * JavaScript line endings (line feed, carriage return, Unicode line and paragraph separators): piece
 * splitting. OpenCode only splits on line feed.
 */
const OTHER_LINE_ENDS = /[\n\r\u2028\u2029]/

/** Path designated by a line that, stripped of whitespace, starts with a marker (empty: none). */
function lineTarget(line: string): string {
  const header = trim(line)
  for (const marker of MARKERS) if (header.startsWith(marker)) return trim(header.slice(marker.length))
  return ""
}

/**
 * Broad read, deduplicated: path of any line (split on line feed) that, stripped of whitespace,
 * starts with one of the four markers, wherever it is (outside the envelope, in a body, an indented move
 * line). It contains the exact read. With `pieces` (protected-locations rule only), it also adds the
 * pieces split on carriage return and Unicode line and paragraph separators: a header placed after
 * one of them, a path cut at one of them. The pieces reproduce the reading of previous plugin versions.
 */
export function patchTargets(text: string, options: { pieces?: boolean } = {}): string[] {
  const found = new Set<string>()
  for (const line of text.split("\n")) {
    const path = lineTarget(line)
    if (path) found.add(path)
  }
  if (options.pieces)
    for (const piece of text.split(OTHER_LINE_ENDS)) {
      const path = lineTarget(piece)
      if (path) found.add(path)
    }
  return [...found]
}

/**
 * Hidden headers, deduplicated: paths found only by splitting at the other line endings a line that, stripped
 * of whitespace, does not start with a marker (for OpenCode, a content line or a rejected line). The rule
 * examines them among the pieces; the summary shows them separately from the files.
 */
export function hiddenHeaders(text: string): string[] {
  const found = new Set<string>()
  for (const line of text.split("\n")) {
    if (lineTarget(line)) continue
    for (const piece of line.split(OTHER_LINE_ENDS)) {
      const path = lineTarget(piece)
      if (path) found.add(path)
    }
  }
  return [...found]
}

/** Patch section as OpenCode applies it. */
export type PatchSection =
  /** `content`: written content, final line feed added as the tool does (`core/src/tool/plugin/patch.ts`). */
  | { readonly type: "add"; readonly path: string; readonly content: string }
  | { readonly type: "delete"; readonly path: string }
  /** `added`: `+` lines without the `+`. */
  | { readonly type: "update"; readonly path: string; readonly moveTo?: string; readonly added: readonly string[] }

/** Exact read: accepted by OpenCode (text read without error, at least one section), and its sections. */
export type PatchReading = { readonly accepted: true; readonly sections: readonly PatchSection[] } | { readonly accepted: false }

const REFUSED: PatchReading = { accepted: false }

const isBlank = (char: string | undefined) => char !== undefined && /\s/.test(char)
const isWord = (char: string | undefined) => char !== undefined && /\w/.test(char)

/**
 * Inline document envelope removed as OpenCode does (`stripHeredoc`, expression
 * `^(?:cat\s+)?<<(['"]?)(\w+)\1\s*\n([\s\S]*?)\n\2\s*$`), rewritten in linear time: the expression backtracks over
 * the line feeds after the opening, in quadratic time when the closing is missing. Same result: ASCII word
 * label, optional matching quotes; closing by a line feed, the label and whitespace to the
 * end; content from the last line feed of the whitespace after the opening, located before the closing.
 */
function stripHeredoc(input: string): string {
  let index = 0
  if (input.startsWith("cat") && isBlank(input[3])) {
    index = 3
    while (isBlank(input[index])) index++
  }
  if (!input.startsWith("<<", index)) return input
  index += 2
  const quote = input[index] === "'" || input[index] === '"' ? input[index] : ""
  if (quote) index++
  const start = index
  while (isWord(input[index])) index++
  if (index === start) return input
  const label = input.slice(start, index)
  if (quote) {
    if (input[index] !== quote) return input
    index++
  }
  let tail = input.length
  while (tail > index && isBlank(input[tail - 1])) tail--
  const close = tail - label.length - 1
  if (close < index || input[close] !== "\n" || input.slice(close + 1, tail) !== label) return input
  let open = -1
  for (let position = index; position < close && isBlank(input[position]); position++) if (input[position] === "\n") open = position
  return open === -1 ? input : input.slice(open + 1, close)
}

/** Section boundary (OpenCode's `isBoundary`): end marker, or add, delete, update header. */
const isBoundary = (line: string) => line === END || line.startsWith(ADD) || line.startsWith(DELETE) || line.startsWith(UPDATE)
const isContextMarker = (line: string) => line === "@@" || line.startsWith("@@ ")

/**
 * Body of an update (OpenCode's `parseUpdate`) from `start`: added lines and index of the boundary that
 * ends it, or rejection. Only trailing whitespace is removed to recognize a boundary: an indented header there is a context
 * line (indented by one space) or an invalid line.
 */
function readUpdate(lines: readonly string[], start: number, end: number): { added: string[]; next: number } | undefined {
  const added: string[] = []
  // Chunks read, and lines of the last one (an empty chunk is rejected).
  let chunks = 0
  let filled = false
  let afterEndOfFile = false
  let index = start
  while (index < end) {
    const line = lines[index]!
    const updateLine = trimEnd(line)
    if (afterEndOfFile) {
      if (updateLine === "") {
        index++
        continue
      }
      if (isContextMarker(updateLine)) afterEndOfFile = false
      else if (isBoundary(updateLine)) break
      else return undefined
    }
    if (updateLine === END_OF_FILE) {
      if (chunks > 0 && !filled) return undefined
      if (chunks > 0) afterEndOfFile = true
      index++
      continue
    }
    if (isBoundary(updateLine)) break
    if (isContextMarker(updateLine)) {
      if (chunks > 0 && !filled) return undefined
      chunks++
      filled = false
      index++
      continue
    }
    if (chunks === 0) chunks = 1
    if (line === "" || line.startsWith(" ") || line.startsWith("-")) filled = true
    else if (line.startsWith("+")) {
      filled = true
      added.push(line.slice(1))
    } else return undefined
    index++
  }
  if (chunks === 0 || !filled) return undefined
  return { added, next: index }
}

/**
 * Exact read, OpenCode 2.0.31 grammar: whitespace trimmed from the whole text, inline document envelope removed,
 * split on line feed only with a final carriage return removed per line; begin and end markers only on
 * the first and last line; headers recognized after trimming their whitespace at the section level (therefore
 * indented: right after the beginning, after an add or a delete), never inside an update body; move
 * line unindented, right after the update header (end-of-file lines excepted), non-empty
 * destination. Any malformed line makes the whole patch rejected, like a patch with no section.
 */
export function readPatch(text: string): PatchReading {
  const lines = stripHeredoc(trim(text))
    .split("\n")
    .map((line) => (line.endsWith("\r") ? line.slice(0, -1) : line))
  const end = lines.length - 1
  if (trim(lines[0]!) !== BEGIN || end <= 0 || trim(lines[end]!) !== END) return REFUSED
  const sections: PatchSection[] = []
  let index = 1
  while (index < end) {
    const header = trim(lines[index]!)
    // Environment identifier: tolerated only right after the begin marker, non-empty value.
    if (index === 1 && header.startsWith(ENVIRONMENT) && trim(header.slice(ENVIRONMENT.length))) {
      index++
      continue
    }
    if (header.startsWith(ADD)) {
      const added: string[] = []
      index++
      while (index < end && !isBoundary(trim(lines[index]!))) {
        if (!lines[index]!.startsWith("+")) return REFUSED
        added.push(lines[index]!.slice(1))
        index++
      }
      const joined = added.join("\n")
      sections.push({ type: "add", path: trim(header.slice(ADD.length)), content: joined === "" || joined.endsWith("\n") ? joined : `${joined}\n` })
      continue
    }
    if (header.startsWith(DELETE)) {
      if (index + 1 < end && !isBoundary(trim(lines[index + 1]!))) return REFUSED
      sections.push({ type: "delete", path: trim(header.slice(DELETE.length)) })
      index++
      continue
    }
    if (header.startsWith(UPDATE)) {
      let next = index + 1
      while (next < lines.length && trimEnd(lines[next]!) === END_OF_FILE) next++
      const move = next < lines.length ? trimEnd(lines[next]!) : undefined
      let moveTo: string | undefined
      if (move !== undefined && (move === trimEnd(MOVE) || move.startsWith(MOVE))) {
        moveTo = trim(move.slice(MOVE.length))
        if (!moveTo) return REFUSED
        next++
      }
      const body = readUpdate(lines, next, end)
      if (!body) return REFUSED
      sections.push({ type: "update", path: trim(header.slice(UPDATE.length)), ...(moveTo ? { moveTo } : {}), added: body.added })
      index = body.next
      continue
    }
    return REFUSED
  }
  return sections.length > 0 ? { accepted: true, sections } : REFUSED
}
