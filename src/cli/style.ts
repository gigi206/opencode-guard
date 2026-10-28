// Terminal layout of the command line: whether the output is a terminal, its width and whether colors are wanted are
// decided by the launcher (`bin/guard`) and passed in; nothing is read from the process here. The escape sequences
// below are the only ones ever printed, and only around text the redaction left unchanged (`main.ts`).

/** The launcher's terminal: present only when the standard output is one. */
export interface Terminal {
  readonly width: number
  readonly color: boolean
}

export type Style = "title" | "group" | "rule" | "deny" | "ask" | "dim" | "warn"
/** Text and its style; the text is already redacted and free of control characters. */
export type Segment = readonly [text: string, style?: Style]

const STYLES: Readonly<Record<Style, readonly [string, string]>> = {
  title: ["\x1b[1m", "\x1b[22m"],
  group: ["\x1b[1;36m", "\x1b[22;39m"],
  rule: ["\x1b[1m", "\x1b[22m"],
  deny: ["\x1b[1;31m", "\x1b[22;39m"],
  ask: ["\x1b[33m", "\x1b[39m"],
  dim: ["\x1b[2m", "\x1b[22m"],
  warn: ["\x1b[33m", "\x1b[39m"],
}

/** Every escape sequence `paint` may print (tests remove them to compare with the uncolored output). */
export const ESCAPES: readonly string[] = [...new Set(Object.values(STYLES).flat())]

const MIN_WIDTH = 60
const MAX_WIDTH = 120
const DEFAULT_WIDTH = 100

/**
 * The launcher's decision: a terminal only when the standard output is one, its width kept between 60 and 120 columns
 * (100 when unknown), colors unless `NO_COLOR` is set and not empty or `TERM` is `dumb`.
 */
export function terminalOf(env: Record<string, string | undefined>, isTTY: boolean | undefined, columns: number | undefined): Terminal | undefined {
  if (!isTTY) return undefined
  const width = columns !== undefined && Number.isFinite(columns) && columns > 0 ? columns : DEFAULT_WIDTH
  return { width: Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, Math.floor(width))), color: !env.NO_COLOR && env.TERM !== "dumb" }
}

/** Lines of at most `width` characters, cut at spaces only: a longer word (a placeholder, a path) stays whole. */
export function wrap(text: string, width: number): string[] {
  const lines: string[] = []
  let line = ""
  for (const word of text.split(" ").filter(Boolean)) {
    if (line && line.length + 1 + word.length > width) {
      lines.push(line)
      line = word
    } else line = line ? `${line} ${word}` : word
  }
  return line ? [...lines, line] : [""]
}

/** The segments joined, each styled one wrapped in its escape sequences when colors are wanted. */
export function paint(segments: readonly Segment[], color: boolean): string {
  return segments.map(([text, style]) => (color && style && text ? `${STYLES[style][0]}${text}${STYLES[style][1]}` : text)).join("")
}
