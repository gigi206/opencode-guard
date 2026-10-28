// Pieces of the terminal layout shared by the commands (`rules`, `show`, `last`): a block's title and table rows whose
// last cell is wrapped. Every text is already cleaned (`Pretty.clean`): widths and cuts are those of the printed text.
import type { Pretty } from "./context.ts"
import { wrap, type Segment, type Style } from "./style.ts"

/** The blocks and their colors: a banner, then a separator line across the terminal. */
export type Block = "builtins" | "custom" | "settings" | "log"
const LINES: Readonly<Record<Block, Style>> = { builtins: "builtinsLine", custom: "customLine", settings: "settingsLine", log: "logLine" }

/** A block's title: its banner, its detail on the same line when it fits, otherwise below it, then the separator line. */
export function title(pretty: Pretty, text: string, detail: string, block: Block): void {
  const banner: Segment = [` ${text} `, block]
  if (!detail || banner[0].length + 2 + detail.length <= pretty.width) pretty.line([banner, ...(detail ? ([[`  ${detail}`, "dim"]] as Segment[]) : [])])
  else {
    pretty.line([banner])
    for (const line of wrap(detail, pretty.width - 1)) pretty.line([[" "], [line, "dim"]])
  }
  pretty.line([["─".repeat(pretty.width), LINES[block]]])
}

/** A heading inside a block. */
export function heading(pretty: Pretty, text: string, detail = "", style: Style = "group"): void {
  pretty.line([["  "], [text, style], ...(detail ? ([[`  ${detail}`, "dim"]] as Segment[]) : [])])
}

/**
 * Lines of a table row: the fixed cells, then `text` wrapped to the terminal's width from its column, continuation lines
 * aligned on it.
 */
export function rowLines(pretty: Pretty, cells: readonly Segment[], column: number, text: string, style?: Style): Segment[][] {
  const [first = "", ...rest] = wrap(text, Math.max(20, pretty.width - column))
  return [[...cells, [first, style]], ...rest.map((line): Segment[] => [[" ".repeat(column)], [line, style]])]
}
