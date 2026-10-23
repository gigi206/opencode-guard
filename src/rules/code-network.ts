// Network access from JavaScript code: decoding of Unicode escapes, shared by the CodeMode rule (tools.ts) and by
// the network check of inline code (shell.ts); network function identifier, used by the latter.

/**
 * Unicode escapes (`\u0065`, `\u{65}`) decoded as the CodeMode parser (acorn) does for identifiers
 * and strings: `f\u0065tch(…)` calls `fetch`. Braced form according to the language grammar: any
 * number of digits (leading zeros included), value at most 0x10FFFF. Only broadens detection.
 */
export function decodeUnicodeEscapes(code: string): string {
  return code.replace(/\\u\{([0-9a-fA-F]+)\}|\\u([0-9a-fA-F]{4})/g, (match, braced: string | undefined, plain: string | undefined) => {
    const point = Number.parseInt(braced ?? plain ?? "", 16)
    return point <= 0x10ffff ? String.fromCodePoint(point) : match
  })
}

/**
 * Network function of a JavaScript engine: first branch of the CodeMode rule test (tools.ts), without the global object,
 * kept there for safety (CodeMode does not know it) but common in a real engine, where it signals no network access.
 */
export const NETWORK_FUNCTION = /\bfetch\b/
