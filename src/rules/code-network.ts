// Network access from inline code: decoding of Unicode escapes, shared by the CodeMode rule (tools.ts) and by
// the network check of inline code (shell.ts); network function identifier and Python HTTP calls, used by the latter.

/**
 * Unicode escapes (`\u0065`, `\u{65}`) decoded as the CodeMode parser (acorn) does for identifiers
 * and strings: `f\u0065tch(…)` calls `fetch`. Braced form according to the language grammar: any
 * number of digits (leading zeros included), value at most 0x10FFFF. Only broadens detection.
 */
export function decodeUnicodeEscapes(code: string): string {
  return code.replace(/\\u\{([0-9a-fA-F]+)\}|\\u([0-9a-fA-F]{4})/g, (match, braced: string | undefined, plain: string | undefined) => {
    // The pattern guarantees one of the two groups.
    const point = Number.parseInt(braced ?? plain!, 16)
    return point <= 0x10ffff ? String.fromCodePoint(point) : match
  })
}

/**
 * Network function of a JavaScript engine: first branch of the CodeMode rule test (tools.ts), without the global object,
 * kept there for safety (CodeMode does not know it) but common in a real engine, where it signals no network access.
 */
export const NETWORK_FUNCTION = /\bfetch\b/

/**
 * Request call of a Python HTTP library (closed list, docs/rules.md): `urllib.request`'s `urlopen` and `urlretrieve`,
 * `http.client`'s connections, and the module-level calls of `requests`, `httpx`, `urllib3` and `aiohttp`. Tested on the
 * code with its literals and comments blanked: an import alone, or a name in a string or a comment, does not count.
 */
export const PYTHON_HTTP_CALL =
  /\b(?:(?:urlopen|urlretrieve|HTTPS?Connection)|(?:requests|httpx)\s*\.\s*(?:get|post|put|patch|delete|head|options|request|stream|Session|Client|AsyncClient)|urllib3\s*\.\s*(?:request|PoolManager|ProxyManager)|aiohttp\s*\.\s*(?:request|ClientSession))\s*\(/
