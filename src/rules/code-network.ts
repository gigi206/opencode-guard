// Network access from inline code: decoding of Unicode escapes, shared by the CodeMode rule (tools.ts) and by
// the network check of inline code (shell.ts); network function identifier and HTTP calls by language, used by the latter.

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

/**
 * Request calls of the own HTTP functions of Ruby, Perl, PHP and of a JavaScript engine's `http` and `https` modules
 * (closed lists, docs/rules.md), tested like `PYTHON_HTTP_CALL` on the code with its comments blanked and each literal
 * replaced by `""`, except an `http(s)://` URL, by `"http:"`, and the name of the `http` or `https` module, by `"https"`.
 * A call that also reads a local file counts only with a URL literal as first argument.
 */
export const OWN_HTTP_CALLS = {
  ruby: /\b(?:Net::HTTP\s*(?:\.|::)\s*(?:get\w*|post\w*|put|patch|delete|head|start|new|request)|(?:HTTParty|RestClient|Faraday)\s*(?:\.|::)\s*(?:get|post|put|patch|delete|head|options|request|new))\b|(?:\bURI\s*\.\s*open|(?<![.\w:])open)\s*(?:\(\s*)?"http:"|\bURI\s*(?:\.\s*parse\s*)?\(\s*"http:"\s*\)\s*\.\s*(?:open|read)\b/,
  perl: /\b(?:LWP::UserAgent|HTTP::Tiny|Mojo::UserAgent)\s*->\s*new\b|(?<![$@%&\w:>])(?:LWP::Simple::)?(?:get|getstore|getprint|mirror|head)\s*(?:\(\s*)?"http:"/,
  php: /\b(?:curl_init|curl_exec|curl_multi_exec|get_headers)\s*\(|(?<![$\w>:])(?:file_get_contents|fopen|file|readfile|copy|get_meta_tags)\s*\(\s*"http:"/,
  javascript: /(?:(?<![.\w$])https?|\brequire\s*\(\s*"https"\s*\))\s*\.\s*(?:request|get)\s*\(/,
}

/**
 * Quoting that the literals of `OWN_HTTP_CALLS` leave out (Ruby's percent literals other than word lists, heredocs, `=begin` and
 * `__END__`; Perl's quote-like operators other than `qw`, heredocs, POD and `__END__`; PHP's heredocs and `?>`; a slash that may
 * open a regular expression in Ruby, Perl and JavaScript, after neither a name, a number, `)` nor `]`), searched in the same
 * blanked code: with one, no call is counted.
 */
export const UNPARSED_QUOTING = {
  ruby: /%[qQxrs]?[^\w\s=]|(?<![\w)\]]\s*)\/|<<[~-]?(?:""|[A-Za-z_])|^=begin\b|^__END__\b/m,
  perl: /(?<![\w$@%&:>])(?:q[qrx]?|m|s|tr|y)\s*[^\w\s,;=)>}\]]|(?<![\w)\]]\s*)\/|<<\s*(?:""|~?[A-Za-z_])|^=[a-zA-Z]|^__(?:END|DATA)__\b/m,
  php: /<<<|\?>/,
  javascript: /(?<![\w)\]]\s*)\//,
}
