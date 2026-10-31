// Secret patterns. Base adapted from packages/http-recorder/src/redaction/secrets.ts
// in OpenCode (MIT, Copyright (c) 2025 opencode), extended and converted into replacement patterns.
//
// Every pattern must have the `g` flag. If it contains a named group `secret`, only that
// group is replaced (the prefix, e.g. `Bearer ` or `API_KEY=`, is kept).
// No inline modifiers `(?i:…)`: use flags (Bun/JSC compatibility).

export interface SecretPattern {
  readonly type: string
  readonly regex: RegExp
  /** Optional filter on the captured value (reduces false positives). */
  readonly accept?: (secret: string) => boolean
  /** Optional trimming of the captured value, before `accept`; only the trimmed part is replaced. */
  readonly trim?: (secret: string) => string
  /** Value then redacted everywhere, even alone, until restart (OpenCode formats without a prefix). */
  readonly learn?: boolean
  /** Hint without `g`: the pattern is only tried on text that contains it (avoids a useless scan). */
  readonly hint?: RegExp
}

/**
 * Removes trailing characters from `chars` at the end of the text, with a loop: a repeated class anchored at the end (`/[,]+$/`)
 * retries at every position of a long run that is not at the end of the text (quadratic time on hostile content).
 */
export function trimEndChars(text: string, chars: string): string {
  let end = text.length
  while (end > 0 && chars.includes(text[end - 1]!)) end--
  return end === text.length ? text : text.slice(0, end)
}

/**
 * Code punctuation around a value: `{password: X}`, `f(token=X)`, `token=(X)`. Final closers
 * are removed, then an initial opener if no other bracket remains; `getToken()` stays `getToken(`.
 */
export function trimBrackets(value: string): string {
  // Substitution reference (`{env:VAR}`, `{file:path}` in OpenCode): left whole, therefore never a secret.
  if (/^\{[A-Za-z]+:[^{}]*\}$/.test(value)) return value
  const trimmed = trimEndChars(value, ")]}")
  return /^[([{]/.test(trimmed) && !/[()[\]{}]/.test(trimmed.slice(1)) ? trimmed.slice(1) : trimmed
}

const PLACEHOLDER_WORDS =
  /example|placeholder|changeme|change_me|your[_-]|xxxx|dummy|redacted|sample|fixme|todo|<|>|\*\*\*/i

/** Shannon entropy in bits per character. */
export function entropy(value: string): number {
  const counts = new Map<string, number>()
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1)
  let bits = 0
  for (const count of counts.values()) {
    const p = count / value.length
    bits -= p * Math.log2(p)
  }
  return bits
}

/** Heuristic for generic assignments: rules out code and placeholders. */
export function looksLikeSecretValue(value: string): boolean {
  if (value.length < 8) return false
  if (PLACEHOLDER_WORDS.test(value)) return false
  // Expressions or member accesses: process.env.X, config.apiKey, getToken()
  if (/^[A-Za-z_$][\w$]*(?:[?!]?\.[A-Za-z_$][\w$]*)+[?!]?$/.test(value)) return false
  // Code or references: ${…}, $(…), [index]; a variable reference alone ($DB_PASS) is not a secret.
  if (/[(){}[\]]/.test(value) || /^\$[A-Za-z_][A-Za-z0-9_]*$/.test(value)) return false
  if (/^(true|false|null|undefined|none|string|number|boolean)$/i.test(value)) return false
  const hasDigit = /\d/.test(value)
  const hasLetter = /[A-Za-z]/.test(value)
  return (hasDigit && hasLetter) || entropy(value) >= 3.5
}

/**
 * Base64 value of a Basic header: printable `user:password` once decoded, password possibly
 * empty (key passed as user: Stripe's `curl -u sk_live_…:`). Decoded "internationalization" is not one.
 */
export function isBasicCredentials(value: string): boolean {
  const decoded = Buffer.from(value, "base64").toString("utf8")
  return /^[^\x00-\x1F\x7F:\uFFFD]+:[^\x00-\x1F\x7F\uFFFD]*$/.test(decoded)
}

/**
 * Value made of words (`internationalization`, `authenticationScheme`): letters only, each uppercase letter followed by at
 * least two lowercase letters, starting with two lowercase letters or an uppercase letter and two lowercase letters. Linear
 * tests: a pattern with nested quantifiers (`(?:[A-Z]?[a-z]{2,})+`) runs away on a long run of letters.
 */
export function isWordLike(value: string): boolean {
  return /^[A-Za-z]+$/.test(value) && !/[A-Z](?![a-z]{2})/.test(value) && /^(?:[a-z]{2}|[A-Z][a-z]{2})/.test(value)
}

/**
 * Secret name from its keyword: the part of the name before it does not count (only the value is replaced).
 * At most 128 characters after the keyword: a `\b[A-Za-z0-9_.-]*` prefix and an unbounded run restarted a
 * scan at every word start of a long run without whitespace (`a-a-a-…`: 4.6 s for 50 KB under Bun; `token-token-…`:
 * 40 s for 12.5 KB).
 */
const SECRET_NAME =
  "(?:api[_-]?key|access[_-]?key|secret|token|passw(?:or)?d|passphrase|pwd|credential|auth[_-]?key|private[_-]?key)[A-Za-z0-9_.-]{0,128}"

/**
 * Unquoted assigned value: a comma does not end it (`DB_PASSWORD=abc,def`), except before a
 * neighboring named argument (`f(password=X,user=y)`); a literal escape (`\n` in JSON text) ends it; trailing
 * commas removed, then code punctuation (`trimBrackets`).
 */
export function trimAssignedValue(value: string): string {
  return trimBrackets(
    trimEndChars(
      value.replace(/\\[nrt][\s\S]*$/, "").replace(/,(?=[A-Za-z_][\w.-]*\s*[:=])[\s\S]*$/, ""),
      ",",
    ),
  )
}

/** Example phrasings from `.env.example` files (`"your secret here"`, `"change me"`, `"enter a password"`). */
const EXAMPLE_PHRASE = /\b(?:your|here|change me|enter|insert|replace|put)\b/i

/** Quoted passphrase: at least one whitespace, long enough, neither a template nor an example. */
function looksLikePassphrase(value: string): boolean {
  return (
    /\S\s+\S/.test(value) &&
    value.trim().length >= 8 &&
    !PLACEHOLDER_WORDS.test(value) &&
    !EXAMPLE_PHRASE.test(value) &&
    !/%[sd]|[{}$`]/.test(value)
  )
}

export const BUILTIN_PATTERNS: readonly SecretPattern[] = [
  {
    type: "private_key",
    // Base64 body (and Proc-Type/DEK-Info headers): a code template `${…}` is not a key. The body stops at the
    // next `-----BEGIN ` and at the `-----END` of the same type (unrolled loop, linear): before, each header scanned
    // all the text that followed (more than 20 s for 1.6 MB of endless headers). A truncated block followed by a complete key
    // is handled by the next pattern.
    regex: /-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----[A-Za-z0-9+/=\s:,.\\]*(?:-(?!----(?:BEGIN |END \1PRIVATE KEY-----))[A-Za-z0-9+/=\s:,.\\]*)*-----END \1PRIVATE KEY-----/g,
  },
  {
    // Header alone (truncated block) followed by base64 lines.
    type: "private_key",
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:(?:\s|\\n)*[A-Za-z0-9+/=]{16,})+/g,
  },
  {
    // PGP private key exported as text (`gpg --export-secret-keys --armor`), complete or truncated: key content required
    // within the 400 characters following the header (text that quotes the marker is not redacted); body bounded to
    // 64 KiB, which never crosses another `-----BEGIN`/`-----END` marker (unbounded: nothing found under Bun beyond
    // ~2 MB, RangeError under Node around 12 MB). Public blocks and signatures are not affected.
    type: "private_key",
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----(?=[\s\S]{0,400}?[A-Za-z0-9+/]{40})(?:(?!-----(?:BEGIN|END) )[\s\S]){0,65536}(?:-----END PGP PRIVATE KEY BLOCK-----)?/g,
  },
  { type: "anthropic_key", regex: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { type: "openai_key", regex: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g },
  { type: "google_api_key", regex: /\bAIza[0-9A-Za-z_-]{30,}/g },
  { type: "aws_access_key", regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { type: "github_token", regex: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g },
  { type: "github_pat", regex: /\bgithub_pat_[A-Za-z0-9_]{50,}/g },
  { type: "gitlab_token", regex: /\bglpat-[A-Za-z0-9_-]{20,}/g },
  { type: "slack_token", regex: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g },
  { type: "slack_webhook", regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/g },
  { type: "stripe_key", regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g },
  { type: "npm_token", regex: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { type: "huggingface_token", regex: /\bhf_[A-Za-z0-9]{30,}\b/g },
  {
    // First segment without `-eyJ` (unrolled loop, linear; a per-character alternative is slow under Bun): otherwise
    // every `eyJ` of a long `eyJ-eyJ-…` run rescanned the run. A header that contains `-eyJ` is redacted from
    // that point (the header contains no secret).
    type: "jwt",
    regex: /\beyJ(?=(?:[A-Za-z0-9_]|-(?!eyJ)){10})[A-Za-z0-9_]*(?:-(?!eyJ)[A-Za-z0-9_]*)*\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  },
  // A word after `Bearer` ("Bearer internationalization") is not a token.
  { type: "bearer_token", regex: /\b(?:Bearer)\s+(?<secret>[A-Za-z0-9._~+/=-]{16,})/gi, accept: (value) => !isWordLike(value) },
  {
    // `Basic …` (any case): only if decoding yields a real `user:password`.
    type: "basic_auth",
    regex: /\bbasic\s+(?<secret>[A-Za-z0-9+/]{16,}={0,2})/gi,
    accept: isBasicCredentials,
  },
  {
    // Password up to the LAST `@` of the authority (`p@ss@host`, `S3cr@tP4ss@host`), ended by `/`, `?`, `#` or a
    // whitespace; user possibly empty (`redis://:<password>@host`). Anchored on `://`, scheme checked backwards
    // (at most 64 characters): a scheme sought from every word start rescanned any run without whitespace.
    type: "url_credentials",
    regex: /:\/\/(?<=\b[a-z][a-z0-9+.-]{0,63}:\/\/)[^\s:/@"'`]*:(?<secret>[^\s/"'`]{3,})(?=@[^\s@/?#"'`]*(?:[/?#\s"'`]|$))/gi,
    accept: (secret) => !PLACEHOLDER_WORDS.test(secret) && !/[(){}[\]$]/.test(secret),
  },
  {
    // Before `generic_secret` (which would only take the first word): quoted phrase after an UPPERCASE
    // environment variable name (`DB_PASSWORD="…"`, `export GPG_PASSPHRASE='…'`). Lowercase keys (`password:
    // "Password"` in a translation file) are not affected. Anchored on the keyword (end of the name, preceded by a
    // separator or the start): a prefix as a repeated class would cost 20 ms per 2.7 MB. Linear capture, whitespace required.
    type: "passphrase",
    regex: /(?<![A-Za-z0-9])(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|PASS)=(?<q>["'])(?<secret>[^"'\n]+)\k<q>/g,
    accept: looksLikePassphrase,
  },
  {
    type: "generic_secret",
    regex: new RegExp(`${SECRET_NAME}["']?\\s*[:=]\\s*["']?(?<secret>[^\\s"'\`;]{8,})`, "gi"),
    trim: trimAssignedValue,
    accept: looksLikeSecretValue,
  },
  {
    // `pass` as a whole name or last component (`DB_PASS=…`, `pass: …`, `smtp.pass = …`), never in `bypass` or
    // `compass`. `:` only followed by whitespace: `pass:openai/key` designates an entry of the `pass` manager, not a
    // value. A path is not a password (`plugins/pass: /home/…: no such file`). Anchored on `pass`, preceded
    // by a separator or the start (same cost as the other patterns).
    type: "generic_secret",
    regex: /(?<![A-Za-z0-9])pass["']?(?:\s*=|\s*:\s)\s*["']?(?<secret>[^\s"'`;]{8,})/gi,
    trim: trimAssignedValue,
    accept: (value) => looksLikeSecretValue(value) && !/^(?:[~/]|\.\.?\/)/.test(value),
  },
  {
    // Option separated from its value by whitespace (`docker login --password value`); exact name (`--token-file` is
    // not one). Except after a database client on the same line: for `psql` (`--password` without an argument) and
    // `mysql --password` without `=`, the next word is the database name. 200-character window: unbounded, a
    // line that repeats the option would make the search quadratic (28 s for 400 KB).
    type: "generic_secret",
    regex:
      /(?<![\w-])--(?:password|passwd|pass|passphrase|token|api-key|apikey|auth-token|access-token|client-secret)(?<!\b(?:mysql\w*|mariadb\w*|psql|pg_\w+|createdb|dropdb|createuser|dropuser|clickhouse-client)\b[^\n]{0,200})\s+["']?(?<secret>[^\s"'`;|&]{8,})/gi,
    trim: trimBrackets,
    accept: looksLikeSecretValue,
  },
]

/** Minimum length of a configuration secret replaced as is (`knownSecrets` of `createRedactor`). */
export const MIN_KNOWN_SECRET = 8

/** Words searched in the name (substring, case ignored; PASS only as a whole component). */
const ENV_SECRET_NAMES = /(?:API|AUTH|BEARER|CREDENTIAL|KEY|PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|(?:^|_)PASS(?:_|$))/i
/**
 * Fixed-name passwords that the words above do not recognize (exact names, case preserved): MySQL and
 * MariaDB client, sshpass. No PWD word: only the path filter would then protect `PWD` (current directory).
 */
const EXACT_SECRET_NAMES = new Set(["MYSQL_PWD", "SSHPASS"])
/** Names whose value can be a phrase (whitespace accepted). */
const PHRASE_ENV_NAMES = /PASSWORD|PASSWD|PASSPHRASE|SECRET|(?:^|_)PASS(?:_|$)/i
const SAFE_ENV_VALUES = new Set(["fixture", "test", "test-key"])

/**
 * Environment variable values that look like secrets
 * (http-recorder heuristic, filtered to rule out paths and URLs without credentials).
 */
export function envSecretValues(env: Record<string, string | undefined>): Array<{ name: string; value: string }> {
  return Object.entries(env).flatMap(([name, value]) => {
    const exact = EXACT_SECRET_NAMES.has(name)
    if (!value || !(exact || ENV_SECRET_NAMES.test(name)) || value.length < 12) return []
    if (SAFE_ENV_VALUES.has(value.toLowerCase())) return []
    if (/^[~./]/.test(value) || /^\d+$/.test(value)) return []
    if (/\s/.test(value) && (!(exact || PHRASE_ENV_NAMES.test(name)) || value.trim() !== value)) return []
    if (/^[a-z][a-z0-9+.-]*:\/\/[^@]*$/i.test(value)) return []
    return [{ name, value }]
  })
}
