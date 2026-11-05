// Secret patterns. Base adapted from packages/http-recorder/src/redaction/secrets.ts
// in OpenCode (MIT, Copyright (c) 2025 opencode), extended and converted into replacement patterns.
// Provider token formats from the gitleaks default configuration (MIT, Copyright (c) 2019 Zachary Rice) and the
// trufflehog Docker Hub detector (AGPL-3.0, format only), translated to JavaScript syntax and bounded.
//
// Every pattern must have the `g` flag. If it contains a named group `secret`, only that
// group is replaced (the prefix, e.g. `Bearer ` or `API_KEY=`, is kept).
// No inline modifiers `(?i:…)`: use flags (Bun/JSC compatibility).

export interface SecretPattern {
  readonly type: string
  readonly regex: RegExp
  /** Optional filter on the captured value (reduces false positives); `groups`: the named groups of the match. */
  readonly accept?: (secret: string, groups?: Readonly<Record<string, string | undefined>>) => boolean
  /** Optional trimming of the captured value, before `accept`; only the trimmed part is replaced. */
  readonly trim?: (secret: string) => string
  /** Value then redacted everywhere, even alone, until restart (OpenCode formats without a prefix). */
  readonly learn?: boolean
  /** Regexp without `g`, or any test: the pattern is only tried on text that passes it (avoids a useless scan). */
  readonly hint?: { test(text: string): boolean }
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

/** Keywords of a secret name. */
const SECRET_WORDS = "api[_-]?key|access[_-]?key|secret|token|passw(?:or)?d|passphrase|pwd|credential|auth[_-]?key|private[_-]?key"

/**
 * Secret name from its keyword: the part of the name before it does not count (only the value is replaced).
 * At most 128 characters after the keyword: a `\b[A-Za-z0-9_.-]*` prefix and an unbounded run restarted a
 * scan at every word start of a long run without whitespace (`a-a-a-…`: 4.6 s for 50 KB under Bun; `token-token-…`:
 * 40 s for 12.5 KB).
 */
const SECRET_NAME = `(?:${SECRET_WORDS})[A-Za-z0-9_.-]{0,128}`

/** The tags that HTML writes without a closing tag, or that end a value in a page written by hand. */
const HTML_TAG = /<(?:br|hr|td|tr|th|li|p|div|span|b|i|a|ul|ol|table|code|pre)>/
/** Before any `<`: a comparison (`a.key===b<c`), an address with a variable part (`https://x.<Domain>/`), a sentence of a non-Latin text. */
const NOT_A_GLUED_VALUE = /^(?:=|[a-z][a-z0-9+.-]*:\/\/|[^<]*[^\x21-\x7e<])/i

/**
 * Unquoted value glued to markup (`<t>password=X</t>`), which it would otherwise run into, and fail for its `<` and `>`:
 * it stops at a closing tag, a self-closing tag, `<!` and the end of a CDATA section, whatever precedes them. Unless it reads
 * as something else (`NOT_A_GLUED_VALUE`), also at an HTML tag of the closed list and, only if what precedes is no identifier
 * or path of code, at a `<` followed by a letter: `token=parseToken2<Claims>(raw)` and `x.parse::<Ident>()` are generics,
 * `a<b` a comparison.
 */
export function beforeMarkup(value: string): string {
  const closing = value.search(/<\\?[/!]|<[A-Za-z][\w:.-]*\/>|\]\]>/)
  const head = closing < 0 ? value : value.slice(0, closing)
  if (NOT_A_GLUED_VALUE.test(head)) return head
  const tag = head.search(HTML_TAG)
  if (tag > 0) return head.slice(0, tag)
  const open = head.search(/<[A-Za-z]/)
  return open > 0 && !/^[&*]*(?:[\w$.]|::|->)+$/.test(head.slice(0, open)) ? head.slice(0, open) : head
}

/**
 * Unquoted assigned value: a comma does not end it (`DB_PASSWORD=abc,def`), except before a
 * neighboring named argument (`f(password=X,user=y)`); a literal escape (`\n` in JSON text) ends it; trailing
 * commas removed, then code punctuation (`trimBrackets`).
 */
export function trimAssignedValue(value: string): string {
  return trimBrackets(
    trimEndChars(
      beforeMarkup(value).replace(/\\[nrt][\s\S]*$/, "").replace(/,(?=[A-Za-z_][\w.-]*\s*[:=])[\s\S]*$/, ""),
      ",",
    ),
  )
}

/**
 * Names ending in `key` whose value is not a secret (database, cache and storage keys, public keys, the WebSocket handshake
 * nonce, identifiers of business objects and of the keyboard). Not `resource`: an Azure resource key is a secret.
 */
const NOT_SECRET_KEYS = ["public", "primary", "foreign", "sort", "partition", "cache", "idempotency", "storage", "i18n", "translation", "query", "row", "map", "hash", "object", "react", "websocket", "webSocket", "WebSocket", "issue", "job", "menu", "hot", "shortcut", "label", "message", "property"]

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

/** Neither a path nor, for the `key` names, a key identifier or the name of an environment variable. */
const isPassValue = (value: string) => looksLikeSecretValue(value) && !/^(?:[~/]|\.\.?\/)/.test(value)
const isKeyValue = (value: string) => isPassValue(value) && !/^0x[0-9A-Fa-f]{8,40}$/.test(value) && !/^[A-Z]+(?:_[A-Z]+)+$/.test(value)

/**
 * A name whose last component is `key`, the case kept (`AccountKey`, `master_key`; not `monkey`, nor `publicKey`). `projectKey`
 * and `organizationKey` only in that form, an identifier of Sonar and the like: `PROJECT_KEY` may be the key of a service.
 */
const KEY_NAME = `(?<!(?:${NOT_SECRET_KEYS.flatMap((name) => [name, name[0]!.toUpperCase() + name.slice(1), name.toUpperCase()]).join("|")})[_.-]?)(?:(?<=[_.-])(?:KEY|[Kk]ey)|(?<![Pp]roject|[Oo]rganization)(?<=[a-z])Key)`
const PASS_AT_END = /(?<![A-Za-z0-9])pass$/i
const KEY_AT_END = new RegExp(`${KEY_NAME}$`)

/**
 * The names of the assignments above and the value each accepts, for markup: `inName` for the name attribute of a tag,
 * `atEnd` for an element, whose name must end with the word (`<tokenizer>`, `<tokens>`, `<passwordEncoder>` are not secrets).
 */
const MARKUP_NAMES: ReadonlyArray<{ inName: RegExp; atEnd: RegExp; accept: (value: string) => boolean }> = [
  { inName: new RegExp(SECRET_WORDS, "i"), atEnd: new RegExp(`(?<!public[_.-]?key[_.-]?)(?:${SECRET_WORDS}|credentials)$`, "i"), accept: looksLikeSecretValue },
  { inName: PASS_AT_END, atEnd: PASS_AT_END, accept: isPassValue },
  { inName: KEY_AT_END, atEnd: KEY_AT_END, accept: isKeyValue },
]

/** Blanks, and the end of a CDATA section, around the value of an element or an attribute. */
function trimMarkupValue(value: string): string {
  const trimmed = value.trim()
  return trimmed.endsWith("]]>") ? trimmed.slice(0, -3).trim() : trimmed
}

/** One word, not a Windows (`%DB_PW%`) or a Maven and Ant (`@db.pw@`) reference, nor an escaped `<placeholder>`. */
const isMarkupValue = (value: string) => !/\s/.test(value) && !/^[%@][\w.-]+[%@]$/.test(value) && !/^&lt;.*&gt;$/.test(value)

/**
 * A file, not the key it leads to: `~`, absolute, Windows, `${…}/`, or under `.ssh`, for a private or ssh key only: an access
 * key may start with `/`. Without `+` nor `=`, which only base64 has here.
 */
const KEY_FILE = /^(?:~|\/|\.\.?[/\\]|[A-Za-z]:[/\\]|\$\{[^}]*\}[/\\]|(?:[\w.-]+[/\\])*\.ssh[/\\])[^+=]*$/
const isKeyFile = (name: string, value: string) => /(?:private|ssh)[_.-]?key$/i.test(name) && KEY_FILE.test(value)

/**
 * A name that holds a word of a secret name but describes something else, by how it ends: its address, its kind, its form
 * field. `id` alone as a component: `ApiKeyAndroid` is a key.
 */
const NOT_A_VALUE_NAME = /(?:url|uri|endpoint|issuer|audience|name|type|path|file|location|header|algo(?:rithm)?|hash|policy|length|lifetime|expir\w*|timeout|ttl|field|toggle|submit|button|btn|label|input|form|reset|confirm\w*|question|hint|encoder|tokenizer|store|service|ref|(?<![a-z])id|public[_.-]?key[_.-]?token)$/i

/** The value of a name written apart from it, in an attribute or a sibling element. */
function isSecretOfName(name: string, value: string): boolean {
  return !NOT_A_VALUE_NAME.test(name) && !isKeyFile(name, value) && MARKUP_NAMES.some((rule) => rule.inName.test(name) && rule.accept(value))
}

const MARKUP_NAME_ATTRIBUTE = /(?:^|\s)(?:key|name|id)\s*=\s*(\\?["'])([^"'<>]{1,256})\1/gi

/** The value of a `value` attribute or the content of a tag, judged by the `key`, `name` or `id` of the tag. */
function isAttributeSecret(value: string, groups?: Readonly<Record<string, string | undefined>>): boolean {
  if (!isMarkupValue(value)) return false
  for (const [, , name] of `${groups?.before ?? ""} ${groups?.after ?? ""}`.matchAll(MARKUP_NAME_ATTRIBUTE)) {
    if (isSecretOfName(name!, value)) return true
  }
  return false
}

const MARKUP_WORDS = new RegExp(`${SECRET_WORDS}|pass|key`, "i")
/** Markup patterns: on a text that has a `<` and a word of a secret name, nothing else. */
const MARKUP_HINT = { test: (text: string) => text.includes("<") && MARKUP_WORDS.test(text) }

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
  // Personal (glpat-), runner (glrt-), deploy (gldt-), pipeline trigger (glptt-) and runner registration (GR1348941) tokens.
  { type: "gitlab_token", regex: /\b(?:glpat-|glrt-|gldt-|GR1348941)[A-Za-z0-9_-]{20,}|\bglptt-[0-9a-f]{40}\b/g },
  // Slack app-level tokens and configuration tokens before `slack_token`, which would cut `xoxe.xoxb-` (gitleaks `slack-app-token`, `slack-config-*`).
  { type: "slack_app_token", regex: /\bxapp-\d-[A-Za-z0-9]+-\d+-[A-Za-z0-9]+/gi },
  // The `xoxe-<digit>-` prefix is Slack's alone: a minimum length is enough, no published length is guaranteed.
  { type: "slack_config_token", regex: /\bxoxe(?:\.xox[bp]-\d-[A-Za-z0-9]{163,166}(?![A-Za-z0-9])|-\d-[A-Za-z0-9]{40,})/gi },
  { type: "slack_token", regex: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g },
  { type: "slack_webhook", regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/g },
  { type: "stripe_key", regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g },
  { type: "npm_token", regex: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { type: "huggingface_token", regex: /\bhf_[A-Za-z0-9]{30,}\b/g },
  // Provider formats with a prefix of their own: an exact length, then no further token character (a longer run is
  // something else). Formats that gitleaks recognizes only near the provider's name (Mailgun, Cloudflare API keys,
  // Sentry access tokens, New Relic) are left to `generic_secret` and the decision model.
  // trufflehog detectors `replicate`, `groq`, `resend`: exact shapes, `re_` also starts ordinary identifiers (`re_compile`).
  { type: "replicate_token", regex: /\br8_[A-Za-z0-9_-]{37}(?![A-Za-z0-9_-])/g },
  { type: "groq_key", regex: /\bgsk_[A-Za-z0-9]{52}(?![A-Za-z0-9_-])/g },
  { type: "resend_key", regex: /\bre_[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24}(?![A-Za-z0-9_-])/g },
  // gitleaks `notion-api-token`; the older `secret_` prefix is not covered.
  { type: "notion_token", regex: /\bntn_[0-9]{11}[A-Za-z0-9]{35}(?![A-Za-z0-9_-])/g },
  // Nosey Parker np.google.2.
  { type: "google_oauth_secret", regex: /\bGOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_-])/g },
  // detect-secrets `DiscordBotTokenDetector`; same three parts as the example in Discord's API reference.
  { type: "discord_bot_token", regex: /\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}(?![A-Za-z0-9_-])/g },
  // gitleaks `telegram-bot-api-token` (the case of its fixed `A` kept; bare: a port is never followed by 35 characters).
  { type: "telegram_bot_token", regex: /\b[0-9]{5,16}:A[A-Za-z0-9_-]{34}(?![A-Za-z0-9_-])/g },
  // https://docs.mapbox.com/api/accounts/tokens : three parts, `sk`, a base64url JSON object (so `eyJ`), a signature (22
  // characters in its example). `sk.` alone also opens Java and Kotlin names. `pk.` tokens are public: left alone.
  { type: "mapbox_secret_token", regex: /\bsk\.eyJ[A-Za-z0-9_-]{40,}(?:\.[A-Za-z0-9_-]{20,})+/g },
  { type: "sendgrid_key", regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g },
  { type: "digitalocean_token", regex: /\bdo[opr]_v1_[a-f0-9]{64}(?![A-Za-z0-9])/g },
  { type: "pypi_token", regex: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,1000}/g },
  { type: "dockerhub_token", regex: /\b(?:dckr_pat_[A-Za-z0-9_-]{27}|dckr_oat_[A-Za-z0-9_-]{32})(?![A-Za-z0-9_-])/g },
  // Current Vault service (hvs.) and batch (hvb.) tokens; the old `s.` form is too close to any identifier.
  { type: "vault_token", regex: /\b(?:hvs\.[A-Za-z0-9_-]{90,120}|hvb\.[A-Za-z0-9_-]{138,300})(?![A-Za-z0-9_-])/g },
  { type: "shopify_token", regex: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g },
  { type: "atlassian_token", regex: /\bATATT3[A-Za-z0-9_=-]{186}(?![A-Za-z0-9_=-])/g },
  { type: "twilio_key", regex: /\bSK[0-9a-fA-F]{32}\b/g },
  { type: "linear_key", regex: /\blin_api_[A-Za-z0-9]{40}\b/g },
  { type: "grafana_token", regex: /\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b|\bglc_[A-Za-z0-9+/]{32,400}={0,3}/g },
  { type: "databricks_token", regex: /\bdapi[a-f0-9]{32}(?:-\d)?\b/g },
  { type: "doppler_token", regex: /\bdp\.pt\.[A-Za-z0-9]{43}\b/g },
  { type: "postman_key", regex: /\bPMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}\b/g },
  { type: "pulumi_token", regex: /\bpul-[a-f0-9]{40}\b/g },
  {
    type: "sentry_token",
    regex:
      /\bsntryu_[a-f0-9]{64}\b|\bsntrys_eyJpYXQiO[A-Za-z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[A-Za-z0-9+/]{10,200}={0,2}_[A-Za-z0-9+/]{43}/g,
  },
  { type: "age_secret_key", regex: /\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}/g },
  { type: "square_token", regex: /\bsq0atp-[A-Za-z0-9_-]{22,60}(?![A-Za-z0-9_-])/g },
  { type: "flyio_token", regex: /\bfo1_[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])|\b(?:fm1[ar]|fm2)_[A-Za-z0-9+/]{100,}={0,3}/g },
  { type: "planetscale_token", regex: /\bpscale_(?:tkn|oauth|pw)_[A-Za-z0-9_=.-]{32,64}/g },
  { type: "terraform_token", regex: /\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,70}/g, hint: /\.atlasv1\./ },
  { type: "cloudflare_origin_key", regex: /\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b/g },
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
    // Other schemes of an Authorization header (`Authorization: Token …`, GitHub's `token`, `ApiKey`, Okta's `SSWS`,
    // Discord's `Bot`): the name of the header is required, these words are common elsewhere.
    type: "authorization_token",
    regex: /\bAuthorization["']?\s*[:=]\s*["']?(?:Token|ApiKey|Api-Key|SSWS|Bot)\s+(?<secret>[A-Za-z0-9._~+/=-]{16,})/gi,
    accept: (value) => !isWordLike(value),
  },
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
    accept: isPassValue,
  },
  {
    // A name whose last component is `key` (`ENCRYPTION_KEY=…`, `master_key: …`, Azure's `AccountKey=…`): after a
    // separator, or `Key` after a lower-case letter, never `monkey` or `hotkey`; a bare `key` (a YAML or JSON key) is not
    // one. Names of keys that are not secrets (`publicKey`, `primaryKey`, `sortKey`, `cacheKey`…) are excluded, and so are
    // paths (`SSH_KEY=~/.ssh/id_ed25519`), hexadecimal key identifiers (`GPG_KEY=0x1A2B3C4D`) and the name of an environment
    // variable (`EnvVaultClientKey = "BAO_CLIENT_KEY"`). Anchored on the keyword, like the others.
    type: "generic_secret",
    regex: new RegExp(`${KEY_NAME}["']?\\s*[:=]\\s*["']?(?<secret>[^\\s"'\`;]{8,})`, "g"),
    trim: trimAssignedValue,
    accept: isKeyValue,
  },
  {
    // `curl -u user:password` (`--user`, `-uuser:password`): only after `curl` in the same command (not `docker run -u
    // 1000:1000`, `sort -u`), and only the part after the first colon; a variable (`$PASS`) is not a secret. 200-character
    // window, as below.
    type: "generic_secret",
    regex: /(?<=\bcurl\b[^\n|;&]{0,200})(?<![\w-])(?:-u(?:\s+|(?=[^\s-]))|--user(?:\s+|=))["']?[^\s:"'`$]*:(?<secret>[^\s"'`]{3,})/g,
    accept: (value) => !/^\$/.test(value) && !PLACEHOLDER_WORDS.test(value),
  },
  {
    // `sshpass -p password`, then `mysql -ppassword` (MySQL, MariaDB: the value is glued to `-p`; `-p` alone asks for it
    // and the next word is the database; `-P3306` is the port).
    type: "generic_secret",
    regex: /(?<=\bsshpass\b[^\n|;&]{0,200})(?<![\w-])-p\s*["']?(?<secret>[^\s"'`]{3,})/g,
    accept: (value) => !/^\$/.test(value) && !PLACEHOLDER_WORDS.test(value),
  },
  {
    type: "generic_secret",
    regex: /(?<=\b(?:mysql\w*|mariadb\w*)\b[^\n|;&]{0,200})(?<![\w-])-p["']?(?<secret>[^\s"'`-][^\s"'`]{2,})/g,
    accept: (value) => !/^\$/.test(value) && !PLACEHOLDER_WORDS.test(value),
  },
  {
    // Option separated from its value by whitespace (`docker login --password value`); exact name (`--token-file` is
    // not one). Except after a database client on the same line: for `psql` (`--password` without an argument) and
    // `mysql --password` without `=`, the next word is the database name. 200-character window: unbounded, a
    // line that repeats the option would make the search quadratic (28 s for 400 KB).
    type: "generic_secret",
    regex:
      /(?<![\w-])--(?:password|passwd|pass|passphrase|token|api-key|apikey|auth-token|access-token|client-secret)(?<!\b(?:mysql\w*|mariadb\w*|psql|pg_\w+|createdb|dropdb|createuser|dropuser|clickhouse-client)\b[^\n]{0,200})\s+["']?(?<secret>[^\s"'`;|&]{8,})/gi,
    trim: (value) => trimBrackets(beforeMarkup(value)),
    accept: looksLikeSecretValue,
  },
  {
    // `<password>…</password>`, with a namespace (`db:password`), attributes, blanks or a CDATA section around the value; the
    // closing tag in a lookahead, the capture at the end of the match (see `scanText`). Every repetition stops at a `<` or
    // is bounded: each `<` costs at most the stretch up to the next one, or a bound.
    type: "markup_secret",
    regex: /<(?<tag>[A-Za-z_][\w.:-]{0,128})(?:\s[^<>]{0,8192})?(?<!\/)>(?:\s{0,64}<!\[CDATA\[)?(?<secret>[^<]{1,2048})(?=<\/\k<tag>\s{0,64}>)/gi,
    hint: MARKUP_HINT,
    trim: trimMarkupValue,
    accept: (value, groups) => {
      const tag = groups?.tag ?? ""
      return isMarkupValue(value) && !isKeyFile(tag, value) && MARKUP_NAMES.some((rule) => rule.atEnd.test(tag) && rule.accept(value))
    },
  },
  {
    // `<add key="password" value="…"/>`, `<property value="…" name="db.password"/>`: the end of the tag is looked for first,
    // so that the last `value` of a tag is enough and no tag is walked again from each of its `value`; `after` has the same
    // bound, or each `value` of a tag longer than it would scan it in vain. The tag may be cut by the end of the text, and its
    // quotes escaped by a JSON text (`value=\"…\"`).
    type: "markup_secret",
    regex: /<[A-Za-z_][\w.:-]{0,128}(?=[^<>]{0,18432}(?:>|$))(?<before>\s[^<>]{0,8192})?\svalue\s*=\s*(?<q>\\?["'])(?<secret>(?:(?!\k<q>)[^<>]){1,2048})\k<q>(?=(?<after>[^<>]{0,18432})(?:>|$))/gi,
    hint: MARKUP_HINT,
    trim: trimMarkupValue,
    accept: isAttributeSecret,
  },
  {
    // `<entry key="password">…</entry>`, `<property name="hibernate.connection.password">…</property>`: the attribute of an
    // element with content. A closed list of tags: on any tag, the `id` of a documentation title would count (`<h4 id="token">`).
    type: "markup_secret",
    regex: /<(?<tag>entry|prop|property|param|parameter|setting|add|env|variable|constant)\s(?<before>[^<>]{0,8192})(?<!\/)>(?:\s{0,64}<!\[CDATA\[)?(?<secret>[^<]{1,2048})(?=<\/\k<tag>\s{0,64}>)/gi,
    hint: MARKUP_HINT,
    trim: trimMarkupValue,
    accept: isAttributeSecret,
  },
  {
    // The name in a sibling element: a plist's `<key>password</key><string>…</string>`, Hadoop's `<name>…</name><value>…</value>`.
    type: "markup_secret",
    regex: /<(?:key|name)>\s{0,64}(?<sib>[^<>]{1,256})<\/(?:key|name)>\s{0,64}<(?:string|value)>(?:\s{0,64}<!\[CDATA\[)?(?<secret>[^<]{1,2048})(?=<\/(?:string|value)>)/gi,
    hint: MARKUP_HINT,
    trim: trimMarkupValue,
    accept: (value, groups) => isMarkupValue(value) && isSecretOfName((groups?.sib ?? "").trim(), value),
  },
]

/**
 * What each built-in format catches (`guard redaction`, docs/rules.md: a test compares them). A type may group several
 * patterns (`private_key`, `generic_secret`): turning it off (`secretPatterns`, global configuration only) turns them
 * all off.
 */
export const FORMAT_SUMMARIES: ReadonlyMap<string, string> = new Map([
  ["private_key", "private keys in PEM blocks (whole or truncated) and PGP private key blocks"],
  ["anthropic_key", "Anthropic API keys (sk-ant-…)"],
  ["openai_key", "OpenAI API keys (sk-…, sk-proj-…, sk-svcacct-…, sk-admin-…)"],
  ["google_api_key", "Google API keys (AIza…)"],
  ["aws_access_key", "AWS access key identifiers (AKIA…, ASIA…)"],
  ["github_token", "GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)"],
  ["github_pat", "GitHub fine-grained personal access tokens (github_pat_…)"],
  ["gitlab_token", "GitLab personal, runner, deploy and trigger tokens (glpat-, glrt-, gldt-, glptt-, GR1348941…)"],
  ["slack_token", "Slack tokens (xoxa-, xoxb-, xoxp-, xoxo-, xoxs-, xoxr-)"],
  ["slack_webhook", "Slack incoming webhook addresses"],
  ["stripe_key", "Stripe secret and restricted keys (sk_live_, rk_test_…)"],
  ["npm_token", "npm access tokens (npm_…)"],
  ["huggingface_token", "Hugging Face tokens (hf_…)"],
  ["slack_app_token", "Slack app-level tokens (xapp-)"],
  ["slack_config_token", "Slack configuration tokens (xoxe-, at least 40 characters after the digit; xoxe.xoxb-, xoxe.xoxp-)"],
  ["replicate_token", "Replicate API tokens (r8_…)"],
  ["groq_key", "Groq API keys (gsk_…)"],
  ["resend_key", "Resend API keys (re_ followed by 8 and 24 Base58 characters)"],
  ["notion_token", "Notion API tokens (ntn_…)"],
  ["google_oauth_secret", "Google OAuth client secrets (GOCSPX-…)"],
  ["discord_bot_token", "Discord bot tokens (three parts of 24 to 26, 6 and 27 characters, the first starting with M, N or O)"],
  ["telegram_bot_token", "Telegram bot tokens (digits, colon, A and 34 characters)"],
  ["mapbox_secret_token", "Mapbox secret tokens (sk.eyJ…, three parts as Mapbox documents; public pk. tokens are not masked)"],
  ["sendgrid_key", "SendGrid API keys (SG.…)"],
  ["digitalocean_token", "DigitalOcean tokens (dop_v1_, doo_v1_, dor_v1_)"],
  ["pypi_token", "PyPI upload tokens (pypi-AgEI…)"],
  ["dockerhub_token", "Docker Hub access tokens (dckr_pat_, dckr_oat_)"],
  ["vault_token", "HashiCorp Vault service and batch tokens (hvs., hvb.)"],
  ["shopify_token", "Shopify access tokens and shared secrets (shpat_, shpca_, shppa_, shpss_)"],
  ["atlassian_token", "Atlassian API tokens (ATATT3…)"],
  ["twilio_key", "Twilio API keys (SK followed by 32 hexadecimal digits)"],
  ["linear_key", "Linear API keys (lin_api_…)"],
  ["grafana_token", "Grafana service account and cloud tokens (glsa_, glc_)"],
  ["databricks_token", "Databricks tokens (dapi…)"],
  ["doppler_token", "Doppler personal tokens (dp.pt.…)"],
  ["postman_key", "Postman API keys (PMAK-…)"],
  ["pulumi_token", "Pulumi access tokens (pul-…)"],
  ["sentry_token", "Sentry user and organization tokens (sntryu_, sntrys_)"],
  ["age_secret_key", "age secret keys (AGE-SECRET-KEY-1…)"],
  ["square_token", "Square access tokens (sq0atp-…)"],
  ["flyio_token", "Fly.io tokens (fo1_, fm1a_, fm1r_, fm2_)"],
  ["planetscale_token", "PlanetScale tokens and passwords (pscale_tkn_, pscale_oauth_, pscale_pw_)"],
  ["terraform_token", "HashiCorp Terraform Cloud tokens (….atlasv1.…)"],
  ["cloudflare_origin_key", "Cloudflare Origin CA keys (v1.0-…)"],
  ["jwt", "JSON Web Tokens (three base64url segments starting with eyJ)"],
  ["bearer_token", "the token after Bearer, unless it reads as an ordinary word"],
  ["authorization_token", "the credential after Authorization: Token, ApiKey, Api-Key, SSWS or Bot, unless it reads as an ordinary word"],
  ["basic_auth", "the value after Basic, when it decodes to user:password"],
  ["url_credentials", "the password of an address that carries a user and a password before the host, unless it is a placeholder or code"],
  ["passphrase", "a quoted phrase assigned to an upper-case PASSWORD, PASSWD, PASSPHRASE, SECRET or PASS variable"],
  [
    "generic_secret",
    "a value assigned to a name such as api_key, secret, token, password, pwd, credential or pass, or to a name that ends in key (ENCRYPTION_KEY, AccountKey) (name = value, name: value, in a text or glued to a tag, <t>name=value</t>), or given to a command-line option such as --password or --token, or the password given to curl -u, sshpass -p or mysql -p; only a value that looks like a secret (not code, a path, a variable or a placeholder)",
  ],
  [
    "markup_secret",
    "the content of an XML or HTML element whose name ends with such a word (<password>value</password>, <db:password>), the value attribute of a tag, or the content of an element such as entry or property, whose key, name or id holds one (<add key=\"password\" value=\"…\"/>, <entry key=\"password\">value</entry>), or the element that follows a key or a name holding one (<key>password</key><string>value</string>); only one word that looks like a secret, by the same checks",
  ],
])

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
