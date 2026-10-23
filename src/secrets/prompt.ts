import { looksLikeSecretValue, trimEndChars } from "./patterns.ts"
import { placeholder, PLACEHOLDER_RE, type RedactResult } from "./redact.ts"

// Secrets typed in natural language in the prompt (English and French keyword variants are recognized): applied ONLY to the
// user prompt, after the general patterns (too many false positives in documentation or code in
// tool outputs). Never sent to the decision model: it would receive the secret in clear text.

const SPACE = "[\\s\\u00A0\\u202F]"
const KEYWORDS = [
  `mots?${SPACE}+de${SPACE}+passe`,
  "mdp",
  "password",
  "passwd",
  "passphrase",
  "pwd",
  "secret",
  "token",
  "jeton",
  `cl[ée]s?${SPACE}+(?:d['’]${SPACE}*)?api`,
  "api[\\s_-]?key",
  `cl[ée]${SPACE}+secr[èe]te`,
].join("|")

/** Keywords that unambiguously designate a password: the only ones allowed without a separator (`mdp Xy7!…`). */
const PASSWORD_KEYWORD = /^(?:mots?[\s  ]+de[\s  ]+passe|mdp|password|passwd|passphrase)$/i

const PROMPT_SECRET = new RegExp(
  `(?<![\\p{L}\\d_])(?<keyword>${KEYWORDS})(?![\\p{L}\\d_])` +
    `(?<separator>${SPACE}*[:=]\\s*|[^\\S\\n]+(?:est|is|c['’]est|vaut)[^\\S\\n]+|[^\\S\\n]*(?:→|->)[^\\S\\n]*|[^\\S\\n]+)` +
    // `,` and `;` allowed in the value (`Abcdef12;Zz9!`), removed only at the end (sentence punctuation).
    `(?:["'\`«“][^\\S\\n]*)?(?<value>[^\\s"'\`»”]{8,})`,
  "giu",
)

/** Path or URL (`/etc/x`, `~/.ssh`, `config/secrets2.yaml`, `feature/login-2fa`, `https://…`): not a secret. */
function isPathLike(value: string): boolean {
  return /^[/~.]/.test(value) || value.includes("://") || /^[\w.-]+(?:\/[\w.-]+)+$/.test(value)
}

/** "Strong" value: a symbol (other than `_ . -`), or uppercase + lowercase + digit (`hardcoded2`, `base64url` excluded). */
function isStrong(value: string): boolean {
  return /[^A-Za-z0-9_.-]/.test(value) || (/[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value))
}

export function redactPromptSecrets(text: string): RedactResult<string> {
  let count = 0
  const value = text.replace(PROMPT_SECRET, (...args: unknown[]) => {
    const match = args[0] as string
    const groups = args[args.length - 1] as { keyword: string; separator: string; value: string }
    const secret = trimEndChars(groups.value, ".,;:)")
    if (secret.length < 8 || PLACEHOLDER_RE.test(secret) || isPathLike(secret)) return match
    const assignment = /[:=]/.test(groups.separator)
    const bare = !assignment && !/\S/.test(groups.separator)
    const keyword = groups.keyword.toLowerCase()
    // `pwd` (also the command) only with `:` or `=`; without a separator, only a password keyword.
    if (keyword === "pwd" && !assignment) return match
    if (bare && !PASSWORD_KEYWORD.test(keyword)) return match
    if (!looksLikeSecretValue(secret) || (!assignment && !isStrong(secret))) return match
    count++
    const at = match.lastIndexOf(secret)
    return match.slice(0, at) + placeholder("prompt_secret") + match.slice(at + secret.length)
  })
  return { value: count ? value : text, count }
}

/**
 * Note added to the redacted prompt: the model sees the placeholder without knowing where it comes from. Without `[[…]]`: copying it
 * does not trigger the placeholder rule.
 */
export const PROMPT_NOTE =
  "[guard] A secret typed in this message was masked (GUARD_REDACTED placeholder) before being sent. Do not try to recover or guess it; if it is needed, ask the user to provide it another way, for example through an environment variable."
