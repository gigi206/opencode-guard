// Note added to a redacted prompt. Secrets typed in plain words (`mon mot de passe est …`) are found by the decision
// model (`promptCheck` option, `src/hooks/prompt-check.ts`), never by keywords of a given language.

/**
 * Note added to the redacted prompt: the model sees the placeholder without knowing where it comes from. Without `[[…]]`: copying it
 * does not trigger the placeholder rule.
 */
export const PROMPT_NOTE =
  "[guard] A secret typed in this message was masked (GUARD_REDACTED placeholder) before being sent. Do not try to recover or guess it; if it is needed, ask the user to provide it another way, for example through an environment variable."
