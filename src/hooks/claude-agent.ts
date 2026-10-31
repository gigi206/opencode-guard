import type { GuardContext, Logger } from "../types.ts"

// OpenCode 2.2.x's "Claude Agent" provider runs the local `claude` program instead of HTTP requests or WebSocket frames:
// neither `http.request` nor `experimental.ws.send` sees what it sends, so the wire safety net does not apply to it
// (outputs and prompts are still redacted at the source). When it is connected, a warning says so: at startup, then at
// the first prompt that finds it connected (the user may connect it later). Never throws, never blocks a prompt.

/** Provider identifier (`Provider.ID.claudeAgent`, OpenCode 2.2.5). */
export const CLAUDE_AGENT = "claude-agent"

/** Prompts between two checks: the check is an API call, a prompt costs it at most once a minute. */
const RECHECK_MS = 60_000

export const CLAUDE_AGENT_WARNING =
  'the "Claude Agent" provider is connected: its requests go through the local claude program, not through HTTP requests or WebSocket frames, so the wire safety net does not redact them (outputs and prompts are still redacted at the source)'

export async function registerClaudeAgentWarning(ctx: GuardContext, log: Logger, now: () => number = Date.now): Promise<void> {
  const active = ctx.integration?.connection?.active
  if (typeof active !== "function") return
  let warned = false
  let checked = -Infinity
  const check = async () => {
    if (warned || now() - checked < RECHECK_MS) return
    checked = now()
    try {
      if (await active.call(ctx.integration!.connection, CLAUDE_AGENT)) {
        warned = true
        log.warn(CLAUDE_AGENT_WARNING)
      }
    } catch {}
  }
  await check()
  await ctx.session.hook("prompt", () => {
    void check()
  })
}
