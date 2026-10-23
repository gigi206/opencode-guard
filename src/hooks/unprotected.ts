import type { GuardContext, Logger } from "../types.ts"

// Unprotected agent (`unprotectedAgent` option): no rules, no decision model, no redaction, except the
// placeholder rule (it protects the real secret from being overwritten, not from access). Only on the USER's choice: the session
// agent is recorded when the prompt is sent (the TUI calls `switchAgent` before sending). A switch made mid-turn
// by the model (server API) leaves the session protected until the next prompt.

export interface UnprotectedDeps {
  readonly agent?: string
  readonly askAs: "ask" | "deny"
  readonly log: Logger
}

export interface UnprotectedGate {
  /** True only for the unprotected agent, if it was the session agent at the last prompt. */
  isUnprotected(sessionID: string | undefined, agent: string | undefined): Promise<boolean>
  /** Session agent at the time of this prompt (recorded); shared between `prompt` hooks. */
  notePrompt(sessionID: string, messageID: string | undefined): Promise<boolean>
}

/** Everything is protected (option absent, unattended mode, or agent unavailable at startup). */
export const PROTECTED: UnprotectedGate = {
  isUnprotected: async () => false,
  notePrompt: async () => false,
}

/** Maximum recorded sessions: beyond that, the oldest are forgotten (and thus protected). */
const MAX_SESSIONS = 1000

const DESCRIPTION = "Build without the guard plugin: no confirmation, no decision model, no secret redaction"

export async function registerUnprotected(ctx: GuardContext, deps: UnprotectedDeps): Promise<UnprotectedGate> {
  const id = deps.agent
  if (!id) return PROTECTED
  if (deps.askAs === "deny") {
    deps.log.warn(`unattended mode (askAs: deny): unprotected agent "${id}" ignored, every agent is protected`)
    return PROTECTED
  }

  // Agent created if it does not exist yet (our transforms run before configuration): `build` permissions.
  await ctx.agent.transform((editor) => {
    if (editor.get(id)) return
    const build = editor.get("build")
    editor.update(id, (agent) => {
      agent.mode = "primary"
      agent.description = DESCRIPTION
      if (build) agent.permissions = structuredClone(build.permissions)
    })
  })

  /** Session → whether the unprotected agent was the session agent (primary mode checked) at the user's last prompt. */
  const promptAgents = new Map<string, boolean>()
  const pending = new Map<string, Promise<boolean>>()

  async function lookup(sessionID: string): Promise<boolean> {
    try {
      promptAgents.delete(sessionID)
      const agent = (await ctx.session.get({ sessionID }))?.agent
      // Mode checked once per prompt (not on every tool call or WebSocket frame).
      const unprotected = agent === id && (await isPrimary())
      if (promptAgents.size >= MAX_SESSIONS) promptAgents.delete(promptAgents.keys().next().value!)
      promptAgents.set(sessionID, unprotected)
      return unprotected
    } catch (error) {
      promptAgents.delete(sessionID)
      deps.log.error("unprotected agent: session lookup failed, session kept protected", error)
      return false
    }
  }

  /** Actual agent mode: a project redefining it as `all`/`subagent` (launchable by the model) makes it protected. */
  async function isPrimary(): Promise<boolean> {
    try {
      const result = await ctx.agent.get({ agentID: id!, location: { directory: ctx.location.directory } })
      return result?.data?.mode === "primary"
    } catch {
      return false
    }
  }

  const gate: UnprotectedGate = {
    async isUnprotected(sessionID, agent) {
      return Boolean(sessionID) && agent === id && promptAgents.get(sessionID!) === true
    },
    notePrompt(sessionID, messageID) {
      // Without a message identifier (OpenCode v2.0.29 always provides it): read specific to this prompt, never shared
      // with another prompt in the session.
      if (!messageID) return lookup(sessionID)
      // Multiple `prompt` hooks (recording, redaction): a single session read per message.
      const key = `${sessionID}\u0000${messageID}`
      let result = pending.get(key)
      if (!result) {
        result = lookup(sessionID)
        pending.set(key, result)
        void result.finally(() => setTimeout(() => pending.delete(key), 5_000).unref?.())
      }
      return result
    },
  }

  // Registered independently of `redactPrompt`: without it, the agent would never be unprotected (and without reporting it).
  await ctx.session.hook("prompt", async (event) => {
    try {
      if (await gate.notePrompt(event.sessionID, event.messageID)) deps.log.debug(`prompt: unprotected agent "${id}" selected by the user`)
    } catch (error) {
      deps.log.error("internal error in session.prompt (unprotected agent)", error)
    }
  })
  deps.log.info(`unprotected agent: "${id}" — no checks and no secret redaction once selected by the user (ignored in unattended mode)`)
  return gate
}
