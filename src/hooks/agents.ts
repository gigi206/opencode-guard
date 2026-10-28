import type { GuardContext, Logger } from "../types.ts"

// Main agent of each session, for the `agents` sections: the session agent at the user's last prompt, primary mode
// checked, recorded by a `prompt` hook of its own (independent of `unprotectedAgent` and `askAs`). A child session
// (subagent, prompted by OpenCode's subagent tool through the same hook) records its own agent and its root session:
// its main agent is the root's. An agent switch made by the model mid-turn does not count until the next prompt. The
// hook is always there, but reads a session only while the settings in force have an agent section (`wanted`).

export interface SessionAgents {
  /** Agent of the root session at its last prompt, primary mode checked. */
  readonly main: string
  /** Agent of a child session at its last prompt. */
  readonly sub?: string
}

export interface MainAgents {
  /** `undefined`: main agent unknown (no prompt recorded, plugin reloaded, session unreadable, agent not primary). */
  lookup(sessionID: string): SessionAgents | undefined
}

/** Maximum recorded sessions: beyond that, the oldest are forgotten (and their main agent unknown). */
const MAX_SESSIONS = 1000

export async function registerMainAgents(ctx: GuardContext, log: Logger, wanted: () => boolean = () => true): Promise<MainAgents> {
  /** Session → its root session (unknown: `undefined`) and its agent at its last prompt; for a root, whether it is primary. */
  const sessions = new Map<string, { readonly root?: string; readonly agent?: string; readonly primary: boolean }>()

  await ctx.session.hook("prompt", async (event) => {
    try {
      sessions.delete(event.sessionID)
      if (!wanted()) return
      const session = await ctx.session.get({ sessionID: event.sessionID })
      const agent = session?.agent
      let record: { root?: string; agent?: string; primary: boolean }
      if (session?.parentID) record = { root: sessions.get(session.parentID)?.root, agent, primary: false }
      else {
        const mode = agent === undefined ? undefined : (await ctx.agent.get({ agentID: agent, location: { directory: ctx.location.directory } }))?.data?.mode
        record = { root: event.sessionID, agent, primary: mode === "primary" }
      }
      if (sessions.size >= MAX_SESSIONS) sessions.delete(sessions.keys().next().value!)
      sessions.set(event.sessionID, record)
    } catch (error) {
      sessions.delete(event.sessionID)
      log.error("agent sections: session lookup failed, only the hardenings of the calling agent's section apply", error)
    }
  })

  return {
    lookup(sessionID) {
      const record = sessions.get(sessionID)
      const root = record?.root === sessionID ? record : record?.root === undefined ? undefined : sessions.get(record.root)
      if (!record || !root?.primary || root.agent === undefined) return undefined
      return root === record ? { main: root.agent } : { main: root.agent, ...(record.agent === undefined ? {} : { sub: record.agent }) }
    },
  }
}
