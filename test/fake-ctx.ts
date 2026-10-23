import type { AgentInfoLike, AssertInput, GuardContext } from "../src/types.ts"

type Callback = (event: any) => Promise<void> | void

/** Fake context: captures registered callbacks and simulates `permission.assert`. */
export function fakeContext(options: Record<string, unknown> = {}) {
  const hooks = new Map<string, Callback[]>()
  const asserts: AssertInput[] = []
  let assertBehaviour: (input: AssertInput) => Promise<void> = async () => {}
  const register = (domain: string) => async (name: string, callback: Callback) => {
    const key = `${domain}.${name}`
    hooks.set(key, [...(hooks.get(key) ?? []), callback])
    return { dispose: async () => {} }
  }
  // Agents (like OpenCode: `build` exists before external plugin transforms) and each session's current agent.
  const agents = new Map<string, AgentInfoLike>([
    ["build", { mode: "primary", permissions: [{ action: "*", resource: "*", effect: "allow" }, { action: "question", resource: "*", effect: "allow" }] }],
  ])
  const sessionAgents = new Map<string, string>()
  let failLookups = false
  const lookups = { session: 0, agent: 0 }
  const ctx = {
    options,
    location: { directory: "/project" },
    agent: {
      transform: async (callback: (editor: unknown) => void) => {
        callback({
          get: (id: string) => agents.get(id),
          update: (id: string, update: (agent: AgentInfoLike) => void) => {
            const agent = agents.get(id) ?? { mode: "primary", permissions: [{ action: "*", resource: "*", effect: "allow" }] }
            agents.set(id, agent)
            update(agent)
          },
        })
        return { dispose: async () => {} }
      },
      get: async ({ agentID }: { agentID: string }) => {
        lookups.agent++
        if (failLookups) throw new Error("lookup failed")
        const data = agents.get(agentID)
        if (!data) throw new Error(`agent not found: ${agentID}`)
        return { data }
      },
    },
    tool: { hook: register("tool") },
    permission: {
      hook: register("permission"),
      assert: async (input: AssertInput) => {
        asserts.push(input)
        return assertBehaviour(input)
      },
    },
    session: {
      hook: register("session"),
      get: async ({ sessionID }: { sessionID: string }) => {
        lookups.session++
        if (failLookups) throw new Error("lookup failed")
        return { agent: sessionAgents.get(sessionID) }
      },
    },
  } as unknown as GuardContext

  /** Triggers all callbacks of a hook, in order, on the same object (like OpenCode). */
  async function trigger<E>(key: string, event: E): Promise<E> {
    for (const callback of hooks.get(key) ?? []) await callback(event)
    return event
  }

  return {
    ctx,
    hooks,
    asserts,
    trigger,
    onAssert: (fn: (input: AssertInput) => Promise<void>) => {
      assertBehaviour = fn
    },
    agents,
    lookups,
    /** Server-side session agent (TUI: Shift+Tab then `switchAgent` before sending; or switch through the API). */
    switchAgent: (sessionID: string, agent: string) => sessionAgents.set(sessionID, agent),
    failLookups: (value: boolean) => {
      failLookups = value
    },
  }
}
