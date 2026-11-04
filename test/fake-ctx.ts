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
  const sessionModels = new Map<string, { providerID: string; id: string }>()
  const sessionParents = new Map<string, string>()
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
        const [model, parentID] = [sessionModels.get(sessionID), sessionParents.get(sessionID)]
        return { agent: sessionAgents.get(sessionID), ...(model ? { model } : {}), ...(parentID ? { parentID } : {}) }
      },
    },
  } as unknown as GuardContext

  /**
   * Triggers all callbacks of a hook, in order, on the same object (like OpenCode). A shell permission evaluation carries
   * a tool call's source, as OpenCode's shell tool always gives one, unless the event sets `source` itself (`undefined`:
   * none, the shell condition of a scheduled task); its identifier matches no call of the tests.
   */
  async function trigger<E>(key: string, event: E): Promise<E> {
    const record = event as Record<string, unknown>
    if (key === "permission.evaluate" && record && record.action === "shell" && !("source" in record))
      record.source = { type: "tool", messageID: "msg_fake", id: "call_fake_source" }
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
    switchModel: (sessionID: string, providerID: string, id: string) => sessionModels.set(sessionID, { providerID, id }),
    /** Child session of `parentID` (subagent). */
    setParent: (sessionID: string, parentID: string) => sessionParents.set(sessionID, parentID),
    failLookups: (value: boolean) => {
      failLookups = value
    },
  }
}
