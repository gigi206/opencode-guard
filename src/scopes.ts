// Settings of each call (guard.json files, `agents` and `projects` sections): the version in force, rebuilt when a
// guard.json file changes (identity of the candidates checked at most once per interval: never a read per call), and the
// scope of the call from the main agent recorded at the user's last prompt (`hooks/agents.ts`).
import { resolveVersion, type AgentRelaxation, type GuardConfig, type Scope, type Version } from "./config.ts"
import { waiverSummary } from "./rules/features.ts"
import { guardIdentity, readGuardFiles, type GuardPaths } from "./guard-file.ts"
import type { MainAgents } from "./hooks/agents.ts"
import type { CustomRule } from "./rules/types.ts"
import type { Logger, ModelRef } from "./types.ts"

/** guard.json files checked for a change at most this often. */
export const GUARD_CHECK_MS = 2000

/** A request about to leave for a provider: its model and why it is made; a request with no model is never relaxed. */
export interface RelaxRequest {
  readonly model?: ModelRef | undefined
  readonly kind?: string | undefined
}

/**
 * What an `agents` section relaxes for this call, decided each time and never for a whole session; `undefined`: nothing.
 * `agent` absent (prompt hook): the session's main agent. Without `request` (tool and prompt hooks, which are not told the
 * model): the session's model at the last prompt.
 */
export type RelaxationOf = (sessionID: string | undefined, agent: string | undefined, request?: RelaxRequest) => AgentRelaxation | undefined

export interface ScopeResolver {
  relaxation: RelaxationOf
  /** Settings of a call (`agent`: the agent making it); throws only on an internal error. */
  resolve(sessionID: string | undefined, agent: string | undefined): Scope
  /** guard.json files checked for a change (when due), then: do the settings in force have an agent section? */
  sectioned(): boolean
  /** Some scope of the version in force checks scripts: the files written are tracked. */
  tracking(): boolean
  /** guard.json files checked for a change (when due): for the hooks that redact without resolving a scope. */
  refresh(): void
  /** The user's rules of the version in force (after `resolve`); never throws. */
  rules(): readonly CustomRule[]
}

export interface ScopeDeps {
  readonly config: GuardConfig
  /** Candidate guard.json files and their identity when read at startup; absent: the startup settings only. */
  readonly paths?: GuardPaths
  readonly identity?: string
  /** Main agents recorded at the prompt; absent (their hook could not be registered): main agent always unknown. */
  readonly agents?: MainAgents
  readonly log: Logger
  readonly now?: () => number
  readonly intervalMs?: number
  /** Called with the version in force at creation and with each new one (`redactionOff` for the redactor). */
  readonly onVersion?: (version: Version) => void
}

export function createScopes(deps: ScopeDeps): ScopeResolver {
  const { config, log } = deps
  const clock = deps.now ?? Date.now
  const interval = deps.intervalMs ?? GUARD_CHECK_MS
  // Without a guard.json file, `agents`, `projects` or `trustedProjects`: the startup settings, same objects as before.
  const base: Scope = { policy: config.policy, decisionModel: config.features.decisionModel, scripts: config.features.scripts, modelGrants: config.modelGrants }
  const plain: Version = {
    base,
    scope: () => base,
    agents: new Set(),
    tracking: base.scripts,
    profile: config.profile,
    trusted: false,
    warnings: [],
    rules: config.rules,
    summary: "",
  }
  let current = config.version ?? plain
  let identity = deps.identity
  let checked = clock()
  deps.onVersion?.(current)
  announce(current)

  function announce(version: Version) {
    for (const [agent, relaxed] of version.relaxations ?? []) {
      const what = relaxed.guardOff ? "no checks and no redaction" : [...relaxed.off].map((name) => `${name} off`).join(", ")
      const where = relaxed.models ? (relaxed.models.length ? `on ${relaxed.models.join(", ")}` : "on no model: invalid models") : "on any model"
      if (deps.config.askAs === "deny") log.warn(`unattended mode (askAs: deny): agent section of ${agent} not relaxed`)
      else if (relaxed.models) log.info(`agent ${agent}: ${what} ${where}, once selected by the user`)
      else log.warn(`agent ${agent}: ${what} ${where}, once selected by the user: a change of model is not protected`)
    }
  }

  function reload() {
    const { layers } = config
    if (!deps.paths || !layers || clock() - checked < interval) return
    checked = clock()
    const next = guardIdentity(deps.paths)
    if (next === identity) return
    try {
      const files = readGuardFiles(deps.paths)
      // Started with a guard.json file: its removal is resolved by layers too (the startup settings held it).
      current = files.length > 0 || layers.keyed || config.version ? resolveVersion(layers, files, current) : plain
      identity = next
      deps.onVersion?.(current)
      announce(current)
      log.info(`guard.json re-read (${current.summary || "guard.json: none; startup settings"}${waiverSummary(current.base.policy)})`)
      for (const warning of current.warnings) log.warn(warning)
      for (const error of current.errors ?? []) log.error(error)
    } catch (error) {
      // Identity kept: the files are read again at the next check.
      log.error("guard.json could not be re-read: previous settings kept", error)
    }
  }

  return {
    relaxation(sessionID, agent, request) {
      try {
        reload()
        if (deps.config.askAs === "deny" || sessionID === undefined || !current.relaxations) return undefined
        const seen = deps.agents?.lookup(sessionID)
        // The main agent the user chose at the last prompt, in a root session: never a subagent, never another agent.
        if (!seen || seen.child || (agent !== undefined && agent !== seen.main)) return undefined
        const relaxed = current.relaxations.get(seen.main)
        // A title, a compaction or a generation may run under the same agent, with history the agent's model never sees.
        if (!relaxed || (request?.kind !== undefined && request.kind !== "primary")) return undefined
        if (!relaxed.models) return relaxed
        const model = request ? request.model : seen.model
        return model && relaxed.models.includes(`${model.providerID}/${model.id}`) ? relaxed : undefined
      } catch (error) {
        log.error("agent sections: relaxation not resolved, the agent stays protected", error)
        return undefined
      }
    },
    resolve(sessionID, agent) {
      reload()
      const version = current
      if (version.agents.size === 0) return version.base
      const seen = sessionID === undefined ? undefined : deps.agents?.lookup(sessionID)
      // Main agent unknown: only the hardenings of the calling agent's section. Known: the calling agent counts only if
      // it is the recorded one (main agent of a root session, subagent of a child session).
      if (!seen) return version.scope(undefined, undefined, agent)
      const recorded = seen.sub ?? seen.main
      return version.scope(seen.main, seen.sub, agent !== undefined && agent !== recorded ? agent : undefined)
    },
    sectioned() {
      reload()
      return current.agents.size > 0
    },
    tracking: () => current.tracking,
    refresh: reload,
    rules: () => current.rules,
  }
}
