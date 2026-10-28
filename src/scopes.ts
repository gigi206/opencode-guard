// Settings of each call (guard.json files, `agents` and `projects` sections): the version in force, rebuilt when a
// guard.json file changes (identity of the candidates checked at most once per interval: never a read per call), and the
// scope of the call from the main agent recorded at the user's last prompt (`hooks/agents.ts`).
import { resolveVersion, type GuardConfig, type Scope, type Version } from "./config.ts"
import { guardIdentity, readGuardFiles, type GuardPaths } from "./guard-file.ts"
import type { MainAgents } from "./hooks/agents.ts"
import type { Logger } from "./types.ts"

/** guard.json files checked for a change at most this often. */
export const GUARD_CHECK_MS = 2000

export interface ScopeResolver {
  /** Settings of a call (`agent`: the agent making it); throws only on an internal error. */
  resolve(sessionID: string | undefined, agent: string | undefined): Scope
  /** guard.json files checked for a change (when due), then: do the settings in force have an agent section? */
  sectioned(): boolean
  /** Some scope of the version in force checks scripts: the files written are tracked. */
  tracking(): boolean
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
    summary: "",
  }
  let current = config.version ?? plain
  let identity = deps.identity
  let checked = clock()

  function reload() {
    const { layers } = config
    if (!deps.paths || !layers || clock() - checked < interval) return
    checked = clock()
    const next = guardIdentity(deps.paths)
    if (next === identity) return
    try {
      const files = readGuardFiles(deps.paths)
      // Started with a guard.json file: its removal is resolved by layers too (the startup settings held it).
      current = files.length > 0 || layers.keyed || config.version ? resolveVersion(layers, files) : plain
      identity = next
      log.info(`guard.json re-read (${current.summary || "guard.json: none; startup settings"})`)
      for (const warning of current.warnings) log.warn(warning)
    } catch (error) {
      // Identity kept: the files are read again at the next check.
      log.error("guard.json could not be re-read: previous settings kept", error)
    }
  }

  return {
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
  }
}
