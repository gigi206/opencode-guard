// OpenCode V2 plugin "guard".
// `import type` only: @opencode/plugin is provided by OpenCode at runtime, and Node refuses
// type-stripping of .ts sources located in node_modules (tests).
import type { Plugin } from "@opencode/plugin"
import { readFileSync, realpathSync } from "node:fs"
import { homedir } from "node:os"
import { isAbsolute, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { DEFAULT_PROMPT_CHECK, defaultLogFile, displayURL, FEATURE_NAMES, parseConfig, type Features, type GuardConfig, type GuardFile } from "./config.ts"
import { createDecider } from "./decide.ts"
import { guardIdentity, guardPaths, readGuardFiles } from "./guard-file.ts"
import { registerMainAgents, type MainAgents } from "./hooks/agents.ts"
import { registerGate } from "./hooks/gate.ts"
import { registerClaudeAgentWarning } from "./hooks/claude-agent.ts"
import { createUserShellCheck, registerOutputCheck, type UserShellCheck } from "./hooks/output-check.ts"
import { createPromptGate, type PromptGate } from "./hooks/prompt-check.ts"
import { registerRedaction } from "./hooks/redaction.ts"
import { PROTECTED, registerUnprotected, type UnprotectedGate } from "./hooks/unprotected.ts"
import { createModelClient } from "./model/client.ts"
import { isRegularFile } from "./real-path.ts"
import { declaredOutputCheck, declaredPluginOptions, declaresPlugin, globalConfigDirectory, packageInstall, type OutputCheckState } from "./output-check.ts"
import { RULE_FEATURES, waiverSummary } from "./rules/features.ts"
import { createScopes } from "./scopes.ts"
import { isSecretFile, protectedWriteKind } from "./rules/sensitive-paths.ts"
import { serviceDirectories, serviceSecretSource } from "./secrets/opencode-service.ts"
import { createRedactor, type Redactor } from "./secrets/redact.ts"
import { createLogger, type GuardContext } from "./types.ts"

/** OpenCode system configuration directory (packages/core/src/config/discovery.ts, `systemDirectory`). */
export function systemConfigDirectory(platform: NodeJS.Platform = process.platform, env: NodeJS.ProcessEnv = process.env): string {
  if (platform === "darwin") return "/Library/Application Support/opencode"
  if (platform === "win32") return join(env.ProgramData || "C:\\ProgramData", "opencode")
  return "/etc/opencode"
}

/** Server's current directory; removed: unknown (`process.cwd()` would throw). */
function currentDirectory(): string | undefined {
  try {
    return process.cwd()
  } catch {
    return undefined
  }
}

/** Real path (plugin directory reached through a symbolic link); missing or unreadable entry: resolved path. */
function realPath(path: string): string {
  try {
    return realpathSync(path)
  } catch {
    return resolve(path)
  }
}

/**
 * Plugin declared in the system configuration, loaded after the project ones: a project can then no
 * longer remove it (`-guard`, `-*`), block it with a policy, or replace its options.
 */
export function enforcedBySystemConfig(pluginDir: string, systemDir: string): boolean {
  return ["opencode.json", "opencode.jsonc"].some((name) => {
    try {
      // JSONC: comments roughly stripped (outside strings); an unreadable file counts as "not enforced".
      const text = readFileSync(join(systemDir, name), "utf8").replace(/("(?:[^"\\]|\\.)*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (_, s) => s ?? "")
      const plugins = (JSON.parse(text.replace(/,(\s*[}\]])/g, "$1")) as { plugins?: unknown }).plugins
      return (
        Array.isArray(plugins) &&
        plugins.some((entry) => {
          const target = typeof entry === "string" ? entry : (entry as { package?: unknown } | null)?.package
          return typeof target === "string" && declaresPlugin(target, pluginDir)
        })
      )
    } catch {
      return false
    }
  })
}

/** The key and headers come from the settings ({env:…}): redacted even if they are not in the environment. */
export function knownSecrets(config: GuardConfig): Array<{ name: string; value: string }> {
  return [
    ...(config.decision?.apiKey ? [{ name: "decision.apiKey", value: config.decision.apiKey }] : []),
    ...Object.entries(config.decision?.headers ?? {}).map(([name, value]) => ({ name: `decision.headers.${name}`, value })),
  ]
}

/**
 * Configured log file: refused if it designates a credential file or a write-protected location
 * (OpenCode configuration, plugin directory, startup files, `~/.ssh`, git hooks, `/etc`) → default
 * log, with a warning (without the path). The default path is always accepted (fallback without a loop); a final
 * symbolic link is refused on every write by the logger itself.
 */
export function checkedLogFile(
  file: string | undefined,
  fallback: string | undefined,
  home: string | undefined,
  protectedDirs: readonly string[],
  warnings: string[],
  cwd: string | undefined = currentDirectory(),
): string | undefined {
  if (!file) return file
  // Never `resolve` a relative path without a directory: it would call `process.cwd()`, which throws if the server
  // directory was deleted (the plugin would no longer load).
  const absoluteOf = (path: string) => (isAbsolute(path) ? resolve(path) : cwd === undefined ? undefined : resolve(cwd, path))
  const absolute = absoluteOf(file)
  // Unknown current directory: relative path not checked (it is already reported as relative).
  if (absolute === undefined) return file
  if (fallback !== undefined && absolute === absoluteOf(fallback)) return file
  const reason = isSecretFile(absolute, home)
    ? "it is a credential file"
    : protectedWriteKind(absolute, home, { protectedDirs })
      ? "it is a protected location"
      : undefined
  if (!reason) return file
  warnings.push(`logFile refused (${reason}): logging to the default log file`)
  return fallback
}

/** Directories the rules protect, from the server's environment; also read by `guard test` (cli/test.ts). */
export function guardDirectories(env: Record<string, string | undefined>, globalDir: string | undefined) {
  // The plugin directory is hot-reloaded: modifying it would disable the guardrail. Real form too (plugin loaded
  // through a path containing a symbolic link).
  const pluginDir = resolve(fileURLToPath(new URL("..", import.meta.url)))
  // Installed from a package: OpenCode loads the highest generation of the entry, so a new one written beside this
  // directory would replace the plugin at the next start. The whole entry counts as the plugin.
  const install = packageInstall(pluginDir)
  const pluginDirs = [...new Set([pluginDir, realPath(pluginDir), ...(install ? [install.entry, realPath(install.entry)] : [])])]
  // OpenCode global configuration directory resolved from the server environment (`OPENCODE_CONFIG_DIR`,
  // `XDG_CONFIG_HOME`): protected like the default directory, which the rules recognize by name only.
  const configDir = globalDir ? resolve(globalDir) : undefined
  const protectedDirs = [...new Set([...pluginDirs, ...(configDir ? [configDir, realPath(configDir)] : [])])]
  // Directories of the service files (`service.json`: server password), resolved the same way.
  const serviceDirs = [...new Set(serviceDirectories(env).map((dir) => resolve(dir)))]
  return { pluginDir, pluginDirs, protectedDirs, serviceDirs }
}

export async function setupGuard(
  ctx: GuardContext,
  env: Record<string, string | undefined> = process.env,
  systemDir: string = systemConfigDirectory(),
  globalDir: string | undefined = globalConfigDirectory(env),
  scopeClock?: { readonly now: () => number; readonly intervalMs: number },
  home?: string,
) {
  const { pluginDir, pluginDirs, protectedDirs, serviceDirs } = guardDirectories(env, globalDir)
  // Settings by agent and by project: guard.json files (global, and each `.opencode` OpenCode reads for the session
  // directory), identity taken before reading (a change in between is seen at the next check). Never throws.
  const paths = guardPaths(ctx.location.directory, globalDir, systemDir)
  let identity: string | undefined
  let files: GuardFile[] = []
  const unread: string[] = []
  try {
    identity = guardIdentity(paths)
    files = readGuardFiles(paths)
  } catch {
    unread.push("guard.json files could not be read: they are read again at the next check")
  }
  const project = (() => {
    try {
      return realpathSync(ctx.location.directory)
    } catch {
      return undefined
    }
  })()
  const realOrUndefined = (path: string) => {
    try {
      return realpathSync(path)
    } catch {
      return undefined
    }
  }
  // Relaxations (`profile`, `ruleOverrides`): kept only if the global or system configuration declares them too, or the
  // project is trusted when a guard.json file or a section exists.
  const { config, warnings } = parseConfig(ctx.options, env, () => declaredPluginOptions({ pluginDir, globalDir, systemDir, env }), {
    files,
    ...(project ? { project } : {}),
    realPath: realOrUndefined,
    regularFile: isRegularFile,
  })
  warnings.push(...unread)
  // OpenCode service password and remote access route: re-read from its files (`env` directories).
  const runtimeSecrets = serviceSecretSource(serviceDirectories(env))
  const formats = createRedactor({ extraPatterns: config.secretPatterns, disabledTypes: config.disabledPatterns, allowlist: config.allowlist, env, knownSecrets: knownSecrets(config), runtimeSecrets })
  // Formats turned off by the global guard.json (`redactionOff`): every redaction first checks the guard.json files
  // (at most every 2 seconds, like the tool calls), so that a format turned back on is redacted again without waiting
  // for a tool call. Set once the settings are resolved (`createScopes` below); until then, nothing extra is turned off.
  let refreshFormats = () => {}
  const redactor: Redactor = {
    redactString: (text) => (refreshFormats(), formats.redactString(text)),
    redactDeep: (value, options) => (refreshFormats(), formats.redactDeep(value, options)),
    containsSecret: (value) => (refreshFormats(), formats.containsSecret(value)),
  }
  let homeError: unknown
  try {
    home ??= homedir()
  } catch (error) {
    homeError = error
  }
  // Created after the redactor: every log line is redacted.
  // Unusable configured file: falls back to the default log (the service's error output cannot be consulted).
  const fallback = defaultLogFile(env)
  // Never throw here: the log and hooks would not be created (no protection, nothing in the log).
  let logFile = fallback
  try {
    logFile = checkedLogFile(config.logFile, fallback, home, protectedDirs, warnings)
  } catch {
    warnings.push("logFile could not be checked: logging to the default log file")
  }
  const log = createLogger(config.debug, logFile, (text) => redactor.redactString(text).value, undefined, { fallback })
  for (const warning of warnings) log.warn(warning)
  if (!config.decision) log.warn("decision model disabled: local rules only")
  else if (!config.features.decisionModel) log.warn("decision model disabled (decisionModel: false): local rules only")
  for (const name of FEATURE_NAMES) if (!config.features[name] && name !== "decisionModel") log.warn(FEATURE_OFF[name])
  if (!config.features.dangerousCommands && !config.features.sensitiveFiles && !(config.decision && config.features.decisionModel))
    log.warn("no built-in local rule and no decision model: only the placeholder rule, self-protection and your own rules apply")
  // Settings that leave local asks to the decision model: without it, they do nothing.
  const { localAsksByModel, selfProtectionByModel } = config.policy
  const byModel = [
    ...(localAsksByModel ? ['localAsks "model"'] : []),
    ...[...(config.policy.overrides ?? [])].filter(([, setting]) => setting === "model").map(([rule]) => `ruleOverrides.${rule} "model"`),
    ...(selfProtectionByModel ? ["selfProtectionByModel"] : []),
  ]
  if (byModel.length && !(config.decision && config.features.decisionModel))
    log.warn(`${byModel.join(", ")} retained but the decision model is disabled: these asks stay with you`)
  else if (selfProtectionByModel && !localAsksByModel && ![...(config.policy.overrides ?? [])].some(([rule, setting]) => setting === "model" && RULE_FEATURES.get(rule) === "always"))
    log.warn('selfProtectionByModel has no effect without localAsks "model" or an always-active rule set to "model"')
  // A repository may replace the model's address or switch it on: such a model never allows an ask.
  if (config.decision && config.features.decisionModel && !config.modelGrants)
    log.warn(
      `decision model not declared by the global configuration (${config.modelWithheld}): it may deny, but never allows an ask left to it (heredoc data, CodeMode's fetch, localAsks, "model", selfProtectionByModel): these stay with you`,
    )

  if (homeError !== undefined) log.warn(`home directory unknown (${String(homeError)}): only the ~ and $HOME forms are recognized`)
  // Client created with `decision` even when the switch is off: an agent section may turn the model on (each call says).
  const client = config.decision ? createModelClient(config.decision) : undefined
  const model = config.features.decisionModel ? client : undefined
  const decider = createDecider({ config, redactor, model: client, home, protectedDirs, pluginDirs, serviceDirs, readContent: true, resolveLinks: true, log })

  // Optional parts isolated: their failure must not prevent the guard from loading (plugin not loaded = no
  // protection); the degraded state is announced in the startup line.
  const degraded: string[] = []
  let unprotected: UnprotectedGate = PROTECTED
  try {
    unprotected = await registerUnprotected(ctx, { agent: config.unprotectedAgent, askAs: config.askAs, log })
  } catch (error) {
    log.error("unprotected agent unavailable, every agent stays protected", error)
    degraded.push("unprotected agent: UNAVAILABLE")
  }
  // Main agent of each session, recorded at the prompt while the settings in force have an agent section (an agent
  // section written while OpenCode runs counts from the next prompt).
  let agents: MainAgents | undefined
  let sectioned = () => false
  try {
    agents = await registerMainAgents(ctx, log, () => sectioned())
  } catch (error) {
    log.error("agent sections: main agents cannot be recorded, only the hardenings of the agent sections apply", error)
    degraded.push("main agents: UNAVAILABLE")
  }
  const scopes = createScopes({
    config,
    paths,
    ...(identity === undefined ? {} : { identity }),
    ...(agents ? { agents } : {}),
    log,
    ...(scopeClock ? { now: scopeClock.now, intervalMs: scopeClock.intervalMs } : {}),
    onVersion: (version) => formats.setDisabledTypes(version.redactionOff ?? []),
  })
  sectioned = () => scopes.sectioned()
  refreshFormats = () => scopes.refresh()
  try {
    await registerGate(ctx, {
      decider,
      redactor,
      home,
      rules: config.rules,
      protectedDirs,
      pluginDirs,
      serviceDirs,
      askAs: config.askAs,
      log,
      unprotected,
      active: config.policy,
      trackScripts: config.features.scripts,
      scopes,
      readContent: true,
      resolveLinks: true,
      // Test clock: it also drives the memory of confirmations.
      ...(scopeClock ? { now: scopeClock.now } : {}),
    })
  } catch (error) {
    log.error("guard hooks failed to register: plugin not loaded, NO protection", error)
    throw error
  }
  // Prompt check (on by default with the decision model): same condition as the output check; its gate goes to the
  // prompt hook. Without the decision model, nothing is said unless the user asked for it.
  let promptCheck: OutputCheckState | undefined
  let promptGate: PromptGate | undefined
  if (config.promptCheck && (config.promptCheck.explicit || (model && config.decision))) {
    try {
      promptCheck =
        model && config.decision
          ? declaredOutputCheck({ option: "promptCheck", pluginDir: protectedDirs[0]!, effectiveBaseURL: config.decision.baseURL, globalDir, systemDir, env })
          : { active: false, reason: "the decision model is disabled" }
      if (promptCheck.active && config.decision) {
        promptGate = createPromptGate(ctx, {
          redactor,
          model: createModelClient(config.decision),
          label: config.decision.model,
          threshold: config.promptCheck.threshold,
          tuning: config.promptCheck.tuning,
          questions: config.promptCheck.questions,
          timeoutMs: config.decision.timeoutMs,
          askAs: config.askAs,
          log,
        })
        log.warn("prompt check active: typed prompts, redacted, are sent to the decision model")
      } else if (!promptCheck.active && config.promptCheck.explicit) log.warn(`promptCheck requested but inactive: ${promptCheck.reason}`)
    } catch (error) {
      log.error("prompt check unavailable", error)
      promptCheck = { active: false, reason: "internal error" }
      degraded.push("prompt check: UNAVAILABLE")
    }
  }
  // `!` command outputs, checked on the wire by the output check's search: set below once the output check is active.
  const userShell: { check?: UserShellCheck } = {}
  try {
    await registerRedaction(ctx, {
      userShell,
      redactor,
      redactPrompt: config.features.redactPrompt,
      redactOutputs: config.features.redactOutputs,
      redactWire: config.features.redactWire,
      log,
      unprotected,
      ...(promptGate ? { promptCheck: promptGate } : {}),
    })
  } catch (error) {
    log.error("secret redaction hooks failed to register: secrets may reach the provider", error)
    degraded.push("secret redaction: INCOMPLETE")
  }
  // OpenCode's "Claude Agent" provider bypasses the wire hooks: said in the log when it is connected.
  try {
    await registerClaudeAgentWarning(ctx, log)
  } catch (error) {
    log.error("Claude Agent check unavailable", error)
  }
  // Output check (on by default with the decision model): effective only if the global file declares the same model
  // address and does not turn it off; otherwise inactive, with the reason in words when the user set it.
  let outputCheck: OutputCheckState | undefined
  if (config.outputCheck && (config.outputCheck.explicit || (model && config.decision))) {
    try {
      outputCheck =
        model && config.decision
          ? declaredOutputCheck({ pluginDir: protectedDirs[0]!, effectiveBaseURL: config.decision.baseURL, globalDir, systemDir, env })
          : { active: false, reason: "the decision model is disabled" }
      if (outputCheck.active && config.decision) {
        await registerOutputCheck(ctx, {
          redactor,
          model: createModelClient({ ...config.decision, timeoutMs: config.outputCheck.timeoutMs }),
          label: config.decision.model,
          threshold: config.outputCheck.threshold,
          tuning: config.outputCheck.tuning,
          skip: config.outputCheck.skip,
          questions: config.outputCheck.questions,
          prompt: config.promptCheck ?? DEFAULT_PROMPT_CHECK,
          askAs: config.askAs,
          log,
          unprotected,
        })
        userShell.check = createUserShellCheck({
          model: createModelClient({ ...config.decision, timeoutMs: config.outputCheck.timeoutMs }),
          label: config.decision.model,
          threshold: config.outputCheck.threshold,
          tuning: config.outputCheck.tuning,
          questions: config.outputCheck.questions,
        })
        log.warn("output check active: tool outputs, redacted, are sent to the decision model")
      } else if (!outputCheck.active && config.outputCheck.explicit) log.warn(`outputCheck requested but inactive: ${outputCheck.reason}`)
    } catch (error) {
      log.error("output check unavailable", error)
      outputCheck = { active: false, reason: "internal error" }
      degraded.push("output check: UNAVAILABLE")
    }
  }
  // Always written: a misspelled {env:…} variable (empty askAs → "ask") is visible here.
  const confirmations = config.askAs === "deny" ? "denied (unattended mode)" : "ask"
  const enforced = enforcedBySystemConfig(protectedDirs[0]!, systemDir) ? "enforced" : "not enforced"
  const modelText = model && config.decision ? `${config.decision.model} via ${displayURL(config.decision.baseURL)} (${config.decision.protocol})` : "disabled"
  const disabled = FEATURE_NAMES.filter((name) => !config.features[name])
  // Built-in redaction formats turned off: a relaxation, always shown.
  const formatsOff = [...new Set([...config.disabledPatterns, ...(config.version?.redactionOff ?? [])])]
  const off = `${disabled.length ? `; disabled: ${disabled.join(", ")}` : ""}${formatsOff.length ? `; redaction formats off: ${formatsOff.join(", ")}` : ""}`
  // Profile and rule settings retained, only when they differ from the defaults.
  const profile = config.profile === "standard" ? "" : `; profile: ${config.profile}`
  const settings = [...(config.policy.overrides ?? [])].map(([rule, setting]) => `${rule} ${setting}`)
  const overrides = `${settings.length ? `; rule overrides: ${settings.join(", ")}` : ""}${localAsksByModel ? "; local asks: model" : ""}${selfProtectionByModel ? "; self-protection by model" : ""}${waiverSummary(config.policy)}`
  // Prompt check: its state whenever the decision model is on (`off` when turned off, so that a project doing it shows).
  const custom = (settings: { custom: boolean } | undefined) => (settings?.custom ? " (custom settings)" : "")
  const prompted = promptCheck !== undefined ? `; prompt check: ${promptCheck.active ? "active" : "inactive"}${custom(config.promptCheck)}` : model && !config.promptCheck ? "; prompt check: off" : ""
  const outputs = outputCheck !== undefined ? `; output check: ${outputCheck.active ? "active" : "inactive"}${custom(config.outputCheck)}` : model && !config.outputCheck ? "; output check: off" : ""
  const checked = `${outputs}${prompted}`
  log.info(`active (decision model: ${modelText}; confirmations: ${confirmations}; system config: ${enforced}${profile}${overrides}${off}${checked}${degraded.map((item) => `; ${item}`).join("")})`)
  if (config.version) log.info(`settings by agent and by project (${config.version.summary})`)
  if (config.askAs === "deny") log.warn("unattended mode (askAs: deny): every confirmation request is denied")
}

/** Startup warning for each switch at `false` (decision model: dedicated message). */
const FEATURE_OFF: Record<keyof Features, string> = {
  dangerousCommands: "local rules for dangerous actions disabled (dangerousCommands: false)",
  sensitiveFiles: "local rules for credential files and outgoing secrets disabled (sensitiveFiles: false)",
  decisionModel: "decision model disabled (decisionModel: false)",
  scripts: "checks of scripts written then run disabled (scripts: false)",
  redactOutputs: "redaction of tool results and errors disabled (redactOutputs: false): secrets are stored in the history",
  redactPrompt: "redaction of the typed prompt disabled (redactPrompt: false)",
  redactWire: "redaction of model requests disabled (redactWire: false): only what is redacted at the source is protected",
}

const GuardPlugin = {
  id: "guard",
  setup: (ctx) => setupGuard(ctx),
} satisfies Plugin.Plugin

export default GuardPlugin
