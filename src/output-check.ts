// `outputCheck` option: effective only if the user's global configuration file (or the system
// configuration) also declares it for this plugin, with the same decision model address. A repository can replace the plugin's
// options (project configuration loaded after the global one): it cannot thereby enable sending outputs to its
// own server. At the slightest doubt, the option stays inactive.
import { readFileSync, realpathSync } from "node:fs"
import { isAbsolute, join, resolve } from "node:path"
import { declaredDecision, normalizedURL, outputCheckRequested, type PluginDeclaration } from "./config.ts"

/**
 * OpenCode 2.0.31 global configuration directory (`util/src/global.ts`, `global-roots.ts`): `OPENCODE_CONFIG_DIR`
 * if set, otherwise `$XDG_CONFIG_HOME/opencode`, otherwise `~/.config/opencode`; server environment.
 */
export function globalConfigDirectory(env: Record<string, string | undefined>): string | undefined {
  if (env.OPENCODE_CONFIG_DIR) return env.OPENCODE_CONFIG_DIR
  const config = env.XDG_CONFIG_HOME || (env.HOME ? join(env.HOME, ".config") : undefined)
  return config ? join(config, "opencode") : undefined
}

export type OutputCheckState = { readonly active: true } | { readonly active: false; readonly reason: string }

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value)

function realPath(path: string): string {
  try {
    return realpathSync(path)
  } catch {
    return resolve(path)
  }
}

/**
 * Configuration text as OpenCode reads it (`core/src/config/variable.ts`): `{env:NAME}` replaced by the
 * server environment value, or an empty string; JSONC comments and trailing commas removed.
 */
function parseConfigText(text: string, env: Record<string, string | undefined>): unknown {
  const substituted = text.replace(/\{env:([^}]+)\}/g, (_, name: string) => JSON.stringify(env[name] || "").slice(1, -1))
  const stripped = substituted.replace(/("(?:[^"\\]|\\.)*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (_, s) => s ?? "")
  return JSON.parse(stripped.replace(/,(\s*[}\]])/g, "$1"))
}

type FileResult = { readonly options?: Record<string, unknown>; readonly reason?: string }

/** Options of the plugin entry in a configuration directory (same detection as `enforcedBySystemConfig`). */
function pluginOptions(dir: string, pluginDir: string, env: Record<string, string | undefined>): FileResult {
  let found = false
  for (const name of ["opencode.json", "opencode.jsonc"]) {
    let text: string
    try {
      text = readFileSync(join(dir, name), "utf8")
    } catch {
      continue
    }
    found = true
    let config: unknown
    try {
      config = parseConfigText(text, env)
    } catch {
      return { reason: "it is not valid JSON" }
    }
    const plugins = isRecord(config) ? config.plugins : undefined
    if (!Array.isArray(plugins)) continue
    for (const entry of plugins) {
      const target = typeof entry === "string" ? entry : isRecord(entry) ? entry.package : undefined
      if (typeof target !== "string" || !isAbsolute(target) || (realPath(target) !== pluginDir && resolve(target) !== pluginDir)) continue
      return { options: isRecord(entry) && isRecord(entry.options) ? entry.options : {} }
    }
  }
  return { reason: found ? "it does not declare this plugin" : "it is missing or unreadable" }
}

/**
 * Plugin entry of the global file and of the system configuration, read like `declaredOutputCheck` (relaxations of
 * `config.ts`: `profile`, `ruleOverrides`); reason in words (never a value) for an entry not found.
 */
export function declaredPluginOptions(input: {
  readonly pluginDir: string
  readonly globalDir: string | undefined
  readonly systemDir: string | undefined
  readonly env: Record<string, string | undefined>
}): PluginDeclaration[] {
  return (
    [
      ["global", input.globalDir],
      ["system", input.systemDir],
    ] as const
  ).map(([label, dir]) => (dir ? { label, ...pluginOptions(dir, input.pluginDir, input.env) } : { label, reason: "its directory is unknown" }))
}

/**
 * Is the option declared, with the same address as the effective configuration, by the global file or by the
 * system configuration? Reason in words (never a value) otherwise.
 */
export function declaredOutputCheck(input: {
  readonly pluginDir: string
  readonly effectiveBaseURL: string
  readonly globalDir: string | undefined
  readonly systemDir: string | undefined
  readonly env: Record<string, string | undefined>
}): OutputCheckState {
  const effective = normalizedURL(input.effectiveBaseURL)
  const reasons: string[] = []
  for (const [label, dir] of [
    ["global", input.globalDir],
    ["system", input.systemDir],
  ] as const) {
    if (!dir) {
      reasons.push(`${label} configuration directory unknown`)
      continue
    }
    const file = pluginOptions(dir, input.pluginDir, input.env)
    if (!file.options) {
      reasons.push(`${label} configuration: ${file.reason}`)
      continue
    }
    const options = file.options
    // Values read from another file: never followed (the plugin reads no referenced file).
    if (JSON.stringify([options.outputCheck, options.decision, options.jev]).includes("{file:")) {
      reasons.push(`${label} configuration: it uses a {file:…} reference`)
      continue
    }
    if (!outputCheckRequested(options.outputCheck)) {
      reasons.push(`${label} configuration: outputCheck is not enabled there`)
      continue
    }
    const declared = normalizedURL(declaredDecision(options)?.baseURL)
    if (!effective || !declared || declared !== effective) {
      reasons.push(`${label} configuration: the decision model address differs`)
      continue
    }
    return { active: true }
  }
  return { active: false, reason: reasons.join("; ") }
}
