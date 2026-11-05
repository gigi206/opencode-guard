// `outputCheck` and `promptCheck` options: effective only if the user's global configuration file (or the system
// configuration) also declares it for this plugin, with the same decision model address. A repository can replace the plugin's
// options (project configuration loaded after the global one): it cannot thereby enable sending outputs or prompts to
// its own server. At the slightest doubt, the option stays inactive.
import { readFileSync, realpathSync } from "node:fs"
import { basename, dirname, isAbsolute, join, resolve } from "node:path"
import { checkRequested, declaredDecision, modelSwitchedOn, normalizedURL, type PluginDeclaration } from "./config.ts"

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
 * Where OpenCode installed a package plugin (`packages/util/src/npm.ts`, v2.2.5):
 * `<cache>/npm/<key>/<generation>/node_modules/<name>`. `entry` holds every generation of one package specifier, and
 * OpenCode loads the highest one. Undefined for a plugin directory of any other form (a local plugin).
 */
export function packageInstall(pluginDir: string): { readonly entry: string; readonly generation: string; readonly name: string } | undefined {
  const modules = dirname(pluginDir)
  const generation = dirname(modules)
  if (basename(modules) !== "node_modules" || !/^\d+$/.test(basename(generation))) return undefined
  return { entry: dirname(generation), generation, name: basename(pluginDir) }
}

/**
 * Does a configured plugin target designate this plugin? An absolute target by its path. A package specifier only when
 * it is, word for word, the one this generation was installed from (the `package.json` OpenCode writes next to
 * `node_modules`): a name alone would also accept someone else's package. At the slightest doubt: no.
 */
export function declaresPlugin(target: string, pluginDir: string): boolean {
  if (isAbsolute(target)) return realPath(target) === pluginDir || resolve(target) === pluginDir
  const install = packageInstall(pluginDir)
  if (!install) return false
  try {
    const manifest = JSON.parse(readFileSync(join(install.generation, "package.json"), "utf8")) as unknown
    const dependencies = isRecord(manifest) ? manifest.dependencies : undefined
    return isRecord(dependencies) && dependencies[install.name] === target
  } catch {
    return false
  }
}

/**
 * Configuration text as OpenCode reads it (`core/src/config/variable.ts`, v2.2.0): `{env:NAME}` replaced by the
 * server environment value, or an empty string, as is; escaped for JSON only when the raw text does not parse;
 * JSONC comments and trailing commas removed.
 */
function parseConfigText(text: string, env: Record<string, string | undefined>): unknown {
  const parse = (escape: boolean) => {
    const substituted = text.replace(/\{env:([^}]+)\}/g, (_, name: string) => (escape ? JSON.stringify(env[name] || "").slice(1, -1) : env[name] || ""))
    const stripped = substituted.replace(/("(?:[^"\\]|\\.)*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (_, s) => s ?? "")
    return JSON.parse(stripped.replace(/,(\s*[}\]])/g, "$1")) as unknown
  }
  try {
    return parse(false)
  } catch {
    return parse(true)
  }
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
      if (typeof target !== "string" || !declaresPlugin(target, pluginDir)) continue
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
 * Does a global source want this check, with a decision model of its own switched on, that is not the model in use (other
 * address, or none)? Then the check does not run because of the effective options, not by the user's choice. `false` when
 * no global source declares a model: nothing is cut for a user without one.
 */
export function checkCutByModel(input: {
  readonly option: "outputCheck" | "promptCheck"
  readonly enabledBySection: boolean
  readonly pluginDir: string
  readonly effectiveBaseURL: unknown
  readonly globalDir: string | undefined
  readonly systemDir: string | undefined
  readonly env: Record<string, string | undefined>
}): boolean {
  const effective = normalizedURL(input.effectiveBaseURL)
  return [input.globalDir, input.systemDir].some((dir) => {
    const options = dir ? pluginOptions(dir, input.pluginDir, input.env).options : undefined
    if (!options || JSON.stringify([options[input.option], options.decision]).includes("{file:")) return false
    if ((!input.enabledBySection && !checkRequested(options[input.option])) || !modelSwitchedOn(options)) return false
    const declared = normalizedURL(declaredDecision(options)?.baseURL)
    return declared !== undefined && declared !== effective
  })
}

/**
 * Is the option declared, with the same address as the effective configuration, by the global file or by the
 * system configuration? Reason in words (never a value) otherwise.
 */
export function declaredOutputCheck(input: {
  /** Option checked (default `outputCheck`); both are on when the file leaves them out. */
  readonly option?: "outputCheck" | "promptCheck"
  /** A `projects` section of a global source turns it on: a file that turns it off does not count. */
  readonly enabledBySection?: boolean
  readonly pluginDir: string
  readonly effectiveBaseURL: string
  readonly globalDir: string | undefined
  readonly systemDir: string | undefined
  readonly env: Record<string, string | undefined>
}): OutputCheckState {
  const effective = normalizedURL(input.effectiveBaseURL)
  const option = input.option ?? "outputCheck"
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
    if (JSON.stringify([options[option], options.decision]).includes("{file:")) {
      reasons.push(`${label} configuration: it uses a {file:…} reference`)
      continue
    }
    if (!input.enabledBySection && !checkRequested(options[option])) {
      reasons.push(`${label} configuration: ${option} is not enabled there`)
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
