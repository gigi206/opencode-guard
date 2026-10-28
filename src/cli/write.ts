// Changes of the global guard.json, the only file the command line writes: a rule's setting (top level, `agents[…]`,
// `projects[…]` or both) and `trustedProjects`. The existing file passes the plugin's own checks first (a file the
// plugin would ignore is never replaced); the new content is then resolved by the plugin's functions (a setting must
// hold in the scope written, otherwise the plugin's warning is the refusal), and written atomically: exclusive temporary
// file in the same directory, renamed over it unless the file changed since it was read. Unknown keys are kept; objects
// emptied by a removal are removed.
import { randomBytes } from "node:crypto"
import { closeSync, constants, fchmodSync, fsyncSync, lstatSync, openSync, renameSync, statSync, unlinkSync, writeSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import type { GuardFile, Version } from "../config.ts"
import { GUARD_FILE, guardIdentity, MAX_GUARD_FILE_BYTES, readGuardFiles } from "../guard-file.ts"
import { CliError, projectDirectory, readSources, realOrUndefined, resolution, type CliIo, type Sources } from "./context.ts"

type Json = Record<string, unknown>
const isObject = (value: unknown): value is Json => value !== null && typeof value === "object" && !Array.isArray(value)

/** Words of the setting commands, written as is (`allow` is read as `off` by the plugin). */
export const SETTINGS = ["allow", "off", "ask", "deny", "model"] as const
export type SettingWord = (typeof SETTINGS)[number]

/** Section written: the top level, an agent's, a project's (real path), or an agent's inside a project's. */
export interface Target {
  readonly agent?: string
  readonly project?: string
}

const placeOf = (target: Target) =>
  [target.project === undefined ? "" : `projects[${JSON.stringify(target.project)}]`, target.agent === undefined ? "" : `agents[${JSON.stringify(target.agent)}]`]
    .filter(Boolean)
    .join(".") || "the top level"

interface GlobalGuard {
  readonly path: string
  readonly data: Json
  /** Present file as the plugin reads it; absent: a new file. */
  readonly file?: GuardFile
  readonly mode?: number
  /** Device, inode, mode, size and dates of the path before it was read (absence included). */
  readonly identity: string
}

function globalGuard(sources: Sources): GlobalGuard {
  if (!sources.globalDir) throw new CliError("OpenCode's global configuration directory is unknown: none of OPENCODE_CONFIG_DIR, XDG_CONFIG_HOME and HOME is set")
  const path = join(sources.globalDir, GUARD_FILE)
  const paths = { global: path, projects: [], roots: [] }
  const identity = guardIdentity(paths)
  const [file] = readGuardFiles(paths)
  if (!file) return { path, data: {}, identity }
  if (!file.data) throw new CliError(`${path} is left as is: ${file.reason ?? "it cannot be read"} (the plugin ignores it; fix it by hand)`)
  return { path, data: structuredClone(file.data) as Json, file, mode: lstatSync(path).mode & 0o7777, identity }
}

/** Keys from the top level down to the section; a level present but not an object is never replaced. */
function sectionOf(data: Json, target: Target, create: boolean): Json | undefined {
  const keys = [...(target.project === undefined ? [] : ["projects", target.project]), ...(target.agent === undefined ? [] : ["agents", target.agent])]
  let current = data
  for (const [index, key] of keys.entries()) {
    if (current[key] === undefined) {
      if (!create) return undefined
      current[key] = {}
    } else if (!isObject(current[key]))
      throw new CliError(`${keys.slice(0, index + 1).map((part) => JSON.stringify(part)).join(" › ")} in the global guard.json is not an object: it is left as is (fix it by hand)`)
    current = current[key] as Json
  }
  return current
}

/** Removes the objects emptied along the section's keys, from the deepest. */
function prune(data: Json, target: Target): void {
  const keys = [...(target.project === undefined ? [] : ["projects", target.project]), ...(target.agent === undefined ? [] : ["agents", target.agent]), "ruleOverrides"]
  for (let depth = keys.length; depth > 0; depth--) {
    const parent = keys.slice(0, depth - 1).reduce<Json>((node, key) => node[key] as Json, data)
    const value = parent[keys[depth - 1]!]
    if (!isObject(value) || Object.keys(value).length > 0) return
    delete parent[keys[depth - 1]!]
  }
}

/** Plugin's resolution of the new content for the target's project; refused unless `holds`, with the plugin's new warnings. */
function check(io: CliIo, sources: Sources, guard: GlobalGuard, data: Json, project: string | undefined, holds: (version: Version) => boolean): Version {
  const after = resolution(io, sources, project, [{ label: "global guard.json", global: true, data }])
  if (holds(after)) return after
  const before = resolution(io, sources, project, guard.file ? [guard.file] : []).warnings
  const reasons = after.warnings.filter((line) => !before.includes(line))
  throw new CliError(`refused, nothing written: ${reasons.length ? reasons.join("; ") : "the plugin would not apply this setting there"}`)
}

function write(guard: GlobalGuard, data: Json): void {
  const text = `${JSON.stringify(data, null, 2)}\n`
  if (Buffer.byteLength(text) > MAX_GUARD_FILE_BYTES)
    throw new CliError(`refused, nothing written: ${guard.path} would be larger than ${MAX_GUARD_FILE_BYTES} bytes, and the plugin would ignore it`)
  const dir = dirname(guard.path)
  try {
    if (!statSync(dir).isDirectory()) throw new Error()
  } catch {
    throw new CliError(`refused, nothing written: OpenCode's global configuration directory ${dir} does not exist`)
  }
  const temp = join(dir, `.${GUARD_FILE}.${randomBytes(6).toString("hex")}.tmp`)
  let fd: number | undefined
  try {
    fd = openSync(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600)
    fchmodSync(fd, guard.mode ?? 0o600)
    const buffer = Buffer.from(text)
    for (let offset = 0; offset < buffer.length; ) offset += writeSync(fd, buffer, offset)
    fsyncSync(fd)
    closeSync(fd)
    fd = undefined
    // Changed since it was read (another command, an editor): never overwritten.
    if (guardIdentity({ global: guard.path, projects: [], roots: [] }) !== guard.identity)
      throw new CliError(`refused, nothing written: ${guard.path} changed while the command ran; run it again`)
    renameSync(temp, guard.path)
  } catch (error) {
    if (fd !== undefined)
      try {
        closeSync(fd)
      } catch {}
    try {
      unlinkSync(temp)
    } catch {}
    if (error instanceof CliError) throw error
    throw new CliError(`${guard.path} could not be written (${String((error as { code?: unknown } | undefined)?.code ?? error)})`)
  }
}

/** Setting in force for the rule in the target's scope, and the source and section that set it. */
function inForce(version: Version, target: Target, rule: string) {
  return version.settings?.(target.agent).find((setting) => setting.key === `ruleOverrides.${rule}`)
}

export function setRule(io: CliIo, word: SettingWord, rule: string, target: Target): void {
  const sources = readSources(io)
  const guard = globalGuard(sources)
  const data = structuredClone(guard.data)
  const section = sectionOf(data, target, true)!
  if (section.ruleOverrides !== undefined && !isObject(section.ruleOverrides))
    throw new CliError(`ruleOverrides in ${placeOf(target)} of the global guard.json is not an object: it is left as is (fix it by hand)`)
  const overrides = (section.ruleOverrides ??= {}) as Json
  if (overrides[rule] === word) {
    io.out(`ruleOverrides.${rule} is already "${word}" in ${placeOf(target)} of ${guard.path}: nothing changed`)
    return
  }
  overrides[rule] = word
  const setting = word === "allow" ? "off" : word
  check(io, sources, guard, data, target.project, (version) => (target.agent === undefined ? version.base : version.scope(target.agent, undefined, undefined)).policy.overrides?.get(rule) === setting)
  write(guard, data)
  io.out(`ruleOverrides.${rule} set to "${word}" in ${placeOf(target)} of ${guard.path}`)
}

export function resetRule(io: CliIo, rule: string, target: Target): void {
  const sources = readSources(io)
  const guard = globalGuard(sources)
  const data = structuredClone(guard.data)
  const section = sectionOf(data, target, false)
  const overrides = section?.ruleOverrides
  if (overrides !== undefined && !isObject(overrides))
    throw new CliError(`ruleOverrides in ${placeOf(target)} of the global guard.json is not an object: it is left as is (fix it by hand)`)
  if (!overrides || !Object.hasOwn(overrides, rule)) io.out(`ruleOverrides.${rule} is not set in ${placeOf(target)} of ${guard.path}: nothing changed`)
  else {
    delete overrides[rule]
    prune(data, target)
    write(guard, data)
    io.out(`ruleOverrides.${rule} removed from ${placeOf(target)} of ${guard.path}`)
  }
  const still = inForce(resolution(io, sources, target.project, [{ label: "global guard.json", global: true, data }]), target, rule)
  if (still) io.out(`ruleOverrides.${rule} is still "${still.value}" there, set by ${still.origin}`)
}

/** Directory given (real path; `allowMissing`: absolute path), or the project of the current directory. */
export function directoryOf(io: CliIo, given: string | undefined, allowMissing = false): string {
  if (given === undefined) return projectDirectory(io.cwd)
  const path = resolve(io.cwd, given)
  const real = realOrUndefined(path)
  if (real === undefined) {
    if (allowMissing) return path
    throw new CliError(`refused, nothing written: ${path} does not exist`)
  }
  if (!statSync(real).isDirectory()) throw new CliError(`refused, nothing written: ${path} is not a directory`)
  return real
}

const listedAs = (entry: unknown, dir: string) => entry === dir || (typeof entry === "string" && entry !== "*" && realOrUndefined(entry) === dir)

export function trust(io: CliIo, dir: string): void {
  const sources = readSources(io)
  const guard = globalGuard(sources)
  const data = structuredClone(guard.data)
  const listed = data.trustedProjects
  if (listed !== undefined && listed !== "*" && !Array.isArray(listed))
    throw new CliError('trustedProjects in the global guard.json is neither "*" nor a list: it is left as is (fix it by hand)')
  const all = listed === "*" || (Array.isArray(listed) && listed.includes("*"))
  if (all || (Array.isArray(listed) && listed.some((entry) => listedAs(entry, dir)))) {
    io.out(`${dir === "*" || all ? 'every project is already trusted ("*")' : `${dir} is already listed`} in trustedProjects of ${guard.path}: nothing changed`)
    return
  }
  if (Array.isArray(listed)) listed.push(dir)
  else data.trustedProjects = dir === "*" ? "*" : [dir]
  if (dir === "*") io.err("warning: every project becomes trusted: the settings of any project may relax yours")
  else if (dir === "/" || dir === realOrUndefined(io.env.HOME ?? ""))
    io.err(`warning: every project under ${dir} becomes trusted: their settings may relax yours`)
  check(io, sources, guard, data, dir === "*" ? (realOrUndefined(io.cwd) ?? resolve(io.cwd)) : dir, (version) => version.trusted)
  write(guard, data)
  io.out(`${dir === "*" ? '"*" (every project)' : dir} added to trustedProjects in ${guard.path}`)
}

export function untrust(io: CliIo, dir: string): void {
  const sources = readSources(io)
  const guard = globalGuard(sources)
  const data = structuredClone(guard.data)
  const listed = data.trustedProjects
  if (listed !== undefined && listed !== "*" && !Array.isArray(listed))
    throw new CliError('trustedProjects in the global guard.json is neither "*" nor a list: it is left as is (fix it by hand)')
  if (listed === "*" && dir !== "*") throw new CliError(`every project is trusted (trustedProjects "*" in ${guard.path}): remove it first with untrust --all`)
  const kept = Array.isArray(listed) ? listed.filter((entry) => (dir === "*" ? entry !== "*" : !listedAs(entry, dir))) : []
  if (listed === undefined || (Array.isArray(listed) && kept.length === listed.length)) io.out(`${dir === "*" ? '"*"' : dir} is not in trustedProjects of ${guard.path}: nothing changed`)
  else {
    if (kept.length) data.trustedProjects = kept
    else delete data.trustedProjects
    write(guard, data)
    io.out(`${dir === "*" ? '"*" (every project)' : dir} removed from trustedProjects in ${guard.path}`)
  }
  if (dir === "*") return
  const after = resolution(io, sources, dir, [{ label: "global guard.json", global: true, data }])
  if (after.trusted) io.out(`${dir} is still trusted (trustedProjects of the global sources: ${after.listed?.join(", ")})`)
}
