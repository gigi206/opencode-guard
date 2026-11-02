// Changes of the global guard.json, the only file the command line writes: a rule's setting (top level, `agents[…]`,
// `projects[…]` or both), a file's exception (top level or `projects[…]`), the user's `rules` (top level) and
// `trustedProjects`. The existing file passes the plugin's own checks first (a file the plugin would ignore is never
// replaced); the new content is then resolved by the plugin's functions (a setting must hold in the scope written,
// otherwise the plugin's warning is the refusal), and written atomically: exclusive temporary file in the same
// directory, renamed over it unless the file changed since it was read. Unknown keys are kept; objects emptied by a
// removal are removed.
import { randomBytes } from "node:crypto"
import { closeSync, constants, fchmodSync, fsyncSync, lstatSync, openSync, renameSync, statSync, unlinkSync, writeSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { GUARD_RULES, parseConfig, REDACTION_OFF, ruleIdOf, rulesOption, type GuardFile, type Version } from "../config.ts"
import { GUARD_FILE, guardIdentity, guardPaths, MAX_GUARD_FILE_BYTES, readGuardFiles } from "../guard-file.ts"
import { RULE_FEATURES, TARGETED_RULES } from "../rules/features.ts"
import { hasParentComponent } from "../rules/sensitive-paths.ts"
import { INTERNAL_ERROR_RULE } from "../rules/types.ts"
import { CliError, projectDirectory, readSources, realOrUndefined, resolution, type CliIo, type Sources } from "./context.ts"

type Json = Record<string, unknown>
const isObject = (value: unknown): value is Json => value !== null && typeof value === "object" && !Array.isArray(value)

/** Words of the setting commands, written as is (`allow` is read as `off` by the plugin). */
export const SETTINGS = ["off", "ask", "deny", "model"] as const
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

/** Names that would reach the prototype of every object instead of a key of the file: refused as agent or rule names. */
const PROTOTYPE_NAMES = new Set(["__proto__", "constructor", "prototype"])

function ownName(kind: string, name: string): void {
  if (PROTOTYPE_NAMES.has(name)) throw new CliError(`refused, nothing written: ${JSON.stringify(name)} cannot be ${kind} name (it would reach every object's prototype)`)
}

/** Keys from the top level down to the section, read and created as own properties; a level present but not an object is never replaced. */
function sectionOf(data: Json, target: Target, create: boolean): Json | undefined {
  const keys = [...(target.project === undefined ? [] : ["projects", target.project]), ...(target.agent === undefined ? [] : ["agents", target.agent])]
  if (target.agent !== undefined) ownName("an agent", target.agent)
  if (target.project !== undefined) ownName("a project", target.project)
  let current = data
  for (const [index, key] of keys.entries()) {
    if (!Object.hasOwn(current, key)) {
      if (!create) return undefined
      current[key] = {}
    } else if (!isObject(current[key]))
      throw new CliError(`${keys.slice(0, index + 1).map((part) => JSON.stringify(part)).join(" › ")} in the global guard.json is not an object: it is left as is (fix it by hand)`)
    current = current[key] as Json
  }
  return current
}

/** Removes the objects emptied along the section's keys (and `ruleOverrides` unless told otherwise), from the deepest. */
function prune(data: Json, target: Target, leaf: string | undefined = "ruleOverrides"): void {
  const keys = [...(target.project === undefined ? [] : ["projects", target.project]), ...(target.agent === undefined ? [] : ["agents", target.agent]), ...(leaf ? [leaf] : [])]
  for (let depth = keys.length; depth > 0; depth--) {
    const parent = keys.slice(0, depth - 1).reduce<Json>((node, key) => node[key] as Json, data)
    const value = parent[keys[depth - 1]!]
    if (!isObject(value) || Object.keys(value).length > 0) return
    delete parent[keys[depth - 1]!]
  }
}

/** The section's name in the plugin's warnings. */
const labelOf = (target: Target) =>
  ["global guard.json", ...(target.project === undefined ? [] : [`projects[${JSON.stringify(target.project)}]`]), ...(target.agent === undefined ? [] : [`agents.${target.agent}`])].join(", ")

/** A value already written in the section that the plugin sets aside there (not `holds`): its warnings about that key, said. */
function ignoredThere(io: CliIo, sources: Sources, guard: GlobalGuard, target: Target, key: string, holds: (version: Version) => boolean): void {
  const version = resolution(io, sources, target.project, guard.file ? [guard.file] : [])
  if (holds(version)) return
  for (const line of version.warnings) if ((line.startsWith(`${labelOf(target)}: `) || line.startsWith(`${key} `)) && line.includes(key)) io.out(`but the plugin ignores it there: ${line}`)
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
  ownName("a rule", rule)
  const sources = readSources(io)
  const guard = globalGuard(sources)
  const data = structuredClone(guard.data)
  const section = sectionOf(data, target, true)!
  if (section.ruleOverrides !== undefined && !isObject(section.ruleOverrides))
    throw new CliError(`ruleOverrides in ${placeOf(target)} of the global guard.json is not an object: it is left as is (fix it by hand)`)
  const overrides = (section.ruleOverrides ??= {}) as Json
  const holds = (version: Version) => (target.agent === undefined ? version.base : version.scope(target.agent, undefined, undefined)).policy.overrides?.get(rule) === word
  if (Object.hasOwn(overrides, rule) && overrides[rule] === word) {
    io.out(`ruleOverrides.${rule} is already "${word}" in ${placeOf(target)} of ${guard.path}: nothing changed`)
    ignoredThere(io, sources, guard, target, `ruleOverrides.${rule}`, holds)
    return
  }
  overrides[rule] = word
  check(io, sources, guard, data, target.project, holds)
  write(guard, data)
  io.out(`ruleOverrides.${rule} set to "${word}" in ${placeOf(target)} of ${guard.path}`)
  // A rule that accepts exceptions: "off" is not one.
  if (word === "off" && TARGETED_RULES.has(rule)) io.out(`the whole rule ${rule} is off there, for every file (one file only: guard rules off ${rule} --path <file>)`)
}

export function resetRule(io: CliIo, rule: string, target: Target): void {
  ownName("a rule", rule)
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
  const after = resolution(io, sources, target.project, [{ label: "global guard.json", global: true, data }])
  const still = inForce(after, target, rule)
  if (still) io.out(`ruleOverrides.${rule} is still "${still.value}" there, set by ${still.origin}`)
  else {
    // Without a setting, a rule of a group applies only if its group's switch is on there (profile included).
    const group = RULE_FEATURES.get(rule)
    const switched = group && group !== "always" ? after.settings?.(target.agent).find((item) => item.key === group) : undefined
    if (switched && switched.value === false) io.out(`${rule} still does not apply there: its group ${group} is off, set by ${switched.origin}`)
  }
}

/**
 * A built-in redaction format turned off (`off`) or back on, in `redactionOff` of the global guard.json. Back on: a
 * format that `redactionOff` of the global or system configuration also turns off stays off, and the command says so.
 */
export function setRedaction(io: CliIo, type: string, off: boolean): void {
  const sources = readSources(io)
  const guard = globalGuard(sources)
  const data = structuredClone(guard.data)
  const listed = data[REDACTION_OFF]
  if (listed !== undefined && !Array.isArray(listed)) throw new CliError(`${REDACTION_OFF} in the global guard.json is not a list: it is left as is (fix it by hand)`)
  const list: unknown[] = listed ?? []
  if (off) {
    if (list.includes(type)) io.out(`${type} is already in ${REDACTION_OFF} of ${guard.path}: nothing changed`)
    else {
      data[REDACTION_OFF] = [...list, type]
      check(io, sources, guard, data, undefined, (version) => (version.redactionOff ?? []).includes(type))
      write(guard, data)
      io.out(`${type} turned off: added to ${REDACTION_OFF} in ${guard.path}`)
      io.err(`warning: ${type} values are no longer redacted (tool outputs, prompts, the wire, the log), the rules no longer see them as secrets, and the decision model receives them in clear`)
    }
    return
  }
  if (!list.includes(type)) io.out(`${type} is not in ${REDACTION_OFF} of ${guard.path}: nothing changed`)
  else {
    const kept = list.filter((entry) => entry !== type)
    if (kept.length) data[REDACTION_OFF] = kept
    else delete data[REDACTION_OFF]
    write(guard, data)
    io.out(`${type} turned back on: removed from ${REDACTION_OFF} in ${guard.path}`)
  }
  const { config } = parseConfig(sources.options, io.env, () => sources.declarations)
  if (config.disabledPatterns.includes(type))
    io.out(`${type} is still off: ${REDACTION_OFF} of the ${sources.origin ?? "global configuration"} (opencode.json) turns it off; remove "${type}" there by hand`)
}

/**
 * A file's absolute path (from the current directory) and its real path, absent when it does not exist. A `..` component
 * is refused: the plugin ignores such an exception (the file the kernel opens depends on the links before it).
 */
function fileOf(io: CliIo, given: string): { readonly path: string; readonly real?: string } {
  if (hasParentComponent(given)) throw new CliError(`refused, nothing written: ${given} has a ".." component (give the path without it)`)
  const path = resolve(io.cwd, given)
  const real = realOrUndefined(path)
  return { path, ...(real === undefined ? {} : { real }) }
}

/** An entry of an exceptions list names the file: its real path, or its absolute path once the file no longer exists. */
const namesFile = (entry: unknown, file: ReturnType<typeof fileOf>) =>
  typeof entry === "string" && (entry === file.path || (file.real !== undefined && (entry === file.real || (entry.startsWith("/") && realOrUndefined(entry) === file.real))))

/** `exceptions.<rule>` of the section: created if asked; a level present but not of its shape is never replaced. */
function exceptionList(data: Json, target: Target, rule: string, create: boolean): unknown[] | undefined {
  const section = sectionOf(data, target, create)
  if (!section) return undefined
  if (section.exceptions !== undefined && !isObject(section.exceptions))
    throw new CliError(`exceptions in ${placeOf(target)} of the global guard.json is not an object: it is left as is (fix it by hand)`)
  if (section.exceptions === undefined && !create) return undefined
  const exceptions = (section.exceptions ??= {}) as Json
  if (exceptions[rule] !== undefined && !Array.isArray(exceptions[rule]))
    throw new CliError(`exceptions.${rule} in ${placeOf(target)} of the global guard.json is not a list: it is left as is (fix it by hand)`)
  if (exceptions[rule] === undefined && !create) return undefined
  return (exceptions[rule] ??= []) as unknown[]
}

/** Adds the real path of an existing regular file to `exceptions.<rule>`; the plugin's resolution must retain it there. */
export function exceptPath(io: CliIo, rule: string, given: string, target: Target): void {
  const sources = readSources(io)
  const guard = globalGuard(sources)
  const { path, real } = fileOf(io, given)
  if (real === undefined) throw new CliError(`refused, nothing written: ${path} does not exist`)
  if (!statSync(real).isFile()) throw new CliError(`refused, nothing written: ${path} is not a regular file`)
  const data = structuredClone(guard.data)
  const list = exceptionList(data, target, rule, true)!
  if (list.some((entry) => namesFile(entry, { path, real }))) {
    io.out(`${real} is already in exceptions.${rule} in ${placeOf(target)} of ${guard.path}: nothing changed`)
    return
  }
  list.push(real)
  const after = check(io, sources, guard, data, target.project, (version) => version.base.policy.exceptions?.get(rule)?.has(real) === true)
  write(guard, data)
  io.out(`${real} added to exceptions.${rule} in ${placeOf(target)} of ${guard.path}${real === path ? "" : ` (the real path of ${path})`}`)
  // An exception only lifts a confirmation: none while the rule is off (or its group) or denies there.
  const setting = inForce(after, target, rule)
  const group = RULE_FEATURES.get(rule)!
  const switched = after.settings?.(target.agent).find((item) => item.key === group)
  if (setting && (setting.value === "off" || setting.value === "deny"))
    io.out(`the exception has no effect there while ruleOverrides.${rule} is "${setting.value}", set by ${setting.origin}`)
  else if (!setting && switched && switched.value === false) io.out(`the exception has no effect there while ${rule} does not apply: its group ${group} is off, set by ${switched.origin}`)
}

/**
 * Removes the file from `exceptions.<rule>` (emptied list and objects removed); says whether another source or section
 * still excepts it for the target's project, otherwise for the current directory (project guard.json files included).
 */
export function resetPath(io: CliIo, rule: string, given: string, target: Target): void {
  const sources = readSources(io)
  const guard = globalGuard(sources)
  const file = fileOf(io, given)
  const shown = file.real ?? file.path
  const data = structuredClone(guard.data)
  const list = exceptionList(data, target, rule, false)
  const kept = list?.filter((entry) => !namesFile(entry, file)) ?? []
  if (!list || kept.length === list.length) io.out(`${shown} is not in exceptions.${rule} in ${placeOf(target)} of ${guard.path}: nothing changed`)
  else {
    const exceptions = sectionOf(data, target, false)!.exceptions as Json
    if (kept.length) exceptions[rule] = kept
    else delete exceptions[rule]
    prune(data, target, "exceptions")
    write(guard, data)
    io.out(`${shown} removed from exceptions.${rule} in ${placeOf(target)} of ${guard.path}`)
  }
  const dir = target.project ?? realOrUndefined(io.cwd) ?? resolve(io.cwd)
  const files = [{ label: "global guard.json", global: true, data }, ...readGuardFiles(guardPaths(dir, sources.globalDir, io.systemDir)).filter((item) => !item.global)]
  const still = resolution(io, sources, dir, files)
    .settings?.(undefined)
    .find((row) => row.key === `exceptions.${rule}` && row.value === shown)
  if (still) io.out(`${shown} is still excepted for ${rule} in ${dir}, by ${still.origin}`)
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

/** `guard set` setting whose value is a whole number of minutes, from 1 to 60 (`unset` turns it off). */
export const MINUTES = "rememberConfirmations"

/** Policy settings `guard set` writes, and the values each takes (`ruleOverrides`: `guard rules`; `MINUTES`: a number). */
export const SWITCHES: Readonly<Record<string, readonly string[]>> = {
  profile: ["standard", "credentials-only"],
  localAsks: ["ask", "model"],
  selfProtectionByModel: ["true", "false"],
  dangerousCommands: ["true", "false"],
  sensitiveFiles: ["true", "false"],
  scripts: ["true", "false"],
  decisionModel: ["true", "false"],
  [MINUTES]: [],
}

/** The value as written in guard.json: a boolean for a switch, a number of minutes, otherwise the word. */
function switchValue(key: string, raw: string): string | boolean | number {
  const word = raw.trim().toLowerCase()
  if (key === MINUTES) {
    const minutes = /^\d{1,2}$/.test(word) ? Number(word) : 0
    if (minutes >= 1 && minutes <= 60) return minutes
    throw new CliError(`invalid value for ${key}: whole minutes from 1 to 60 expected (guard unset ${key} turns it off)`)
  }
  const allowed = SWITCHES[key]!
  if (allowed[0] === "true") {
    if (word === "true" || word === "on") return true
    if (word === "false" || word === "off") return false
  } else if (allowed.includes(word)) return word
  throw new CliError(`invalid value for ${key}: ${allowed.join(" or ")} expected${allowed[0] === "true" ? " (or on, off)" : ""}`)
}

/** New warnings of the plugin's resolution that name the key: the setting would not hold there. */
function refusedFor(io: CliIo, sources: Sources, guard: GlobalGuard, data: Json, target: Target, key: string): string[] {
  const after = resolution(io, sources, target.project, [{ label: "global guard.json", global: true, data }]).warnings
  const before = resolution(io, sources, target.project, guard.file ? [guard.file] : []).warnings
  return after.filter((line) => !before.includes(line) && line.includes(key))
}

/** A policy setting (`guard set <key> <value>`) at the target, refused when the plugin would not apply it there. */
export function setSwitch(io: CliIo, key: string, raw: string, target: Target): void {
  const value = switchValue(key, raw)
  const sources = readSources(io)
  const guard = globalGuard(sources)
  const data = structuredClone(guard.data)
  const section = sectionOf(data, target, true)!
  if (section[key] === value) {
    io.out(`${key} is already ${JSON.stringify(value)} in ${placeOf(target)} of ${guard.path}: nothing changed`)
    return
  }
  section[key] = value
  const refused = refusedFor(io, sources, guard, data, target, key)
  if (refused.length) throw new CliError(`refused, nothing written: ${refused.join("; ")}`)
  write(guard, data)
  io.out(`${key} set to ${JSON.stringify(value)} in ${placeOf(target)} of ${guard.path}`)
  const still = resolution(io, sources, target.project, [{ label: "global guard.json", global: true, data }]).settings?.(target.agent).find((item) => item.key === key)
  // As `guard show` prints it: minutes with their unit.
  if (still && String(still.value) !== (key === MINUTES ? `${value} min` : String(value))) io.out(`${key} is still ${JSON.stringify(still.value)} there, set by ${still.origin}`)
}

/** Removal of a policy setting at the target (`guard unset <key>`), and what is then in force there. */
export function unsetSwitch(io: CliIo, key: string, target: Target): void {
  const sources = readSources(io)
  const guard = globalGuard(sources)
  const data = structuredClone(guard.data)
  const section = sectionOf(data, target, false)
  if (!section || !Object.hasOwn(section, key)) io.out(`${key} is not set in ${placeOf(target)} of ${guard.path}: nothing changed`)
  else {
    delete section[key]
    prune(data, target, "")
    write(guard, data)
    io.out(`${key} removed from ${placeOf(target)} of ${guard.path}`)
  }
  const now = resolution(io, sources, target.project, [{ label: "global guard.json", global: true, data }]).settings?.(target.agent).find((item) => item.key === key)
  if (now) io.out(`${key} is now ${JSON.stringify(now.value)} there, set by ${now.origin}`)
}

/** A rule `guard rules add` writes: the fields of an entry of `rules`, as given. */
export interface NewRule {
  readonly pattern: string
  readonly verdict: string
  readonly reason?: string
  readonly tools?: readonly string[]
  readonly flags?: string
}

/** The rules option the plugin gets without a project's opencode.json, and its source in words. */
function optionRules(io: CliIo, sources: Sources) {
  return { rules: parseConfig(sources.options, io.env).config.rules, origin: `rules option of the ${sources.origin ?? "global configuration"}` }
}

/** `rules` of the global guard.json; a value that is not a list is never replaced. */
function ruleList(data: Json): unknown[] | undefined {
  if (data.rules !== undefined && !Array.isArray(data.rules)) throw new CliError("rules in the global guard.json is not a list: it is left as is (fix it by hand)")
  return data.rules as unknown[] | undefined
}

/** Positions of the entries the plugin reads as the rule `id` (their own identifier, or the file's default one). */
const positionsOf = (list: readonly unknown[], id: string) => list.flatMap((entry, index) => (isObject(entry) && ruleIdOf(entry, index, GUARD_RULES) === id ? [index] : []))

/**
 * Adds a rule to `rules` of the global guard.json: refused for an invalid verdict or pattern (compiled as the plugin does),
 * a built-in or reserved identifier, and one already used by the rules option or the file. Messages name the rule and
 * its source, never its pattern.
 */
export function addRule(io: CliIo, id: string, rule: NewRule): void {
  if (!id.trim()) throw new CliError("refused, nothing written: the rule identifier is empty")
  ownName("a rule", id)
  if (rule.verdict !== "ask" && rule.verdict !== "deny") throw new CliError('refused, nothing written: the verdict must be "ask" or "deny"')
  if (RULE_FEATURES.has(id)) throw new CliError(`refused, nothing written: ${id} is the identifier of a built-in rule (guard rules --builtins lists them)`)
  if (id === INTERNAL_ERROR_RULE) throw new CliError(`refused, nothing written: ${id} is reserved for the plugin's internal errors`)
  const sources = readSources(io)
  const guard = globalGuard(sources)
  const options = optionRules(io, sources)
  if (options.rules.some((option) => option.id === id)) throw new CliError(`refused, nothing written: a rule ${id} already exists in the ${options.origin}`)
  const data = structuredClone(guard.data)
  const list = ruleList(data) ?? []
  if (positionsOf(list, id).length) throw new CliError(`refused, nothing written: a rule ${id} already exists in rules of ${guard.path}`)
  const entry: Json = {
    id,
    pattern: rule.pattern,
    verdict: rule.verdict,
    ...(rule.reason === undefined ? {} : { reason: rule.reason }),
    ...(rule.tools === undefined ? {} : { tools: rule.tools }),
    ...(rule.flags === undefined ? {} : { flags: rule.flags }),
  }
  // Compiled before anything is written; the regex engine's message, which quotes the pattern, is never printed.
  if (!rulesOption([entry], []).length) throw new CliError(`refused, nothing written: the pattern of ${id} is not a valid regular expression${rule.flags === undefined ? "" : " with these flags"}`)
  list.push(entry)
  data.rules = list
  check(io, sources, guard, data, undefined, (version) => version.guardRules?.some((applied) => applied.id === id && applied.verdict === rule.verdict) === true)
  write(guard, data)
  io.out(`rule ${id} (${rule.verdict}) added to rules in ${guard.path}`)
}

/** Removes the rule from `rules` of the global guard.json (an emptied list is removed); never from the rules option. */
export function removeRule(io: CliIo, id: string): void {
  const sources = readSources(io)
  const guard = globalGuard(sources)
  const options = optionRules(io, sources)
  const inOptions = options.rules.some((option) => option.id === id)
  const data = structuredClone(guard.data)
  const list = ruleList(data)
  const positions = list ? positionsOf(list, id) : []
  if (!positions.length) {
    if (inOptions) throw new CliError(`rule ${id} is defined only in the ${options.origin} (opencode.json), which guard never writes: nothing removed`)
    io.out(`rule ${id} is not in rules of ${guard.path}: nothing changed`)
    return
  }
  const kept = list!.filter((_, index) => !positions.includes(index))
  if (kept.length) data.rules = kept
  else delete data.rules
  write(guard, data)
  io.out(`rule ${id} removed from rules in ${guard.path}`)
  if (inOptions) io.out(`a rule ${id} is still defined in the ${options.origin}`)
  // A rule written by hand under a built-in identifier set aside the ruleOverrides of that built-in rule.
  else if (RULE_FEATURES.has(id)) {
    const dir = realOrUndefined(io.cwd) ?? resolve(io.cwd)
    const again = resolution(io, sources, dir, [{ label: "global guard.json", global: true, data }])
      .settings?.(undefined)
      .find((row) => row.key === `ruleOverrides.${id}` && row.origin !== "default")
    if (again) io.out(`ruleOverrides.${id} "${String(again.value)}" (${again.origin}) applies again to the built-in rule ${id}`)
  }
}
