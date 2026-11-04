// The plugin's version for `guard show`: its commit, and whether it is the HEAD or a tag. Installed from a Git specifier,
// the commit comes from the lock file OpenCode wrote beside `node_modules` and the references from `git ls-remote`, unless
// offline; run from a repository, everything comes from that repository. A failure only leaves the state unknown.
import { execFileSync } from "node:child_process"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { packageInstall } from "../output-check.ts"
import type { Style } from "./style.ts"

/** `git` with these arguments, in that directory: its output, or `undefined` if it fails. */
export type Git = (args: readonly string[], directory?: string) => string | undefined

const REMOTE_TIMEOUT_MS = 3000

/** Neither the user's nor a project's git configuration: nothing they set can run or redirect this command. */
export const runGit: Git = (args, directory = "/") => {
  try {
    return execFileSync("git", [...args], {
      cwd: directory,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: REMOTE_TIMEOUT_MS,
      env: { PATH: process.env.PATH, GIT_TERMINAL_PROMPT: "0", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" },
    })
  } catch {
    return undefined
  }
}

export interface PluginVersion {
  /** Where the plugin comes from. */
  readonly source: string
  readonly state: string
  readonly style: Style
}

const SHORT = 7
const short = (commit: string) => commit.slice(0, SHORT)

/** The Git entry of the installed plugin: its specifier, its commit and its repository's address. */
function installed(generation: string, name: string) {
  try {
    const lock = JSON.parse(readFileSync(join(generation, "package-lock.json"), "utf8"))
    const resolved = lock?.packages?.[`node_modules/${name}`]?.resolved
    const specifier = lock?.packages?.[""]?.dependencies?.[name]
    const match = typeof resolved === "string" ? /github\.com[/:]([\w.-]+\/[\w.-]+?)(?:\.git)?#([0-9a-f]{40})$/.exec(resolved) : null
    if (!match || typeof specifier !== "string") return undefined
    return { specifier, url: `https://github.com/${match[1]}.git`, commit: match[2]! }
  } catch {
    return undefined
  }
}

/** Tags of a commit in `git ls-remote` lines: an annotated tag counts by the commit it points to (`^{}`). */
function remoteTags(lines: readonly (readonly string[])[], commit: string): string[] {
  const tags = lines.flatMap(([sha, ref]) => (sha === commit && ref?.startsWith("refs/tags/") ? [ref.slice("refs/tags/".length).replace(/\^\{\}$/, "")] : []))
  return [...new Set(tags)]
}

/** The commit, what it is, and how much is known about it. */
function described(commit: string, head: boolean, tags: readonly string[]): { state: string; style: Style } {
  const what = [...(head ? ["HEAD"] : []), ...tags.map((tag) => `tag ${tag}`)]
  return what.length ? { state: `${short(commit)} (${what.join(", ")})`, style: "good" } : { state: `${short(commit)} (not HEAD, no tag)`, style: "warn" }
}

export function pluginVersion(directory: string, git: Git, offline: boolean): PluginVersion {
  const install = packageInstall(directory)
  if (install) {
    const entry = installed(install.generation, install.name)
    if (!entry) return { source: "plugin", state: "commit unknown", style: "warn" }
    const source = `plugin (${entry.specifier})`
    const unknown = (why: string) => ({ source, state: `${short(entry.commit)} (${why})`, style: "dim" as const })
    if (offline) return unknown("HEAD and tags not checked")
    const remote = git(["ls-remote", entry.url])
    if (remote === undefined) return unknown("repository not reached")
    const lines = remote.split("\n").map((line) => line.split("\t"))
    return { source, ...described(entry.commit, lines.some(([sha, ref]) => ref === "HEAD" && sha === entry.commit), remoteTags(lines, entry.commit)) }
  }
  const commit = git(["rev-parse", "HEAD"], directory)?.trim()
  if (!commit) return { source: `plugin (${directory})`, state: "commit unknown", style: "dim" }
  const tags = (git(["tag", "--points-at", "HEAD"], directory) ?? "").split("\n").filter(Boolean)
  return { source: `plugin (${directory})`, ...described(commit, true, tags) }
}
