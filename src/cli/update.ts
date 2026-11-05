// `guard update`: the plugin installed from a Git specifier, updated by OpenCode. OpenCode's output is relayed, never parsed;
// what changed is read from the lock files (`version.ts`). Always with the specifier: without one, OpenCode would update every
// plugin. `--check` only runs `opencode plugin check`.
import { execFile } from "node:child_process"
import { packageInstall } from "../output-check.ts"
import { CliError, type CliIo } from "./context.ts"
import { installed, latestCommit, short } from "./version.ts"

export interface OpencodeRun {
  /** Exit code; with `problem`, whatever is known. */
  readonly code: number
  readonly stdout: string
  readonly stderr: string
  /** `opencode` did not run to its end, in words. */
  readonly problem?: string
}

/** `opencode` with these arguments, in that directory, with that environment, for at most that long. */
export type Opencode = (args: readonly string[], options: { readonly cwd: string; readonly env: CliIo["env"]; readonly timeout: number }) => Promise<OpencodeRun>

const CHECK_TIMEOUT_MS = 60_000
const UPDATE_TIMEOUT_MS = 300_000
const MAX_OUTPUT_BYTES = 1024 * 1024

/**
 * No shell, and nothing read from the keyboard. `BUN_BE_BUN` goes: the launcher of a Git install sets it to run this command
 * with the Bun inside OpenCode, and `opencode` would be Bun with it. The rest of the environment is passed on as it is.
 */
export const runOpencode: Opencode = (args, { cwd, env, timeout }) =>
  new Promise((done) => {
    const { BUN_BE_BUN: _, ...environment } = env
    const child = execFile("opencode", [...args], { cwd, env: environment, timeout, maxBuffer: MAX_OUTPUT_BYTES, encoding: "utf8" }, (error, stdout, stderr) => {
      const code = (error as { code?: unknown } | null)?.code
      if (!error) done({ code: 0, stdout, stderr })
      else if (typeof code === "number") done({ code, stdout, stderr })
      else if (code === "ENOENT") done({ code: 1, stdout, stderr, problem: "opencode not found: is it in PATH?" })
      else if (error.killed) done({ code: 1, stdout, stderr, problem: `opencode stopped after ${timeout / 1000} s, or for printing too much` })
      else done({ code: 1, stdout, stderr, problem: `opencode failed: ${error.message}` })
    })
    child.stdin?.end()
  })

const ESCAPE_SEQUENCE = /\x1b\[[0-9;?]*[ -/]*[@-~]/g

function relay(text: string, print: (line: string) => void): void {
  const lines = text.replace(ESCAPE_SEQUENCE, "").split(/\r?\n/)
  if (!lines.at(-1)) lines.pop()
  for (const line of lines) print(line)
}

const PINNED = /#[0-9a-f]{40}$/i
const CHANGE_PINNED = "to change version, edit the commit in opencode.json, in the plugin entry and in its plugin.use policy if it has one, then restart the server"

/** What the lock files say: the commit before and after, or that it is not known. */
function change(io: CliIo, before: string | undefined, after: string | undefined): void {
  if (!after) io.out(`The installed commit could not be read${before ? ` (it was ${short(before)})` : ""}: guard show gives it.`)
  else if (after === before) io.out(`Nothing changed: still at ${short(after)}.`)
  else {
    io.out(before ? `Installed commit: ${short(before)} -> ${short(after)}.` : `Installed commit: ${short(after)} (before: unknown).`)
    io.out("Whether OpenCode has loaded it yet: guard status, on its files line; if it has not, restart the server.")
  }
}

/** Exit code: 0, the one `opencode` gave, or 1 when it did not run to its end. A plugin that cannot be updated is a refusal. */
export async function update(io: CliIo, directory: string, check: boolean): Promise<number> {
  const install = packageInstall(directory)
  if (!install) throw new CliError(`the plugin runs from a directory, not from a Git install: nothing run (${directory} is updated with Git)`)
  const specifier = installed(install.generation, install.name)?.specifier
  if (!specifier || specifier.startsWith("-")) throw new CliError("the installed plugin's lock file gives no Git specifier: nothing run")
  if (PINNED.test(specifier)) {
    if (!check) throw new CliError(`${specifier} is pinned to a commit: nothing run; ${CHANGE_PINNED}`)
    // A full commit cannot move: nothing to ask OpenCode, and not a failure.
    io.out(`${specifier} is pinned to a commit: nothing to check; ${CHANGE_PINNED}.`)
    return 0
  }
  const verb = check ? "check" : "update"
  const before = check ? undefined : latestCommit(install.entry, install.name)
  if (!check) io.out(`Running opencode plugin update ${specifier}`)
  const ran = await (io.opencode ?? runOpencode)(["plugin", verb, specifier], { cwd: io.cwd, env: io.env, timeout: check ? CHECK_TIMEOUT_MS : UPDATE_TIMEOUT_MS })
  relay(ran.stdout, io.out)
  relay(ran.stderr, io.err)
  const failure = ran.problem ?? (ran.code ? `opencode plugin ${verb} exited with code ${ran.code}` : undefined)
  if (failure) io.err(`guard: ${failure}`)
  if (!check) change(io, before, latestCommit(install.entry, install.name))
  return failure ? ran.code || 1 : 0
}
