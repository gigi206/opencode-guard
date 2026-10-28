// `guard show`: the policy settings in force for the current directory (and a main agent), each with the file and
// section it comes from, the project's trust and the settings set aside with the reason (the warnings of the plugin's
// resolution). Only from the files read faithfully here; no other option of the configuration is ever printed.
import { resolve } from "node:path"
import { guardPaths, readGuardFiles } from "../guard-file.ts"
import { readSources, realOrUndefined, resolution, type CliIo } from "./context.ts"

export function show(io: CliIo, agent: string | undefined): void {
  const sources = readSources(io)
  const directory = realOrUndefined(io.cwd) ?? resolve(io.cwd)
  const paths = guardPaths(directory, sources.globalDir, io.systemDir)
  const files = readGuardFiles(paths)
  const version = resolution(io, sources, directory, files)
  io.out(`Settings for ${directory}${agent === undefined ? "" : ` with the main agent ${agent}`}, read from:`)
  for (const entry of sources.declarations) io.out(`  ${entry.label} configuration (opencode.json): ${entry.options ? "declares the plugin" : (entry.reason ?? "not read")}`)
  const global = files.find((file) => file.global)
  if (paths.global) io.out(`  global guard.json (${paths.global}): ${!global ? "absent" : global.data ? "read" : `ignored, ${global.reason}`}`)
  for (const file of files.filter((item) => !item.global)) io.out(`  ${file.label}: ${file.data ? "read" : `ignored, ${file.reason}`}`)
  io.out(
    "  Not read: the plugin options OpenCode merges from a project's opencode.json (.opencode included) or from OPENCODE_CONFIG_CONTENT; where they are set, the plugin may run with other settings (its log shows them at startup).",
  )
  io.out(`This project: ${version.trusted ? "trusted" : "not trusted"} (trustedProjects: ${version.listed?.length ? version.listed.join(", ") : "none"})`)
  io.out("Settings in force:")
  const settings = version.settings?.(agent) ?? []
  const width = (pick: (row: (typeof settings)[number]) => string) => Math.max(...settings.map((row) => pick(row).length))
  const [key, value] = [width((row) => row.key), width((row) => String(row.value))]
  for (const row of settings) io.out(`  ${row.key.padEnd(key)}  ${String(row.value).padEnd(value)}  ${row.origin}`)
  if (version.warnings.length) {
    io.out("Set aside:")
    for (const warning of version.warnings) io.out(`  ${warning}`)
  }
}
