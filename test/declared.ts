// Plugin options as the global configuration declares them: what turns a protection off counts only from there.
import "./tmp.ts"
import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { declaredPluginOptions } from "../src/output-check.ts"

type Json = Record<string, unknown>
const SWITCHES = ["redactOutputs", "redactPrompt", "redactWire", "dangerousCommands", "sensitiveFiles", "decisionModel", "scripts", "outputCheck", "promptCheck"]

/** The switches among these options. */
export const switchesOf = (options: Json): Json => Object.fromEntries(Object.entries(options).filter(([key]) => SWITCHES.includes(key)))

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))

/** A temporary global configuration directory that declares the plugin with these options. */
export function globalConfig(options: Json): string {
  const dir = mkdtempSync(join(tmpdir(), "guard-declared-"))
  writeFileSync(join(dir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options }] }))
  return dir
}

/** The `declared` argument of `parseConfig`: that file read as the plugin reads it, no system configuration. */
export function declaring(options: Json) {
  const globalDir = globalConfig(options)
  return () => declaredPluginOptions({ pluginDir: PLUGIN_DIR, globalDir, systemDir: join(globalDir, "no-system"), env: {} })
}
