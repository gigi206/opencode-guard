// `guard options`: every option has an entry, what an entry says about a value is what the plugin's reading does with it,
// a secret is never printed. Fake settings in throwaway directories, nothing is run.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { main } from "../src/cli/main.ts"
import { OPTIONS } from "../src/cli/options.ts"
import { DECISION_KEYS, DEFAULT_OUTPUT_CHECK, DEFAULT_PROMPT_TUNING, OPTION_KEYS, OUTPUT_CHECK_KEYS, parseConfig, PROMPT_CHECK_KEYS, THRESHOLD_KEYS } from "../src/config.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
const KEY = "KEY-MARKER-opencode-guard"
const BASE = { baseURL: "https://decision.example.invalid/v1", model: "m" }

function world(options: Record<string, unknown>, raw?: string, env: Record<string, string> = {}, guard?: Record<string, unknown>) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-options-")))
  const [globalDir, systemDir, home, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "project")]
  for (const dir of [globalDir, systemDir, home, project]) mkdirSync(dir, { recursive: true })
  writeFileSync(join(globalDir, "opencode.json"), raw ?? JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options }] }))
  if (guard) writeFileSync(join(globalDir, "guard.json"), JSON.stringify(guard))
  return (args: string[], terminal?: { width: number; color: boolean }) => {
    const [out, err]: string[][] = [[], []]
    const code = main(args, { env: { HOME: home, OPENCODE_CONFIG_DIR: globalDir, ...env }, cwd: project, systemDir, out: (line) => out.push(line), err: (line) => err.push(line), ...(terminal ? { terminal } : {}) })
    return { code, out, err }
  }
}
const row = (lines: readonly string[], name: string) => lines.find((line) => line.startsWith(`${name} `))?.trim().split(/ {2,}/)
const names = new Set(OPTIONS.map((entry) => entry.name))
const set = (name: string, value: unknown): Record<string, unknown> => {
  const [head, leaf] = name.split(".")
  if (!leaf) return { [head!]: value }
  return { [head!]: { ...(head === "decision" ? BASE : {}), [leaf]: value } }
}

describe("guard options: entries", () => {
  it("every option and sub-option has exactly one entry", () => {
    assert.equal(names.size, OPTIONS.length)
    const nested = ["decision", "thresholds", "outputCheck", "promptCheck"]
    for (const key of OPTION_KEYS) assert.ok(names.has(key) || nested.includes(key), key)
    for (const key of DECISION_KEYS) assert.ok(names.has(`decision.${key}`), key)
    for (const key of THRESHOLD_KEYS) assert.ok(names.has(`thresholds.${key}`), key)
    for (const key of OUTPUT_CHECK_KEYS) assert.ok(names.has(`outputCheck.${key}`), key)
    for (const key of PROMPT_CHECK_KEYS) assert.ok(names.has(`promptCheck.${key}`), key)
    for (const key of Object.keys(DEFAULT_OUTPUT_CHECK.tuning)) assert.ok(names.has(`outputCheck.${key}`), key)
    for (const key of Object.keys(DEFAULT_PROMPT_TUNING)) assert.ok(names.has(`promptCheck.${key}`), key)
  })
  it("every option is in the documentation", () => {
    const docs = ["configuration.md", "decision-model.md"].map((file) => readFileSync(join(PLUGIN_DIR, "docs", file), "utf8")).join("\n")
    for (const name of names) assert.ok(docs.includes(name.split(".").pop()!), name)
  })
  it("the bounds of a number are those of the plugin", () => {
    for (const entry of OPTIONS.filter((item) => item.range && !["rememberConfirmations"].includes(item.name))) {
      const [min, max] = entry.range!
      const accepted = (value: number) => {
        const options = set(entry.name, value)
        const { config } = parseConfig(options, {}, () => [{ label: "global", options }])
        return entry.read(config) === value
      }
      assert.ok(accepted(min), `${entry.name} min`)
      assert.ok(accepted(max), `${entry.name} max`)
      assert.ok(!accepted(max + 1), `${entry.name} above`)
      if (min > 0) assert.ok(!accepted(min - 1), `${entry.name} below`)
    }
  })
  it("the values of a closed list are those of the plugin", () => {
    for (const entry of OPTIONS.filter((item) => item.values && !["outputCheck", "promptCheck", "localAsks"].includes(item.name))) {
      for (const [value] of entry.values!) {
        const options = set(entry.name, value)
        const { config } = parseConfig(options, {}, () => [{ label: "global", options }])
        assert.equal(String(entry.read(config)), value, entry.name)
      }
      const options = set(entry.name, "no-such-value")
      assert.notEqual(entry.read(parseConfig(options, {}, () => [{ label: "global", options }]).config), "no-such-value", entry.name)
    }
  })
})

describe("guard options: table", () => {
  it("the default comes from the plugin; a value set is marked with its origin", () => {
    const { code, out } = world({ debug: true, cacheMax: 500 })(["options"])
    assert.equal(code, 0)
    assert.deepEqual(row(out, "debug"), ["debug", "boolean", "true", "false", "global opencode.json", "overridden"])
    assert.deepEqual(row(out, "cacheMax"), ["cacheMax", "integer", "500", "500", "global opencode.json", "same as default"])
    assert.deepEqual(row(out, "maxStateChars"), ["maxStateChars", "integer", "4000", "4000", "default", "default"])
  })
  it("a value refused is shown beside the one retained", () => {
    const run = world({ cacheTtlMs: 9_999_999 })
    assert.equal(row(run(["options"]).out, "cacheTtlMs")![5], "ignored")
    const lines = run(["options", "--explain", "cacheTtlMs"]).out.join("\n")
    assert.match(lines, /In force: \d+ \(written: 9999999, ignored/)
  })
  it("a rule set has its own row", () => {
    const lines = world({ ruleOverrides: { eval: "deny" } })(["options"]).out
    assert.deepEqual(row(lines, "ruleOverrides.eval")?.slice(2), ["deny", "none", "global opencode.json", "overridden"])
    assert.equal(row(lines, "ruleOverrides")![2], "1 rule")
  })
  it("the scope of a setting: opencode.json, then guard.json over it, and the defaults of the decision model", () => {
    const run = world({ decision: BASE, localAsks: "ask" }, undefined, {}, { localAsks: "model", ruleOverrides: { eval: "deny" } })
    const lines = run(["options"]).out
    assert.match(row(lines, "localAsks")!.join(" "), /global guard\.json/)
    assert.deepEqual(row(lines, "ruleOverrides.eval")?.slice(2, 4), ["deny", "none"])
    assert.match(row(lines, "ruleOverrides.eval")![4]!, /global guard\.json/)
    assert.deepEqual(row(lines, "decision.timeoutMs")?.slice(2, 4), ["5000", "5000"])
    assert.deepEqual(row(lines, "decision.protocol")?.slice(2, 4), ["chat", "chat"])
  })
  it("a secret is never printed, in the table or the explanation", () => {
    const run = world({ decision: { ...BASE, apiKey: KEY, headers: { "X-Test": KEY } }, allowlist: [KEY] })
    for (const args of [["options"], ["options", "--explain", "all"], ["options", "--explain", "decision.apiKey"]]) {
      const text = run(args).out.join("\n")
      assert.ok(!text.includes(KEY), args.join(" "))
    }
    const lines = run(["options"]).out
    assert.equal(row(lines, "decision.apiKey")![2], "set")
    assert.equal(row(lines, "decision.headers")![2], "1 header")
    assert.equal(row(lines, "allowlist")![2], "1 entry")
  })
  it("a terminal gets the aligned layout, and redirected output none of it", () => {
    const run = world({ debug: true })
    const pretty = run(["options"], { width: 170, color: false }).out
    assert.ok(pretty.some((line) => line.includes("Option") && line.includes("In force") && line.includes("Default")))
    assert.ok(pretty.some((line) => /^ {4}debug\s+boolean\s+true\s+false\s+global opencode.json, overridden/.test(line)))
  })
})

describe("guard options: explanation", () => {
  it("type, bounds, values and meaning", () => {
    const run = world({})
    const askAs = run(["options", "--explain", "askAs"]).out.join("\n")
    assert.match(askAs, /Type: string/)
    assert.match(askAs, /Value deny: every confirmation becomes a refusal/)
    assert.match(run(["options", "--explain", "cacheMax"]).out.join("\n"), /Range: 0 to 10000/)
  })
  it("an {env:…} reference is shown with what it resolves to here", () => {
    const raw = JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: { askAs: "{env:FAKE_ASK}" } }] })
    const text = world({}, raw, { FAKE_ASK: "deny" })(["options", "--explain", "askAs"]).out.join("\n")
    assert.match(text, /In force: deny/)
    assert.match(text, /Reference: \{env:FAKE_ASK\}.*the server's may differ/)
  })
  it("all explains every option; an unknown one is an error", () => {
    const run = world({})
    const lines = run(["options", "--explain", "all"]).out
    for (const name of names) assert.ok(lines.includes(name), name)
    assert.equal(run(["options", "--explain", "nosuch"]).code, 1)
  })
})
