// `guard rules`: the built-in rules, then the user's own rules (`rules` option) as the plugin reads them from the options
// it gets without a project's opencode.json (the system entry, loaded last, else the global one), with the rules set
// aside and the plugin's warning; `--builtins` and `--custom` keep one section. Run in process on test directories.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { main } from "../src/cli/main.ts"
import { ruleLines } from "../src/cli/rules.ts"
import { RULE_FEATURES } from "../src/rules/features.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
type Json = Record<string, unknown>

/** Global and system configuration directories of a test; each declares the plugin with these options when given. */
function world(setup: { readonly global?: Json; readonly system?: Json } = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-rules-")))
  const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "app")]
  for (const dir of [globalDir, systemDir, home, data, project]) mkdirSync(dir, { recursive: true })
  for (const [dir, options] of [[globalDir, setup.global], [systemDir, setup.system]] as const)
    if (options) writeFileSync(join(dir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options }] }))
  const env = { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }
  return (...args: string[]) => {
    const out: string[] = []
    const err: string[] = []
    const code = main(args, { env, cwd: project, systemDir, out: (line: string) => out.push(line), err: (line: string) => err.push(line) })
    return { code, out, err }
  }
}

const NO_PROD = { id: "no-prod", pattern: "--env=prod", verdict: "deny", reason: "production deployments are forbidden" }
const NOTE = /^ {2}Not shown: a project's opencode\.json can replace this whole list/

describe("guard rules: built-in rules and the user's own", () => {
  it("CLI-1: by default, the built-in rules then the user's rules of the global configuration, with the note", () => {
    const r = world({ global: { rules: [NO_PROD, { pattern: "kubectl apply", verdict: "ask", tools: ["shell", "patch"] }] } })("rules")
    assert.equal(r.code, 0)
    assert.equal(r.err.length, 0)
    assert.equal(r.out[0], "Built-in rules:")
    const builtins = ruleLines()
    assert.deepEqual(r.out.slice(1, 1 + builtins.length), builtins.map((line) => `  ${line}`))
    const own = r.out.slice(1 + builtins.length)
    assert.equal(own[0], "Your rules (rules option of the global configuration):")
    assert.match(own[1]!, /^ {2}no-prod +deny +shell +production deployments are forbidden +\/--env=prod\/$/)
    assert.match(own[2]!, /^ {2}custom-1 +ask +shell,patch +custom rule 1 +\/kubectl apply\/$/)
    assert.match(own[3]!, NOTE)
    assert.equal(own.length, 4)
  })

  it("CLI-2: --builtins keeps the former output, --custom the user's section; both are the default; an unknown option is a usage error", () => {
    const run = world({ global: { rules: [NO_PROD] } })
    const builtins = run("rules", "--builtins")
    assert.equal(builtins.code, 0)
    assert.deepEqual(builtins.out, ruleLines())
    assert.equal(builtins.out.length, RULE_FEATURES.size)
    const custom = run("rules", "--custom")
    assert.equal(custom.code, 0)
    assert.equal(custom.out[0], "Your rules (rules option of the global configuration):")
    assert.match(custom.out[1]!, /^ {2}no-prod +deny /)
    assert.match(custom.out.at(-1)!, NOTE)
    assert.deepEqual(run("rules", "--builtins", "--custom").out, run("rules").out)
    assert.equal(run("rules", "--frobnicate").code, 2)
    assert.equal(run("rules", "extra").code, 2)
  })

  it("CLI-3: the system entry replaces the global one, rules included, as for the plugin", () => {
    const replaced = world({ global: { rules: [NO_PROD] }, system: { rules: [{ id: "sys-only", pattern: "terraform apply", verdict: "ask" }] } })("rules", "--custom")
    assert.equal(replaced.out[0], "Your rules (rules option of the system configuration, which replaces the global entry):")
    assert.match(replaced.out[1]!, /^ {2}sys-only +ask +shell /)
    assert.ok(!replaced.out.some((line) => line.includes("no-prod")))
    // The system entry without rules: none, even though the global file has some.
    const none = world({ global: { rules: [NO_PROD] }, system: {} })("rules", "--custom")
    assert.equal(none.out[0], "Your rules (rules option of the system configuration, which replaces the global entry):")
    assert.equal(none.out[1], "  none")
  })

  it("CLI-4: rules the plugin sets aside are listed with its warning; renamed and reused identifiers are shown as applied", () => {
    const r = world({
      global: {
        rules: [
          { id: "bad-verdict", pattern: "x", verdict: "block" },
          { id: "no-pattern", verdict: "ask" },
          { id: "bad-regex", pattern: "(", verdict: "ask" },
          { id: "placeholder", pattern: "reserved-id", verdict: "ask" },
          { id: "v1-tool", pattern: "make deploy", verdict: "ask", tools: ["bash"] },
          { id: "eval", pattern: "eval-again", verdict: "deny" },
        ],
      },
    })("rules", "--custom")
    assert.equal(r.code, 0)
    const text = r.out.join("\n")
    assert.match(text, /^ {2}custom-3 +ask +shell +custom rule 3 +\/reserved-id\/$/m)
    assert.match(text, /^ {2}v1-tool +ask +bash,shell +custom rule 4 +\/make deploy\/$/m)
    assert.match(text, /^ {2}eval +deny +shell +custom rule 5 +\/eval-again\/ {2}\(same identifier as a built-in rule\)$/m)
    const aside = r.out.slice(r.out.indexOf("  Set aside:") + 1, -1)
    assert.ok(aside.length >= 5, text)
    assert.ok(aside.every((line) => /^ {4}(?:invalid )?rules\b/.test(line)), text)
    for (const fragment of ["rules[0].verdict", "rules[1]: missing pattern", "rules[2]: invalid regex", 'rules[3].id "placeholder"', 'rules[4].tools: "bash"'])
      assert.ok(aside.some((line) => line.includes(fragment)), fragment)
    assert.ok(!r.out.some((line) => /^ {2}(?:bad-verdict|no-pattern|bad-regex) /.test(line)))
  })

  it("CLI-5: a pattern shaped like a secret is redacted, like every line of the command", () => {
    const fake = `ghp_${"a1B2".repeat(9)}`
    const r = world({ global: { rules: [{ id: "token-in-command", pattern: fake, verdict: "deny" }] } })("rules", "--custom")
    const text = r.out.join("\n")
    assert.ok(!text.includes(fake))
    assert.match(text, /^ {2}token-in-command +deny +shell .*\[\[GUARD_REDACTED:/m)
  })

  it("CLI-6: without the plugin declared, the user's section says why; the built-in rules are still listed", () => {
    const run = world()
    const all = run("rules")
    assert.equal(all.code, 0)
    assert.equal(all.out[0], "Built-in rules:")
    assert.equal(all.out.length, 1 + RULE_FEATURES.size + 1)
    assert.match(all.out.at(-1)!, /^Your rules: none read, the plugin is not declared \(global configuration: .+; system configuration: .+\)$/)
    assert.deepEqual(run("rules", "--builtins").out, ruleLines())
  })
})
