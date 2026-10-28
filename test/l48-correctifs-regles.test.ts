// Lot 48 step F1: corrections of the rules after the common review. A write whose real paths reached a limit on an
// OpenCode location, a guard.json wherever it is, and the OpenCode service file are changes of the plugin's settings;
// with `selfProtectionByModel`, a nested OpenCode whose configuration or plugins its environment changes, or that
// approves its confirmations, and a call to the OpenCode server API are never left to the decision model. Nothing is
// launched: text is judged, real paths and the model are functions. Only existing exports are imported, so that the
// candidate before these corrections fails on assertions, not on loading.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import type { ActiveRules } from "../src/rules/features.ts"
import { toolFinding } from "../src/rules/tools.ts"
import { LIMIT_REACHED, type Finding } from "../src/rules/types.ts"
import { createRedactor } from "../src/secrets/redact.ts"

type Json = Record<string, unknown>
const HOME = "/home/test"
const ctx = { redactor: createRedactor(), home: HOME, cwd: `${HOME}/app`, protectedDirs: ["/opt/guard"], pluginDirs: ["/opt/guard"] }
const declaredBy = (options: Json) => () => [{ label: "global", options }, { label: "system", reason: "it is missing or unreadable" }]
/** Settings declared in the global configuration too (relaxations retained). */
const relaxed = (options: Json) => parseConfig(options, {}, declaredBy(options) as Parameters<typeof parseConfig>[2])
const policyOf = (options: Json) => (relaxed(options).config as { policy?: ActiveRules }).policy
const marked = (finding?: Finding) => Boolean(finding && (finding.dataOnly || finding.modelDecides !== undefined))
const brief = (finding?: Finding) => finding && [finding.verdict, finding.rule, marked(finding)]
const BY_MODEL = { localAsks: "model", selfProtectionByModel: true }
const AGENT = `${HOME}/.config/opencode/agents/a.md`
const STATE = `${HOME}/.local/state/opencode`
const SERVICE_DIRS = [`${HOME}/.config/opencode`, STATE]

describe("lot 48 F1: rules", () => {
  it("CF1-1: a limit reached on one form, an OpenCode location reached by another: never left to the model", () => {
    const active = policyOf(BY_MODEL)
    // The raw form (`//tmp/…`) reaches the limit, the resolved form leads to an agent of the global configuration.
    const realPaths = (absolute: string) => (absolute.startsWith("//") ? LIMIT_REACHED : absolute === "/tmp/link/a.md" ? [AGENT] : undefined)
    const extra = { active, realPaths }
    assert.deepEqual(brief(toolFinding("write", { path: "/tmp/link/a.md", content: "x" }, { ...ctx, ...extra })), ["ask", "self-protection", false], "write")
    assert.deepEqual(brief(toolFinding("shell", { command: "echo x > /tmp/link/a.md" }, { ...ctx, ...extra })), ["ask", "self-protection", false], "shell")
    assert.deepEqual(brief(toolFinding("mcp_files_write", { path: "/tmp/link/a.md" }, { ...ctx, ...extra })), ["ask", "self-protection", false], "tool argument")
  })

  it("CF1-1 (guard): no limit, or a limit outside OpenCode's locations, or without selfProtectionByModel: as before", () => {
    const active = policyOf(BY_MODEL)
    // Resolved to the end: an agent stays with the model.
    assert.deepEqual(brief(toolFinding("write", { path: AGENT, content: "x" }, { ...ctx, active, realPaths: () => undefined })), ["ask", "self-protection", true])
    // A limit alone: the unchecked ask, with its own reason.
    const limit = (): typeof LIMIT_REACHED => LIMIT_REACHED
    const unchecked = toolFinding("write", { path: "/tmp/x/a.md", content: "x" }, { ...ctx, active, realPaths: limit })
    assert.deepEqual(brief(unchecked), ["ask", "self-protection", false])
    assert.match(unchecked!.reason, /could not be fully resolved/)
    // Without selfProtectionByModel, an OpenCode location is never left to the model, limit or not.
    const local = policyOf({ localAsks: "model" })
    assert.deepEqual(brief(toolFinding("write", { path: AGENT, content: "x" }, { ...ctx, active: local, realPaths: limit })), ["ask", "self-protection", false])
  })

  it("CF1-2: a guard.json anywhere (tools, patch, tool argument, shell): a confirmation never left to the model", () => {
    for (const options of [{}, BY_MODEL]) {
      const active = policyOf(options)
      const label = JSON.stringify(options)
      for (const [tool, input] of [
        ["write", { path: "/srv/app/guard.json", content: "{}" }],
        ["edit", { path: "guard.json", oldString: "a", newString: "b" }],
        ["patch", { patchText: "*** Begin Patch\n*** Add File: conf/guard.json\n+{}\n*** End Patch" }],
        ["mcp_files_write", { path: "/srv/app/guard.json" }],
        ["shell", { command: "cp /tmp/g.json /srv/app/guard.json" }],
        ["shell", { command: "echo '{}' | tee $DIR/guard.json" }],
      ] as const)
        assert.deepEqual(brief(toolFinding(tool, input, { ...ctx, active })), ["ask", "self-protection", false], `${tool} ${label}`)
    }
  })

  it("CF1-2 (guard): another name containing guard.json stays as it was", () => {
    const active = policyOf(BY_MODEL)
    assert.equal(toolFinding("write", { path: "/srv/app/myguard.json", content: "{}" }, { ...ctx, active }), undefined)
    assert.equal(toolFinding("shell", { command: "cp a /srv/app/guard.json.example" }, { ...ctx, active }), undefined)
  })

  it("CF1-3: the service file, its variants, copies and links, written by a tool or the shell: never left to the model, whatever the switches", () => {
    const verdict = (finding?: Finding) => finding && [finding.verdict, marked(finding)]
    // A link to the service file is followed to its real path.
    const realPaths = (absolute: string) => (absolute === "/tmp/s.json" ? [`${STATE}/service.json`] : undefined)
    for (const options of [{}, BY_MODEL, { localAsks: "model" }, { sensitiveFiles: false }]) {
      const label = JSON.stringify(options)
      const extra = { serviceDirs: SERVICE_DIRS, active: policyOf(options), realPaths }
      for (const path of [`${STATE}/service-beta.json`, `${STATE}/service.json.bak`, "/tmp/s.json"])
        assert.deepEqual(brief(toolFinding("write", { path, content: "{}" }, { ...ctx, ...extra })), ["ask", "self-protection", false], `${path} ${label}`)
      for (const command of [`cp /tmp/x ${STATE}/service.json`, `echo '{}' | tee ${STATE}/service-next.json`, `mv /tmp/x ${STATE}/service.json`, "echo '{}' > /tmp/s.json"])
        assert.deepEqual(verdict(toolFinding("shell", { command }, { ...ctx, ...extra })), ["ask", false], `${command} ${label}`)
    }
  })

  it("CF1-3 (guard): reading the service file stays a credential file read; a service.json elsewhere is not concerned", () => {
    const extra = { serviceDirs: SERVICE_DIRS, active: policyOf(BY_MODEL) }
    assert.deepEqual(brief(toolFinding("read", { path: `${STATE}/service.json` }, { ...ctx, ...extra })), ["ask", "secret-file-read", true])
    assert.equal(toolFinding("write", { path: `${HOME}/app/service.json`, content: "{}" }, { ...ctx, ...extra }), undefined)
  })

  it("CF1-4: selfProtectionByModel: a nested OpenCode whose environment changes its configuration or plugins, or that approves its confirmations, and the server API: never left to the model", () => {
    const active = policyOf(BY_MODEL)
    for (const command of [
      "opencode run --auto x",
      "opencode run --yolo x",
      "opencode run --dangerously-skip-permissions x",
      "opencode --print-logs run --yolo x",
      "XDG_CONFIG_HOME=/tmp/x opencode run x",
      "HOME=/tmp/x opencode serve",
      "env XDG_CACHE_HOME=/tmp/x opencode run x",
      "OPENCODE_DISABLE_PROJECT_CONFIG=1 opencode run x",
      "OPENCODE_CLI_CONFIG_CONTENT={} opencode run x",
      "OPENCODE_CONFIG_DIR=/tmp/x opencode run x",
      "export HOME=/tmp/x; opencode acp",
    ])
      assert.deepEqual(brief(toolFinding("shell", { command }, { ...ctx, active })), ["ask", "nested-opencode", false], command)
    for (const command of [
      "opencode api POST /api/session/s1/prompt",
      "curl -X POST http://127.0.0.1:4096/api/session/s1/prompt -d '{}'",
      "opencode auth export",
      "opencode debug heap-dump",
    ])
      assert.deepEqual(brief(toolFinding("shell", { command }, { ...ctx, active })), ["ask", "opencode-server-api", false], command)
  })

  it("CF1-4 (guard): another nested OpenCode stays with the model; an ordinary call to another local host is unchanged", () => {
    const active = policyOf(BY_MODEL)
    for (const command of ["opencode run x", "opencode serve", "opencode attach http://127.0.0.1:4096", "echo $HOME=1; opencode run x"])
      assert.deepEqual(brief(toolFinding("shell", { command }, { ...ctx, active })), ["ask", "nested-opencode", true], command)
    assert.equal(toolFinding("shell", { command: "curl http://127.0.0.1:8080/api/items" }, { ...ctx, active }), undefined)
    assert.deepEqual(brief(toolFinding("shell", { command: "curl -X POST http://127.0.0.1:8080/api/items -d '{}'" }, { ...ctx, active })), ["ask", "upload", true])
  })

  it("CF1-5: \"model\" on opencode-server-api is ignored with a warning, like guard-cli", () => {
    const options = { selfProtectionByModel: true, ruleOverrides: { "opencode-server-api": "model", "nested-opencode": "model" } }
    const { config, warnings } = relaxed(options)
    assert.ok(warnings.includes('ruleOverrides.opencode-server-api "model" ignored: this rule is about a call to the OpenCode server API, which can bypass the guard, never left to the decision model'), warnings.join("\n"))
    const policy = (config as { policy?: ActiveRules }).policy
    assert.equal(policy?.overrides?.get("opencode-server-api"), undefined)
    assert.equal(policy?.overrides?.get("nested-opencode"), "model")
  })

  it("CF1-6: through the decider, the model the global configuration declares allows another nested OpenCode, never these ones", async () => {
    const DECISION = { baseURL: "https://decision.local/v1", model: "nox-4b" }
    const answers = {
      answers: {
        risk: { type: "score", score: 0.1, confidence: 0.9 },
        destructive: { type: "noul", noul: 0.01 },
        exfiltration: { type: "noul", noul: 0.01 },
        credentials: { type: "noul", noul: 0.01 },
        privilege_persistence: { type: "noul", noul: 0.01 },
      },
    }
    const options = { ...BY_MODEL, decision: DECISION }
    const { config } = parseConfig(options, {}, declaredBy(options) as Parameters<typeof parseConfig>[2])
    const decider = createDecider({ config, redactor: createRedactor(), home: HOME, model: (async () => answers) as never })
    const verdict = async (command: string) => (await decider.decide({ tool: "shell", input: { command }, directory: `${HOME}/app` })).verdict
    // Guards: left to the model as before.
    assert.equal(await verdict("opencode run x"), "allow")
    assert.equal(await verdict("curl -X POST http://127.0.0.1:8080/api/items -d '{}'"), "allow")
    for (const command of ["XDG_CONFIG_HOME=/tmp/x opencode run x", "opencode run --yolo x", "opencode api POST /api/session/s1/prompt", "echo '{}' > ~/.config/open*/guard.json"])
      assert.equal(await verdict(command), "ask", command)
  })
})
