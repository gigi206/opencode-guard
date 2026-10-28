// Lot 48, common review R1 (decision and rules): each test states the intended behavior; a failing one proves a defect.
// Only symbols the deployed code already exports are imported, so that it fails on assertions, not on loading.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import type { ActiveRules } from "../src/rules/features.ts"
import { toolFinding } from "../src/rules/tools.ts"
import { LIMIT_REACHED, type Finding } from "../src/rules/types.ts"
import { createRedactor } from "../src/secrets/redact.ts"

type Json = Record<string, unknown>
const HOME = "/home/test"
const ctx = { redactor: createRedactor(), home: HOME, cwd: `${HOME}/app`, protectedDirs: ["/opt/guard", "/srv/cfg"], pluginDirs: ["/opt/guard"] }
const declaredBy = (options: Json) => () => [{ label: "global", options }, { label: "system", reason: "it is missing or unreadable" }]
/** Settings declared in the global configuration too (relaxations retained). */
const relaxed = (options: Json) => parseConfig(options, {}, declaredBy(options) as Parameters<typeof parseConfig>[2])
const policyOf = (options: Json) => (relaxed(options).config as { policy?: ActiveRules }).policy
const marked = (finding?: Finding) => Boolean(finding && (finding.dataOnly || finding.modelDecides !== undefined))
const brief = (finding?: Finding) => finding && [finding.verdict, finding.rule, marked(finding)]
const shell = (command: string, extra: Json = {}) => brief(toolFinding("shell", { command }, { ...ctx, ...extra }))
const BY_MODEL = { localAsks: "model", selfProtectionByModel: true }

describe("lot 48 review R1", () => {
  it("RL1-1: selfProtectionByModel, real path of an OpenCode location not checked (limit): never left to the model", () => {
    const active = policyOf(BY_MODEL)
    const agent = `${HOME}/.config/opencode/agents/a.md`
    // Same target, resolved to the end: a link to the settings is never left to the model (guard).
    const linked = (absolute: string) => (absolute === agent ? [`${HOME}/.config/opencode/guard.json`] : undefined)
    assert.deepEqual(shell("echo x > ~/.config/opencode/agents/a.md", { active, realPaths: linked }), ["ask", "self-protection", false])
    // Not resolved to the end: it may be the same link.
    const limit = (absolute: string) => (absolute === agent ? LIMIT_REACHED : undefined)
    assert.deepEqual(brief(toolFinding("write", { path: agent, content: "{}" }, { ...ctx, active, realPaths: limit })), ["ask", "self-protection", false], "write")
    assert.deepEqual(brief(toolFinding("edit", { path: agent, oldString: "a", newString: "b" }, { ...ctx, active, realPaths: limit })), ["ask", "self-protection", false], "edit")
    assert.deepEqual(shell("echo x > ~/.config/opencode/agents/a.md", { active, realPaths: limit }), ["ask", "self-protection", false], "shell")
  })

  it("RL1-2: the service file (its environment) written by a tool or the shell: a confirmation never left to the model, whatever the switches", () => {
    const service = `${HOME}/.local/share/opencode/service`
    const extra = { serviceDirs: [service] }
    const active = policyOf(BY_MODEL)
    const verdict = (finding?: Finding) => finding && [finding.verdict, marked(finding)]
    for (const [tool, input] of [
      ["write", { path: `${service}/service.json`, content: "{}" }],
      ["edit", { path: `${service}/service.json`, oldString: "a", newString: "b" }],
      ["patch", { patchText: `*** Begin Patch\n*** Update File: ${service}/service.json\n@@\n-a\n+b\n*** End Patch` }],
    ] as const)
      assert.deepEqual(verdict(toolFinding(tool, input, { ...ctx, ...extra, active })), ["ask", false], tool)
    for (const options of [BY_MODEL, { localAsks: "model" }, { sensitiveFiles: false }])
      assert.deepEqual(verdict(toolFinding("shell", { command: `echo '{}' > ${service}/service.json` }, { ...ctx, ...extra, active: policyOf(options) })), ["ask", false], JSON.stringify(options))
  })

  it("RL1-4: a guard.json written through a directory known only once expanded: a confirmation, like opencode.json", () => {
    const active = policyOf(BY_MODEL)
    // Witness: opencode.json is recognized by its name wherever it is.
    assert.deepEqual(shell("echo x > ~/.config/open*/opencode.json", { active }), ["ask", "self-protection", false])
    for (const command of ["echo '{}' > ~/.config/open*/guard.json", "cp /tmp/g.json ~/.config/open?ode/guard.json", "echo '{}' > $CONFIG/guard.json"])
      assert.deepEqual(shell(command, { active }), ["ask", "self-protection", false], command)
  })
})
