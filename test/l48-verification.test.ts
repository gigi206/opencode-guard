// Lot 48, targeted check of step F: each VER test states the intended behaviour and fails on the candidate (a defect);
// its witness passes. Nothing is launched: text is judged, real paths and the model are functions. Only existing exports
// are imported.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import type { ActiveRules } from "../src/rules/features.ts"
import { toolFinding } from "../src/rules/tools.ts"
import { createRedactor } from "../src/secrets/redact.ts"

type Json = Record<string, unknown>
const HOME = "/home/test"
const PROJECT = `${HOME}/work/app`
const ctx = { redactor: createRedactor(), home: HOME, cwd: PROJECT, protectedDirs: ["/opt/guard"], pluginDirs: ["/opt/guard"] }
const declaredBy = (options: Json) => () => [{ label: "global", options }, { label: "system", reason: "it is missing or unreadable" }]
const policyOf = (options: Json) => (parseConfig(options, {}, declaredBy(options) as Parameters<typeof parseConfig>[2]).config as { policy?: ActiveRules }).policy

const DECISION = { baseURL: "https://decision.local/v1", model: "nox-4b" }
const HEREDOC = "cat > notes.md <<'EOF'\nsudo apt install x\nEOF"
const answers = (score: number) => ({
  answers: {
    risk: { type: "score", score, confidence: 0.9 },
    destructive: { type: "noul", noul: 0.01 },
    exfiltration: { type: "noul", noul: 0.01 },
    credentials: { type: "noul", noul: 0.01 },
    privilege_persistence: { type: "noul", noul: 0.01 },
  },
})

/** Verdict on the heredoc-data ask: effective options, global and system plugin entries, project guard.json. */
async function heredoc(setup: { effective: Json; global?: Json; system?: Json; projectGuard?: Json; score?: number }) {
  const declared = () => [
    setup.global ? { label: "global", options: setup.global } : { label: "global", reason: "it does not declare this plugin" },
    setup.system ? { label: "system", options: setup.system } : { label: "system", reason: "it is missing or unreadable" },
  ]
  const files = setup.projectGuard ? [{ label: `${PROJECT}/.opencode/guard.json`, global: false, dir: PROJECT, data: setup.projectGuard }] : []
  const { config } = parseConfig(setup.effective, {}, declared as Parameters<typeof parseConfig>[2], { files, project: PROJECT, realPath: (path: string) => path })
  const scope = (config as { version?: { scope: (main?: string, sub?: string, call?: string) => unknown } }).version?.scope("build", undefined, undefined)
  const decider = createDecider({ config, redactor: createRedactor(), home: HOME, model: (async () => answers(setup.score ?? 0.1)) as never })
  return (await decider.decide({ tool: "shell", input: { command: HEREDOC }, directory: PROJECT, ...(scope ? { scope } : {}) } as never)).verdict
}

describe("lot 48 targeted check of step F", () => {
  it("VER-1: protected-write set to deny stays a deny for a file named guard.json or the service file, a link included", () => {
    const active = policyOf({ ruleOverrides: { "protected-write": "deny" } })
    const links = new Map([
      [`${PROJECT}/guard.json`, ["/etc/cron.d/job"]],
      [`${PROJECT}/other.json`, ["/etc/cron.d/job"]],
      [`${HOME}/.local/state/opencode/service.json`, [`${HOME}/.bashrc`]],
    ])
    const extra = { active, realPaths: (absolute: string) => links.get(absolute), serviceDirs: [`${HOME}/.config/opencode`, `${HOME}/.local/state/opencode`] }
    const verdict = (tool: string, input: Json) => toolFinding(tool, input, { ...ctx, ...extra })?.verdict
    // Witness: a link with another name.
    assert.equal(verdict("write", { path: `${PROJECT}/other.json`, content: "x" }), "deny")
    for (const target of ["/etc/guard.json", `${HOME}/.ssh/guard.json`, `${PROJECT}/guard.json`, `${HOME}/.local/state/opencode/service.json`]) {
      assert.equal(verdict("write", { path: target, content: "x" }), "deny", `write ${target}`)
      assert.equal(verdict("shell", { command: `echo x > ${target}` }), "deny", `shell ${target}`)
    }
  })

  it("VER-2: the system configuration switches the model off: a project guard.json that switches it on gets no allow", async () => {
    const off = { decision: DECISION, decisionModel: false }
    // Witness: switched off by the global file.
    assert.equal(await heredoc({ effective: off, global: off, projectGuard: { decisionModel: true } }), "ask")
    assert.equal(await heredoc({ effective: off, system: off, projectGuard: { decisionModel: true } }), "ask", "global file silent")
    assert.equal(await heredoc({ effective: off, global: { decision: DECISION }, system: off, projectGuard: { decisionModel: true } }), "ask", "global file without the switch")
  })

  it("VER-3: thresholds replaced by a project do not make the declared model allow what it refuses with the global ones", async () => {
    // Witness: the global thresholds, high risk: refused.
    assert.equal(await heredoc({ effective: { decision: DECISION }, global: { decision: DECISION }, score: 2.9 }), "deny")
    const loose = { askNoul: 1, askExfiltration: 1, askRisk: 3, denyNoul: 1, denyRisk: 3 }
    assert.notEqual(await heredoc({ effective: { decision: DECISION, thresholds: loose }, global: { decision: DECISION }, score: 2.9 }), "allow")
  })

  it("VER-4: guard show prints no control character of a project's guard.json", async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-ver-")))
    const [globalDir, systemDir, home, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "work", "app")]
    for (const dir of [globalDir, systemDir, home, join(project, ".opencode"), join(project, ".git")]) mkdirSync(dir, { recursive: true })
    const [csi, rlo] = [String.fromCharCode(155), String.fromCharCode(8238)]
    writeFileSync(join(project, ".opencode", "guard.json"), JSON.stringify({ ["x\u001b]0;title\u0007y"]: 1, localAsks: `a${csi}2J${rlo}b`, agents: { ["b\u001b[2Jc"]: { localAsks: "model" } } }))
    const { main } = (await import(new URL("../src/cli/main.ts", import.meta.url).href)) as { main: (argv: readonly string[], io: unknown) => number }
    const out: string[] = []
    const code = main(["show"], { env: { HOME: home, OPENCODE_CONFIG_DIR: globalDir }, cwd: project, systemDir, out: (line: string) => out.push(line), err: (line: string) => out.push(line) })
    assert.equal(code, 0)
    assert.match(out.join("\n"), /unknown option x/)
    // C0 (newline aside), DEL, C1, and the bidirectional controls, by code point.
    const ranges = [[0, 9], [11, 31], [127, 159], [1564, 1564], [8206, 8207], [8232, 8238], [8294, 8297]]
    assert.doesNotMatch(out.join("\n"), new RegExp(`[${ranges.map(([from, to]) => `${String.fromCharCode(from!)}-${String.fromCharCode(to!)}`).join("")}]`))
  })
})
