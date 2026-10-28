// Lot 48, short check of step G: the case kept in the suite (VG-2). Nothing is launched: the model is a function.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import { createRedactor } from "../src/secrets/redact.ts"

type Json = Record<string, unknown>
type Declared = Parameters<typeof parseConfig>[2]
const HOME = "/home/test"
const PROJECT = `${HOME}/work/app`
const DECISION = { baseURL: "https://decision.local/v1", model: "nox-4b" }
const declaredBy = (global: Json) => () => [{ label: "global", options: global }, { label: "system", reason: "it is missing or unreadable" }]

describe("lot 48 step G, short check", () => {
  it("VG-2: a project's secretPatterns hide data from the model, which then allows what the global sources' model would not", async () => {
    const verdict = async (effective: Json) => {
      const { config } = parseConfig(effective, {}, declaredBy({ decision: DECISION }) as Declared)
      // Redactor built as the plugin builds it (index.ts): the effective secretPatterns and allowlist.
      const redactor = createRedactor({ extraPatterns: config.secretPatterns, allowlist: config.allowlist })
      const model = async (request: { state: unknown }) => {
        const risk = JSON.stringify(request.state).includes("sudo") ? 2.9 : 0.1
        return {
          answers: {
            risk: { type: "score", score: risk, confidence: 0.9 },
            destructive: { type: "noul", noul: 0.01 },
            exfiltration: { type: "noul", noul: 0.01 },
            credentials: { type: "noul", noul: 0.01 },
            privilege_persistence: { type: "noul", noul: 0.01 },
          },
        }
      }
      const decider = createDecider({ config, redactor, home: HOME, model: model as never })
      const command = "cat > notes.md <<'EOF'\nsudo apt install x\nEOF"
      return (await decider.decide({ tool: "shell", input: { command }, directory: PROJECT } as never)).verdict
    }
    // Guard: the global sources' configuration.
    assert.equal(await verdict({ decision: DECISION }), "deny")
    assert.notEqual(await verdict({ decision: DECISION, secretPatterns: [{ pattern: "sudo[^\\n]*" }] }), "allow")
  })

  it("VG-2b: secretPatterns declared the same by the global sources keep the model's allowance", () => {
    const patterns = [{ type: "internal", pattern: "INT-[A-Z0-9]{8}" }]
    const grants = (effective: Json, global: Json) => parseConfig(effective, {}, declaredBy(global) as Declared).config.modelGrants
    assert.equal(grants({ decision: DECISION, secretPatterns: patterns }, { decision: DECISION, secretPatterns: patterns }), true)
    assert.equal(grants({ decision: DECISION }, { decision: DECISION }), true)
    assert.equal(grants({ decision: DECISION, secretPatterns: patterns }, { decision: DECISION }), false)
  })
})
