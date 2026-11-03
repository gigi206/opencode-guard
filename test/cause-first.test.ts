import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { guardAction } from "../src/hooks/gate.ts"
import { shownCause } from "../src/hooks/secret-check.ts"
import { createRedactor } from "../src/secrets/redact.ts"

describe("cause at the head of a check's confirmation", () => {
  it("a failure of the check is shown in capitals, any other cause as is", () => {
    for (const cause of ["model timeout", "model unavailable", "internal error", "check too slow", "too long to check"]) assert.equal(shownCause(cause), cause.toUpperCase())
    assert.equal(shownCause("nox-4b 0.85, not located"), "nox-4b 0.85, not located")
  })
  it("a long MCP tool name never hides the cause nor the choice", () => {
    const tool = `mcp_${"very_long_server_name_".repeat(8)}tool`
    for (const cause of ["model timeout", "model unavailable", "internal error"]) {
      const action = guardAction(createRedactor(), `${shownCause(cause)}: approve to pass on, reject to withhold: ${tool} output not fully checked`)
      assert.ok(action.includes(`${cause.toUpperCase()}: approve to pass on, reject to withhold`), action)
    }
  })
})
