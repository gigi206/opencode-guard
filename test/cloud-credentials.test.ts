// Credentials of cloud command lines, a service account key recognized by its content, and MCP arguments that name a file under
// the usual names of a copy. Fake paths and values; nothing is read.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createCredentialContent, hasPrivateKeyHeader } from "../src/credential-content.ts"
import { argumentPaths, toolFinding } from "../src/rules/tools.ts"
import { createRedactor } from "../src/secrets/redact.ts"

const redactor = createRedactor()
const ctx = { redactor, home: "/home/test", cwd: "/project" }
const rule = (tool: string, input: unknown, context: Parameters<typeof toolFinding>[2] = ctx) => {
  const found = toolFinding(tool, input, context)
  return found ? `${found.verdict}:${found.rule}` : "none"
}
const PEM = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"
const SERVICE_ACCOUNT = JSON.stringify({ type: "service_account", project_id: "x", private_key_id: "abc", private_key: PEM }, null, 2)

describe("credential files of cloud command lines", () => {
  it("each default location asks, and a backup of it", () => {
    for (const path of [
      ".config/gcloud/application_default_credentials.json",
      ".config/gcloud/credentials.db",
      ".config/gcloud/access_tokens.db",
      ".config/gcloud/legacy_credentials/me@example.test/adc.json",
      ".azure/accessTokens.json",
      ".azure/msal_token_cache.json",
      ".azure/msal_token_cache.bin",
      ".azure/service_principal_entries.json",
      ".terraform.d/credentials.tfrc.json",
      ".azure/accessTokens.json.bak",
    ])
      assert.equal(rule("read", { path: `/home/test/${path}` }), "ask:secret-file-read", path)
  })
  it("witness: their neighbours do not", () => {
    for (const path of [".config/gcloud/properties", ".config/gcloud/active_config", ".azure/config", ".terraform.d/plugins/x"]) assert.equal(rule("read", { path: `/home/test/${path}` }), "none", path)
  })
  it("a service account file is recognized by its content", () => {
    assert.ok(hasPrivateKeyHeader(SERVICE_ACCOUNT))
    assert.ok(hasPrivateKeyHeader(`\r\n  ${SERVICE_ACCOUNT.replace("BEGIN PRIVATE", "BEGIN RSA PRIVATE")}`))
  })
  it("witness: a PEM mention elsewhere in JSON, or no PEM, is no key", () => {
    assert.ok(!hasPrivateKeyHeader(JSON.stringify({ note: "-----BEGIN PRIVATE KEY-----" })))
    assert.ok(!hasPrivateKeyHeader(JSON.stringify({ private_key: "see the vault" })))
  })
  /** Verdict of `read` on a file with this content, through the content check of a real call. */
  const readFile = (content: string) => {
    const dir = mkdtempSync(join(tmpdir(), "cloud-credentials-"))
    try {
      const path = join(dir, "file")
      writeFileSync(path, content)
      return rule("read", { path }, { ...ctx, credentialContent: createCredentialContent({ directories: [dir] }) })
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }
  it("a read of a service account file asks", () => {
    assert.equal(readFile(SERVICE_ACCOUNT), "ask:secret-file-read")
  })
  it("witness: a key quoted in code or a document does not", () => {
    assert.equal(readFile(`# Key\n\n\`\`\`json\n${JSON.stringify({ private_key: PEM })}\n\`\`\`\n`), "none")
    assert.equal(readFile(`const sa = ${JSON.stringify({ private_key: PEM })}\n`), "none")
  })
  it("witness: the tokens in these files are masked, as any token", () => {
    const body = "a1B2c3D4e5F6g7H8i9J0".repeat(4).slice(0, 67)
    assert.equal(redactor.redactString(JSON.stringify({ credentials: { "app.terraform.io": { token: `aBcDeFgHiJkLmN.atlasv1.${body}` } } })).count, 1)
    const jwt = `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4eHh4eHh4eHgifQ.${"c2lnbmF0dXJl".repeat(3)}`
    assert.equal(redactor.redactString(JSON.stringify({ accessToken: jwt })).count, 1)
  })
})

describe("MCP arguments under the usual names of a copy", () => {
  it("a name alone under a path key asks", () => {
    for (const input of [{ source: ".env" }, { src: "secrets/.env" }, { from: ".env" }, { sources: [".env"] }, { input: ".env" }, { input: "config/.env" }])
      assert.equal(rule("mcp__fs__copy", input), "ask:secret-file-read", JSON.stringify(input))
  })
  it("witness: a key that already named a path, and a path shape under any key", () => {
    assert.equal(rule("mcp__fs__copy", { sourcePath: ".env" }), "ask:secret-file-read")
    assert.equal(rule("mcp__fs__copy", { source: "./secrets/.env", destination: "/tmp/x" }), "ask:secret-file-read")
    assert.equal(rule("mcp__fs__copy", { output: "/home/test/.bashrc" }), "ask:protected-write")
  })
  it("a write to a protected location under to or target asks", () => {
    assert.equal(rule("mcp__fs__copy", { to: "opencode.json" }), "ask:self-protection")
    assert.equal(rule("mcp__fs__copy", { target: ".opencode/guard.json" }), "ask:self-protection")
    assert.equal(rule("mcp__fs__copy", { output: "opencode.json" }), "ask:self-protection")
  })
  it("witness: free text and other values under these keys stay silent", () => {
    for (const input of [{ source: "the wiki" }, { input: "fix the bug in config/.env" }, { input: "how do I set up ~/.ssh/config?" }, { input: "explain the /.aws/credentials format" }, { to: "see config/.env" }, { from: "me@example.test", to: "you@example.test" }, { source: "web", target: "es2022", output: "json" }])
      assert.equal(rule("mcp__fs__x", input), "none", JSON.stringify(input))
  })
  it("witness: the words are read at the end of a key only", () => {
    assert.ok(!argumentPaths({ sourceType: ".env" }).includes(".env"))
    assert.ok(argumentPaths({ sourcePath: ".env" }).includes(".env"))
  })
})
