import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { execFileSync } from "node:child_process"
import { randomBytes } from "node:crypto"
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, renameSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { setupGuard } from "../src/index.ts"
import { serviceDirectories, serviceSecretSource } from "../src/secrets/opencode-service.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fakeContext } from "./fake-ctx.ts"

// Fake values in OpenCode 2.1.1 formats (service-config.ts, pairing.ts, credential.ts), drawn on each run.
const password = () => randomBytes(32).toString("base64url")
const route = () => randomBytes(8).toString("hex")
const pairingCode = () => randomBytes(16).toString("base64url")
const opaque = () => randomBytes(30).toString("base64url")

/** Fake XDG directories; `write` replaces the file like OpenCode (temporary file renamed). */
function serviceHome() {
  const root = mkdtempSync(join(tmpdir(), "guard-oc-service-"))
  const env = { XDG_CONFIG_HOME: join(root, "config"), XDG_STATE_HOME: join(root, "state") }
  const [config, state] = serviceDirectories(env)
  mkdirSync(config!, { recursive: true })
  mkdirSync(state!, { recursive: true })
  const write = (dir: string, name: string, content: unknown) => {
    const file = join(dir, name)
    writeFileSync(file + ".tmp", typeof content === "string" ? content : JSON.stringify(content, null, 2))
    renameSync(file + ".tmp", file)
  }
  return { env, config: config!, state: state!, write }
}

const nextTask = () => new Promise((resolve) => setImmediate(resolve))

/** Imitation of a `uqr` QR code (half blocks), indented like `opencode pair`. */
function qrBlock(rows: number) {
  const cells = "█▀▄ "
  const line = () => "██" + Array.from({ length: 37 }, () => cells[randomBytes(1)[0]! % 4]).join("") + "██"
  return [`  ${"█".repeat(41)}`, ...Array.from({ length: rows - 2 }, () => `  ${line()}`), `  ${"█".repeat(41)}`].join("\n")
}

describe("batch 43: OpenCode service secrets (values read from its files)", () => {
  it("directories: XDG config and state, none without HOME or XDG", () => {
    assert.deepEqual(serviceDirectories({ HOME: "/h" }), ["/h/.config/opencode", "/h/.local/state/opencode"])
    assert.deepEqual(serviceDirectories({ XDG_CONFIG_HOME: "/c", XDG_STATE_HOME: "/s" }), ["/c/opencode", "/s/opencode"])
    assert.deepEqual(serviceDirectories({}), [])
    assert.deepEqual(serviceDirectories({ HOME: "/h", OPENCODE_CONFIG_DIR: "/o" }), ["/o", "/h/.config/opencode", "/h/.local/state/opencode"])
  })

  it("configuration directory set by OPENCODE_CONFIG_DIR: password and route redacted", () => {
    const home = serviceHome()
    const dir = mkdtempSync(join(tmpdir(), "guard-oc-config-dir-"))
    const pw = password()
    const rt = route()
    home.write(dir, "service.json", { password: pw, remote: { route: rt } })
    const redactor = createRedactor({ runtimeSecrets: serviceSecretSource(serviceDirectories({ ...home.env, OPENCODE_CONFIG_DIR: dir })) })
    assert.equal(redactor.redactString(`${pw} ${rt}`).count, 2)
  })

  it("password (configuration and state) and route redacted, alone or within text", () => {
    const home = serviceHome()
    const pw = password()
    const rt = route()
    const other = password()
    home.write(home.config, "service.json", { port: 4096, password: pw, remote: { route: rt } })
    home.write(home.state, "service-beta.json", { url: "http://127.0.0.1:4096", pid: 1, password: other })
    const redactor = createRedactor({ runtimeSecrets: serviceSecretSource(serviceDirectories(home.env)) })
    const out = redactor.redactString(`${pw}\nremote https://x.invalid/${rt}/ et ${other}`).value
    for (const value of [pw, rt, other]) assert.ok(!out.includes(value))
    assert.match(out, /GUARD_REDACTED:opencode:service-password/)
    assert.match(out, /GUARD_REDACTED:opencode:remote-route/)
    assert.equal(redactor.containsSecret({ deep: [`x${pw}x`] }), true)
  })

  it("chosen password: at least 8 characters; allowlist respected", () => {
    const home = serviceHome()
    home.write(home.config, "service.json", { password: "Ab3dE6gH" })
    home.write(home.state, "service.json", { password: "Ab3dE6g" })
    const redactor = createRedactor({ runtimeSecrets: serviceSecretSource(serviceDirectories(home.env)) })
    assert.match(redactor.redactString("Ab3dE6gH").value, /GUARD_REDACTED/)
    assert.equal(redactor.redactString("the word Ab3dE6g alone").count, 0)
    const pw = password()
    const allowed = serviceHome()
    allowed.write(allowed.config, "service.json", { password: pw })
    const permissive = createRedactor({ allowlist: [pw], runtimeSecrets: serviceSecretSource(serviceDirectories(allowed.env)) })
    assert.equal(permissive.redactString(pw).count, 0)
  })

  it("password replaced between two calls: the new and the old stay redacted", async () => {
    const home = serviceHome()
    const first = password()
    home.write(home.config, "service.json", { password: first })
    const redactor = createRedactor({ runtimeSecrets: serviceSecretSource(serviceDirectories(home.env)) })
    assert.equal(redactor.redactString(first).count, 1)
    await nextTask()
    const second = password()
    home.write(home.config, "service.json", { password: second })
    await nextTask()
    const out = redactor.redactString(`${first} ${second}`).value
    assert.ok(!out.includes(first) && !out.includes(second))
  })

  it("file created during the call (password created on first read): seen when the call returns", async () => {
    const home = serviceHome()
    const redactor = createRedactor({ runtimeSecrets: serviceSecretSource(serviceDirectories(home.env)) })
    assert.equal(redactor.redactString("nothing").count, 0)
    await nextTask()
    const pw = password()
    home.write(home.config, "service.json", { password: pw })
    await nextTask()
    assert.equal(redactor.redactString(pw).count, 1)
  })

  it("read or parse failure: already-seen values stay redacted, then the repaired file is read again", async () => {
    const home = serviceHome()
    const pw = password()
    home.write(home.config, "service.json", { password: pw })
    const redactor = createRedactor({ runtimeSecrets: serviceSecretSource(serviceDirectories(home.env)) })
    assert.equal(redactor.redactString(pw).count, 1)
    await nextTask()
    home.write(home.config, "service.json", '{ "password": "tronqu')
    await nextTask()
    assert.equal(redactor.redactString(pw).count, 1)
    await nextTask()
    const next = password()
    home.write(home.config, "service.json", { password: next })
    await nextTask()
    assert.equal(redactor.redactString(`${pw} ${next}`).count, 2)
  })

  it("without a source, no file is read (default redactor, environment included)", () => {
    const home = serviceHome()
    const pw = password()
    home.write(home.config, "service.json", { password: pw })
    assert.equal(createRedactor({ env: home.env }).redactString(pw).count, 0)
    assert.equal(createRedactor().redactString(pw).count, 0)
  })

  it("missing, unreadable, too large or differently named files: no error, nothing redacted (guardrail)", () => {
    const home = serviceHome()
    home.write(home.config, "service.json.bak", { password: password() })
    home.write(home.config, "opencode.json", { password: password() })
    mkdirSync(join(home.state, "service-x.json"))
    home.write(home.config, "service-locked.json", { password: password() })
    chmodSync(join(home.config, "service-locked.json"), 0)
    home.write(home.state, "service-big.json", JSON.stringify({ password: password(), pad: "x".repeat(1 << 20) }))
    const source = serviceSecretSource([...serviceDirectories(home.env), "/nonexistent/guard"])
    assert.deepEqual(source(), [])
  })

  it("named pipe instead of the file: ignored without blocking (guardrail; the race between check and read is not reproduced here)", () => {
    const home = serviceHome()
    execFileSync("mkfifo", [join(home.config, "service.json")])
    assert.deepEqual(serviceSecretSource(serviceDirectories(home.env))(), [])
  })

  it("service.json read first, then at most 31 other files per directory", () => {
    const home = serviceHome()
    const main = password()
    for (let i = 0; i < 40; i++) home.write(home.config, `service-c${String(i).padStart(2, "0")}.json`, { password: password() })
    home.write(home.config, "service.json", { password: main })
    const values = serviceSecretSource([home.config])()
    assert.equal(values.length, 32)
    assert.ok(values.some((secret) => secret.value === main))
  })

  it("repeated reads: no file descriptor left open", async () => {
    const home = serviceHome()
    const source = serviceSecretSource(serviceDirectories(home.env))
    const open = () => readdirSync("/proc/self/fd").length
    home.write(home.config, "service.json", { password: password() })
    source()
    await nextTask()
    const before = open()
    for (let i = 0; i < 20; i++) {
      home.write(home.config, "service.json", { password: password() })
      home.write(home.state, "service.json", "{ invalide")
      source()
      await nextTask()
    }
    assert.equal(open(), before)
  })

  it("symlink to a file: followed; unreadable directory: no error", () => {
    const home = serviceHome()
    const elsewhere = mkdtempSync(join(tmpdir(), "guard-oc-link-"))
    const pw = password()
    home.write(elsewhere, "real.json", { password: pw })
    symlinkSync(join(elsewhere, "real.json"), join(home.config, "service.json"))
    chmodSync(home.state, 0)
    const redactor = createRedactor({ runtimeSecrets: serviceSecretSource(serviceDirectories(home.env)) })
    assert.equal(redactor.redactString(pw).count, 1)
  })
})

describe("batch 43: OpenCode credentials and pairing (format, then learned value)", () => {
  it("indented export: keys and OAuth tokens redacted, the rest intact; lone value redacted afterwards", () => {
    const key = opaque()
    const refresh = opaque()
    const access = opaque()
    const entries = [
      { id: "cred_1", integrationID: "acme", label: "work", active: true, value: { type: "key", key } },
      { id: "cred_2", integrationID: "other", label: "me", active: false, value: { type: "oauth", methodID: "browser", refresh, access, expires: 1767225600000 } },
      { id: "cred_3", integrationID: "cloud", label: "ext", active: false, value: { type: "external", methodID: "cli" } },
    ]
    const redactor = createRedactor()
    const out = redactor.redactString(JSON.stringify(entries, null, 2)).value
    for (const value of [key, refresh, access]) assert.ok(!out.includes(value))
    for (const kept of ["cred_1", "acme", "work", "browser", "1767225600000", "external"]) assert.ok(out.includes(kept))
    assert.equal((out.match(/GUARD_REDACTED:opencode_credential/g) ?? []).length, 3)
    assert.equal(redactor.redactString(`value alone: ${refresh}`).value, "value alone: [[GUARD_REDACTED:opencode_credential]]")
    assert.equal(redactor.containsSecret([key]), true)
  })

  it("compact JSON, fields in the other order, value repeated alone in the same output", () => {
    const key = opaque()
    const access = opaque()
    const redactor = createRedactor()
    const text = `{"value":{"key":"${key}","type":"key"}}\n{"access":"${access}","refresh":"${opaque()}","type":"oauth"}\nextrait : ${key}`
    const out = redactor.redactString(text).value
    assert.ok(!out.includes(key) && !out.includes(access))
    assert.equal((out.match(/GUARD_REDACTED:opencode_credential/g) ?? []).length, 4)
  })

  it("pairing: links, API response and QR code redacted; lone code redacted afterwards", () => {
    const code = pairingCode()
    const redactor = createRedactor()
    const output = [
      "",
      "  Open a link to connect. Links work once and expire in 5 minutes.",
      "",
      `  http://127.0.0.1:4096/auth/connect/${code}`,
      `  https://192.168.1.10:4096/auth/connect/${code}`,
      "",
      qrBlock(23),
      "",
    ].join("\n")
    const out = redactor.redactString(output).value
    assert.ok(!out.includes(code))
    assert.ok(!/[█▀▄]/.test(out))
    assert.match(out, /GUARD_REDACTED:qr_code/)
    assert.ok(out.includes("Open a link to connect."))
    assert.equal(redactor.redactString(`code ${code}`).count, 1)
    const api = createRedactor()
    const other = pairingCode()
    assert.ok(!api.redactString(JSON.stringify({ code: other, expires_in: 300 })).value.includes(other))
    const third = pairingCode()
    assert.ok(!api.redactString(`{"expires_in": 300, "code": "${third}"}`).value.includes(third))
    assert.equal(api.redactString(`${other} ${third}`).count, 2)
  })

  it("key with base64 characters (+, /, =), including starting with /: redacted", () => {
    // Uppercase letter and digit guaranteed: standard base64 with `/` requires them, otherwise the test would depend on the draw.
    for (const key of [`Q7${randomBytes(30).toString("base64")}`, `/Q7+${randomBytes(30).toString("base64")}`]) {
      const redactor = createRedactor()
      assert.ok(!redactor.redactString(JSON.stringify({ type: "key", key })).value.includes(key), key)
      assert.equal(redactor.redactString(key).count, 1)
    }
  })

  it("at most 1,000 learned values: the next one is redacted in its format, not alone", () => {
    const redactor = createRedactor()
    for (let i = 0; i < 1000; i++) redactor.redactString(JSON.stringify({ type: "key", key: opaque() }))
    const key = opaque()
    assert.ok(!redactor.redactString(JSON.stringify({ type: "key", key })).value.includes(key))
    assert.equal(redactor.redactString(key).count, 0)
  })

  it("leaf seen before the one carrying the format, in the same call: redacted too", () => {
    const key = opaque()
    const redactor = createRedactor()
    const out = redactor.redactDeep({ first: `seule ${key}`, export: JSON.stringify({ type: "key", key }) }).value
    assert.ok(!JSON.stringify(out).includes(key))
  })

  it("without the format: nothing is redacted or learned", () => {
    const redactor = createRedactor()
    // Just above the length threshold (20): neither shortcut, nor sentence, nor path, nor address; just below: token.
    const plain = [
      JSON.stringify({ type: "key", key: "Enter" }),
      JSON.stringify({ type: "key", key: "Meta+Alt+F4" }),
      JSON.stringify({ type: "key", key: "Ctrl+Shift+Alt+PageDown" }),
      JSON.stringify({ type: "key", key: "a short sentence typed here" }),
      JSON.stringify({ type: "key", key: "/home/user/proj/notes_2.txt" }),
      JSON.stringify({ type: "key", key: "~/projects/demo/k3y-file" }),
      JSON.stringify({ type: "key", key: "https://example.invalid/k9" }),
      JSON.stringify({ type: "key", key: "src/components/button2/view" }),
      JSON.stringify({ type: "key", key: "api7.example.internal:8443" }),
      JSON.stringify({ type: "key", key: "editorFontSize.default.value" }),
      JSON.stringify({ type: "key", key: "build-cache-worker-service" }),
      JSON.stringify({ type: "key", key: "my-feature-flag-2024-notes" }),
      JSON.stringify({ type: "oauth", refresh: randomBytes(15).toString("base64url").slice(0, 19), access: "x" }),
      Array.from({ length: 5 }, (_, i) => `  ${"█".repeat(30 - i * 4)}${" ".repeat(i * 4)}`).join("\n"),
      JSON.stringify({ key: "settings.editor.fontSize.default", value: 14 }),
      JSON.stringify({ code: "ABCDEFGHIJKLMNOPQRSTUV" }),
      `path /auth/connect/ and ${pairingCode()} alone`,
      ["  █▀▄ █▀▄ █▀▄ █▀▄", "  █▀▄ █▀▄ █▀▄ █▀▄", "  █▀▄ █▀▄ █▀▄ █▀▄", "  █▀▄ █▀▄ █▀▄ █▀▄"].join("\n"),
      "progression ████████░░░░ 60 %",
    ]
    for (const text of plain) assert.equal(redactor.redactString(text).count, 0, text)
  })

  it("allowlist: a permitted value is neither redacted nor learned", () => {
    const key = opaque()
    const redactor = createRedactor({ allowlist: [key] })
    assert.equal(redactor.redactString(JSON.stringify({ type: "key", key })).count, 0)
    assert.equal(redactor.redactString(key).count, 0)
  })
})

describe("batch 43: wiring in setupGuard (output, error, prompt, safety net)", () => {
  async function guarded(env: Record<string, string>) {
    const fake = fakeContext()
    await setupGuard(fake.ctx, env)
    return fake
  }
  const base = { sessionID: "ses_1", agent: "build", messageID: "msg_1", id: "call_1" }

  it("service password redacted in the output, the error, the prompt and the safety net", async () => {
    const home = serviceHome()
    const pw = password()
    home.write(home.config, "service.json", { password: pw })
    const { trigger } = await guarded(home.env)
    const after = await trigger("tool.execute.after", { ...base, tool: "shell", input: {}, status: "completed", result: { output: `${pw}\n` } })
    assert.ok(!JSON.stringify(after.result).includes(pw))
    const failed = await trigger("tool.execute.after", { ...base, tool: "shell", input: {}, status: "error", error: new Error(`failure ${pw}`) })
    assert.ok(!failed.error.message.includes(pw))
    const prompt = await trigger("session.prompt", { prompt: { text: `the word ${pw}` } })
    assert.ok(!prompt.prompt.text.includes(pw))
    const body = JSON.stringify({ messages: [{ role: "tool", content: `output ${pw}` }] })
    const request = new Request("https://provider.invalid/v1", { method: "POST", body, headers: { "content-type": "application/json" } })
    const sent = await (await trigger("session.http.request", { kind: "primary", request })).request.text()
    assert.ok(!sent.includes(pw))
  })

  it("file written after startup: seen by output redaction only", async () => {
    const home = serviceHome()
    const { trigger } = await guarded(home.env)
    await nextTask()
    const pw = password()
    home.write(home.state, "service.json", { password: pw })
    await nextTask()
    const after = await trigger("tool.execute.after", { ...base, tool: "shell", input: {}, status: "completed", result: { output: pw } })
    assert.ok(!JSON.stringify(after.result).includes(pw))
  })

  it("environment without HOME or XDG: nothing is read", async () => {
    const home = serviceHome()
    const pw = password()
    home.write(home.config, "service.json", { password: pw })
    const { trigger } = await guarded({})
    const result = { output: pw }
    const after = await trigger("tool.execute.after", { ...base, tool: "shell", input: {}, status: "completed", result })
    assert.equal(after.result, result)
  })
})
