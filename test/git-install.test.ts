// Plugin installed by OpenCode from a Git specifier: declaration, self-protection of the whole cache entry.
import { strict as assert } from "node:assert"
import { execFileSync, spawnSync } from "node:child_process"
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { after, describe, it } from "node:test"
import { declaredOutputCheck, declaredPluginOptions, declaresPlugin, packageInstall } from "../src/output-check.ts"
import { enforcedBySystemConfig } from "../src/index.ts"
import { protectedWriteKind } from "../src/rules/sensitive-paths.ts"
import { toolFinding } from "../src/rules/tools.ts"
import { createRedactor } from "../src/secrets/redact.ts"

const root = mkdtempSync(join(tmpdir(), "guard-git-"))
after(() => rmSync(root, { recursive: true, force: true }))
const SPEC = "github:gigi206/opencode-guard#d446ab1ba672698fe5c9cc2e720aaf38d9251e2d"
const entry = join(root, "npm", "git-opencode-guard-a1247262eb86")
const generation = join(entry, "1793784590749")
const pluginDir = join(generation, "node_modules", "opencode-guard")
mkdirSync(pluginDir, { recursive: true })
writeFileSync(join(generation, "package.json"), JSON.stringify({ dependencies: { "opencode-guard": SPEC } }))

function configWith(target: string) {
  const dir = mkdtempSync(join(root, "config-"))
  writeFileSync(join(dir, "opencode.json"), JSON.stringify({ plugins: [{ package: target, options: { promptCheck: true, decision: { baseURL: "https://m.example/v1" } } }] }))
  return dir
}

describe("plugin installed from a Git specifier", () => {
  it("is recognized only by the exact specifier of its generation", () => {
    assert.equal(declaresPlugin(SPEC, pluginDir), true)
    for (const other of ["github:gigi206/opencode-guard#main", "github:gigi206/opencode-guard", "github:someone/opencode-guard#d446ab1ba672698fe5c9cc2e720aaf38d9251e2d", "opencode-guard", "./opencode-guard", ""])
      assert.equal(declaresPlugin(other, pluginDir), false, other)
  })

  it("keeps recognizing a local plugin by its path, never by a specifier", () => {
    assert.equal(declaresPlugin(pluginDir, pluginDir), true)
    assert.equal(declaresPlugin(SPEC, join(root, "clone")), false)
  })

  it("refuses when the manifest is missing or malformed", () => {
    const dir = join(root, "npm", "other", "12", "node_modules", "opencode-guard")
    mkdirSync(dir, { recursive: true })
    assert.equal(declaresPlugin(SPEC, dir), false)
    writeFileSync(join(root, "npm", "other", "12", "package.json"), "not json")
    assert.equal(declaresPlugin(SPEC, dir), false)
  })

  it("finds the entry only in the form of an OpenCode install", () => {
    assert.deepEqual(packageInstall(pluginDir), { entry, generation, name: "opencode-guard" })
    assert.equal(packageInstall(join(root, "clone")), undefined)
    assert.equal(packageInstall(join(root, "latest", "node_modules", "opencode-guard")), undefined)
  })

  it("reads the options of the global file and of the system configuration", () => {
    const dir = configWith(SPEC)
    const [global] = declaredPluginOptions({ pluginDir, globalDir: dir, systemDir: undefined, env: {} })
    assert.equal(global?.options?.promptCheck, true)
    assert.deepEqual(declaredOutputCheck({ option: "promptCheck", pluginDir, effectiveBaseURL: "https://m.example/v1", globalDir: dir, systemDir: undefined, env: {} }), { active: true })
    assert.equal(enforcedBySystemConfig(pluginDir, dir), true)
    assert.equal(enforcedBySystemConfig(pluginDir, configWith("github:someone/opencode-guard#main")), false)
  })

  it("protects the entry, a future generation included", () => {
    const context = { protectedDirs: [pluginDir, entry], pluginDirs: [pluginDir, entry] }
    for (const path of [join(pluginDir, "index.ts"), join(generation, "package.json"), join(entry, "9999999999999", "node_modules", "opencode-guard", "index.ts"), entry])
      assert.ok(protectedWriteKind(path, undefined, context), path)
    assert.equal(protectedWriteKind(join(root, "npm", "git-superpowers-0958a5557860", "x"), undefined, context), undefined)
  })

  it("asks before updating a package plugin, by the command or by the server API", () => {
    const ctx = { redactor: createRedactor(), home: "/home/test" }
    const found = (command: string) => {
      const finding = toolFinding("shell", { command }, ctx)
      return finding && `${finding.verdict}:${finding.rule}`
    }
    assert.equal(found("opencode plugin update"), "ask:self-protection")
    assert.equal(found(`opencode plugin update ${SPEC}`), "ask:self-protection")
    assert.equal(found("curl http://localhost:4096/api/plugin/update"), "ask:opencode-server-api")
    assert.equal(found("opencode plugin check"), undefined)
  })

  it("installs the command over a link, without writing through it", () => {
    const bin = mkdtempSync(join(root, "bin-"))
    const linked = join(root, "linked-guard")
    writeFileSync(linked, "original")
    symlinkSync(linked, join(bin, "guard"))
    const script = join(import.meta.dirname, "..", "tools", "install-cli.sh")
    execFileSync("sh", [script], { env: { ...process.env, GUARD_BIN_DIR: bin }, stdio: "pipe" })
    const target = join(bin, "guard")
    assert.equal(lstatSync(target).isSymbolicLink(), false)
    assert.equal(readFileSync(linked, "utf8"), "original")
    assert.ok(statSync(target).mode & 0o100)
    const config = mkdtempSync(join(root, "empty-"))
    const run = spawnSync("sh", [target, "show"], { env: { ...process.env, OPENCODE_CONFIG_DIR: config }, encoding: "utf8" })
    assert.equal(run.status, 1)
    assert.match(run.stderr, /no Git specifier/)
  })
})
