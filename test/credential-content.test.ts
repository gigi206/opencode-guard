import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdtempSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createCredentialContent, hasPrivateKeyHeader, MAX_LOOKUPS, MAX_OPENED, type ContentIo } from "../src/credential-content.ts"
import { createDecider } from "../src/decide.ts"
import { isCredentialFile } from "../src/rules/sensitive-paths.ts"
import { LIMIT_REACHED } from "../src/rules/types.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { FAKE } from "./fixtures.ts"

/** Directory with a fake key under an arbitrary name, an ordinary file and a link to the key. */
function workspace() {
  const dir = mkdtempSync(join(tmpdir(), "guard-content-"))
  writeFileSync(join(dir, "deploy_material"), `${FAKE.privateKey}\n`)
  writeFileSync(join(dir, "notes"), "nothing secret here\n")
  symlinkSync(join(dir, "deploy_material"), join(dir, "lien"))
  return dir
}

/** Spy I/O: each file is regular or not, and its content is fixed. */
function spyIo(files: Record<string, { regular: boolean; content?: string }>) {
  const calls = { stat: 0, open: 0 }
  const io: ContentIo = {
    stat: (path) => {
      calls.stat++
      const file = files[path]
      if (!file) throw new Error("ENOENT")
      return { isFile: () => file.regular }
    },
    open: (path) => {
      calls.open++
      return Object.keys(files).indexOf(path) + 3
    },
    isFile: (fd) => Object.values(files)[fd - 3]?.regular === true,
    read: (fd, buffer) => buffer.write(Object.values(files)[fd - 3]?.content ?? "", "latin1"),
    close: () => {},
  }
  return { io, calls }
}

describe("batch 23: private keys recognized by their content", () => {
  it("recognized headers", () => {
    assert.equal(hasPrivateKeyHeader(FAKE.privateKey), true)
    assert.equal(hasPrivateKeyHeader("Bag Attributes\n    localKeyID: 01\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA"), true)
    assert.equal(hasPrivateKeyHeader("-----BEGIN PGP PRIVATE KEY BLOCK-----\n"), true)
    assert.equal(hasPrivateKeyHeader("PuTTY-User-Key-File-3: ssh-ed25519\n"), true)
    assert.equal(hasPrivateKeyHeader("-----BEGIN PUBLIC KEY-----\n"), false)
    assert.equal(hasPrivateKeyHeader("-----BEGIN CERTIFICATE-----\n"), false)
    assert.equal(hasPrivateKeyHeader("a line mentioning PRIVATE KEY without a marker"), false)
    // The header must open the file: a key quoted in code or a document (test data) does not count.
    assert.equal(hasPrivateKeyHeader(`export const KEY = \`${FAKE.privateKey}\`\n`), false)
    assert.equal(hasPrivateKeyHeader(`# Exemple\n\n${FAKE.privateKey}\n`), false)
    // Complete certificate before the key, empty lines and Windows line endings: recognized.
    assert.equal(hasPrivateKeyHeader(`\r\n-----BEGIN CERTIFICATE-----\r\nMIIB\r\n-----END CERTIFICATE-----\r\n${FAKE.privateKey}`), true)
    assert.equal(hasPrivateKeyHeader(`subject=CN = exemple\nissuer=CN = exemple\n${FAKE.privateKey}`), true)
  })

  it("real files: arbitrary name, relative or absolute, link followed", () => {
    const dir = workspace()
    const content = createCredentialContent({ directories: [dir] })
    assert.equal(content("deploy_material"), true)
    assert.equal(content(join(dir, "deploy_material")), true)
    assert.equal(content("lien"), true)
    assert.equal(content("notes"), false)
    assert.equal(content("absent"), false)
    assert.equal(content(dir), false)
    // Several candidate directories: the file is found from one of them.
    assert.equal(createCredentialContent({ directories: ["/nowhere", dir] })("deploy_material"), true)
  })

  it("never open a file that is not regular (named pipe, device)", () => {
    const { io, calls } = spyIo({ "/w/tube": { regular: false } })
    const content = createCredentialContent({ directories: ["/w"], io })
    assert.equal(content("tube"), false)
    assert.equal(calls.stat, 1)
    assert.equal(calls.open, 0)
  })

  it("tokens ignored without lookup: variables, globs, URL, /dev, /proc, /sys", () => {
    const { io, calls } = spyIo({})
    const content = createCredentialContent({ directories: ["/w"], home: "/home/u", io })
    for (const token of ["$KEY", "k*", "k?", "{a,b}", "https://exemple.invalid/k", "~other/k", "/dev/sda", "/proc/self/environ", "/sys/x"])
      assert.equal(content(token), false, token)
    // Literal token too long to be checked: limit (ask), still without lookup.
    assert.equal(content("x".repeat(1025)), LIMIT_REACHED)
    assert.equal(calls.stat, 0)
  })

  it("caps: lookups and files opened per call, memoized results", () => {
    const absent = spyIo({})
    const many = createCredentialContent({ directories: ["/w"], io: absent.io })
    for (let i = 0; i < MAX_LOOKUPS + 50; i++) many(`f${i}`)
    assert.equal(absent.calls.stat, MAX_LOOKUPS)
    const files = Object.fromEntries(Array.from({ length: MAX_OPENED + 10 }, (_, i) => [`/w/f${i}`, { regular: true, content: "text" }]))
    const regular = spyIo(files)
    const opened = createCredentialContent({ directories: ["/w"], io: regular.io })
    for (let i = 0; i < MAX_OPENED + 10; i++) opened(`f${i}`)
    assert.equal(regular.calls.open, MAX_OPENED)
    opened("f0")
    assert.equal(regular.calls.open, MAX_OPENED)
  })

  it("isCredentialFile: known names, or content if the predicate is provided", () => {
    assert.equal(isCredentialFile("deploy_material", {}), false)
    assert.equal(isCredentialFile("deploy_material", { credentialContent: () => true }), true)
    assert.equal(isCredentialFile(".env", { credentialContent: () => false }), true)
  })

  it("decider: ask when reading a key with an unusual name (shell, read tool), depending on the option", async () => {
    const dir = workspace()
    const { config } = parseConfig({})
    const redactor = createRedactor()
    const reading = createDecider({ config, redactor, readContent: true })
    const shell = await reading.decide({ tool: "shell", input: { command: "cat deploy_material" }, directory: dir })
    assert.equal(shell.rule, "secret-file-read")
    assert.equal(shell.verdict, "ask")
    const read = await reading.decide({ tool: "read", input: { path: join(dir, "deploy_material") }, directory: dir })
    assert.equal(read.rule, "secret-file-read")
    // Shell launch directory (workdir): relative path resolved from it.
    const workdir = await reading.decide({ tool: "shell", input: { command: "cat deploy_material" }, directory: "/elsewhere", cwds: [dir] })
    assert.equal(workdir.rule, "secret-file-read")
    assert.notEqual((await reading.decide({ tool: "shell", input: { command: "cat notes" }, directory: dir })).rule, "secret-file-read")
    // Without the option (measurement tools, tests): names only.
    const names = createDecider({ config, redactor })
    assert.notEqual((await names.decide({ tool: "shell", input: { command: "cat deploy_material" }, directory: dir })).rule, "secret-file-read")
    // sensitiveFiles switch off: rule not evaluated.
    const off = createDecider({ config: parseConfig({ sensitiveFiles: false }).config, redactor, readContent: true })
    assert.notEqual((await off.decide({ tool: "shell", input: { command: "cat deploy_material" }, directory: dir })).rule, "secret-file-read")
  })
})
