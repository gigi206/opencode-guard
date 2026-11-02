// Lot 48, exceptions for absolute paths only. The `HOME` of a shell command is the one of the session's environment, which
// the plugin does not see: a home-relative word never gives a target, so neither an exception nor the memory of
// confirmations lifts it, for the shell as for the tools; the same file named by its absolute path still is. Fake files
// and a fake home given to the rules only (the real home directory is never consulted), nothing launched.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { after, describe, it } from "node:test"
import { createCredentialContent } from "../src/credential-content.ts"
import { createRealPath } from "../src/real-path.ts"
import { shellFinding } from "../src/rules/shell.ts"
import { toolFinding } from "../src/rules/tools.ts"
import { createRedactor } from "../src/secrets/redact.ts"

type Json = Record<string, unknown>
const RULE = "secret-file-read"

const roots: string[] = []
after(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true })
})

/** A fake home `<root>/home` with its `.netrc` (the excepted file), and a working directory `<root>/work`. */
function files() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-cre-")))
  roots.push(root)
  const home = join(root, "home")
  const work = join(root, "work")
  for (const dir of [home, work]) mkdirSync(dir, { recursive: true })
  const netrc = join(home, ".netrc")
  writeFileSync(netrc, "machine example.invalid\n")
  return { home, work, netrc }
}

/** Rule context of a call run in `dir`, home `home`, with the resolvers of a call and the given exceptions or memory. */
function context(dir: string, home: string, active: Json, remembered?: (rule: string, targets: readonly string[]) => boolean) {
  return {
    redactor: createRedactor(),
    home,
    cwd: dir,
    cwds: [dir],
    credentialContent: createCredentialContent({ directories: [dir], home }),
    realPaths: createRealPath({ directories: [dir] }),
    active: { dangerousCommands: true, sensitiveFiles: true, ...active },
    ...(remembered ? { remembered } : {}),
  } as Parameters<typeof shellFinding>[1]
}

describe("exceptions and memory: absolute paths only", () => {
  it("CRE-1: the shell: the excepted file named home-relative asks (witness: by its absolute path, lifted)", () => {
    const fs = files()
    const ctx = context(fs.work, fs.home, { exceptions: new Map([[RULE, new Set([fs.netrc])]]) })
    assert.equal(shellFinding(`cat ${fs.netrc}`, ctx), undefined)
    assert.equal(shellFinding("cat ~/.netrc", ctx)?.rule, RULE)
  })

  it("CRE-2: the read tool: the excepted file named home-relative asks (witness: by its absolute path, lifted)", () => {
    const fs = files()
    const ctx = context(fs.work, fs.home, { exceptions: new Map([[RULE, new Set([fs.netrc])]]) })
    assert.equal(toolFinding("read", { path: fs.netrc }, ctx), undefined)
    assert.equal(toolFinding("read", { path: "~/.netrc" }, ctx)?.rule, RULE)
  })

  it("CRE-3: the memory of confirmations, shell: the remembered file named home-relative asks (witness: absolute, lifted)", () => {
    const fs = files()
    const ctx = context(fs.work, fs.home, { rememberMinutes: 10 }, (rule, targets) => rule === RULE && targets.length === 1 && targets[0] === fs.netrc)
    assert.equal(shellFinding(`cat ${fs.netrc}`, ctx), undefined)
    assert.equal(shellFinding("cat ~/.netrc", ctx)?.rule, RULE)
  })

  it("CRE-4: the memory of confirmations, read tool: the remembered file named home-relative asks (witness: absolute, lifted)", () => {
    const fs = files()
    const ctx = context(fs.work, fs.home, { rememberMinutes: 10 }, (rule, targets) => rule === RULE && targets.length === 1 && targets[0] === fs.netrc)
    assert.equal(toolFinding("read", { path: fs.netrc }, ctx), undefined)
    assert.equal(toolFinding("read", { path: "~/.netrc" }, ctx)?.rule, RULE)
  })
})
