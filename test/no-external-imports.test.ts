// Guard of the test files: a delivered test never refers to a session's temporary folder nor imports a module outside
// the repository (an older tree to compare with is frozen in the test instead). Text of the files is read, nothing runs.
import "./tmp.ts"
import assert from "node:assert/strict"
import { readdirSync, readFileSync } from "node:fs"
import { dirname, isAbsolute, join, relative, resolve } from "node:path"
import { describe, it } from "node:test"
import { fileURLToPath } from "node:url"

const TEST_DIR = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(TEST_DIR, "..")
// Built in two pieces so that this file does not match itself.
const SESSION_TMP = "/tmp/" + "claude-"

/** Every file of the test folder, helpers included. */
const files = readdirSync(TEST_DIR, { recursive: true, withFileTypes: true })
  .filter((entry) => entry.isFile() && /\.[cm]?[jt]s$/.test(entry.name))
  .map((entry) => join(entry.parentPath, entry.name))

/** Module names a file imports, statically, dynamically or by require; a dynamic import not given a literal is kept as is. */
function imported(text: string): { names: string[]; computed: string[] } {
  const names: string[] = []
  const computed: string[] = []
  for (const match of text.matchAll(/^\s*(?:import|export)\b[^"'`;]*?\bfrom\s*["']([^"']+)["']/gm)) names.push(match[1]!)
  for (const match of text.matchAll(/^\s*import\s*["']([^"']+)["']/gm)) names.push(match[1]!)
  for (const match of text.matchAll(/\brequire\(\s*["']([^"']+)["']\s*\)/g)) names.push(match[1]!)
  for (const match of text.matchAll(/\bimport\(\s*([^)]*\)?)/g)) {
    const literal = /^["']([^"'$]+)["']\s*\)/.exec(match[1]!) ?? /^new URL\(\s*["']([^"'$]+)["']\s*,\s*import\.meta\.url\s*\)/.exec(match[1]!)
    if (literal) names.push(literal[1]!)
    else computed.push(match[0])
  }
  return { names, computed }
}

/** A relative or absolute module name resolved outside the repository (a bare package name stays inside). */
function outside(file: string, name: string): boolean {
  const path = name.startsWith("file:") ? fileURLToPath(name) : name
  if (!isAbsolute(path) && !path.startsWith(".")) return false
  const rel = relative(ROOT, resolve(dirname(file), path))
  return rel.startsWith("..") || isAbsolute(rel)
}

describe("test files: no external imports", () => {
  it("NOEXT-1: the folder is read (helpers and test files)", () => {
    assert.ok(files.length >= 50, `${files.length} files`)
    assert.ok(files.some((file) => file.endsWith("tmp.ts")))
  })

  it("NOEXT-2: no file names a session's temporary folder", () => {
    assert.deepEqual(files.filter((file) => readFileSync(file, "utf8").includes(SESSION_TMP)).map((file) => relative(ROOT, file)), [])
  })

  it("NOEXT-3: every import resolves inside the repository, and a dynamic import names its module literally", () => {
    const wrong: string[] = []
    for (const file of files) {
      const { names, computed } = imported(readFileSync(file, "utf8"))
      for (const name of names) if (outside(file, name)) wrong.push(`${relative(ROOT, file)}: ${name}`)
      for (const call of computed) wrong.push(`${relative(ROOT, file)}: ${call}`)
    }
    assert.deepEqual(wrong, [])
  })

  it("NOEXT-4: witnesses of the reading", () => {
    const file = join(TEST_DIR, "x.test.ts")
    // Built in pieces so that this file does not match itself.
    const call = "imp" + "ort("
    const text = `import { a } from "../src/a.ts"\nimport "./tmp.ts"\nconst b = await ${call}\`\${X}/src/b.ts\`)\nconst m = await ${call}new URL("../src/m.ts", import.meta.url).href)\n`
    assert.deepEqual(imported(text), { names: ["../src/a.ts", "./tmp.ts", "../src/m.ts"], computed: [`${call}\`\${X}/src/b.ts\`)`] })
    assert.equal(outside(file, "../src/a.ts"), false)
    assert.equal(outside(file, "node:fs"), false)
    assert.equal(outside(file, "../../x/src/a.ts"), true)
    assert.equal(outside(file, "/opt/x/a.ts"), true)
    assert.equal(outside(file, `${ROOT}/src/a.ts`), false)
  })
})
