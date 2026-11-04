// `guard show`: the plugin's commit, and whether it is the HEAD or a tag. Fake install directories and a fake `git`: nothing
// reaches the network.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, it } from "node:test"
import { pluginVersion, type Git } from "../src/cli/version.ts"

const COMMIT = "49889ca6861d8e3e0cac8ce0ce8b225f7d50ae31"
const OTHER = "1".repeat(40)
const SPECIFIER = "github:gigi206/opencode-guard#main"

function installed(resolved = `git+ssh://git@github.com/gigi206/opencode-guard.git#${COMMIT}`) {
  const generation = join(mkdtempSync(join(tmpdir(), "guard-version-")), "git-opencode-guard-abc", "1793823165297")
  const plugin = join(generation, "node_modules", "opencode-guard")
  mkdirSync(plugin, { recursive: true })
  const lock = { packages: { "": { dependencies: { "opencode-guard": SPECIFIER } }, "node_modules/opencode-guard": { version: "0.1.0", resolved } } }
  writeFileSync(join(generation, "package-lock.json"), JSON.stringify(lock))
  return plugin
}

const remote =
  (lines: readonly string[]): Git =>
  (args) => {
    assert.deepEqual(args, ["ls-remote", "https://github.com/gigi206/opencode-guard.git"])
    return lines.join("\n")
  }

describe("guard show: installed from Git", () => {
  it("the commit installed is the repository's HEAD", () => {
    const version = pluginVersion(installed(), remote([`${COMMIT}\tHEAD`, `${COMMIT}\trefs/heads/main`]), false)
    assert.deepEqual(version, { source: `plugin (${SPECIFIER})`, state: "49889ca (HEAD)", style: "good" })
  })
  it("a tag on the commit, an annotated one by the commit it points to", () => {
    const lines = [`${OTHER}\tHEAD`, `${COMMIT}\trefs/tags/v1.0`, `${OTHER}\trefs/tags/v2.0`, `${COMMIT}\trefs/tags/v2.0^{}`]
    assert.equal(pluginVersion(installed(), remote(lines), false).state, "49889ca (tag v1.0, tag v2.0)")
  })
  it("both HEAD and a tag", () => {
    assert.equal(pluginVersion(installed(), remote([`${COMMIT}\tHEAD`, `${COMMIT}\trefs/tags/v1.0`]), false).state, "49889ca (HEAD, tag v1.0)")
  })
  it("neither: said as a warning", () => {
    const version = pluginVersion(installed(), remote([`${OTHER}\tHEAD`, `${OTHER}\trefs/tags/v1.0`]), false)
    assert.equal(version.state, "49889ca (not HEAD, no tag)")
    assert.equal(version.style, "warn")
  })
  it("repository not reached, or offline without any lookup", () => {
    assert.equal(pluginVersion(installed(), () => undefined, false).state, "49889ca (repository not reached)")
    const refused: Git = () => assert.fail("no lookup offline")
    assert.equal(pluginVersion(installed(), refused, true).state, "49889ca (HEAD and tags not checked)")
  })
  it("a lock file that does not give a commit of a known form", () => {
    assert.equal(pluginVersion(installed("https://example.test/x.tgz"), () => "", false).state, "commit unknown")
  })
})

describe("guard show: run from a repository", () => {
  const local =
    (tags: string): Git =>
    (args, directory) => {
      assert.equal(directory, "/repo")
      return args[0] === "rev-parse" ? `${COMMIT}\n` : tags
    }
  it("the commit, with the tags that point to it", () => {
    assert.deepEqual(pluginVersion("/repo", local(""), true), { source: "plugin (/repo)", state: "49889ca (HEAD)", style: "good" })
    assert.equal(pluginVersion("/repo", local("v1.0\nv1.1\n"), true).state, "49889ca (HEAD, tag v1.0, tag v1.1)")
  })
  it("not a repository", () => {
    assert.equal(pluginVersion("/repo", () => undefined, false).state, "commit unknown")
  })
})
