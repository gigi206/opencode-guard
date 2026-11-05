// `guard update` and `guard update --check`: fake install directories, and either an injected `opencode` or a fake one first
// in PATH. The real OpenCode is never run. The rule tests only judge commands, as text: nothing is run.
import "./tmp.ts"
import assert from "node:assert/strict"
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { delimiter, join } from "node:path"
import { after, describe, it } from "node:test"
import { completionScript } from "../src/cli/completion.ts"
import { main, USAGE } from "../src/cli/main.ts"
import { runOpencode, update, type Opencode } from "../src/cli/update.ts"
import { parseConfig } from "../src/config.ts"
import { toolFinding } from "../src/rules/tools.ts"
import { createRedactor } from "../src/secrets/redact.ts"

const root = mkdtempSync(join(tmpdir(), "guard-update-"))
after(() => rmSync(root, { recursive: true, force: true }))
const OLD = "9708d28".padEnd(40, "0")
const NEW = "abcdef1".padEnd(40, "0")
const BRANCH = "github:gigi206/opencode-guard#main"

let installs = 0
/** A generation of an install, with a lock file like OpenCode's. */
function generation(entry: string, number: number, commit: string, specifier: string): string {
  const dir = join(entry, String(number))
  const plugin = join(dir, "node_modules", "opencode-guard")
  mkdirSync(plugin, { recursive: true })
  const lock = { packages: { "": { dependencies: { "opencode-guard": specifier } }, "node_modules/opencode-guard": { resolved: `git+ssh://git@github.com/gigi206/opencode-guard.git#${commit}` } } }
  writeFileSync(join(dir, "package-lock.json"), JSON.stringify(lock))
  return plugin
}
function installed(specifier = BRANCH) {
  const entry = join(root, String(++installs), "git-opencode-guard-abc")
  return { entry, plugin: generation(entry, 1000, OLD, specifier) }
}

/** `guard update` on this directory: what was run, what was printed. */
async function run(directory: string, check: boolean, opencode: Opencode) {
  const calls: Array<readonly string[]> = []
  const [out, err]: string[][] = [[], []]
  const io = {
    env: { MARK: "kept" },
    cwd: root,
    systemDir: "/nonexistent",
    out: (line: string) => out.push(line),
    err: (line: string) => err.push(line),
    opencode: ((args, options) => (calls.push(args), opencode(args, options))) as Opencode,
  }
  let code: number
  try {
    code = await update(io, directory, check)
  } catch (error) {
    err.push((error as Error).message)
    code = 1
  }
  return { code, out, err, calls }
}
const silent: Opencode = async () => ({ code: 0, stdout: "", stderr: "" })
const refused: Opencode = () => assert.fail("opencode must not run")

describe("guard update", () => {
  it("UPD-1: the exact arguments, the specifier always there; the new generation's commit is read; how to check the loading", async () => {
    const { entry, plugin } = installed()
    const result = await run(plugin, false, async () => {
      generation(entry, 2000, NEW, BRANCH)
      return { code: 0, stdout: "updated somehow\n", stderr: "" }
    })
    assert.deepEqual(result.calls, [["plugin", "update", BRANCH]])
    assert.equal(result.code, 0)
    assert.deepEqual(result.out, [`Running opencode plugin update ${BRANCH}`, "updated somehow", "Installed commit: 9708d28 -> abcdef1.", "Whether OpenCode has loaded it yet: guard status, on its files line; if it has not, restart the server."])
  })
  it("UPD-2: same commit: said, even when OpenCode made a new generation or printed anything", async () => {
    const { entry, plugin } = installed()
    const result = await run(plugin, false, async () => {
      generation(entry, 2000, OLD, BRANCH)
      return { code: 0, stdout: "all updated!\n", stderr: "" }
    })
    assert.equal(result.code, 0)
    assert.equal(result.out.at(-1), "Nothing changed: still at 9708d28.")
    assert.ok(!result.out.some((line) => line.startsWith("Installed commit")))
  })
  it("UPD-3: a failure keeps OpenCode's exit code and its output; a success is never claimed", async () => {
    const { plugin } = installed()
    const result = await run(plugin, false, async () => ({ code: 7, stdout: "out\n", stderr: "err\n" }))
    assert.equal(result.code, 7)
    assert.deepEqual(result.err, ["err", "guard: opencode plugin update exited with code 7"])
    assert.equal(result.out.at(-1), "Nothing changed: still at 9708d28.")
  })
  it("UPD-4: a commit that cannot be read afterwards is not a success story", async () => {
    const { entry, plugin } = installed()
    const result = await run(plugin, false, async () => {
      mkdirSync(join(entry, "2000"))
      return { code: 0, stdout: "", stderr: "" }
    })
    assert.equal(result.out.at(-1), "The installed commit could not be read (it was 9708d28): guard show gives it.")
  })
  it("UPD-5: run from a directory: refused, nothing run", async () => {
    const result = await run(join(root, "clone"), false, refused)
    assert.equal(result.code, 1)
    assert.match(result.err[0]!, /runs from a directory, not from a Git install: nothing run/)
    assert.equal((await run(join(root, "clone"), true, refused)).code, 1)
  })
  it("UPD-6: a pinned commit: update refused and says what to do, --check has nothing to check", async () => {
    const { plugin } = installed(`github:gigi206/opencode-guard#${OLD}`)
    const updated = await run(plugin, false, refused)
    assert.equal(updated.code, 1)
    assert.match(updated.err[0]!, /pinned to a commit: nothing run; to change version, edit the commit in opencode\.json/)
    const checked = await run(plugin, true, refused)
    assert.equal(checked.code, 0)
    assert.match(checked.out[0]!, /pinned to a commit: nothing to check/)
  })
  it("UPD-7: a short commit or a tag is a specifier like a branch", async () => {
    for (const specifier of ["github:gigi206/opencode-guard#9708d28", "github:gigi206/opencode-guard#v1.0"])
      assert.deepEqual((await run(installed(specifier).plugin, false, silent)).calls, [["plugin", "update", specifier]])
  })
  it("UPD-8: no lock file, or a specifier read as an option: refused, nothing run", async () => {
    const { plugin, entry } = installed()
    rmSync(join(entry, "1000", "package-lock.json"))
    assert.equal((await run(plugin, false, refused)).code, 1)
    assert.equal((await run(installed("--foo").plugin, true, refused)).code, 1)
  })
})

describe("guard update --check", () => {
  it("CHK-1: only opencode plugin check, relayed with its exit code; no commit is read", async () => {
    const { plugin } = installed()
    const ok = await run(plugin, true, async () => ({ code: 0, stdout: "Server\n  guard 9708d28 (current)\n", stderr: "" }))
    assert.deepEqual(ok.calls, [["plugin", "check", BRANCH]])
    assert.deepEqual([ok.code, ok.out], [0, ["Server", "  guard 9708d28 (current)"]])
    const bad = await run(plugin, true, async () => ({ code: 4, stdout: "", stderr: "\x1b[31mno\x1b[0m\r\n" }))
    assert.deepEqual([bad.code, bad.out, bad.err], [4, [], ["no", "guard: opencode plugin check exited with code 4"]])
  })
})

describe("the real runner, with a fake opencode first in PATH", () => {
  const bin = join(root, "bin")
  const trace = join(root, "trace")
  mkdirSync(bin)
  writeFileSync(
    join(bin, "opencode"),
    `#!/bin/sh
for word in "$@"; do printf '%s\\n' "$word"; done > "${trace}"
printf 'BUN_BE_BUN=%s MARK=%s\\n' "\${BUN_BE_BUN-unset}" "$MARK" >> "${trace}"
pwd >> "${trace}"
echo printed
echo complained >&2
read -r line && echo "read: $line"
[ "$1" = "slow" ] && exec sleep 30
exit 3
`,
  )
  chmodSync(join(bin, "opencode"), 0o755)
  const env = { PATH: `${bin}${delimiter}/usr/bin${delimiter}/bin`, MARK: "kept", BUN_BE_BUN: "1" }
  it("RUN-1: no shell: the specifier is one word; the environment passes but for BUN_BE_BUN; exit code and outputs; no keyboard", async () => {
    const word = "a b;$(touch x)#'"
    const ran = await runOpencode(["plugin", "update", word], { cwd: root, env, timeout: 10_000 })
    assert.deepEqual(ran, { code: 3, stdout: "printed\n", stderr: "complained\n" })
    assert.deepEqual(readFileSync(trace, "utf8").split("\n").slice(0, 5), ["plugin", "update", word, "BUN_BE_BUN=unset MARK=kept", root])
  })
  it("RUN-2: too long: a problem in words, never a success", async () => {
    const ran = await runOpencode(["slow"], { cwd: root, env, timeout: 300 })
    assert.equal(ran.code, 1)
    assert.match(ran.problem!, /stopped after 0\.3 s/)
  })
  it("RUN-3: opencode missing: clear error, non-zero code, whatever the command", async () => {
    const { plugin } = installed()
    const [out, err]: string[][] = [[], []]
    const io = { env: { PATH: join(root, "empty") }, cwd: root, systemDir: "/nonexistent", out: (line: string) => out.push(line), err: (line: string) => err.push(line) }
    assert.equal(await update(io, plugin, true), 1)
    assert.deepEqual(err, ["guard: opencode not found: is it in PATH?"])
    assert.equal(await update(io, plugin, false), 1)
    assert.equal(err.at(-1), "guard: opencode not found: is it in PATH?")
  })
})

describe("the command line", () => {
  const cli = async (...args: string[]) => {
    const [out, err]: string[][] = [[], []]
    const code = await main(args, { env: {}, cwd: root, systemDir: "/nonexistent", out: (line) => out.push(line), err: (line) => err.push(line), opencode: refused })
    return { code, first: err[0] }
  }
  it("CLI-1: --check alone: anything else is a usage error, nothing run", async () => {
    for (const [args, message] of [
      [["update", "--check", "--foo"], "unexpected argument --foo"],
      [["update", "x", "--check"], "unexpected argument x"],
      [["update", "--foo"], "unknown option --foo"],
      [["update", "x"], "unexpected argument x"],
    ] as const) {
      const { code, first } = await cli(...args)
      assert.deepEqual([code, first], [2, `guard: ${message}`], args.join(" "))
    }
  })
  it("CLI-2: this checkout runs from a directory: refused with code 1 through main", async () => {
    assert.equal((await cli("update")).code, 1)
    assert.equal((await cli("update", "--check")).code, 1)
  })
  it("CLI-3: help and completion name it", () => {
    assert.match(USAGE, /\n {2}update --check {2,}/)
    assert.match(completionScript("bash"), /\n\s+update\) words="--check" ;;/)
  })
})

describe("guard update by an agent", () => {
  const ctx = { redactor: createRedactor(), home: "/home/test", cwd: "/tmp/p", protectedDirs: ["/opt/guard"], pluginDirs: ["/opt/guard"], realPaths: (path: string) => [path] }
  const found = (command: string, extra = {}) => {
    const finding = toolFinding("shell", { command }, { ...ctx, ...extra })
    return finding && `${finding.verdict}:${finding.rule}`
  }
  it("witness: SEC-1: guard update asks, bare, under a shell, behind a prefix", () => {
    for (const command of ["guard update", "bash -c 'guard update'", "sh -c 'x; guard update'", "FOO=1 guard update", "env guard update", "timeout 5 guard update", "sudo guard update", "cd /tmp && guard update", "~/.local/bin/guard update", "echo x | guard update", 'echo "$(guard update)"'])
      assert.equal(found(command), "ask:guard-cli", command)
  })
  it("witness: SEC-2: never left to the decision model, whatever the settings", () => {
    const options = { localAsks: "model", selfProtectionByModel: true, ruleOverrides: { "guard-cli": "model" } }
    const declared = () => [{ label: "global", options }] as never
    const active = (parseConfig(options, {}, declared).config as { policy?: unknown }).policy
    const finding = toolFinding("shell", { command: "guard update" }, { ...ctx, active } as never)
    assert.equal(finding?.verdict, "ask")
    assert.equal(finding?.rule, "guard-cli")
    assert.ok(!finding?.modelDecides)
    // The same finding as a neighbouring command.
    const neighbour = toolFinding("shell", { command: "guard show" }, { ...ctx, active } as never)
    assert.deepEqual({ ...finding, reason: "" }, { ...neighbour, reason: "" })
  })
  it("SEC-3: guard update --check alone, recognized exactly, does not ask", () => {
    assert.equal(found("guard update --check"), undefined)
    assert.equal(found(`  "guard" update --check;\n`), undefined)
  })
  it("witness: SEC-4: no free pass for anything else", () => {
    for (const command of [
      "guard update --check; guard update",
      "guard update --check && guard update",
      "guard update --check\nguard update",
      "guard update --check | guard update",
      "guard update --check --foo",
      "guard update x --check",
      "guard update --check x",
      "guard --check update",
      "guard update --check=true",
      "guard update -c",
      "guard update --check > /tmp/x",
      "guard update --check $X",
      "guard update --check `x`",
      "FOO=1 guard update --check",
      "PATH=/tmp/x guard update --check",
      "BUN_BE_BUN=1 guard update --check",
      "/tmp/x/guard update --check",
      "./guard update --check",
      "guard update --check # x",
      "env guard update --check",
      "env PATH=/tmp/x guard update --check",
      "command guard update --check",
      "timeout 5 guard update --check",
      "sudo guard update --check",
      "bash -c 'guard update --check'",
      "(guard update --check)",
      "cat .x | guard update --check",
      "cat notes.txt; guard update --check",
      "guard update --check 2>&1",
      "guard rules off eval; guard update --check",
    ])
      assert.equal(found(command), "ask:guard-cli", command)
  })
  it("witness: SEC-4b: with a deletion after it: an ask, and guard-cli's where the deletion alone would go to the decision model", () => {
    assert.equal(found("guard update --check && rm x"), "ask:file-delete")
    const options = { localAsks: "model", selfProtectionByModel: true }
    const active = (parseConfig(options, {}, () => [{ label: "global", options }] as never).config as { policy?: unknown }).policy
    const finding = toolFinding("shell", { command: "guard update --check && rm x" }, { ...ctx, active } as never)
    assert.deepEqual([finding?.verdict, finding?.rule, finding?.modelDecides], ["ask", "guard-cli", undefined])
  })
  it("witness: SEC-5: opencode plugin update run directly asks, never left to the decision model, under a shell too", () => {
    const options = { localAsks: "model", selfProtectionByModel: true }
    const active = (parseConfig(options, {}, () => [{ label: "global", options }] as never).config as { policy?: unknown }).policy
    for (const command of ["opencode plugin update", `opencode plugin update ${BRANCH}`, "bash -c 'opencode plugin update'"]) {
      assert.equal(found(command), "ask:self-protection", command)
      const finding = toolFinding("shell", { command }, { ...ctx, active } as never)
      assert.deepEqual([finding?.verdict, finding?.rule, finding?.modelDecides], ["ask", "self-protection", undefined], command)
    }
  })
})
