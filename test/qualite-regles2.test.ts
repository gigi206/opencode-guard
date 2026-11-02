// Quality batch, points Q2, Q3 and Q16: the hidden aliases of OpenCode's `--auto` without a subcommand; with
// `protected-write` set to `deny`, a later target's class not hidden by a limit reached on an earlier one; inline
// interpreter code that writes the plugin's settings or launches `guard` or another OpenCode by its name, and a target
// whose directory is known once the shell runs a substitution, given the finding of the equivalent shell form. Text is
// judged, nothing runs.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { parseConfig } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import { createRealPath } from "../src/real-path.ts"
import { shellFinding } from "../src/rules/shell.ts"
import { toolFinding } from "../src/rules/tools.ts"
import type { Finding } from "../src/rules/types.ts"
import { createRedactor } from "../src/secrets/redact.ts"

type Json = Record<string, unknown>
type Declared = Parameters<typeof parseConfig>[2]
const HOME = "/home/test"
const PROJECT = `${HOME}/work/app`
const SETTINGS = `${HOME}/.config/opencode`
const DECISION = { baseURL: "https://decision.local/v1", model: "nox-4b" }
const declaredBy = (global: Json) => () => [{ label: "global", options: global }, { label: "system", reason: "it is missing or unreadable" }]
const brief = (finding?: Finding) => (finding ? `${finding.verdict}:${finding.rule}` : "none")
const shell = (command: string) => brief(toolFinding("shell", { command }, { redactor: createRedactor(), home: HOME, cwd: PROJECT } as never))

/** A fake model: every call judged harmless (it would allow whatever it is asked to decide). */
const lenientModel = async () => ({
  answers: {
    risk: { type: "score", score: 0.1, confidence: 0.9 },
    destructive: { type: "noul", noul: 0.01 },
    exfiltration: { type: "noul", noul: 0.01 },
    credentials: { type: "noul", noul: 0.01 },
    privilege_persistence: { type: "noul", noul: 0.01 },
  },
})

/** Final verdict and rule of a shell command with the default settings, without a model and with a lenient one. */
async function decided(command: string) {
  const out: string[] = []
  for (const withModel of [false, true]) {
    const options = withModel ? { decision: DECISION } : {}
    const { config } = parseConfig(options, {}, declaredBy(options) as Declared)
    const decider = createDecider({ config, redactor: createRedactor(), home: HOME, ...(withModel ? { model: lenientModel as never } : {}) })
    const decision = await decider.decide({ tool: "shell", input: { command }, directory: PROJECT } as never)
    out.push(`${decision.verdict}:${decision.rule ?? decision.source}`)
  }
  return out
}

/** Each pair: the finding of the code form, then that of the equivalent shell form (the same expected). */
function equivalent(cases: ReadonlyArray<readonly [code: string, plain: string]>, expected: string) {
  assert.deepEqual(
    cases.map(([code, plain]) => [shell(code), shell(plain)]),
    cases.map(() => [expected, expected]),
  )
}

/**
 * A fake file system: a deep directory chain (following it exhausts the limit on link checks) and a link of the project
 * to a file of `/etc`; `protected-write` set to `deny`.
 */
function denyWorld() {
  const deep = `/deep${"/d".repeat(260)}`
  const dirs = new Set(["/home", HOME, `${HOME}/work`, PROJECT, "/etc", "/deep"])
  for (let path = "/deep"; path.length < deep.length; ) dirs.add((path += "/d"))
  const io = {
    lstat: (path: string) => {
      if (path === `${PROJECT}/ln-etc`) return { isSymbolicLink: () => true }
      if (dirs.has(path)) return { isSymbolicLink: () => false }
      throw new Error("missing")
    },
    readlink: () => "/etc/x.conf",
  }
  const options = { ruleOverrides: { "protected-write": "deny" } }
  const active = parseConfig(options, {}, declaredBy(options) as Declared).config.policy
  const ctx = () => ({
    redactor: createRedactor(),
    home: HOME,
    cwd: PROJECT,
    protectedDirs: ["/opt/guard"],
    pluginDirs: ["/opt/guard"],
    realPaths: createRealPath({ io, directories: [PROJECT], processDirectory: PROJECT } as never),
    active,
  })
  return { deep, ctx }
}

describe("quality batch, points Q2, Q3 and Q16", () => {
  it("QR2-1: OpenCode without a subcommand with a hidden alias of --auto asks like --auto, never left to the model", async () => {
    // Guards: the main name; OpenCode without a subcommand and without such an option.
    assert.equal(shell("opencode --auto"), "ask:nested-opencode")
    assert.equal(shell("opencode --version"), "none")
    const cases = ["opencode --yolo", "opencode --dangerously-skip-permissions", `cd ${PROJECT} && opencode -m x/y --yolo`, "nohup opencode --dangerously-skip-permissions --prompt hi"]
    assert.deepEqual(
      [...cases.map((command) => shell(command)), ...(await decided(cases[0]!)), ...(await decided(cases[1]!))],
      [...cases.map(() => "ask:nested-opencode"), "ask:nested-opencode", "ask:nested-opencode", "ask:nested-opencode", "ask:nested-opencode"],
    )
  })

  it("QR2-2: protected-write set to deny keeps its denial when an earlier target used up the limit on link checks", () => {
    const { deep, ctx } = denyWorld()
    const patch = (files: string[]) => `*** Begin Patch\n${files.map((file) => `*** Add File: ${file}\n+x\n`).join("")}*** End Patch`
    const tool = (name: string, input: Json) => brief(toolFinding(name, input, ctx() as never))
    // Guards: each target alone.
    assert.equal(tool("patch", { patchText: patch([`${PROJECT}/ln-etc`]) }), "deny:protected-write")
    assert.equal(tool("patch", { patchText: patch([`${deep}/guard.json`]) }), "ask:self-protection")
    // Proof: the link after the deep target, whose pieces use up the limit.
    assert.equal(tool("patch", { patchText: patch([`${deep}/guard.json`, `${PROJECT}/ln-etc`]) }), "deny:protected-write")
    // The shell already classifies every target first: the same denial.
    assert.equal(brief(shellFinding(`echo x > ${deep}/guard.json; echo y > ${PROJECT}/ln-etc`, ctx() as never)), "deny:protected-write")
  })

  it("QR2-3: inline code that launches guard by its name gets the finding of the shell form (guard-cli)", async () => {
    equivalent(
      [
        [`python3 -c "import os; os.system('guard rules off self-protection')"`, "guard rules off self-protection"],
        [`python3 -c 'import subprocess; subprocess.run(["guard", "rules", "off", "self-protection"])'`, "guard rules off self-protection"],
        [`node -e "require('child_process').execSync('guard set localAsks true')"`, "guard set localAsks true"],
        [`ruby -e 'system("guard redaction off github")'`, "guard redaction off github"],
        [`perl -e 'system("guard", "rules", "reset")'`, "guard rules reset"],
      ],
      "ask:guard-cli",
    )
    assert.deepEqual(await decided(`python3 -c "import os; os.system('guard rules off self-protection')"`), ["ask:guard-cli", "ask:guard-cli"])
  })

  it("QR2-4: inline code that launches another OpenCode by its name gets the finding of the shell form (nested-opencode)", async () => {
    equivalent(
      [
        [`node -e "require('child_process').execSync('opencode run hi')"`, "opencode run hi"],
        [`python3 -c "import subprocess; subprocess.Popen(['opencode', 'serve'])"`, "opencode serve"],
        [`bun -e "Bun.spawnSync(['opencode', '--yolo'])"`, "opencode --yolo"],
        [`php -r "shell_exec('opencode web');"`, "opencode web"],
      ],
      "ask:nested-opencode",
    )
    assert.deepEqual(await decided(`node -e "require('child_process').execSync('opencode run --auto hi')"`), ["ask:nested-opencode", "ask:nested-opencode"])
  })

  it("QR2-5: inline code that writes a settings file at a literal path gets the finding of the shell form (self-protection)", async () => {
    equivalent(
      [
        [`python3 -c "open('${SETTINGS}/guard.json','w').write('{}')"`, `echo '{}' > ${SETTINGS}/guard.json`],
        [`python3 -c "import pathlib; pathlib.Path('${SETTINGS}/opencode.json').write_text('{}')"`, `echo '{}' > ${SETTINGS}/opencode.json`],
        [`node -e "require('fs').writeFileSync('$HOME/.config/opencode/guard.json', '{}')"`, `echo '{}' > $HOME/.config/opencode/guard.json`],
        [`node -e "require('fs').copyFileSync('a.ts', '${SETTINGS}/plugin/x.ts')"`, `cp a.ts ${SETTINGS}/plugin/x.ts`],
        [`perl -e 'open(my $f, ">${SETTINGS}/guard.json"); print $f "{}"'`, `echo '{}' > ${SETTINGS}/guard.json`],
        [`ruby -e 'File.write("opencode.json", "{}")'`, `echo '{}' > opencode.json`],
        [`php -r "file_put_contents('${SETTINGS}/guard.json', '{}');"`, `echo '{}' > ${SETTINGS}/guard.json`],
        [`python3 -c "import shutil; shutil.copy('a.json', '${SETTINGS}/guard.json')"`, `cp a.json ${SETTINGS}/guard.json`],
      ],
      "ask:self-protection",
    )
    assert.deepEqual(await decided(`python3 -c "open('${SETTINGS}/guard.json','w').write('{}')"`), ["ask:self-protection", "ask:self-protection"])
  })

  it("QR2-6: a directory known once the shell runs a substitution that names it: the finding of the literal form", () => {
    equivalent(
      [
        [`cp a.ts "$(echo ~/.config/opencode)/plugin/x.ts"`, `cp a.ts ~/.config/opencode/plugin/x.ts`],
        [`cp a.ts "\`echo $HOME/.config/opencode\`/plugins/x.ts"`, `cp a.ts $HOME/.config/opencode/plugins/x.ts`],
        [`mv y.ts "$(printf %s ${SETTINGS})/plugin/"`, `mv y.ts ${SETTINGS}/plugin/`],
        [`echo x > "$(echo ~/.config/opencode)/plugin/y.ts"`, `echo x > ~/.config/opencode/plugin/y.ts`],
        [`echo x >> $(echo ~/.config/opencode)/guard.json`, `echo x >> ~/.config/opencode/guard.json`],
      ],
      "ask:self-protection",
    )
  })

  it("QR2-7: witnesses: reads, other literals, other substitutions and heredoc data stay as they were", () => {
    const cases = [
      // A read of a settings file by inline code, like a read by the shell.
      `python3 -c "import json; print(json.load(open('opencode.json')))"`,
      `node -e "console.log(require('fs').readFileSync('${SETTINGS}/guard.json', 'utf8'))"`,
      `python3 -c "d = json.load(open('opencode.json')); open('out.json', 'w').write(str(d))"`,
      // Names without an execution sink, or not launched.
      `python3 -c "print('guard rules off')"`,
      `python3 -c "import os; os.system('echo opencode')"`,
      `node -e "require('fs').writeFileSync('out/guard-notes.txt', 'x')"`,
      // A substitution that names no OpenCode location, before a plugin directory of the project.
      `cp a.ts "$(git rev-parse --show-toplevel)/plugin/x.ts"`,
      `cp a.ts "$(git rev-parse --show-toplevel)/plugins/x.ts"`,
      `echo x > "$(git rev-parse --show-toplevel)/plugin/x.ts"`,
      // Code in heredoc data that is only written.
      `cat > notes.md <<'EOF'\npython3 -c "import os; os.system('guard rules off self-protection')"\nEOF`,
    ]
    assert.deepEqual(
      cases.map((command) => shell(command)),
      cases.map(() => "none"),
    )
  })
})
