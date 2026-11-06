// Files the plugin cannot read: `opaque-document` asks before `read` or a raw reader hands over a document, `opaque-image`
// does the same for an image once a setting turns it on. Commands are only judged, never run: they are text passed to
// the rules. A test named `witness:` also holds without these rules.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { describe, it } from "node:test"
import { fileURLToPath } from "node:url"
import { main } from "../src/cli/main.ts"
import { parseConfig, resolveVersion, type GuardFile } from "../src/config.ts"
import { createDecider } from "../src/decide.ts"
import { decidable, type Finding } from "../src/rules/types.ts"
import { rulePolicy, type ActiveRules, type RuleOverride } from "../src/rules/features.ts"
import { RULE_DETAILS, ruleSettings } from "../src/rules/details.ts"
import { toolFinding } from "../src/rules/tools.ts"
import { createRedactor } from "../src/secrets/redact.ts"
import { fastEnough } from "./budget.ts"
import { declaring } from "./declared.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
const base = { redactor: createRedactor(), home: "/home/test", cwd: "/home/test/app", protectedDirs: ["/opt/guard"] }
const SWITCHES = { dangerousCommands: true, sensitiveFiles: true }
const policy = (settings: Record<string, RuleOverride>, switches: Partial<ActiveRules> = {}) => rulePolicy({ ...SWITCHES, ...switches }, new Map(Object.entries(settings)))
const judge = (tool: string, input: unknown, active?: ActiveRules): Finding | undefined => toolFinding(tool, input, { ...base, ...(active ? { active } : {}) })
const shell = (command: string, active?: ActiveRules) => judge("shell", { command }, active)
const IMAGES_ON = policy({ "opaque-image": "ask" })

/** Forms of a raw read of `report.pdf`, written for a shell the rules only read. */
const READS = [
  "cat report.pdf",
  "cat REPORT.PDF",
  "base64 report.pdf",
  "xxd report.pdf",
  "hexdump -C report.pdf",
  "od -c report.pdf",
  "strings report.pdf",
  "head -n 5 report.pdf",
  "tail -c 100 report.pdf",
  "cat notes.txt report.pdf",
  "/bin/cat report.pdf",
  "\\cat report.pdf",
  "A=1 cat report.pdf",
  "timeout 5 cat report.pdf",
  "cat < report.pdf",
  "cat<report.pdf",
  "base64 0< report.pdf",
  "cat -- -report.pdf",
  'cat "my report.pdf"',
  "cat *.pdf",
  "cat {a,b}.pdf",
  "cat report.{txt,pdf}",
  "bash -c 'cat report.pdf'",
  'sh -c "xxd report.pdf | head"',
  "ca\"\"t report.pdf",
  "c\\at report.pdf",
  'cat report."pd"f',
  "cat report.p\\df",
  'cat "report".pdf',
  "cat $'report.pdf'",
  "env -S 'cat report.pdf'",
  'echo "$(cat report.pdf)"',
  "echo `cat report.pdf`",
  "cat <(strings report.pdf)",
  "{ cat report.pdf; }",
  "(cat report.pdf)",
  "if od -c report.pdf; then echo ok; fi",
  "ls; cat report.pdf",
  "cat \\\n report.pdf",
  "bash <<'E'\ncat report.pdf\nE",
  "sh <<E\ncat report.pdf\nE",
  "echo 'cat report.pdf' | sh",
  "printf 'cat report.pdf' | bash",
  "sh -s <<< 'cat report.pdf'",
  "bash <<< 'cat report.pdf'",
  "cat <<E\n$(cat report.pdf)\nE",
  // A shell launched in a form the words alone hide.
  "bash<<'E'\ncat report.pdf\nE",
  "sh<<<'cat report.pdf'",
  "if true; then bash <<'E'\ncat report.pdf\nE\nfi",
  "if a; then b; else bash <<'E'\ncat report.pdf\nE\nfi",
  "for i in 1; do sh <<'E'\ncat report.pdf\nE\ndone",
  "echo cat report.pdf | sh",
  "echo -n cat report.pdf | bash",
  // Forms the words alone hide.
  "cat <(echo x) report.pdf",
  "cat notes.txt <(echo x) report.pdf",
  "cat >(tee x) report.pdf",
  'echo "$(<report.pdf)"',
  "echo $(< report.pdf)",
  "cat `echo report.pdf`",
  "cat {report.pdf,notes.txt}",
]

/** Readings each statement keeps, and an operand after an option's value. */
const KEPT = [
  "time bash <<'E'\ncat report.pdf\nE",
  "nice sh <<'E'\ncat report.pdf\nE",
  "ls; bash <<'E'\ncat report.pdf\nE",
  "cat <<'E' | sh\ncat report.pdf\nE",
  "watch 'cat report.pdf'",
  "script -c 'cat report.pdf' /dev/null",
  "echo 'cat report.pdf' |\n sh",
  "{ echo 'cat report.pdf'; } | sh",
  "(echo 'cat report.pdf'; echo done) | sh",
  "(echo 'cat report.pdf'; echo done; echo x) | sh",
  "{ echo 'cat report.pdf'; echo fi; } | sh",
  "for i in 1; do echo 'cat report.pdf'; done | sh",
  "if true; then echo 'cat report.pdf'; fi | sh",
  "sh -c \"sh -c 'cat report.pdf'\"",
  "bash -c 'echo \"cat report.pdf\" | sh'",
  "xxd report.pdf out.hex",
  "xxd -l 100 report.pdf",
  "xxd -s 0 report.pdf out.hex",
  "od -N 4 report.pdf",
  "head -c 4 report.pdf",
]

describe("opaque-document: what asks", () => {
  for (const command of KEPT) it(`witness: ${JSON.stringify(command)}`, () => assert.equal(shell(command)?.rule, "opaque-document"))
  for (const extension of ["pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "odt", "ods", "odp", "rtf"])
    it(`read and cat of a .${extension}, any case`, () => {
      assert.equal(judge("read", { path: `/home/test/app/a.${extension}` })?.rule, "opaque-document")
      assert.equal(judge("read", { filePath: `a.${extension.toUpperCase()}` })?.rule, "opaque-document")
      assert.equal(shell(`cat a.${extension}`)?.rule, "opaque-document")
    })

  for (const command of READS) it(`shell: ${JSON.stringify(command)}`, () => assert.equal(shell(command)?.rule, "opaque-document"))

  it("the reason says the plugin cannot see inside and what a yes means, with no path or content", () => {
    const expected = "the guard plugin cannot see inside this document: answering yes lets it through unchecked"
    assert.deepEqual(shell("cat secret-name.pdf"), { verdict: "ask", rule: "opaque-document", reason: expected })
    assert.deepEqual(judge("read", { path: "secret-name.pdf" }), { verdict: "ask", rule: "opaque-document", reason: expected })
    assert.equal(RULE_DETAILS.get("opaque-document")?.reason, expected)
  })
})

describe("opaque-document: what stays free", () => {
  const free = [
    "echo rapport.pdf",
    'git commit -m "fix report.pdf"',
    'git commit -m "fix; cat report.pdf"',
    "echo 'cat report.pdf'",
    "cat notes.pdf.md",
    "cat report.pdf.bak",
    "pdftotext report.pdf -",
    "pandoc report.docx",
    "unzip -p report.docx word/document.xml",
    "libreoffice --headless --convert-to txt report.docx",
    "python3 tool.py report.pdf",
    "file report.pdf",
    "ls report.pdf",
    "cp report.pdf copy.pdf",
    "grep -l word report.pdf",
    "cat notes.txt > report.pdf",
    "head notes.txt >> report.pdf",
    "# cat report.pdf",
    "cat <<'E'\ncat report.pdf\nE",
    "cat <<< report.pdf",
    "find . -name '*.pdf' | head -5",
    "ls *.pdf | tail -3",
  ]
  for (const command of free) it(`witness: ${JSON.stringify(command)}`, () => assert.equal(shell(command), undefined))
  const notRead = [
    // A launch elsewhere in the command runs nothing of what this statement quotes.
    "./x.sh; git commit -m 'cat report.pdf'",
    "sh run.sh; git commit -m 'cat report.pdf fixes'",
    "./x.sh\ngit commit -m 'cat report.pdf'",
    "./x.sh && git commit -m 'cat report.pdf'",
    "./x.sh || echo 'cat report.pdf'",
    "./x.sh & echo 'cat report.pdf'",
    "echo then; ./x.sh; git commit -m 'cat report.pdf'",
    "bash run.sh; cat > notes.md <<'E'\ncat report.pdf\nE",
    "bash y.sh; grep -c 'tail report.pdf' docs/*.md",
    "bash y.sh; echo 'hello; cat report.pdf'",
    "bash <<'E'\necho 'cat report.pdf'\nE",
    "bash -c 'echo \"cat report.pdf\"'",
    "sh -c 'git commit -m \"cat report.pdf\"'",
    // The value of an option and the file written are not read.
    "head -c $(stat -c %s report.pdf) x.bin",
    "head -n $(wc -l report.pdf) x.txt",
    'tail -n "$(grep -c x report.pdf)" b.txt',
    "xxd -l $(stat -c %s report.pdf) x.bin",
    "xxd -r -p hex.txt report.pdf",
    "xxd a.bin report.pdf",
    "base64 -i a.txt -o report.pdf",
    "base64 -o report.pdf",
  ]
  for (const command of notRead) it(`free: ${JSON.stringify(command)}`, () => assert.equal(shell(command), undefined))
  for (const command of ["cat > x.sh <<'E'\ncat report.pdf\nE", "tee x.txt <<'E'\ncat report.pdf\nE", "python3 - <<'E'\nprint('cat report.pdf')\nE"])
    it(`witness: a heredoc nothing runs as shell code: ${JSON.stringify(command)}`, () => assert.equal(shell(command), undefined))
  it("witness: read of a Markdown or code file named after a document", () => {
    for (const path of ["x.pdf.md", "x.docx.ts", "pdf", "notes.txt"]) assert.equal(judge("read", { path }), undefined, path)
  })
})

describe("opaque-document: the rule it comes after", () => {
  const rule = (command: string, active?: ActiveRules) => shell(command, active)?.rule
  it("writing a location the plugin protects keeps its own reason", () => {
    assert.equal(rule("cat report.pdf > opencode.json"), "self-protection")
    assert.equal(rule("cat report.pdf > /etc/x"), "protected-write")
  })
  it("witness: deny still refuses next to another ask", () => {
    for (const command of ["cat report.pdf; rm -rf x", "cat report.pdf > opencode.json"]) assert.equal(shell(command, policy({ "opaque-document": "deny" }))?.verdict, "deny", command)
  })
  it("witness: another rule left to the model does not take its confirmation away", () => {
    for (const active of [policy({ rm: "model" }), policy({}, { localAsksByModel: true })]) assert.equal(decidable(shell("cat report.pdf; rm -rf x", active)!), false)
  })
})

describe("opaque files named by read, by their first bytes", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "guard-opaque-read-")))
  const webp = Buffer.concat([Buffer.from("RIFF"), Buffer.alloc(4), Buffer.from("WEBPVP8 ")])
  const files: Record<string, Buffer | string> = {
    "renamed.txt": "%PDF-1.7\n",
    "renamed.png": "%PDF-1.7\n",
    "png.txt": Buffer.from("89504e470d0a1a0a0000", "hex"),
    "jpeg.txt": Buffer.from("ffd8ffe00000", "hex"),
    "gif.txt": "GIF89a",
    "webp.txt": webp,
    "wave.txt": "RIFF\0\0\0\0WAVEfmt ",
    "bmp.txt": "BM\0\0",
    "plain.txt": "a line\n",
    "empty.txt": "",
    "real.png": Buffer.from("89504e470d0a1a0a0000", "hex"),
  }
  for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content)
  mkdirSync(join(dir, "dir.txt"))
  symlinkSync(join(dir, "renamed.txt"), join(dir, "link.md"))
  const decider = (options: Record<string, unknown> = {}, readContent = true) => createDecider({ config: parseConfig(options, {}, declaring(options)).config, redactor: createRedactor(), readContent })
  const rule = async (name: string, options?: Record<string, unknown>, readContent?: boolean) => (await decider(options, readContent).decide({ tool: "read", input: { path: join(dir, name) }, directory: dir })).rule
  const IMAGES = { ruleOverrides: { "opaque-image": "ask" } }
  for (const name of ["renamed.txt", "renamed.png", "link.md"]) it(`${name} holds a PDF`, async () => assert.equal(await rule(name), "opaque-document"))
  for (const name of ["png.txt", "jpeg.txt", "gif.txt", "webp.txt"]) it(`${name} holds an image, once the rule is on`, async () => assert.equal(await rule(name, IMAGES), "opaque-image"))
  it("a relative path starts from the directory of the call", async () => {
    assert.equal((await decider().decide({ tool: "read", input: { filePath: "renamed.txt" }, directory: dir })).rule, "opaque-document")
  })
  for (const name of ["wave.txt", "bmp.txt", "plain.txt", "empty.txt", "absent.txt", "dir.txt"])
    it(`witness: ${name} is not what read attaches`, async () => assert.doesNotMatch(String(await rule(name, IMAGES)), /^opaque/))
  it("witness: an image with the rule off, and a real PNG, stay free", async () => {
    for (const name of ["png.txt", "real.png"]) assert.doesNotMatch(String(await rule(name)), /^opaque/)
  })
  it("witness: off goes for the bytes too", async () => {
    assert.doesNotMatch(String(await rule("renamed.txt", { ruleOverrides: { "opaque-document": "off" } })), /^opaque/)
  })
  it("witness: without reading the content, the name alone counts", async () => assert.doesNotMatch(String(await rule("renamed.txt", {}, false)), /^opaque/))
  it("witness: the shell still goes by the name", async () => {
    assert.doesNotMatch(String((await decider().decide({ tool: "shell", input: { command: "cat renamed.txt" }, directory: dir })).rule), /^opaque/)
  })
})

describe("opaque-document: settings", () => {
  it("active with dangerousCommands off: it belongs to sensitiveFiles", () => {
    const active = policy({}, { dangerousCommands: false })
    assert.equal(shell("cat report.pdf", active)?.rule, "opaque-document")
    assert.equal(judge("read", { path: "report.pdf" }, active)?.rule, "opaque-document")
  })
  it("witness: off with sensitiveFiles off or set to off, on either channel", () => {
    for (const active of [policy({}, { sensitiveFiles: false }), policy({ "opaque-document": "off" })]) {
      assert.equal(shell("cat report.pdf", active), undefined)
      assert.equal(judge("read", { path: "report.pdf" }, active), undefined)
    }
  })
  it("deny turns the ask into a refusal, on either channel", () => {
    const active = policy({ "opaque-document": "deny" })
    assert.equal(shell("cat report.pdf", active)?.verdict, "deny")
    assert.equal(judge("read", { path: "report.pdf" }, active)?.verdict, "deny")
  })
  it("a setting turns it on with its group off", () => {
    assert.equal(shell("cat report.pdf", policy({ "opaque-document": "ask" }, { sensitiveFiles: false }))?.rule, "opaque-document")
  })
  it("model and localAsks never leave it to the decision model: nothing to judge but a name", () => {
    for (const active of [policy({ "opaque-document": "model" }), policy({}, { localAsksByModel: true })]) {
      for (const found of [shell("cat report.pdf", active), judge("read", { path: "report.pdf" }, active)]) {
        assert.equal(found?.rule, "opaque-document")
        assert.equal(found?.verdict, "ask")
        assert.equal(found && decidable(found), false)
      }
    }
  })
  it("a form that reaches the rule through a heredoc is never left to the decision model either", () => {
    for (const command of ["bash <<'E'\ncat report.pdf\nE", "cat <<E\n$(cat report.pdf)\nE"]) {
      const found = shell(command, policy({}, { localAsksByModel: true }))
      assert.equal(found?.rule, "opaque-document", command)
      assert.equal(found && decidable(found), false, command)
    }
  })
  it("model on it is kept with a warning that says the ask stays with the user", () => {
    const { warnings, config } = parseConfig({ ruleOverrides: { "opaque-document": "model" } }, {}, declaring({ ruleOverrides: { "opaque-document": "model" } }))
    assert.ok(warnings.some((line) => /ruleOverrides\.opaque-document "model": the decision model gets only the file's name/.test(line)), warnings.join("\n"))
    assert.equal(config.policy.overrides?.get("opaque-document"), "model")
  })
  it("the settings text says what model does", () => {
    assert.match(ruleSettings("opaque-document", "sensitiveFiles"), /"model" asks like "ask"/)
  })
})

describe("opaque-image: off by default", () => {
  const images = ["png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff"]
  it("witness: with no setting, whatever the policy, nothing asks", () => {
    for (const active of [undefined, policy({}), policy({ "opaque-document": "deny" })]) {
      for (const extension of images) {
        assert.equal(judge("read", { path: `a.${extension}` }, active), undefined, extension)
        assert.equal(shell(`cat a.${extension}`, active), undefined, extension)
      }
    }
  })
  for (const extension of images)
    it(`set to ask: read and cat of a .${extension}, any case`, () => {
      assert.equal(judge("read", { path: `a.${extension}` }, IMAGES_ON)?.rule, "opaque-image")
      assert.equal(judge("read", { filePath: `a.${extension.toUpperCase()}` }, IMAGES_ON)?.rule, "opaque-image")
      assert.equal(shell(`xxd a.${extension}`, IMAGES_ON)?.rule, "opaque-image")
    })
  it("the reason names an image, with no path", () => {
    assert.equal(judge("read", { path: "a.png" }, IMAGES_ON)?.reason, "the guard plugin cannot see inside this image: answering yes lets it through unchecked")
  })
  it("deny refuses; a setting turns it on with sensitiveFiles off", () => {
    assert.equal(judge("read", { path: "a.png" }, policy({ "opaque-image": "deny" }))?.verdict, "deny")
    assert.equal(shell("cat a.png", policy({ "opaque-image": "ask" }, { sensitiveFiles: false }))?.rule, "opaque-image")
  })
  it("model turns it on and asks like ask: the model does not see the pixels", () => {
    const found = judge("read", { path: "a.png" }, policy({ "opaque-image": "model" }))
    assert.equal(found?.verdict, "ask")
    assert.equal(found && decidable(found), false)
  })
  it("witness: off stays off, the other rules unchanged", () => {
    const active = policy({ "opaque-image": "off" })
    assert.equal(judge("read", { path: "a.png" }, active), undefined)
    assert.equal(shell("git reset --hard", active)?.rule, "git-reset-hard")
  })
  it("witness: the extraction itself asks nothing, and its image asks nothing while the rule is off", () => {
    for (const command of ["pdfimages report.pdf out", "unzip report.docx"]) assert.equal(shell(command, IMAGES_ON), undefined, command)
    assert.equal(judge("read", { path: "out-000.png" }), undefined)
  })
  it("the second step of an extraction asks while the rule is on", () => {
    assert.equal(judge("read", { path: "out-000.png" }, IMAGES_ON)?.rule, "opaque-image")
  })
})

describe("opaque-image: who can turn it on", () => {
  const PROJECT = "/w/app"
  const inputs = (files: readonly GuardFile[]) => ({ files, project: PROJECT, realPath: (path: string) => path, regularFile: () => true })
  const projectFile = (data: Record<string, unknown>): GuardFile => ({ label: "project guard.json (/w/app/.opencode/guard.json)", global: false, dir: PROJECT, data })
  const globalFile = (data: Record<string, unknown>): GuardFile => ({ label: "global guard.json", global: true, data })

  it("an untrusted project's guard.json turns it on: that only hardens", () => {
    const { config, warnings } = parseConfig({}, {}, declaring({}), inputs([projectFile({ ruleOverrides: { "opaque-image": "ask" } })]))
    assert.equal(config.policy.overrides?.get("opaque-image"), "ask", warnings.join("\n"))
    assert.deepEqual(warnings.filter((line) => line.includes("opaque-image")), [])
  })
  it("an agent section of an untrusted project's guard.json turns it on for that agent only", () => {
    const files = [projectFile({ agents: { build: { ruleOverrides: { "opaque-image": "ask" } } } })]
    const { config } = parseConfig({}, {}, declaring({}), inputs(files))
    const version = resolveVersion(config.layers!, files)
    assert.equal(judge("read", { path: "a.png" }, version.scope("build", undefined, undefined).policy)?.rule, "opaque-image")
    assert.equal(judge("read", { path: "a.png" }, version.scope("plan", undefined, undefined).policy), undefined)
  })
  it("its model too, with the warning only", () => {
    const { config } = parseConfig({}, {}, declaring({}), inputs([projectFile({ ruleOverrides: { "opaque-image": "model" } })]))
    assert.equal(config.policy.overrides?.get("opaque-image"), "model")
  })
  it("an untrusted project does not turn it off once the global configuration turned it on", () => {
    const { config, warnings } = parseConfig({}, {}, declaring({}), inputs([globalFile({ ruleOverrides: { "opaque-image": "ask" } }), projectFile({ ruleOverrides: { "opaque-image": "off" } })]))
    assert.equal(config.policy.overrides?.get("opaque-image"), "ask")
    assert.ok(warnings.some((line) => /opaque-image.*ignored/.test(line)), warnings.join("\n"))
  })
  it("the plugin options of a project, read without guard.json layers, turn it on without the global configuration", () => {
    const { config } = parseConfig({ ruleOverrides: { "opaque-image": "ask" } }, {}, declaring({}))
    assert.equal(config.policy.overrides?.get("opaque-image"), "ask")
  })
  it("off refused on a rule that stays off anyway is not said to be ignored", () => {
    const { config, warnings } = parseConfig({ ruleOverrides: { "opaque-image": "off" } }, {}, declaring({}))
    assert.equal(config.policy.overrides?.has("opaque-image") ?? false, false)
    assert.deepEqual(warnings.filter((line) => /opaque-image.*ignored/.test(line)), [])
  })
  it("off over a rule the global configuration turned on: its setting stays, and the off is said to be ignored", () => {
    const { config, warnings } = parseConfig({ ruleOverrides: { "opaque-image": "off" } }, {}, declaring({ ruleOverrides: { "opaque-image": "ask" } }))
    assert.equal(config.policy.overrides?.get("opaque-image"), "ask")
    assert.equal(warnings.filter((line) => /opaque-image.*ignored/.test(line)).length, 1, warnings.join("\n"))
  })
  it("witness: those options still do not turn off opaque-document", () => {
    const { config, warnings } = parseConfig({ ruleOverrides: { "opaque-document": "off" } }, {}, declaring({}))
    assert.equal(config.policy.overrides?.has("opaque-document") ?? false, false)
    assert.ok(warnings.some((line) => /opaque-document.*ignored/.test(line)), warnings.join("\n"))
  })
})

describe("guard rules on the opaque rules, in a temporary directory", () => {
  it("model on them relaxes nothing, so an agent is not said to be relaxed by it", () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-opaque-model-")))
    const [globalDir, systemDir, home, data, project] = ["global", "system", "home", "data", "app"].map((name) => join(root, name)) as [string, string, string, string, string]
    for (const dir of [globalDir, systemDir, home, data, project]) mkdirSync(dir)
    writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR }] }))
    const agent = (setting: Record<string, string>) => {
      writeFileSync(join(globalDir, "guard.json"), JSON.stringify({ agents: { n3: { ruleOverrides: setting } } }))
      const out: string[] = []
      main(["agent", "on", "n3"], { env: { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }, cwd: project, systemDir, out: (line) => out.push(line), err: () => {} })
      return out.join("\n")
    }
    assert.doesNotMatch(agent({ "opaque-document": "model" }), /still relaxed/)
    assert.doesNotMatch(agent({ "opaque-image": "model" }), /still relaxed/)
    assert.match(agent({ rm: "model" }), /still relaxed: ruleOverrides\.rm/)
  })
  function run(guardJson?: unknown) {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-opaque-")))
    const [globalDir, systemDir, home, data, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "data"), join(root, "app")]
    for (const dir of [globalDir, systemDir, home, data, project]) mkdirSync(dir, { recursive: true })
    writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: {} }] }))
    if (guardJson) writeFileSync(join(globalDir, "guard.json"), JSON.stringify(guardJson))
    const env = { HOME: home, OPENCODE_CONFIG_DIR: globalDir, XDG_DATA_HOME: data }
    return (...args: string[]) => {
      const out: string[] = []
      const err: string[] = []
      const code = main(args, { env, cwd: project, systemDir, out: (line: string) => out.push(line), err: (line: string) => err.push(line) })
      return { code, out, err }
    }
  }
  const row = (lines: readonly string[]) => lines.find((line) => line.startsWith("opaque-image"))!

  it("the list shows its real state", () => {
    const off = run()
    assert.match(row(off("rules", "--builtins").out as string[]), /^opaque-image\s+sensitiveFiles\s+ask\s+off {2}off by default/)
    const on = run({ ruleOverrides: { "opaque-image": "ask" } })
    assert.match(row(on("rules", "--builtins").out as string[]), /^opaque-image\s+sensitiveFiles\s+ask\s+on {2}off by default/)
  })
  it("--explain gives the details, the settings and the state", () => {
    const out = run()("rules", "--explain", "opaque-image").out as string[]
    assert.ok(out.some((line) => /^ {2}Settings: Off by default.* State here: off\.$/.test(line)), out.join("\n"))
    const document = run()("rules", "--explain", "opaque-document").out as string[]
    assert.ok(document.some((line) => line.includes("pdftotext")), document.join("\n"))
  })
  it("set then reset, the rule said to be off by default again", () => {
    const guard = run()
    const set = guard("rules", "ask", "opaque-image")
    assert.equal(set.code, 0, (set.err as string[]).join("\n"))
    assert.match(row(guard("rules", "--builtins").out as string[]), /\son {2}off by default/)
    const reset = guard("rules", "reset", "opaque-image")
    assert.ok((reset.out as string[]).includes("opaque-image is off by default: it does not apply there without a setting"), (reset.out as string[]).join("\n"))
  })
})

describe("opaque rules: cost", () => {
  it("witness: a long command stays linear", () => {
    const commands = [`cat ${"a.txt ".repeat(40_000)}`, `cat ${"x.{a,".repeat(40_000)}`, `echo ${"$(echo a.pdf) ".repeat(10_000)}`, `cat ${"a.pdf".repeat(50_000)}.txt`, `${"cat a.txt; ".repeat(20_000)}echo a.pdf`, `sh x; echo ${"'a.pdf' ".repeat(20_000)}`, `sh x; echo ${"\"'".repeat(20_000)}.pdf`, "bash x 'a.pdf'; ".repeat(10_000), "bash <<E\ncat a.txt\nE\n".repeat(10_000), `${"x; ".repeat(40_000)}sh 'a.pdf'`, `${"(".repeat(40_000)}a.pdf`, `${"sh -c '".repeat(20_000)}a.pdf`]
    for (const command of commands) {
      const start = performance.now()
      shell(command, IMAGES_ON)
      assert.ok(fastEnough(performance.now() - start, 4_000), command.slice(0, 20))
    }
  })
})
