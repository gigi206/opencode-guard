// `guard settings`: the row of a check's questions speaks of the questions only, not of its other settings. Fake settings in
// throwaway directories, nothing is run.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "node:test"
import { main } from "../src/cli/main.ts"
import { parseConfig } from "../src/config.ts"
import { DEFAULT_OUTPUT_QUESTIONS, DEFAULT_PROMPT_QUESTIONS } from "../src/model/questions.ts"

const PLUGIN_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)))
const decision = { baseURL: "https://decision.example.invalid/v1", model: "m" }
const QUESTIONS = { word: { none: "NONE" } }

function row(options: Record<string, unknown>, name: string) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-questions-")))
  const [globalDir, systemDir, home, project] = [join(root, "global"), join(root, "system"), join(root, "home"), join(root, "project")]
  for (const dir of [globalDir, systemDir, home, project]) mkdirSync(dir, { recursive: true })
  writeFileSync(join(globalDir, "opencode.json"), JSON.stringify({ plugins: [{ package: PLUGIN_DIR, options: { decision, ...options } }] }))
  const out: string[] = []
  const code = main(["settings"], { env: { HOME: home, OPENCODE_CONFIG_DIR: globalDir }, cwd: project, systemDir, out: (line) => out.push(line), err: () => {} })
  assert.equal(code, 0)
  return out.find((line) => line.startsWith(`${name} `))?.trim().split(/ {2,}/)
}

describe("guard settings: questions of a check", () => {
  for (const check of ["outputCheck", "promptCheck"]) {
    for (const settings of [{ threshold: 0.3 }, { partChars: 1000 }, ...(check === "outputCheck" ? [{ skip: ["read"] }, { timeoutMs: 1000 }] : [])]) {
      it(`${check} with only ${Object.keys(settings)[0]}: the questions stay the default ones`, () => {
        const cells = row({ [check]: settings }, `${check}.questions`)
        assert.deepEqual(cells?.slice(2), ["default", "default", "default", "default"])
      })
    }

    it(`witness: ${check} with its questions set shows them custom`, () => {
      const cells = row({ [check]: { questions: QUESTIONS } }, `${check}.questions`)
      assert.deepEqual(cells?.slice(2), ["custom", "default", "global opencode.json", "overridden"])
    })

    it(`witness: ${check} with its questions and a threshold shows them custom`, () => {
      assert.equal(row({ [check]: { threshold: 0.3, questions: QUESTIONS } }, `${check}.questions`)?.[2], "custom")
    })

    it(`witness: ${check} with no setting of its own shows the default questions`, () => {
      assert.equal(row({}, `${check}.questions`)?.[2], "default")
    })

    it(`witness: ${check} with its questions empty shows the default ones`, () => {
      assert.equal(row({ [check]: { questions: {} } }, `${check}.questions`)?.[2], "default")
    })

    it(`witness: ${check} with its questions written as they are by default shows the default ones`, () => {
      const written = check === "outputCheck" ? DEFAULT_OUTPUT_QUESTIONS : DEFAULT_PROMPT_QUESTIONS
      assert.equal(row({ [check]: { questions: written } }, `${check}.questions`)?.[2], "default")
    })

    it(`${check} turned off: its questions are not in force, whatever is written`, () => {
      const cells = row({ [check]: { enabled: false, questions: QUESTIONS } }, `${check}.questions`)
      assert.deepEqual(cells?.slice(2), ["default", "default", "global opencode.json", "same as default"])
    })

    it(`witness: ${check} turned off without questions shows the default ones`, () => {
      assert.equal(row({ [check]: false }, `${check}.questions`)?.[2], "default")
    })

    it(`witness: the custom flag of ${check} still covers its other settings`, () => {
      const options = { decision, [check]: { threshold: 0.3 } }
      const parsed = parseConfig(options, {}, () => [{ label: "global", options }]).config
      assert.equal(parsed[check as "outputCheck" | "promptCheck"]?.custom, true)
    })
  }
})
