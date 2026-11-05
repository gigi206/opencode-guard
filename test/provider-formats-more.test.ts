// More provider formats, each from a public reference (see `patterns.ts`). Fake values at the exact length of each
// format, built at run time; nothing is run.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, realpathSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, it } from "node:test"
import { completionScript } from "../src/cli/completion.ts"
import { redactionOffOption } from "../src/config.ts"
import { BUILTIN_PATTERNS, FORMAT_SUMMARIES } from "../src/secrets/patterns.ts"
import { createRedactor, placeholder } from "../src/secrets/redact.ts"
import { withinBudget } from "./budget.ts"
import { main } from "../src/cli/main.ts"

const redact = (text: string) => createRedactor().redactString(text).value
function run(set: string, length: number, seed = 11): string {
  let a = seed
  let out = ""
  for (let i = 0; i < length; i++) {
    a = (a * 1103515245 + 12345) % 2147483648
    out += set[a % set.length]
  }
  return out
}
const AN = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
const URL64 = `${AN}_-`
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
const DIGITS = "0123456789"

const TOKENS: Array<[string, string]> = [
  ["slack_app_token", `xapp-1-A${run(AN, 10)}-${run(DIGITS, 13)}-${run("abcdef0123456789", 64)}`],
  ["slack_config_token", `xoxe-1-${run(AN, 146)}`],
  ["slack_config_token", `xoxe.xoxp-1-${run(AN, 165)}`],
  ["slack_config_token", `xoxe.xoxb-1-${run(AN, 163)}`],
  ["replicate_token", `r8_${run(URL64, 37)}`],
  ["groq_key", `gsk_${run(AN, 52)}`],
  ["resend_key", `re_${run(B58, 8)}_${run(B58, 24)}`],
  ["notion_token", `ntn_${run(DIGITS, 11)}${run(AN, 35)}`],
  ["google_oauth_secret", `GOCSPX-${run(URL64, 28)}`],
  ["discord_bot_token", `M${run(URL64, 23)}.${run(URL64, 6)}.${run(URL64, 27)}`],
  ["discord_bot_token", `O${run(URL64, 25)}.${run(URL64, 6)}.${run(URL64, 27)}`],
  ["telegram_bot_token", `${run(DIGITS, 10)}:A${run(URL64, 34)}`],
  ["mapbox_secret_token", `sk.eyJ${run(URL64, 60)}.${run(URL64, 22)}`],
  ["mapbox_secret_token", `sk.eyJ${run(URL64, 400)}.${run(URL64, 22)}`],
  ["mapbox_secret_token", `sk.eyJ${run(URL64, 60)}.eyJ${run(URL64, 40)}.${run(URL64, 26)}`],
  ["slack_config_token", `xoxe-1-${run(AN, 40)}`],
  ["slack_config_token", `xoxe-1-${run(AN, 200)}`],
]

describe("more provider formats", () => {
  it("PM-1: each one is masked whole under its type, alone and in a sentence", () => {
    for (const [type, token] of TOKENS) {
      assert.equal(redact(`key ${token} end`), `key ${placeholder(type)} end`, type)
      assert.equal(redact(token), placeholder(type), type)
    }
  })
  it("witness: PM-2: near misses stay", () => {
    for (const text of [
      `r8_${run(URL64, 36)}`,
      `gsk_${run(AN, 51)}`,
      `ntn_${run(AN, 46)}`,
      `GOCSPX-${run(URL64, 27)}`,
      `M${run(URL64, 22)}.${run(URL64, 6)}.${run(URL64, 27)}`,
      `A${run(URL64, 23)}.${run(URL64, 6)}.${run(URL64, 27)}`,
      `xoxe-1-${run(AN, 39)}`,
      `xapp-${run(AN, 10)}`,
      `127001:B${run(URL64, 34)}`,
      `8080:${run(AN, 12)}`,
    ])
      assert.equal(redact(text), text)
  })
  it("witness: PM-3: `re_` identifiers stay: only the exact shape is a key", () => {
    for (const text of ["re_compile", "re_compile_pattern_matcher", `re_${"a".repeat(32)}`, `re_abcdefgh_${"l".repeat(24)}`, `re_${run(B58, 7)}_${run(B58, 24)}`, `re_${run(B58, 8)}_${run(B58, 23)}`])
      assert.equal(redact(`call ${text}(x)`), `call ${text}(x)`)
  })
  it("witness: PM-4: a public Mapbox token and a short `sk.` name stay", () => {
    const pub = `pk.eyJ${run(URL64, 60)}.${run(URL64, 22)}`
    assert.equal(redact(pub), pub)
    for (const text of ["sk.create(options)", `sk.${"ab.".repeat(20)}x`, `sk.eyJ${run(URL64, 39)}.${run(URL64, 22)}`, `sk.eyJ${run(URL64, 60)}.${run(URL64, 19)}`]) assert.equal(redact(text), text)
  })
  it("witness: PM-9: a Java or Kotlin name under the `sk` domain stays", () => {
    for (const text of [
      "at sk.company.project.backend.service.impl.CustomerAccountManagementServiceImplementation.findAll(X.kt:12)",
      "import sk.gov.finance.tax.declarations.internal.persistence.repositories.jpa.custom.TaxDeclarationRepositoryImpl;",
      `sk.${run(AN, 60)}.${run(AN, 22)}`,
    ])
      assert.equal(redact(text), text)
  })
  it("PM-10: a Mapbox token at the end of a sentence is masked without its full stop", () => {
    const token = `sk.eyJ${run(URL64, 60)}.${run(URL64, 22)}`
    assert.equal(redact(`token ${token}.`), `token ${placeholder("mapbox_secret_token")}.`)
  })
  it("witness: PM-11: one character more is something else: the fixed lengths end there", () => {
    const discord = `M${run(URL64, 23)}.${run(URL64, 6)}.${run(URL64, 28)}`
    assert.equal(redact(discord), discord)
    const slack = redact(`xoxe.xoxp-1-${run(AN, 167)}`)
    assert.ok(!slack.includes(placeholder("slack_config_token")), slack)
  })
  it("PM-5: the names live wherever the formats do", async () => {
    const names = [...new Set(TOKENS.map(([type]) => type))]
    assert.equal(names.length, 10)
    const root = realpathSync(mkdtempSync(join(tmpdir(), "guard-pm-")))
    const [globalDir, systemDir] = [join(root, "g"), join(root, "s")]
    for (const dir of [globalDir, systemDir]) mkdirSync(dir)
    const out: string[] = []
    const io = { env: { HOME: root, OPENCODE_CONFIG_DIR: globalDir }, cwd: root, systemDir, out: (line: string) => out.push(line), err: () => {} }
    assert.equal(await main(["redaction"], io), 0)
    const script = completionScript("bash")
    for (const name of names) {
      assert.ok(FORMAT_SUMMARIES.has(name), name)
      assert.ok(BUILTIN_PATTERNS.some((pattern) => pattern.type === name), name)
      assert.deepEqual(redactionOffOption([name], "", []), [name])
      assert.ok(out.join("\n").includes(name), name)
      assert.ok(script.includes(name), name)
    }
  })
  it("witness: PM-6: turned off by name, a format is left alone", () => {
    const [type, token] = TOKENS[5]!
    assert.equal(createRedactor({ disabledTypes: [type] }).redactString(`key ${token} end`).value, `key ${token} end`)
  })
  it("witness: PM-7: hostile runs cost a linear time", () => {
    const start = performance.now()
    for (const text of ["xapp-1-".repeat(100_000), "xapp-1-A-1-".repeat(60_000), `xapp-1-${"A".repeat(1_000_000)}`, "sk.".repeat(200_000), `sk.${"a".repeat(1_000_000)}`, "1234567:A".repeat(60_000), `M${"a".repeat(1_000_000)}`, "re_12345678_".repeat(60_000), "sk.eyJ".repeat(200_000), `sk.eyJ${"a".repeat(1_000_000)}`, `sk.eyJ${"a.".repeat(500_000)}`, "xoxe-1-".repeat(100_000), `xoxe-1-${"a".repeat(1_000_000)}`]) redact(text)
    assert.ok(withinBudget(start, 4000))
  })
})
