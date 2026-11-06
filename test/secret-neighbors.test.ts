// A secret next to a value cut short: what the pattern took past that value is read again. All values are fake.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { createRedactor, placeholder } from "../src/secrets/redact.ts"
import { withinBudget } from "./budget.ts"

const FIRST = "Zq7fK2mXpL9t"
const SECOND = "Bv4nR8wYcT3h"
const generic = placeholder("generic_secret")
const masked = (text: string, allowlist?: readonly string[]) => createRedactor({ env: {}, ...(allowlist ? { allowlist } : {}) }).redactString(text)

describe("secret next to a value cut short", () => {
  const both: ReadonlyArray<[string, string, string]> = [
    ["comma in a call", `f(password=${FIRST},token=${SECOND})`, `f(password=${generic},token=${generic})`],
    ["next table cell", `<td>password=${FIRST}</td><td>token=${SECOND}</td>`, `<td>password=${generic}</td><td>token=${generic}</td>`],
    ["literal line feed", `DB_PASSWORD=${FIRST}\\nAPI_TOKEN=${SECOND}\\n`, `DB_PASSWORD=${generic}\\nAPI_TOKEN=${generic}\\n`],
    ["both key names", `ENCRYPTION_KEY=${FIRST},MASTER_KEY=${SECOND}`, `ENCRYPTION_KEY=${generic},MASTER_KEY=${generic}`],
    ["both pass names", `DB_PASS=${FIRST},SMTP_PASS=${SECOND}`, `DB_PASS=${generic},SMTP_PASS=${generic}`],
  ]
  for (const [name, text, expected] of both) {
    it(name, () => {
      const result = masked(text)
      assert.equal(result.value, expected)
      assert.equal(result.count, 2)
    })
  }

  it("a chain of neighbors, with other arguments between them", () => {
    const result = masked(`user=bob,password=${FIRST},secret=${SECOND},token=${FIRST}x,host=db`)
    assert.equal(result.value, `user=bob,password=${generic},secret=${generic},token=${generic},host=db`)
    assert.equal(result.count, 3)
  })

  it("a first value that is not a secret does not hide its neighbor", () => {
    for (const first of ["process.env.PW", "${DB_PW}", "changeme", "short1"]) {
      assert.equal(masked(`f(password=${first},token=${SECOND})`).value, `f(password=${first},token=${generic})`, first)
    }
  })

  it("an allowed first value does not hide its neighbor", () => {
    assert.equal(masked(`f(password=${FIRST},token=${SECOND})`, [FIRST]).value, `f(password=${FIRST},token=${generic})`)
  })

  it("after a value already replaced by a marker", () => {
    assert.equal(masked(`f(password=${generic},token=${SECOND})`).value, `f(password=${generic},token=${generic})`)
    const known = `sk-ant-api03-${"aB3dE6gH9jK2".repeat(8)}`
    const result = masked(`f(password=${known},token=${SECOND})`)
    assert.ok(!result.value.includes(known) && !result.value.includes(SECOND), result.value)
  })

  it("in a text that holds a line feed as an escape inside JSON", () => {
    const text = JSON.stringify({ data: { ".env": `SECRET_KEY=${FIRST}\nDB_PASSWORD=${SECOND}\nAPI_TOKEN=${FIRST}x\n` } })
    const result = masked(text)
    assert.equal(result.count, 3)
    assert.ok(!result.value.includes(FIRST) && !result.value.includes(SECOND), result.value)
  })

  it("the value of a neighbor ends at any `<`, as documented", () => {
    assert.equal(masked(`password=${FIRST},token=parseToken2<Claims>(raw)`).value, `password=${generic},token=${generic}<Claims>(raw)`)
  })

  for (const unit of [`password=${FIRST},`, `</td><td>token=${FIRST}`, `\\nAPI_TOKEN=${FIRST}`, `password=${FIRST}!<b`, `token=${FIRST}]]>`]) {
    it(`a long run of neighbors is read in linear time: ${unit}`, () => {
      const repeated = 100_000
      const start = performance.now()
      const result = masked(unit.repeat(repeated))
      assert.ok(withinBudget(start, 3000))
      assert.equal(result.count, repeated)
      assert.ok(!result.value.includes(FIRST))
    })
  }

  it("after the end of a CDATA section", () => {
    assert.equal(masked(`password=${FIRST}]]>token=${SECOND}]]>`).value, `password=${generic}]]>token=${generic}]]>`)
  })

  it("witness: other separators keep their result", () => {
    const expected: ReadonlyArray<[string, string, number]> = [
      [`password=${FIRST}&token=${SECOND}`, `password=${generic}`, 1],
      [`password=${FIRST};token=${SECOND}`, `password=${generic};token=${generic}`, 2],
      [`password=${FIRST}, token=${SECOND}`, `password=${generic}, token=${generic}`, 2],
      [`password=${FIRST}\ntoken=${SECOND}`, `password=${generic}\ntoken=${generic}`, 2],
    ]
    for (const [text, value, count] of expected) assert.deepEqual(masked(text), { value, count }, text)
  })

  it("witness: a comma without a neighbor does not end a value", () => {
    assert.deepEqual(masked(`DB_PASSWORD=${FIRST},${SECOND}`), { value: `DB_PASSWORD=${generic}`, count: 1 })
  })

  it("witness: a custom pattern that can match nothing ends", () => {
    const redactor = createRedactor({ env: {}, extraPatterns: [{ type: "custom", regex: /(?<secret>x*)/g }] })
    assert.equal(redactor.redactString("abc").count, 0)
  })

  it("witness: a masked text does not change when read again, as on the wire", () => {
    const once = masked(`f(password=${FIRST},token=${SECOND})`).value
    assert.deepEqual(masked(once), { value: once, count: 0 })
    for (const text of [`<td>password=${FIRST}</td><td>token=${SECOND}</td>`, `password=${FIRST}]]>token=${SECOND}]]>`]) {
      const again = masked(text).value
      assert.deepEqual(masked(again), { value: again, count: 0 })
    }
  })
})

describe("PublicKeyToken", () => {
  const left = [
    '<assemblyIdentity name="Newtonsoft.Json" publicKeyToken="30ad4fe6b2a6aeed" culture="neutral"/>',
    '<Reference Include="System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"/>',
    '"publicKeyToken": "30ad4fe6b2a6aeed"',
  ]
  for (const text of left) {
    it(`left as it is: ${text.slice(0, 40)}`, () => assert.deepEqual(masked(text), { value: text, count: 0 }))
  }

  for (const text of ["PublicKeyToken=b77a5c561934e089", 'publicKeyToken="b77a5c561934e089"', "System.Web, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a, processorArchitecture=MSIL", "List[[System.String, PublicKeyToken=b77a5c561934e089]]"])
    it(`the value of .NET stays: ${text}`, () => assert.deepEqual(masked(text), { value: text, count: 0 }))
  for (const name of ["public_key_token", "PUBLIC_KEY_TOKEN", "public-key-token", "public.key.token", "publickeytoken", "MY_PUBLIC_KEY_TOKEN", "PublicKeyToken"])
    it(`witness: ${name} with another value is masked`, () => assert.equal(masked(`${name}=${FIRST}`).value, `${name}=${generic}`))
  for (const text of ["public_key_tokens=b77a5c561934e089", "public_key_token_v2=b77a5c561934e089", "PublicKeyToken=b77a5c561934e08", "PublicKeyToken=b77a5c561934e089a", "PublicKeyToken=b77a5c561934e089/x"])
    it(`witness: not the form of .NET, masked: ${text}`, () => assert.equal(masked(text).count, 1))
  it("witness: a token that is not a public key token is still masked", () => {
    assert.equal(masked(`keyToken="${FIRST}" api_token=${SECOND}`).count, 2)
  })

  it("witness: another secret word after publicKey is still masked", () => {
    assert.equal(masked(`publicKeyPassword=${FIRST} public_key_secret=${SECOND}`).count, 2)
  })
})
