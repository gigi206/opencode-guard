// The host of a URL in CodeMode code is read as the URL parser reads it: a local address in a short or numeric form asks you,
// like the dotted form, and is never left to the decision model. Text only, nothing is fetched.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { toolFinding } from "../src/rules/tools.ts"
import { createRedactor } from "../src/secrets/redact.ts"

const ctx = { redactor: createRedactor(), home: "/home/test", cwd: "/project" }
const finding = (code: string) => toolFinding("execute", { code }, ctx)
const fetched = (url: string) => finding(`await fetch("${url}")`)

describe("CodeMode: local addresses in any form", () => {
  it("short, numeric and mapped forms of a local address are local", () => {
    for (const url of [
      "http://127.0.0.1/",
      "http://127.1/",
      "http://127.1:4096/api",
      "http://0x7f000001/",
      "http://0x7f.1/",
      "http://2130706433/",
      "http://0177.0.0.1/",
      "http://0/",
      "http://10.1/",
      "http://192.168.1/",
      "http://[::ffff:127.0.0.1]/",
      "HTTP://127.1/",
      "https://user@127.1/",
    ]) {
      const found = fetched(url)
      assert.match(found?.reason ?? "", /local or private address/, url)
      assert.equal(found?.modelDecides, undefined, url)
    }
  })
  it("a template part after the host does not hide it", () => {
    assert.match(finding("await fetch(`http://127.1:${port}/x`)")?.reason ?? "", /local or private address/)
  })
  it("a public address stays with the decision model", () => {
    for (const url of ["https://example.com/", "http://8.8.8.8/", "http://134744072/", "http://0x08080808/"]) {
      const found = fetched(url)
      assert.equal(found?.rule, "codemode-fetch", url)
      assert.ok(found?.modelDecides, url)
    }
  })
  it("text that is not a host never throws", () => {
    for (const url of ["http://[/", "http://:::/", "http://%zz/", `http://${"a".repeat(300)}/`]) assert.doesNotThrow(() => fetched(url), url)
  })
  it("the cost stays linear with many URLs", () => {
    const code = (count: number) => `await fetch("x"); ${'"http://example.com/" '.repeat(count)}`
    const time = (count: number) => {
      const start = performance.now()
      finding(code(count))
      return performance.now() - start
    }
    time(100)
    assert.ok(time(20_000) < 2000)
  })
})
