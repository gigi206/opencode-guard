// Zero-width characters inside a secret: found on a copy without them, replaced only over the stretch recognized, and
// never removed from the rest of the text.
import "./tmp.ts"
import assert from "node:assert/strict"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, it } from "node:test"
import { setupGuard } from "../src/index.ts"
import { createRedactor, placeholder } from "../src/secrets/redact.ts"
import { CONTROL_CHARACTERS, createLogger } from "../src/types.ts"
import { withinBudget } from "./budget.ts"
import { fakeContext } from "./fake-ctx.ts"
import { FAKE } from "./fixtures.ts"

const [ZWSP, ZWNJ, ZWJ, BOM] = ["​", "‌", "‍", "﻿"]
const KEY = FAKE.openai
const split = (zero: string, at = 8) => `${KEY.slice(0, at)}${zero}${KEY.slice(at)}`
const redactor = () => createRedactor()
const redact = (text: string) => redactor().redactString(text)
const MASK = redact(KEY).value

describe("zero-width characters", () => {
  it("ZW-1: each character inside a key: the key is masked whole", () => {
    assert.ok(MASK.startsWith("[[GUARD_REDACTED:"))
    for (const zero of [ZWSP, ZWNJ, ZWJ, BOM]) {
      assert.deepEqual(redact(`key ${split(zero)} end`), { value: `key ${MASK} end`, count: 1 })
      assert.equal(redact(`key ${split(zero, 3)} end`).value, `key ${MASK} end`)
      assert.equal(redact(`key ${split(zero + zero + zero, 12)} end`).value, `key ${MASK} end`)
    }
    const everywhere = [...KEY].join(ZWSP)
    assert.equal(redact(everywhere).value, MASK)
  })
  it("ZW-2: exact boundary: the characters around the key stay, those inside go", () => {
    assert.equal(redact(`a${ZWJ} ${ZWSP}${split(ZWSP)}${ZWNJ} ${BOM}b`).value, `a${ZWJ} ${ZWSP}${MASK}${ZWNJ} ${BOM}b`)
    assert.equal(redact(`${ZWJ}${split(ZWSP)}`).value, `${ZWJ}${MASK}`)
    assert.equal(redact(`${split(ZWSP)}${ZWJ}`).value, `${MASK}${ZWJ}`)
  })
  it("ZW-3: a composed emoji and a phrase with ZWNJ beside a key stay intact", () => {
    const family = `\u{1f468}${ZWJ}\u{1f469}${ZWJ}\u{1f467}${ZWJ}\u{1f466}`
    const persian = `می${ZWNJ}خواهم`
    assert.equal(redact(`${family} ${split(ZWSP)} ${persian}`).value, `${family} ${MASK} ${persian}`)
  })
  it("ZW-4: a value after a token: both found, a zero-width character between them stays", () => {
    const other = FAKE.github
    const github = redact(other).value
    assert.equal(redact(`${split(ZWSP)} x${ZWJ}y ${other.slice(0, 6)}${ZWNJ}${other.slice(6)} end`).value, `${MASK} x${ZWJ}y ${github} end`)
  })
  it("ZW-5: an exact value too, alone, with what a pattern would not recognize", () => {
    const value = "fake-known-value-0123"
    const known = createRedactor({ knownSecrets: [{ name: "key", value }] })
    assert.equal(known.redactString(`a fake-known${ZWSP}-value-0123 b`).value, `a ${placeholder("config:key")} b`)
    const service = createRedactor({ runtimeSecrets: () => [{ name: "service-password", value }] })
    assert.equal(service.redactString(`fake-${BOM}known-value-0123`).value, placeholder("opencode:service-password"))
  })
  it("witness: ZW-6: an assignment keeps its name, and the separator a key leans on still works", () => {
    assert.match(redact(`PASSWORD=Pa55${ZWSP}word-for-test`).value, /^PASSWORD=\[\[GUARD_REDACTED:/)
    assert.equal(redact(`abc${ZWSP}${KEY}`).value, `abc${ZWSP}${MASK}`)
  })
  it("ZW-7: objects and containsSecret", () => {
    const r = redactor()
    const out = r.redactDeep({ a: [split(ZWJ)], b: `\u{1f468}${ZWJ}\u{1f469}` })
    assert.deepEqual(out.value, { a: [MASK], b: `\u{1f468}${ZWJ}\u{1f469}` })
    assert.equal(r.containsSecret({ deep: { text: split(ZWNJ) } }), true)
  })
  it("witness: ZW-8: redacting again changes nothing", () => {
    const once = redact(`a ${ZWJ}${split(ZWSP)} b`).value
    assert.deepEqual(redact(once), { value: once, count: 0 })
  })
  it("ZW-9: a long key split many times and many split keys cost a linear time", () => {
    const start = performance.now()
    const many = `${split(ZWSP)} ${ZWJ} `.repeat(4000)
    const out = redact(many).value
    assert.equal(out, `${MASK} ${ZWJ} `.repeat(4000))
    const noise = `word${ZWNJ}`.repeat(400_000)
    assert.equal(redact(noise).value, noise)
    const dense = `${ZWSP}`.repeat(2_000_000) + split(ZWSP)
    assert.equal(redact(dense).value, `${ZWSP}`.repeat(2_000_000) + MASK)
    assert.ok(withinBudget(start, 4000))
  })
  it("ZW-10: the log has no zero-width character left", () => {
    const file = join(mkdtempSync(join(tmpdir(), "guard-zw-")), "guard.log")
    createLogger(false, file).warn(`a${ZWSP}b${ZWNJ}c${ZWJ}d${BOM}e`)
    assert.match(readFileSync(file, "utf8"), /a b c d e\n$/)
  })
  it("witness: ZW-17: what `guard` prints keeps them", () => {
    const composed = `\u{1f469}${ZWJ}\u{1f4bb} می${ZWNJ}خواهم`
    assert.equal(composed.replace(CONTROL_CHARACTERS, " "), composed)
    assert.equal(`a\u202eb`.replace(CONTROL_CHARACTERS, " "), "a b")
  })
  it("ZW-12: at any position, past the minimum length of the format too, nothing of the key stays", () => {
    const gitlab = `glpat-${"aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF"}`
    for (const token of [KEY, gitlab, FAKE.github]) {
      const mask = redact(token).value
      for (let at = 1; at < token.length; at++) {
        const cut = `${token.slice(0, at)}${ZWSP}${token.slice(at)}`
        assert.deepEqual(redact(`key ${cut} end`), { value: `key ${mask} end`, count: 1 }, String(at))
      }
    }
  })
  it("ZW-13: a token that a zero-width character separates from a word, cut further on: its end goes too", () => {
    assert.equal(redact(`abc${ZWSP}${split(ZWNJ, 30)} end`).value, `abc${ZWSP}${MASK} end`)
    assert.equal(redact(`abc${ZWSP}${KEY.slice(0, 28)}${ZWNJ}${KEY.slice(28, 32)}${ZWJ}${KEY.slice(32)}`).value, `abc${ZWSP}${MASK}`)
  })
  it("ZW-14: through the wire, the end of a cut key does not leave", async () => {
    const root = mkdtempSync(join(tmpdir(), "guard-zw-"))
    const fake = fakeContext({ logFile: join(root, "guard.log") })
    await setupGuard(fake.ctx, { HOME: root })
    const body = JSON.stringify({ messages: [{ content: `key ${split(ZWSP, 30)} end` }] })
    const request = new Request("https://provider.invalid/v1/messages", { method: "POST", body, headers: { "content-type": "application/json" } })
    const event = await fake.trigger("session.http.request", { kind: "primary", request })
    const sent = await (event as { request: Request }).request.text()
    assert.ok(!sent.includes(KEY.slice(30)), sent)
    assert.equal(JSON.parse(sent).messages[0].content, `key ${MASK} end`)
  })
  it("witness: ZW-15: limit: glued to a word and cut before the minimum length, nothing recognizes it", () => {
    const text = `abc${ZWSP}${split(ZWNJ, 8)}`
    assert.equal(redact(text).value, text)
  })
  it("witness: ZW-16: a placeholder already there keeps what follows, and an emoji or Persian text behind a key stays", () => {
    const again = `${MASK}${ZWSP}word`
    assert.deepEqual(redact(again), { value: again, count: 0 })
    assert.equal(redact(`${again} abc${ZWSP}${split(ZWNJ, 30)}`).value, `${again} abc${ZWSP}${MASK}`)
    assert.equal(redact(`abc${ZWSP}${KEY}${ZWJ}\u{1f4bb}`).value, `abc${ZWSP}${MASK}${ZWJ}\u{1f4bb}`)
    assert.equal(redact(`abc${ZWSP}${KEY}${ZWNJ}خواهم`).value, `abc${ZWSP}${MASK}${ZWNJ}خواهم`)
  })
  it("witness: ZW-11: without a key, the text comes back as it was, the same string", () => {
    for (const text of [`\u{1f468}${ZWJ}\u{1f469}`, `a${ZWNJ}b`, `${BOM}plain`, "plain"]) assert.deepEqual(redact(text), { value: text, count: 0 })
  })
})
