import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { createRedactor, isSignedBlock, isToolArguments, PLACEHOLDER_RE } from "../src/secrets/redact.ts"
import { envSecretValues, looksLikeSecretValue } from "../src/secrets/patterns.ts"
import { FAKE, rand } from "./fixtures.ts"

const redactor = createRedactor()

describe("secret patterns", () => {
  for (const [name, secret] of Object.entries(FAKE)) {
    if (name === "password") continue
    it(`detects ${name}`, () => {
      const { value, count } = redactor.redactString(`before ${secret} after`)
      assert.ok(count >= 1, value)
      assert.ok(!value.includes(secret), value)
      assert.ok(PLACEHOLDER_RE.test(value))
      assert.ok(value.startsWith("before ") && value.endsWith(" after"), value)
    })
  }

  it("keeps only the assignment prefix (.env, JSON, YAML)", () => {
    const env = redactor.redactString(`DB_PASSWORD=${FAKE.password}`)
    assert.equal(env.value, "DB_PASSWORD=[[GUARD_REDACTED:generic_secret]]")
    const json = redactor.redactString(`{"api_key": "${FAKE.password}"}`)
    assert.equal(json.value, `{"api_key": "[[GUARD_REDACTED:generic_secret]]"}`)
    const yaml = redactor.redactString(`client_secret: ${FAKE.password}`)
    assert.equal(yaml.value, "client_secret: [[GUARD_REDACTED:generic_secret]]")
  })

  it("keeps `Bearer ` and redacts the token", () => {
    const { value } = redactor.redactString(`Authorization: Bearer ${rand(32, 20)}`)
    assert.equal(value, "Authorization: Bearer [[GUARD_REDACTED:bearer_token]]")
  })

  it("redacts the password in a URL", () => {
    const { value } = redactor.redactString(`postgres://admin:${FAKE.password}@db.local:5432/app`)
    assert.equal(value, "postgres://admin:[[GUARD_REDACTED:url_credentials]]@db.local:5432/app")
  })

  it("redacts a complete PEM block", () => {
    const { value, count } = redactor.redactString(`key:\n${FAKE.privateKey}\nend`)
    assert.equal(count, 1)
    assert.equal(value, "key:\n[[GUARD_REDACTED:private_key]]\nend")
  })

  const negatives = [
    "const token = process.env.API_TOKEN",
    "password: string",
    "api_key = getApiKey()",
    'token: "<your-token-here>"',
    "API_KEY=changeme",
    "SECRET_KEY=${SECRET_KEY}",
    "commit 3f2a9c4e8b1d7f6a5e4c3b2a1d0f9e8c7b6a5d4c",
    "uuid 123e4567-e89b-12d3-a456-426614174000",
    "docker run --rm -it image",
    "https://example.com/path?q=1",
    "let passwordField = document.querySelector('#pw')",
    "apiKeyEnv: config.decision?.apiKeyEnv",
    "postgres://admin:${FAKE.password}@db.local:5432/app",
    "privateKey: `-----BEGIN OPENSSH PRIVATE KEY-----\\n${rand(64, 13)}\\n-----END OPENSSH PRIVATE KEY-----`",
    "if (text.includes('-----BEGIN RSA PRIVATE KEY-----')) warn()",
  ]
  for (const text of negatives) {
    it(`ignores: ${text}`, () => assert.equal(redactor.redactString(text).count, 0, redactor.redactString(text).value))
  }

  it("still redacts a truncated PEM block (header + base64)", () => {
    const truncated = `-----BEGIN RSA PRIVATE KEY-----\n${rand(64, 30)}\n${rand(64, 31)}`
    assert.equal(redactor.redactString(truncated).value, "[[GUARD_REDACTED:private_key]]")
  })

  it("is idempotent", () => {
    const once = redactor.redactString(`OPENAI_API_KEY=${FAKE.openai}`).value
    assert.equal(redactor.redactString(once).count, 0)
  })

  it("looksLikeSecretValue", () => {
    assert.ok(looksLikeSecretValue(FAKE.password))
    assert.ok(!looksLikeSecretValue("config.apiKey"))
    assert.ok(!looksLikeSecretValue("undefined"))
  })
})

describe("known environment values", () => {
  const env = {
    MY_SERVICE_TOKEN: "s3cr3t-value-not-matching-any-pattern",
    SSH_AUTH_SOCK: "/run/user/1000/ssh-agent.socket",
    HOME: "/home/user",
    API_URL: "https://api.example.com/v1",
    SHORT_KEY: "abc",
  }
  it("keeps only plausible secrets", () => {
    assert.deepEqual(
      envSecretValues(env).map((item) => item.name),
      ["MY_SERVICE_TOKEN"],
    )
  })
  it("replaces the exact value", () => {
    const local = createRedactor({ env })
    const { value } = local.redactString(`echo s3cr3t-value-not-matching-any-pattern`)
    assert.equal(value, "echo [[GUARD_REDACTED:env:MY_SERVICE_TOKEN]]")
  })
  it("respects the allowlist", () => {
    const local = createRedactor({ env, allowlist: ["s3cr3t-value-not-matching-any-pattern"] })
    assert.equal(local.redactString("s3cr3t-value-not-matching-any-pattern").count, 0)
  })
})

describe("redactDeep", () => {
  it("does not mutate the input and returns the same reference when nothing changes", () => {
    const clean = { a: ["x", { b: "y" }], n: 1 }
    assert.equal(redactor.redactDeep(clean).value, clean)
    const dirty = { a: ["x", { b: `token=${FAKE.password}` }], n: 1 }
    const snapshot = JSON.stringify(dirty)
    const { value, count } = redactor.redactDeep(dirty)
    assert.equal(count, 1)
    assert.equal(JSON.stringify(dirty), snapshot)
    assert.notEqual(value, dirty)
    assert.equal(value.a[0], "x")
  })
  it("ignores binary content (strict base64, binary data:)", () => {
    assert.equal(redactor.redactString("QUJD".repeat(5_000)).count, 0)
    assert.equal(redactor.redactString(`${"QUJD".repeat(2_500)}\r\n${"QUJD".repeat(2_500)}`).count, 0)
    // Well-formed binary data: URL (valid base64 payload): ignored; prefix followed by something else: analyzed.
    assert.equal(redactor.redactString(`data:image/png;base64,${Buffer.from("\x89PNG\r\n\x1a\n" + "x".repeat(64), "latin1").toString("base64")}`).count, 0)
    assert.equal(redactor.redactString(`data:image/png;base64,${FAKE.openai}`).count, 1)
  })
  it("analyzes a secret buried in a long non-binary string and a textual data:", () => {
    assert.equal(redactor.redactString(`${"x".repeat(20_000)} ${FAKE.openai}`).count, 1)
    assert.equal(redactor.redactString(`${FAKE.openai}${"A".repeat(20_000)}`).count, 1)
    assert.equal(redactor.redactString(`data:text/plain,token=${FAKE.password}`).count, 1)
  })
  it("skips signed blocks when requested", () => {
    const body = {
      messages: [
        { type: "thinking", thinking: FAKE.openai, signature: "sig" },
        { type: "text", text: FAKE.openai },
      ],
    }
    const { value, count } = redactor.redactDeep(body, { skip: isSignedBlock })
    assert.equal(count, 1)
    assert.equal(value.messages[0], body.messages[0])
    assert.ok(!value.messages[1]!.text!.includes(FAKE.openai))
  })
})

describe("post-audit fixes: values with $", () => {
  it("a password containing $ is detected, a variable reference is not", () => {
    assert.equal(redactor.redactString("DB_PASSWORD=$uper$ecret1").value, "DB_PASSWORD=[[GUARD_REDACTED:generic_secret]]")
    assert.equal(redactor.redactString("DB_PASSWORD=$DB_PASS").count, 0)
    assert.equal(redactor.redactString("DB_PASSWORD=${DB_PASS}").count, 0)
  })
})

describe("error redaction (nested cause, stack, identity)", async () => {
  const { redactErrorLike, redactToolError } = await import("../src/secrets/errors.ts")
  class FakeToolError extends Error {
    readonly error?: unknown
    readonly metadata?: Record<string, unknown>
    constructor(props: { message: string; error?: unknown; metadata?: Record<string, unknown> }) {
      super(props.message)
      this.error = props.error
      this.metadata = props.metadata
    }
  }
  class DeclinedLike extends Error {}

  it("redacts the cause (its message replaces the model-side error's)", () => {
    const cause = new Error(`HTTP 401 for https://api.example.com/?token=${FAKE.password}`)
    const error = new FakeToolError({ message: "Unable to execute tool", error: cause })
    const { value, count } = redactToolError(error, redactor)
    assert.equal(count >= 1, true)
    assert.ok(value instanceof FakeToolError)
    assert.ok(!String((value.error as Error).message).includes(FAKE.password))
    assert.ok(!String((value.error as Error).stack).includes(FAKE.password))
    assert.ok(value.error instanceof Error)
  })
  it("cause chain and standard cause (`cause`) traversed", () => {
    const deep = new Error("outer", { cause: new Error(`inner ${FAKE.github}`) })
    const { value } = redactErrorLike({ message: "wrap", error: { message: "mid", error: deep } }, redactor)
    assert.ok(!JSON.stringify(value, (_k, v) => (v instanceof Error ? { m: v.message, c: v.cause } : v)).includes(FAKE.github))
  })
  it("preserves the class (instanceof): a rejection stays a rejection", () => {
    const declined = new DeclinedLike(`declined ${FAKE.github}`)
    const { value } = redactErrorLike(declined, redactor)
    assert.ok(value instanceof DeclinedLike)
    assert.ok(!(value as Error).message.includes(FAKE.github))
  })
  it("message as a getter on the prototype (BlockedError shape)", () => {
    class Blocked extends Error {
      readonly reason: string
      constructor(reason: string) {
        super()
        this.reason = reason
        delete (this as { message?: string }).message // own message removed: the prototype getter applies
      }
      override get message() {
        return this.reason
      }
    }
    const { value } = redactErrorLike(new Blocked(`blocked ${FAKE.aws}`), redactor)
    assert.ok(value instanceof Blocked)
    assert.ok(!(value as Error).message.includes(FAKE.aws))
  })
  it("non-configurable message: the copy still succeeds", () => {
    const frozen = new Error("x")
    Object.defineProperty(frozen, "message", { value: `secret ${FAKE.openai}`, writable: false, configurable: false })
    const { value, count } = redactErrorLike(frozen, redactor)
    assert.equal(count >= 1, true)
    assert.ok(!(value as Error).message.includes(FAKE.openai))
  })
  it("without a secret: same reference", () => {
    const clean = new FakeToolError({ message: "File not found", error: new Error("ENOENT") })
    assert.equal(redactToolError(clean, redactor).value, clean)
  })
  it("constructor that throws: copy preserving the class", () => {
    class Strict extends FakeToolError {
      constructor(props: { message: string; error?: unknown }) {
        if (props.message.includes("GUARD_REDACTED")) throw new Error("validation")
        super(props)
      }
    }
    const { value, count } = redactToolError(new Strict({ message: `token=${FAKE.password}` }), redactor)
    assert.ok(count >= 1) // message + stack
    assert.ok(value instanceof Strict)
    assert.ok(!value.message.includes(FAKE.password))
  })
})

describe("error redaction: deep chains and cycles", async () => {
  const { redactErrorLike, redactToolError } = await import("../src/secrets/errors.ts")
  const SECRET = `token=${FAKE.password}`

  /** Walks everything reachable (including non-enumerable message/stack/error/cause). */
  function reachable(root: unknown): { strings: string[]; objects: Set<object> } {
    const strings: string[] = []
    const objects = new Set<object>()
    const visit = (node: unknown) => {
      if (typeof node === "string") return void strings.push(node)
      if (node === null || typeof node !== "object" || objects.has(node)) return
      objects.add(node)
      for (const key of new Set([...Reflect.ownKeys(node), "message", "stack", "error", "cause"])) {
        let child: unknown
        try {
          child = (node as Record<PropertyKey, unknown>)[key]
        } catch {
          continue
        }
        visit(child)
      }
    }
    visit(root)
    return { strings, objects }
  }
  const assertNoLeak = (copy: unknown, originals: object[]) => {
    const { strings, objects } = reachable(copy)
    assert.ok(!strings.some((s) => s.includes(FAKE.password)), "no reachable string contains the secret")
    for (const original of originals) assert.ok(!objects.has(original), "the copy points to no original")
  }
  const chain = (length: number, via: "error" | "cause", secretAtBottom: boolean) => {
    const nodes: Error[] = []
    for (let i = 0; i < length; i++) nodes.push(new Error(i === length - 1 && secretAtBottom ? SECRET : `level ${i}`))
    for (let i = 0; i < length - 1; i++) Object.defineProperty(nodes[i], via, { value: nodes[i + 1], configurable: true, writable: true })
    return nodes
  }

  for (const via of ["error", "cause"] as const) {
    it(`chain of 6 (${via}) with the secret at the bottom → redacted`, () => {
      const nodes = chain(6, via, true)
      const { value, count } = redactErrorLike(nodes[0], redactor)
      assert.ok(count >= 1)
      assertNoLeak(value, [nodes[5]!])
    })
  }
  it("chain of 6 without a secret → same reference", () => {
    const nodes = chain(6, "error", false)
    assert.equal(redactErrorLike(nodes[0], redactor).value, nodes[0])
  })
  it("chain of 40 with the secret at the bottom → replaced beyond the cap, no leak", () => {
    const nodes = chain(40, "error", true)
    const { value, count } = redactErrorLike(nodes[0], redactor)
    assert.ok(count >= 1)
    assertNoLeak(value, nodes.slice(33))
    assert.ok(reachable(value).strings.some((s) => s.includes("GUARD_REDACTED:cause_too_deep")))
  })
  it("direct cycle (a.error = a) with a secret: terminates, no reference to the original", () => {
    const a = new Error(SECRET) as Error & { error?: unknown }
    a.error = a
    const { value, count } = redactErrorLike(a, redactor)
    assert.ok(count >= 1)
    assertNoLeak(value, [a])
    assert.ok(value instanceof Error)
  })
  it("indirect cycle (a.error = b, b.cause = a): terminates, no reference to the originals", () => {
    const a = new Error(SECRET) as Error & { error?: unknown }
    const b = new Error("wrapper")
    a.error = b
    Object.defineProperty(b, "cause", { value: a, configurable: true, writable: true })
    const { value } = redactErrorLike(a, redactor)
    assertNoLeak(value, [a, b])
  })
  it("cycle without a secret → same reference", () => {
    const a = new Error("clean") as Error & { error?: unknown }
    a.error = a
    assert.equal(redactErrorLike(a, redactor).value, a)
  })
  it("Tool.Error whose cause loops back to itself: no leak", () => {
    class ToolErr extends Error {
      error?: unknown
      constructor(props: { message: string; error?: unknown }) {
        super(props.message)
        this.error = props.error
      }
    }
    const top = new ToolErr({ message: SECRET })
    top.error = top
    const { value } = redactToolError(top, redactor)
    assertNoLeak(value, [top])
  })
})

describe("audit no. 3: value surrounded by code punctuation", () => {
  const R = "[[GUARD_REDACTED:generic_secret]]"
  it("redacts the value, keeps the surrounding brackets", () => {
    const pw = FAKE.password
    assert.equal(redactor.redactString(`{password: ${pw}}`).value, `{password: ${R}}`)
    assert.equal(redactor.redactString(`connect(token=${pw})`).value, `connect(token=${R})`)
    assert.equal(redactor.redactString(`token=(${pw})`).value, `token=(${R})`)
    assert.equal(redactor.redactString(`items[secret=${pw}]`).value, `items[secret=${R}]`)
  })
  it("code, references and values too short once trimmed: never redacted", () => {
    for (const text of ["token=getToken()", "api_key=${API_KEY}", "secret=arr[0123456]", "token=foo.bar(baz)", "token=(abc1234)", "password=(abc12)"])
      assert.equal(redactor.redactString(text).count, 0, text)
  })
  it("idempotent with brackets", () => {
    const once = redactor.redactString(`{password: ${FAKE.password}}`).value
    assert.equal(redactor.redactString(once).count, 0)
  })
  it("trimBrackets", async () => {
    const { trimBrackets } = await import("../src/secrets/patterns.ts")
    assert.equal(trimBrackets("abc123XYZ})"), "abc123XYZ")
    assert.equal(trimBrackets("(abc123XYZ)"), "abc123XYZ")
    assert.equal(trimBrackets("getToken()"), "getToken(")
    assert.equal(trimBrackets("${API_KEY}"), "${API_KEY")
  })
})

describe("audit no. 4: wire safety net, tool call arguments and Gemini sentinel", () => {
  const wire = <T,>(body: T) => redactor.redactDeep(body, { skip: isSignedBlock, unskippable: isToolArguments })
  it("a `signature` key crafted in a tool call's arguments no longer exempts them from redaction", () => {
    const body = {
      messages: [
        { role: "assistant", content: [{ type: "tool_use", id: "t1", name: "mcp_post", input: { signature: "1", text: FAKE.openai } }] },
        { role: "assistant", content: [{ toolUse: { toolUseId: "t2", name: "x", input: { signature: "1", text: FAKE.openai } } }] },
        { role: "model", parts: [{ functionCall: { name: "x", args: { thoughtSignature: "1", text: FAKE.openai } } }] },
      ],
    }
    const { value, count } = wire(body)
    assert.equal(count, 3)
    assert.ok(!JSON.stringify(value).includes(FAKE.openai))
  })
  it("actually signed blocks: intact (including a signed Gemini call)", () => {
    const thinking = { type: "thinking", thinking: FAKE.openai, signature: "sig" }
    const gemini = { functionCall: { name: "x", args: { text: FAKE.openai } }, thoughtSignature: "real-signature" }
    const { value, count } = wire({ content: [thinking], parts: [gemini] })
    assert.equal(count, 0)
    assert.equal(value.content[0], thinking)
    assert.equal(value.parts[0], gemini)
  })
  it("sentinel `skip_thought_signature_validator`: not a signature, the part is redacted", () => {
    const part = { functionCall: { name: "x", args: { text: FAKE.openai } }, thoughtSignature: "skip_thought_signature_validator" }
    const { value, count } = wire({ parts: [part] })
    assert.equal(count, 1)
    assert.equal(value.parts[0]!.thoughtSignature, "skip_thought_signature_validator")
  })
})

describe("audit no. 3 regression: OpenCode substitution references", () => {
  it("{env:VAR} and {file:path} are never redacted; a real value in braces is", () => {
    for (const text of ['"apiKey": "{env:NOX_API_KEY}"', "api_key={file:~/.secrets/nox}", '"token": "{env:GITHUB_TOKEN}"'])
      assert.equal(redactor.redactString(text).count, 0, text)
    assert.equal(redactor.redactString(`token={${FAKE.password}}`).count, 1)
  })
})

describe("session ses_ec3774…: base64-encoded secrets", () => {
  const b64 = (text: string | Buffer) => Buffer.from(text).toString("base64")
  const wrap = (text: string, width = 76, indent = "") => (text.match(new RegExp(`.{1,${width}}`, "g")) ?? []).map((l) => indent + l).join("\n")
  const R = "[[GUARD_REDACTED:base64]]"
  it("`base64` output of a file containing a secret (wrapped at 76): the whole block redacted", () => {
    const file = `DB_HOST: db.example.invalid\nDB_PORT: 5432\nDB_NAME: fausse_db\nDB_USER: faux_utilisateur\nDB_PASSWORD: ${FAKE.password}\n`
    const { value, count } = redactor.redactString(`${wrap(b64(file))}\n`)
    assert.equal(count, 1)
    assert.equal(value, `${R}\n`)
  })
  it("secret split by a newline, indented lines (YAML)", () => {
    const encoded = b64(`header line\nOPENAI_API_KEY=${FAKE.openai}\n`)
    const yaml = `data: |\n${wrap(encoded, 20, "  ")}\n`
    const { value, count } = redactor.redactString(yaml)
    assert.equal(count, 1)
    assert.ok(!value.includes(encoded.slice(0, 20)))
  })
  it("text without a secret, binary, image: unchanged (same reference)", () => {
    for (const text of [b64("Hello, this is an ordinary file with nothing secret.\n"), b64(Buffer.from(Array.from({ length: 300 }, (_, i) => (i * 37) % 256)))]) {
      const result = redactor.redactString(text)
      assert.equal(result.count, 0)
      assert.equal(result.value, text)
    }
  })
  it("binary at the start or archive: decoded text is still analyzed (like `strings`)", () => {
    const noisy = Buffer.concat([Buffer.from(Array.from({ length: 3000 }, (_, i) => (i * 131 + 7) % 256)), Buffer.from(`\ntoken=${FAKE.github}\n`)])
    assert.equal(redactor.redactString(b64(noisy)).count, 1)
    const tarLike = Buffer.concat([Buffer.from(`.env${"\x00".repeat(6)}0000644\x00`), Buffer.alloc(100), Buffer.from(`OPENAI_API_KEY=${FAKE.openai}\n`), Buffer.alloc(200)])
    assert.equal(redactor.redactString(b64(tarLike)).count, 1)
  })
  it("large block (> 10,000 characters) with the secret at the end: no longer skipped as binary", () => {
    const big = `${"ordinary text line\n".repeat(800)}password: ${FAKE.password}\n`
    assert.equal(redactor.redactString(b64(big)).count, 1)
  })
  it("double encoding, encoded environment value, idempotence", () => {
    assert.equal(redactor.redactString(b64(b64(`api_key=${FAKE.openai}`))).count, 1)
    const withEnv = createRedactor({ env: { MY_SERVICE_TOKEN: "zQ8rT2mW9xK4pL7vN3bY6c" } })
    const once = withEnv.redactString(`echo ${b64("value is zQ8rT2mW9xK4pL7vN3bY6c here")}`)
    assert.equal(once.count, 1)
    assert.equal(withEnv.redactString(once.value).count, 0)
  })
  it("PEM, JWT and Basic keep their type", () => {
    assert.match(redactor.redactString(FAKE.privateKey).value, /GUARD_REDACTED:private_key/)
    assert.match(redactor.redactString(`token ${FAKE.jwt}`).value, /GUARD_REDACTED:jwt/)
    assert.match(redactor.redactString(`Authorization: Basic ${b64("admin:Sup3rS3cretPassw0rd")}`).value, /GUARD_REDACTED:basic_auth/)
  })
  it("data:image/ prefix followed by something else: redaction active", () => {
    assert.equal(redactor.redactString(`data:image/png;base64,${b64(`password: ${FAKE.password}`)}\nOPENAI_API_KEY=${FAKE.openai}`).count, 2)
    assert.equal(redactor.redactString(`data:image/png;base64,x\nOPENAI_API_KEY=${FAKE.openai}`).count, 1)
  })
})

describe("session ses_ec361019 (audit by another AI): redaction", async () => {
  const { redactErrorLike, redactToolError } = await import("../src/secrets/errors.ts")
  const idempotent = (text: string) => assert.equal(redactor.redactString(text).count, 0, text)
  it("placeholder stuck to a value: surrounding fragments are redacted, idempotence preserved", () => {
    for (const text of [`MY_PASSWORD=[[GUARD_REDACTED:foo]]${FAKE.password}`, `MY_PASSWORD=${FAKE.password}[[GUARD_REDACTED:foo]]`, `db://u:[[GUARD_REDACTED:x]]${FAKE.password}@h/db`]) {
      const { value, count } = redactor.redactString(text)
      assert.equal(count, 1, text)
      assert.ok(!value.includes(FAKE.password), text)
      idempotent(value)
    }
    for (const text of ["API_KEY=[[GUARD_REDACTED:generic_secret]]", "TOKEN=[[GUARD_REDACTED:x]]...", "PASSWORD=[[GUARD_REDACTED:x]]**"]) idempotent(text)
  })
  it("URL password containing @: redacted up to the last @ of the authority", () => {
    for (const [text, expected] of [
      ["postgres://admin:p@ss@db.local:5432/app", "postgres://admin:[[GUARD_REDACTED:url_credentials]]@db.local:5432/app"],
      [`https://u:S3cr@t${FAKE.password}@host/x`, "https://u:[[GUARD_REDACTED:url_credentials]]@host/x"],
      ["https://u:pa#ss@host", "https://u:[[GUARD_REDACTED:url_credentials]]@host"],
      ["redis://:s3cretPass@cache:6379", "redis://:[[GUARD_REDACTED:url_credentials]]@cache:6379"],
    ])
      assert.equal(redactor.redactString(text).value, expected)
    for (const text of ["https://host/path?email=a@b.c", "ssh://git@github.com:22/repo", "https://u:${PASS}@host"]) assert.equal(redactor.redactString(text).count, 0, text)
  })
  it("lowercase `basic`: redacted only if decoding yields a real user:pass", () => {
    const b64 = Buffer.from(`admin:${FAKE.password}`).toString("base64")
    for (const text of [`authorization: basic ${b64}`, `AUTHORIZATION: BASIC ${b64}`]) assert.ok(!redactor.redactString(text).value.includes(b64), text)
    assert.equal(redactor.redactString("basic internationalization").count, 0)
  })
  it("redactDeep: shared reference redacted everywhere, cycle without leak, depth > 64 examined", () => {
    const shared = { token: FAKE.github }
    const dag = redactor.redactDeep({ a: shared, b: shared, c: [shared] })
    assert.equal(dag.count, 1)
    assert.ok(!JSON.stringify(dag.value).includes(FAKE.github))
    const clean = { x: 1 }
    const same = { a: clean, b: clean }
    assert.equal(redactor.redactDeep(same).value, same)
    const cyclic: Record<string, unknown> = { token: FAKE.github }
    cyclic.self = cyclic
    const out = redactor.redactDeep({ root: cyclic }).value as { root: Record<string, unknown> }
    assert.ok(!JSON.stringify(out).includes(FAKE.github))
    const noSecret: Record<string, unknown> = { a: 1 }
    noSecret.self = noSecret
    assert.equal(redactor.redactDeep(noSecret).value, noSecret)
    let deep: Record<string, unknown> = { token: FAKE.github }
    for (let i = 0; i < 80; i++) deep = { next: deep }
    const deepOut = redactor.redactDeep(deep)
    assert.ok(deepOut.count >= 1)
    assert.ok(!JSON.stringify(deepOut.value).includes(FAKE.github))
  })
  it("errors: every own field (details, reason/body of an AIError) is redacted", () => {
    const error = Object.assign(new Error("boom"), { details: { token: FAKE.github }, code: "E_X" })
    const { value, count } = redactErrorLike(error, redactor)
    assert.equal(count, 1)
    assert.ok(!JSON.stringify((value as { details: unknown }).details).includes(FAKE.github))
    assert.equal((value as { code: string }).code, "E_X")
    // AIError shape (@opencode/ai): `reason` and `cause` refer to the same object, `message` is a getter on reason.
    class InvalidRequest extends Error {
      readonly body: string
      constructor(message: string, body: string) {
        super(message)
        this.body = body
      }
    }
    class AIErrorLike extends Error {
      readonly reason: InvalidRequest
      override readonly cause: InvalidRequest
      constructor(reason: InvalidRequest) {
        super()
        delete (this as { message?: string }).message
        this.reason = reason
        this.cause = reason
      }
      override get message() {
        return this.reason.message
      }
    }
    const ai = new AIErrorLike(new InvalidRequest(`401 for key ${FAKE.openai}`, `{"error":"bad key ${FAKE.openai}"}`))
    class ToolError extends Error {
      readonly error?: unknown
      constructor(props: { message: string; error?: unknown }) {
        super(props.message)
        this.error = props.error
      }
    }
    const redacted = redactToolError(new ToolError({ message: "provider failed", error: ai }), redactor)
    const inner = redacted.value.error as AIErrorLike
    assert.ok(redacted.count >= 2)
    assert.ok(!inner.message.includes(FAKE.openai))
    assert.ok(!String(inner.reason.stack).includes(FAKE.openai))
    assert.ok(!inner.reason.body.includes(FAKE.openai))
    assert.equal(inner.reason, inner.cause)
    // Effect errors: constructor arguments kept under a symbol and read back by toJSON().
    const plainArgs = Symbol("effect/Data/Error/plainArgs")
    class EffectLike extends Error {
      readonly body: string
      constructor(args: { message: string; body: string }) {
        super(args.message)
        this.body = args.body
        Object.defineProperty(this, plainArgs, { value: args, enumerable: false })
      }
      toJSON() {
        return { ...(this as unknown as Record<symbol, object>)[plainArgs], ...this }
      }
    }
    const effect = redactErrorLike(new EffectLike({ message: `bad ${FAKE.openai}`, body: FAKE.openai }), redactor).value as EffectLike
    assert.ok(effect instanceof EffectLike)
    assert.ok(!JSON.stringify(effect).includes(FAKE.openai))
    // Binary data and getters that throw: ignored without error.
    const odd = Object.defineProperty(Object.assign(new Error("x"), { buf: Buffer.from(FAKE.github) }), "bad", {
      enumerable: true,
      get() {
        throw new Error("nope")
      },
    })
    assert.equal(redactErrorLike(odd, redactor).count, 0)
  })
})

describe("batch 7: secrets typed in natural language in the prompt", async () => {
  const { redactPromptSecrets, PROMPT_NOTE } = await import("../src/secrets/prompt.ts")
  const password = `Xy7!${FAKE.password}`
  it("detected (fr/en, separators, non-breaking spaces, typographic apostrophe)", () => {
    for (const text of [`mon mdp est ${password}`, `mon mot de passe : ${password}`, `my password is ${password}`, `le mdp c’est ${password} pour la base`,
      `mdp ${password}`, `le token est ${password}`, `clé API : ${password}`, `api key -> ${password}`, `mon mot\u00A0de passe est ${password}`,
      `mdp: Ab${password};Zz9!`, `mon mdp est ${password}, merci`]) {
      const { value, count } = redactPromptSecrets(text)
      assert.equal(count, 1, text)
      assert.ok(!value.includes(password), text)
      assert.equal(redactPromptSecrets(value).count, 0, `idempotent: ${text}`)
    }
  })
  it("false positives discarded", () => {
    for (const text of ["le token est base64url", "le secret est hardcoded2", "password is stored_in_vault1", "token OAuth2-PKCE flow", "password reset2024 flow",
      "le secret est dans config/secrets2.yaml", "token: src/auth/token2.ts", "branche feature/login-2fa", "password_hash = bcrypt(x)", "tokenizer est GPT2Tokenizer",
      "pwd /home/gigi", "le token est sha256sum", "password: [[GUARD_REDACTED:generic_secret]]", PROMPT_NOTE, "le secret est utf8encoded"])
      assert.equal(redactPromptSecrets(text).count, 0, text)
  })
})

describe("batch 10: redaction coverage — compressed base64 and hex dumps", async () => {
  const zlib = await import("node:zlib")
  const settings = `mode=dev\nANTHROPIC_API_KEY=${FAKE.anthropic}\nport=8080\n`
  /** `xxd` formats (2-byte groups) and `hexdump -C` (separate bytes, column between bars). */
  const xxd = (bytes: Buffer) =>
    Array.from({ length: Math.ceil(bytes.length / 16) }, (_, row) => {
      const chunk = bytes.subarray(row * 16, row * 16 + 16)
      const hex = (chunk.toString("hex").match(/.{1,4}/g) ?? []).join(" ")
      return `${(row * 16).toString(16).padStart(8, "0")}: ${hex.padEnd(39)}  ${chunk.toString("latin1").replace(/[^\x20-\x7e]/g, ".")}`
    }).join("\n")
  const hexdumpC = (bytes: Buffer) =>
    Array.from({ length: Math.ceil(bytes.length / 16) }, (_, row) => {
      const chunk = bytes.subarray(row * 16, row * 16 + 16)
      const pairs = [...chunk].map((b) => b.toString(16).padStart(2, "0"))
      return `${(row * 16).toString(16).padStart(8, "0")}  ${pairs.slice(0, 8).join(" ")}  ${pairs.slice(8).join(" ")}`.padEnd(60) + `|${chunk.toString("latin1").replace(/[^\x20-\x7e]/g, ".")}|`
    }).join("\n")

  it("base64 of gzip content containing a secret: whole block redacted", () => {
    const out = zlib.gzipSync(Buffer.from(settings)).toString("base64").replace(/.{76}/g, "$&\n")
    const result = redactor.redactString(`output:\n${out}\n-- end --`)
    assert.ok(result.count > 0)
    assert.match(result.value, /^output:\n\[\[GUARD_REDACTED:base64\]\]\n-- end --$/)
    // Next line made of base64 characters (read with the block): stream followed by extra bytes, secret redacted anyway.
    const absorbed = redactor.redactString(`${out}\nend`)
    assert.ok(absorbed.count > 0 && !absorbed.value.includes(FAKE.anthropic))
  })

  it("xxd and hexdump -C dump containing a secret: block redacted, surrounding text kept", () => {
    for (const format of [xxd, hexdumpC]) {
      const dump = format(Buffer.from(settings))
      const result = redactor.redactString(`before\n${dump}\nafter`)
      assert.equal(result.value, "before\n[[GUARD_REDACTED:hexdump]]\nafter", format.name)
      assert.ok(!result.value.includes(FAKE.anthropic.slice(-12)))
    }
  })

  it("gzip dump in hexadecimal: decompressed before the search", () => {
    assert.match(redactor.redactString(xxd(zlib.gzipSync(Buffer.from(settings)))).value, /^\[\[GUARD_REDACTED:hexdump\]\]$/)
  })

  it("without a secret: dumps, compressed base64 and ordinary text unchanged", () => {
    const plain = Buffer.from("mode=dev\nport=8080\nname=demo project with ordinary text\n")
    for (const text of [xxd(plain), hexdumpC(plain), zlib.gzipSync(plain).toString("base64"), "00000000 is an address\n0000abcd: ff"])
      assert.deepEqual(redactor.redactString(text), { value: text, count: 0 })
  })

  it("gzip too large once decompressed: no error (cap)", () => {
    const bomb = zlib.gzipSync(Buffer.alloc(8_000_000, 97)).toString("base64")
    assert.equal(redactor.redactString(bomb).count, 0)
  })
})

describe("batch 11: redaction of pass/passphrase names, options, commas, passphrases, xxd", () => {
  const r = createRedactor()
  const w = `Qx7${"kLm2Zp9wR"}` // fake
  const masked = (text: string) => r.redactString(text).count > 0
  it("pass/passphrase as secret names; never in bypass, compass, passthrough", () => {
    for (const text of [`GPG_PASSPHRASE=${w}`, `DB_PASS=${w}`, `smtp.pass: ${w}`, `pass=${w}`]) assert.ok(masked(text), text)
    for (const text of [`bypass=${w}`, `compass_heading=${w}`, `passthrough=${w}`]) assert.ok(!masked(text), text)
    // `pass:entry` (`pass` password manager) and paths: not values.
    for (const text of ['from = "pass:openai/api-key9"', '["pass:vibe/token42x"]', "plugins/pass: /home/u/x9/plugins/pass: no such file"])
      assert.ok(!masked(text), text)
  })
  it("option separated from its value by whitespace; lone variable and neighboring names left alone", () => {
    assert.equal(r.redactString(`docker login -u bob --password ${w} reg.io`).value, "docker login -u bob --password [[GUARD_REDACTED:generic_secret]] reg.io")
    for (const text of ["gh api --token $GITHUB_TOKEN", "--token-limit 4000", "--max-tokens 40000000"]) assert.ok(!masked(text), text)
    // Database client: the word after `--password` is the database name.
    for (const text of ["psql -h db -U u --password app_db_2024", "mysql -u root --password app_db_2024"]) assert.ok(!masked(text), text)
    assert.ok(masked(`redis-cli --pass ${w}\npsql -h db`))
    const start = performance.now()
    r.redactString(`--pass ${w} `.repeat(20_000))
    assert.ok(performance.now() - start < 2000)
  })
  it("comma in a value: redacted entirely, except before a named argument; repetition redacted in the right place", () => {
    assert.equal(r.redactString(`DB_PASSWORD=${w},Tr4ilR3st`).value, "DB_PASSWORD=[[GUARD_REDACTED:generic_secret]]")
    assert.equal(r.redactString(`f(password=${w},user=bob1234x)`).value, "f(password=[[GUARD_REDACTED:generic_secret]],user=bob1234x)")
    assert.equal(r.redactString("password=aaaa1111x,b=aaaa1111x").value, "password=[[GUARD_REDACTED:generic_secret]],b=aaaa1111x")
    // Same case after a stuck placeholder (fragments judged one by one).
    assert.equal(
      r.redactString("PASSWORD=[[GUARD_REDACTED:generic_secret]]aaaa1111x,b=aaaa1111x").value,
      "PASSWORD=[[GUARD_REDACTED:generic_secret]][[GUARD_REDACTED:generic_secret]],b=aaaa1111x",
    )
    assert.ok(!masked("token=process.env.X,"))
    // Literal escaping of JSON text: end of the value (`self.api_key\n` is code).
    assert.ok(!masked("api_key = self.api_key\\n        if api_key is None:"))
  })
  it("quoted passphrase after an uppercase name; lowercase labels and templates left alone", () => {
    assert.equal(r.redactString(`PASSWORD="velvet orbit ${w} lantern"`).value, 'PASSWORD="[[GUARD_REDACTED:passphrase]]"')
    assert.equal(r.redactString("export GPG_PASSPHRASE='velvet orbit lantern harbor'").value, "export GPG_PASSPHRASE='[[GUARD_REDACTED:passphrase]]'")
    for (const text of ['password: "Mot de passe"', '"password": "Enter your password"', 'DB_PASSWORD="%s"', 'DB_PASSWORD="${DB_PASS}"', 'SECRET="your secret here"', 'ADMIN_PASSWORD="change me please"'])
      assert.ok(!masked(text), text)
  })
  it("phrase without a closing quote on a very long line: linear cost", () => {
    const start = performance.now()
    r.redactString(`PASSWORD="${"a b ".repeat(200_000)}`)
    assert.ok(performance.now() - start < 2000)
  })
  it("environment: phrases (PASSWORD/PASSPHRASE/SECRET/PASS names) and PASS names replaced; other values with whitespace left alone", () => {
    const env = createRedactor({ env: { GPG_PASSPHRASE: "velvet orbit lantern harbor", MY_PASS: "Zr8vNq3LxW2k", KEYBOARD_LAYOUT: "fr azerty layout x" } })
    assert.equal(env.redactString("x velvet orbit lantern harbor y").value, "x [[GUARD_REDACTED:env:GPG_PASSPHRASE]] y")
    assert.equal(env.redactString("x Zr8vNq3LxW2k y").value, "x [[GUARD_REDACTED:env:MY_PASS]] y")
    assert.ok(!env.redactString("fr azerty layout x").count)
    assert.deepEqual(envSecretValues({ COMPASS_MODE: "Zr8vNq3LxW2kAB", BYPASS: "Zr8vNq3LxW2kAB" }), [])
  })
  it("xxd: text column entirely hexadecimal not read as bytes", () => {
    // Output of `printf 'GITHUB=ghp_Xy7Qz0a1b2c3d4e5f6a7bRt5Uv8Wq2Zp4Ks9\n' | xxd` (fake token).
    const dump = [
      "00000000: 4749 5448 5542 3d67 6870 5f58 7937 517a  GITHUB=ghp_Xy7Qz",
      "00000010: 3061 3162 3263 3364 3465 3566 3661 3762  0a1b2c3d4e5f6a7b",
      "00000020: 5274 3555 7638 5771 325a 7034 4b73 390a  Rt5Uv8Wq2Zp4Ks9.",
    ].join("\n")
    assert.equal(r.redactString(dump).value, "[[GUARD_REDACTED:hexdump]]")
  })
})

describe("batch 12: Bearer/Basic, Map/Set/RegExp in errors", async () => {
  const { redactToolError } = await import("../src/secrets/errors.ts")
  const r = createRedactor()
  const token = `Qx7kLm2Zp9wR${"tY4uI8oP"}` // fake
  it("Bearer: a word is not a token; a token stays redacted", () => {
    for (const text of ["Bearer internationalization", "Bearer authenticationScheme", "Bearer Internationalization"]) assert.ok(!r.redactString(text).count, text)
    for (const text of [`Authorization: Bearer ${token}`, `Bearer ${FAKE.jwt}`, "Bearer QxkLmZpwRtYuIoPaBcDe"]) assert.ok(r.redactString(text).count, text)
  })
  it("Bearer: long run of letters ending in a digit → linear cost", () => {
    const start = performance.now()
    r.redactString(`Bearer ${"a".repeat(5000)}1`)
    assert.ok(performance.now() - start < 1000)
  })
  it("Basic (all cases): only decodable credentials, including an empty password", () => {
    // Fake key as user, empty password (`curl -u sk_test_…:`): redacted (here by base64 decoding).
    const stripeLike = Buffer.from(`sk_test_${"Ab1".repeat(10)}:`).toString("base64")
    assert.ok(!r.redactString(`Authorization: Basic ${stripeLike}`).value.includes(stripeLike))
    // Unrecognized user, empty password: the Basic rule itself redacts it.
    const emptyPassword = Buffer.from("deploybot2024x:").toString("base64")
    assert.equal(r.redactString(`Authorization: Basic ${emptyPassword}`).value, "Authorization: Basic [[GUARD_REDACTED:basic_auth]]")
    assert.ok(r.redactString(`authorization: basic ${Buffer.from("admin:Qx7kLm2Zp9").toString("base64")}`).count)
    for (const text of ["Basic internationalization", "Basic authenticationScheme here", "basic internationalization"]) assert.ok(!r.redactString(text).count, text)
  })
  it("redactDeep: Map (keys and values) and Set traversed; without a secret, same reference", () => {
    const map = new Map<string, string>([["token", FAKE.openai], [FAKE.github, "x"]])
    const out = r.redactDeep({ headers: map, tags: new Set([FAKE.anthropic]) })
    assert.equal(out.count, 3)
    assert.ok(!JSON.stringify([...(out.value.headers as Map<string, string>)]).includes(FAKE.openai))
    assert.ok(![...(out.value.headers as Map<string, string>).keys()].includes(FAKE.github))
    assert.ok(![...(out.value.tags as Set<string>)].includes(FAKE.anthropic))
    const clean = { headers: new Map([["a", "b"]]) }
    assert.equal(r.redactDeep(clean).value, clean)
  })
  it("error: secret in a Map, a Set, a RegExp, a Map in a plain object → redacted and counted", () => {
    const error = Object.assign(new Error("failure"), {
      details: new Map([["token", FAKE.openai]]),
      tags: new Set([FAKE.github]),
      pattern: new RegExp(FAKE.anthropic),
      context: { headers: new Map([["authorization", `Bearer ${token}`]]) },
    })
    const { value, count } = redactToolError({ message: "x", error }, r)
    assert.equal(count, 4)
    const text = JSON.stringify(value.error, (_key, item) => (item instanceof Map || item instanceof Set ? [...item] : item))
    for (const secret of [FAKE.openai, FAKE.github, FAKE.anthropic, token]) assert.ok(!text.includes(secret))
    assert.ok(String((value.error as { pattern: unknown }).pattern).includes("[[GUARD_REDACTED:anthropic_key]]"))
  })
  it("error: Map without a secret → same error; cycle through a Map → no loop", () => {
    const clean = Object.assign(new Error("failure"), { details: new Map([["a", "b"]]) })
    assert.equal(redactToolError({ message: "x", error: clean }, r).value.error, clean)
    const cyclic = Object.assign(new Error("failure"), { details: new Map<string, unknown>() })
    cyclic.details.set("self", cyclic)
    cyclic.details.set("token", FAKE.openai)
    const out = redactToolError({ message: "x", error: cyclic }, r)
    assert.equal(out.count, 1)
  })
})

describe("batch 13: PGP private key block", () => {
  const r = createRedactor()
  const body = Array.from({ length: 12 }, (_, i) => rand(64, 40 + i)).join("\n") // fake body
  const block = `-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\n${body}\n=Ab3x\n-----END PGP PRIVATE KEY BLOCK-----`
  it("complete or truncated block redacted; neighboring text kept", () => {
    assert.equal(r.redactString(`before\n${block}\nafter`).value, "before\n[[GUARD_REDACTED:private_key]]\nafter")
    assert.equal(r.redactString(`before\n${block.split("=Ab3x")[0]}`).value, "before\n[[GUARD_REDACTED:private_key]]")
  })
  it("public block and signature: intact", () => {
    for (const text of [block.replaceAll("PRIVATE KEY", "PUBLIC KEY"), block.replaceAll("PRIVATE KEY BLOCK", "SIGNATURE")]) assert.equal(r.redactString(text).count, 0)
  })
  it("key without an end line followed by several MB: redacted, without exception; mere mention of the marker: left alone", () => {
    const long = `${block.split("=Ab3x")[0]}\n${"lorem ipsum ".repeat(1_000_000)}`
    const start = performance.now()
    const out = r.redactString(long)
    assert.ok(performance.now() - start < 3000)
    assert.ok(out.value.startsWith("[[GUARD_REDACTED:private_key]]"))
    assert.ok(!out.value.includes(body.split("\n")[0]!))
    const quote = "The format starts with -----BEGIN PGP PRIVATE KEY BLOCK----- followed by a blank line then the body."
    assert.equal(r.redactString(quote).count, 0)
  })
  it("thousands of unterminated headers: linear cost", () => {
    const start = performance.now()
    r.redactString("-----BEGIN PGP PRIVATE KEY BLOCK-----\nAb3x\n".repeat(10_000))
    assert.ok(performance.now() - start < 1000)
  })
})

describe("batch 14: redaction in linear time", () => {
  const r = createRedactor()
  const w = `Qx7${"kLm2Zp9wR"}` // fake
  const masked = (text: string) => r.redactString(text).count > 0
  // Calibrated sizes: the old pattern took 3 to 5 s there under Node (JWT: 1 s under Bun, hence the 500 ms threshold).
  const fast = (text: string, limit = 1000) => {
    const start = performance.now()
    r.redactString(text)
    assert.ok(performance.now() - start < limit)
  }
  it("generic assignment: keyword repeated in a long run without whitespace → linear cost", () => fast("token-".repeat(1000)))
  it("URL credentials: long run of scheme characters → linear cost", () => fast("a+-".repeat(50_000)))
  it("JWT: long run `eyJ-eyJ-…` → linear cost", () => fast("eyJ-".repeat(30_000), 500))
  it("PEM key: thousands of unterminated headers → linear cost", () => fast("-----BEGIN RSA PRIVATE KEY-----\n".repeat(17_000)))
  it("placeholder: unclosed markers → linear search (placeholder rule)", () => {
    const start = performance.now()
    assert.equal(PLACEHOLDER_RE.test("[[GUARD_REDACTED:".repeat(25_000)), false)
    assert.ok(performance.now() - start < 1000)
  })

  it("generic assignment: keyword at the start, middle or end of the name; prefix kept", () => {
    assert.equal(r.redactString(`MY_GITHUB_TOKEN_CI=${w}`).value, "MY_GITHUB_TOKEN_CI=[[GUARD_REDACTED:generic_secret]]")
    for (const text of [`apiKeyProd: ${w}`, `db.password = ${w}`, `"client_secret": "${w}"`, `token_${"x".repeat(120)}=${w}`]) assert.ok(masked(text), text)
  })
  it("URL credentials: compound schemes, uppercase, stuck to another word", () => {
    assert.equal(r.redactString(`git+https://bob:${w}@github.com/x`).value, "git+https://bob:[[GUARD_REDACTED:url_credentials]]@github.com/x")
    for (const text of [`postgresql+psycopg2://u:${w}@db/app`, `HTTPS://u:${w}@h/`, `url=redis://:${w}@cache:6379`, `x.mongodb+srv://u:${w}@c0.net`]) assert.ok(masked(text), text)
  })
  it("JWT: stuck after a dash; header containing `-eyJ` redacted from that point", () => {
    assert.equal(r.redactString(`session-${FAKE.jwt}`).value, "session-[[GUARD_REDACTED:jwt]]")
    assert.equal(r.redactString(`eyJ${"a".repeat(12)}-${FAKE.jwt}`).value, `eyJ${"a".repeat(12)}-[[GUARD_REDACTED:jwt]]`)
  })
  it("PEM key: Proc-Type/DEK-Info headers, JSON-escaped text, truncated key followed by a complete key", () => {
    const lines = [rand(64, 21), rand(64, 22), rand(40, 23)]
    const key = `-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0A1B2C3D4E5F6071\n\n${lines.join("\n")}\n-----END RSA PRIVATE KEY-----`
    assert.equal(r.redactString(`a\n${key}\nb`).value, "a\n[[GUARD_REDACTED:private_key]]\nb")
    assert.equal(r.redactString(JSON.stringify({ key })).value, '{"key":"[[GUARD_REDACTED:private_key]]"}')
    const truncated = `-----BEGIN RSA PRIVATE KEY-----\n${rand(64, 24)}\n${rand(64, 25)}\n`
    const out = r.redactString(`${truncated}${key}`).value
    for (const line of [rand(64, 24), rand(64, 25), ...lines]) assert.ok(!out.includes(line), out)
  })
  it("placeholder: type containing `]` or very long → still recognized by the placeholder rule", () => {
    const custom = createRedactor({ extraPatterns: [{ type: "team]key", regex: /XKEY\d{8}/g }, { type: "t".repeat(300), regex: /YKEY\d{8}/g }] })
    const out = custom.redactString("XKEY12345678 YKEY12345678").value
    assert.ok(out.startsWith("[[GUARD_REDACTED:team_key]] "), out)
    assert.equal(out.match(/\[\[GUARD_REDACTED:[^\]]*\]\]/g)?.length, 2)
    for (const part of out.split(" ")) assert.ok(PLACEHOLDER_RE.test(part), part)
  })
  it("placeholder: unclosed marker stuck before a real placeholder → the preceding value stays redacted", () => {
    const out = r.redactString(`token:${w}.git+ssh://[[GUARD_REDACTED:[[GUARD_REDACTED:generic_secret]]`).value
    assert.ok(!out.includes(w), out)
  })
})

describe("batch 31: environment passwords with PASSWD or fixed names", () => {
  const value = "Zx9fakeValue0123456"
  const names = (env: Record<string, string>) => envSecretValues(env).map((item) => item.name)
  it("name containing PASSWD (case ignored), value with or without spaces → kept", () => {
    assert.deepEqual(names({ DB_PASSWD: value, PASSWD: value, app_passwd_main: value }), ["DB_PASSWD", "PASSWD", "app_passwd_main"])
    assert.deepEqual(names({ DB_PASSWD: "velvet orbit seven lanterns" }), ["DB_PASSWD"])
  })
  it("exact names MYSQL_PWD and SSHPASS → kept, including a value with spaces; case and neighboring names → not", () => {
    assert.deepEqual(names({ MYSQL_PWD: value, SSHPASS: "velvet orbit seven lanterns" }), ["MYSQL_PWD", "SSHPASS"])
    assert.deepEqual(names({ mysql_pwd: value, MYSQL_PWD_FILE: value, MY_SSHPASS_HINT: value }), [])
  })
  it("PWD and OLDPWD (paths) not kept; text containing these paths stays intact", () => {
    const env = { PWD: "/home/user/projects/app", OLDPWD: "/home/user/projects", DB_PASSWD_FILE: "/run/secrets/db-password" }
    assert.deepEqual(names(env), [])
    const text = "cd /home/user/projects/app && ls /home/user/projects /run/secrets/db-password"
    assert.equal(createRedactor({ env }).redactString(text).value, text)
  })
  it("lone value and value within text redacted (as for a PASSWORD name)", () => {
    const local = createRedactor({ env: { DB_PASSWD: value, MYSQL_PWD: "Qw7otherFake0987654" } })
    for (const text of [`${value}\n`, `connected with ${value} to db`, "pw=Qw7otherFake0987654;"]) {
      const out = local.redactString(text).value
      assert.ok(!out.includes(value) && !out.includes("Qw7otherFake0987654"), out)
      assert.match(out, /\[\[GUARD_REDACTED:env:(DB_PASSWD|MYSQL_PWD)\]\]/)
    }
  })
  it("other words unchanged (PASSWORD, PASS as a component, PASS false friends still discarded)", () => {
    assert.deepEqual(names({ DB_PASSWORD: value, DB_PASS: value, COMPASS_MODE: value, BYPASS: value }), ["DB_PASSWORD", "DB_PASS"])
  })
})
