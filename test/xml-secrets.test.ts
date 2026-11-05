// Secrets in XML and HTML: a value glued to a tag, the content of an element, the `value` attribute of a tag named by
// its `key`, `name` or `id`. All values are fake.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { placeholderFinding, toolFinding } from "../src/rules/tools.ts"
import { beforeMarkup } from "../src/secrets/patterns.ts"
import { createRedactor, placeholder } from "../src/secrets/redact.ts"
import { withinBudget } from "./budget.ts"

const VALUE = "Fake-Test-Pw-7391"
const redactor = () => createRedactor({ env: {} })
const masked = (text: string) => redactor().redactString(text)
const generic = placeholder("generic_secret")
const markup = placeholder("markup_secret")

function assertMasked(text: string, expected: string, count = 1): void {
  const result = masked(text)
  assert.equal(result.value, expected, text)
  assert.equal(result.count, count, text)
  assert.ok(!result.value.includes(VALUE), text)
}

function assertLeft(text: string): void {
  const result = masked(text)
  assert.equal(result.count, 0, text)
  assert.equal(result.value, text)
}

describe("value glued to a tag (A)", () => {
  it("name=value stops at the closing tag; the tags stay", () => {
    for (const name of ["password", "a password", "token", "api_key", "DB_PASS", "ENCRYPTION_KEY", "password :"]) {
      const assign = name === "password :" ? "password : " : `${name}=`
      assertMasked(`<t>${assign}${VALUE}</t>`, `<t>${assign}${generic}</t>`)
    }
  })
  it("also before a self-closing tag, a comment, the end of a CDATA section, an escaped closing tag", () => {
    assertMasked(`<t>password=${VALUE}<br/>next</t>`, `<t>password=${generic}<br/>next</t>`)
    assertMasked(`<t>password=${VALUE}<!-- note --></t>`, `<t>password=${generic}<!-- note --></t>`)
    assertMasked(`<t><![CDATA[password=${VALUE}]]></t>`, `<t><![CDATA[password=${generic}]]></t>`)
    assertMasked(`<t>password=${VALUE}<\\/t>`, `<t>password=${generic}<\\/t>`)
  })
  it("also at any `<` after what is no identifier, and for an option", () => {
    assertMasked(`<td>password=${VALUE}<td>next`, `<td>password=${generic}<td>next`)
    assertMasked(`<t>--password ${VALUE}</t>`, `<t>--password ${generic}</t>`)
  })
  it("code punctuation goes on being kept in front of the tag", () => {
    assertMasked(`<t>f(token=${VALUE})</t>`, `<t>f(token=${generic})</t>`)
  })
  it("witness: identifiers before `<`, comparisons and generics; nothing to cut, nothing masked", () => {
    assert.equal(beforeMarkup("parseToken2<Claims>(raw)"), "parseToken2<Claims>(raw)")
    assert.equal(beforeMarkup("a<b"), "a<b")
    for (const text of [
      "token=parseToken2<Claims>(raw)",
      "const token=useState2<Token1>(null)",
      "credential=getProvider42<Foo>(x)",
      "token=<T>",
      "token=<TokenType>",
      "a<b",
      "password=x<y",
      "if (password=abcd1234<limit) go()",
      "<t>password=</t>",
      "<t>password=hunter</t>",
      "<t>password=${DB_PASSWORD}</t>",
      "<t>password=changeme</t>",
      "<t>token=abc</t>",
    ])
      assertLeft(text)
  })
})

describe("content of an element (B)", () => {
  it("element named with a secret word: only the value goes", () => {
    for (const name of ["password", "Password", "PASSWORD", "passwd", "pwd", "secret", "token", "api_key", "apiKey", "dbPassword", "db_password", "jdbc.password", "client-secret", "access_token", "credentials", "passphrase"])
      assertMasked(`<${name}>${VALUE}</${name}>`, `<${name}>${markup}</${name}>`)
  })
  it("namespace, attributes, blanks and lines, CDATA", () => {
    assertMasked(`<db:password>${VALUE}</db:password>`, `<db:password>${markup}</db:password>`)
    assertMasked(`<password encrypted="false" a='1'>${VALUE}</password>`, `<password encrypted="false" a='1'>${markup}</password>`)
    assertMasked(`<password>  ${VALUE}\n  </password >`, `<password>  ${markup}\n  </password >`)
    assertMasked(`<password>\n  <![CDATA[${VALUE}]]>\n</password>`, `<password>\n  <![CDATA[${markup}]]>\n</password>`)
  })
  it("`pass` and a `key` name, as in an assignment", () => {
    assertMasked(`<smtp.pass>${VALUE}</smtp.pass>`, `<smtp.pass>${markup}</smtp.pass>`)
    assertMasked(`<encryptionKey>${VALUE}</encryptionKey>`, `<encryptionKey>${markup}</encryptionKey>`)
    assertMasked(`<AccountKey>${VALUE}</AccountKey>`, `<AccountKey>${markup}</AccountKey>`)
  })
  it("a value equal to the name of the tag: the value goes, not the closing tag", () => {
    assert.equal(masked("<db1password>db1password</db1password>").value, `<db1password>${markup}</db1password>`)
  })
  it("witness: a value already masked stays as it is", () => {
    assert.equal(masked(`<password>${markup}</password>`).count, 0)
  })
  it("what is glued to a masked value goes", () => {
    assert.equal(masked(`<password>${markup}abc123def456</password>`).value, `<password>${markup}${markup}</password>`)
  })
  it("witness: neither an empty element, nor a variable, nor a placeholder, nor a value that fails the checks of `password=`", () => {
    for (const text of [
      "<password/>",
      "<password></password>",
      "<password>${DB_PASSWORD}</password>",
      "<password>${env.DB_PASSWORD_1}</password>",
      "<password>{{ pw }}</password>",
      "<password>%DB_PW%</password>",
      "<password>%DB_PASSWORD_1%</password>",
      "<password>@db.password1@</password>",
      "<password>$DB_PW</password>",
      "<password>$DB_PASSWORD_1</password>",
      "<token>abc</token>",
      "<password>changeme</password>",
      "<password>your-password-1</password>",
      "<password>hunter</password>",
      "<secret>true</secret>",
      "<password>correct horse battery staple</password>",
    ])
      assertLeft(text)
  })
  it("witness: `password=hunter`, too short, is left, like `<password>hunter</password>` above", () => {
    assert.equal(masked("password=hunter").count, 0)
  })
  it("the same value as `password=hunter99x` goes", () => {
    assert.equal(masked("<password>hunter99x</password>").count, 1)
  })
  it("witness: an element whose name only starts with a secret word", () => {
    for (const text of [
      "<passwordEncoder>bcrypt</passwordEncoder>",
      "<passwordEncoder>argon2id-v19</passwordEncoder>",
      "<tokenizer>standard</tokenizer>",
      "<tokenizer>standard2x</tokenizer>",
      "<tokens>12</tokens>",
      "<tokens>abc123def456</tokens>",
      "<credentials>file</credentials>",
      '<token type="x"/>',
      `<token type="x"/>${VALUE}</token>`,
      `<bypass>${VALUE}</bypass>`,
      `<publicKey>${VALUE}</publicKey>`,
      `<key>${VALUE}</key>`,
      `<monkey>${VALUE}</monkey>`,
    ])
      assertLeft(text)
  })
  it("witness: code", () => {
    for (const text of ["Result<Token, E>", "Vec<Secret>", "Box<dyn Token>", "fn f() -> Result<Token, Error> { Ok(x) }", "let a: Vec<Secret> = b;", "a < b && c > d", "<Secret>{value}</Secret>"]) assertLeft(text)
  })
})

describe("value attribute of a named tag (C)", () => {
  it("key, name or id, before or after the value, any quotes", () => {
    assertMasked(`<add key="password" value="${VALUE}"/>`, `<add key="password" value="${markup}"/>`)
    assertMasked(`<add value="${VALUE}" key="password"/>`, `<add value="${markup}" key="password"/>`)
    assertMasked(`<add key='db.password' value='${VALUE}'/>`, `<add key='db.password' value='${markup}'/>`)
    assertMasked(`<property name="spring.datasource.password" value="${VALUE}">`, `<property name="spring.datasource.password" value="${markup}">`)
    assertMasked(`<param id="apiToken" a="1" value="${VALUE}" b="2" />`, `<param id="apiToken" a="1" value="${markup}" b="2" />`)
    assertMasked(`<add\n  key="ClientSecret"\n  value="${VALUE}"\n/>`, `<add\n  key="ClientSecret"\n  value="${markup}"\n/>`)
    assertMasked(`<Add Key="Password" Value="${VALUE}"/>`, `<Add Key="Password" Value="${markup}"/>`)
  })
  it("a tag cut by the end of the text", () => {
    assertMasked(`<add key="password" value="${VALUE}"`, `<add key="password" value="${markup}"`)
  })
  it("`pass` and a `key` name", () => {
    assertMasked(`<add key="smtp.pass" value="${VALUE}"/>`, `<add key="smtp.pass" value="${markup}"/>`)
    assertMasked(`<add name="ENCRYPTION_KEY" value="${VALUE}"/>`, `<add name="ENCRYPTION_KEY" value="${markup}"/>`)
  })
  it("the value equal to the name: the value goes, not the name", () => {
    assert.equal(masked('<add value="pass1word" key="password" id="x"/>').value, `<add value="${markup}" key="password" id="x"/>`)
    assert.equal(masked('<add key="password1" value="password1"/>').value, `<add key="password1" value="${markup}"/>`)
  })
  it("witness: a form field, a name without a secret word, a value that fails the checks", () => {
    for (const text of [
      '<input type="password" value="">',
      '<input type="password" name="pw">',
      `<add key="user" value="${VALUE}"/>`,
      `<add key="publicKey" value="${VALUE}"/>`,
      `<add key="bypass" value="${VALUE}"/>`,
      `<add other="password" value="${VALUE}"/>`,
      '<add key="password" value=""/>',
      '<add key="password" value="changeme"/>',
      '<add key="password" value="${DB_PASSWORD}"/>',
      '<add key="password" value="%DB_PASSWORD_1%"/>',
      '<add key="token" value="abc"/>',
      '<add key="TokenLifetime" value="3600"/>',
      '<add key="SecretName" value="true"/>',
      '<add key="smtp.pass" value="/etc/smtp/pw1"/>',
    ])
      assertLeft(text)
  })
})

describe("secret word as an attribute (D, generic_secret already reads it)", () => {
  it("witness: the attribute goes, an empty one or a placeholder stays", () => {
    assertMasked(`<db password="${VALUE}">`, `<db password="${generic}">`)
    assertMasked(`<db password='${VALUE}'/>`, `<db password='${generic}'/>`)
    assertMasked(`<u db:password="${VALUE}"/>`, `<u db:password="${generic}"/>`)
    assertMasked(`<user api_key="${VALUE}"/>`, `<user api_key="${generic}"/>`)
    assertLeft('<user password="changeme"/>')
    assertLeft('<user password=""/>')
  })
})

describe("the forms of createRedactor", () => {
  it("redactDeep and containsSecret read a string of a tool result", () => {
    const r = redactor()
    const { value, count } = r.redactDeep({ output: [`<password>${VALUE}</password>`], metadata: { line: `<add key="token" value="${VALUE}"/>` } })
    assert.equal(count, 2)
    assert.deepEqual(value, { output: [`<password>${markup}</password>`], metadata: { line: `<add key="token" value="${markup}"/>` } })
    assert.ok(r.containsSecret({ a: `<t>token=${VALUE}</t>` }))
  })
  it("witness: containsSecret on the negatives", () => {
    assert.ok(!redactor().containsSecret({ a: "<password>${DB_PASSWORD}</password>", b: '<input type="password" value="">' }))
  })
  it("a format turned off: the other one goes on", () => {
    const off = createRedactor({ env: {}, disabledTypes: ["markup_secret"] })
    assert.equal(off.redactString(`<t>password=${VALUE}</t>`).count, 1)
    const r = createRedactor({ env: {} })
    r.setDisabledTypes(["generic_secret"])
    assert.equal(r.redactString(`<password>${VALUE}</password>`).count, 1)
  })
  it("witness: `markup_secret` turned off, the elements stay; `generic_secret` turned off, a glued value stays", () => {
    assert.equal(createRedactor({ env: {}, disabledTypes: ["markup_secret"] }).redactString(`<password>${VALUE}</password>`).count, 0)
    assert.equal(createRedactor({ env: {}, disabledTypes: ["generic_secret"] }).redactString(`<t>password=${VALUE}</t>`).count, 0)
  })
  it("the allowlist spares its value only", () => {
    const r = createRedactor({ env: {}, allowlist: [VALUE] })
    assert.equal(r.redactString(`<password>Other-Fake-8264</password>`).count, 1)
  })
  it("witness: an allowed value stays", () => {
    const r = createRedactor({ env: {}, allowlist: [VALUE] })
    assert.equal(r.redactString(`<password>${VALUE}</password><add key="token" value="${VALUE}"/>`).count, 0)
  })
  it("a zero-width character does not hide the value", () => {
    const cut = `${VALUE.slice(0, 5)}​${VALUE.slice(5)}`
    assert.ok(!masked(`<password>${cut}</password>`).value.includes(VALUE.slice(5)))
  })
})

describe("real files", () => {
  it("web.config", () => {
    const file = (v: string) => `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="Environment" value="Production2" />
    <add key="ApiToken" value="${v}" />
    <add key="SmtpPassword" value="${v}" />
    <add key="Password" value="${"$"}{SMTP_PASSWORD}" />
  </appSettings>
  <connectionStrings>
    <add name="Main" connectionString="Server=db1;User Id=app;Password=${v};" providerName="System.Data.SqlClient" />
  </connectionStrings>
  <system.web>
    <authentication mode="Forms"><forms loginUrl="~/login" timeout="2880" /></authentication>
  </system.web>
</configuration>
`
    const result = masked(file(VALUE))
    assert.equal(result.count, 3)
    assert.equal(result.value, file(VALUE).replace(`key="ApiToken" value="${VALUE}"`, `key="ApiToken" value="${markup}"`).replace(`key="SmtpPassword" value="${VALUE}"`, `key="SmtpPassword" value="${markup}"`).replace(`Password=${VALUE}`, `Password=${generic}`))
  })
  it("pom.xml", () => {
    const file = (v: string) => `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example</groupId>
  <artifactId>demo2</artifactId>
  <version>1.2.3-SNAPSHOT</version>
  <properties>
    <java.version>21</java.version>
    <db.password>${v}</db.password>
    <sonar.token>${v}</sonar.token>
    <deploy.password>${"$"}{env.DEPLOY_PASSWORD}</deploy.password>
  </properties>
  <dependencies>
    <dependency><groupId>org.springframework.security</groupId><artifactId>spring-security-crypto</artifactId><version>6.3.1</version></dependency>
  </dependencies>
</project>
`
    const result = masked(file(VALUE))
    assert.equal(result.count, 2)
    assert.equal(result.value, file(markup))
  })
  it("settings.xml", () => {
    const file = (v: string) => `<settings>
  <servers>
    <server>
      <id>releases</id>
      <username>deploy1</username>
      <password>${v}</password>
      <passphrase>${v}</passphrase>
      <privateKey>/home/user/.ssh/id_rsa2</privateKey>
    </server>
    <server><id>snapshots</id><username>u</username><password>${"$"}{env.NEXUS_PASSWORD}</password></server>
  </servers>
</settings>
`
    const result = masked(file(VALUE))
    assert.equal(result.count, 2)
    assert.equal(result.value, file(markup))
  })
})

describe("code is not markup", () => {
  it("a `<` after a path of Rust or C++ does not end the value", () => {
    for (const text of [
      "let hooks_key = hooks_content.parse::<Ident>()?;",
      "peer_key: &ring_like::agreement::UnparsedPublicKey<&[u8]>,",
      "tokenizer: &TokenizerImpl<M, N, PT, PP, D>,",
      "let mut tokenizer = TokenizerBuilder::<",
      "let tokens = various_spaces.parse::<TokenStream>().unwrap();",
      "#vis #ident #colon_token ::pin_project::__private::Pin<&#lifetime (#ty)>,",
      "const uint64_t token = ns::awbarrier_arrive_drop_no_complete<false>(&x);",
      "using InstantiatingSpecializationsKey = llvm::PointerIntPair<Decl *, 2>;",
    ])
      assertLeft(text)
  })
  it("where the value ends", () => {
    assert.equal(beforeMarkup("ns::f<false>(x)"), "ns::f<false>(x)")
    assert.equal(beforeMarkup("x.parse::<Ident>()"), "x.parse::<Ident>()")
    assert.equal(beforeMarkup("&a::b::Key<&[u8]>"), "&a::b::Key<&[u8]>")
    assert.equal(beforeMarkup("a->b<c>"), "a->b<c>")
    assert.equal(beforeMarkup("abc123def<td>next"), "abc123def")
  })
  it("witness: what comes before a `<` that follows no identifier is still cut", () => {
    assert.equal(beforeMarkup("Abcd-1234<xyz!"), "Abcd-1234")
    assertMasked(`<t>password=${VALUE}<td>`, `<t>password=${generic}<td>`)
    assertMasked("<t>token=abc-1234-def<td>next", `<t>token=${generic}<td>next`)
    assert.equal(masked("password=Abcd-1234<xyz!").value, `password=${generic}<xyz!`)
  })
})

describe("what reads as something else is not cut", () => {
  it("a comparison, an address with a variable part, a sentence of another script", () => {
    for (const text of [
      "e.key===a.Enter?0:a.Tab<b>next",
      '"token_uri": "https://service-identity.<Domain>/authenticate"',
      '"pass": "フォームの要素に明示的な<label>があります"',
      '"pass": "範圍屬性僅用於表頭元素（<th>）"',
    ])
      assertLeft(text)
  })
  it("witness: a closing tag ends even those", () => {
    assert.equal(beforeMarkup("https://a.example.org/v2</t>"), "https://a.example.org/v2")
  })
})

describe("an HTML tag without a closing tag ends a value", () => {
  it("the closed list of tags", () => {
    assert.equal(masked("password=abc123def<td>").value, `password=${generic}<td>`)
    assert.equal(masked("<div>token=abc123def456<br>next</div>").value, `<div>token=${generic}<br>next</div>`)
    assert.equal(masked("<li>api_key: abc123def456<li>next").value, `<li>api_key: ${generic}<li>next`)
  })
  it("witness: an identifier before any other tag or a generic stays a generic", () => {
    for (const text of ["token=parseToken2<Claims>(raw)", "let x: Foo<b>", "password=x<p>", "token=abc123def456<section>", `<p>token=abc123def456<td class="a">next`]) assertLeft(text)
  })
})

describe("names that end in key and are no secret", () => {
  it("identifiers of Sonar, of issues, of the keyboard, of .NET", () => {
    for (const text of [
      "<sonar.projectKey>acme_billing-service</sonar.projectKey>",
      "<sonar.projectKey>org.acme:billing-api</sonar.projectKey>",
      "<issueKey>PROJ-1234</issueKey>",
      "<HotKey>Ctrl+Alt+K2</HotKey>",
      "<PublicKeyToken>b77a5c561934e089</PublicKeyToken>",
      '<add key="PublicKeyToken" value="b77a5c561934e089"/>',
    ])
      assertLeft(text)
  })
  it("the same in an assignment", () => {
    for (const text of [`projectKey=${VALUE}`, `organizationKey=${VALUE}`, `issueKey=${VALUE}`, `messageKey=${VALUE}`, `propertyKey=${VALUE}`, `labelKey=${VALUE}`, `MESSAGE_KEY=${VALUE}`, `job_key=${VALUE}`]) assertLeft(text)
  })
  it("witness: the names a service may use for a real key stay masked", () => {
    assertMasked(`PROJECT_KEY=${VALUE}`, `PROJECT_KEY=${generic}`)
    assertMasked(`project_key: ${VALUE}`, `project_key: ${generic}`)
    assertMasked(`ORGANIZATION_KEY=${VALUE}`, `ORGANIZATION_KEY=${generic}`)
    assertMasked(`RESOURCE_KEY=${VALUE}`, `RESOURCE_KEY=${generic}`)
    assertMasked(`SpeechResourceKey=${VALUE}`, `SpeechResourceKey=${generic}`)
    assertMasked(`<SpeechResourceKey>${VALUE}</SpeechResourceKey>`, `<SpeechResourceKey>${markup}</SpeechResourceKey>`)
    assertMasked(`<apiToken>${VALUE}</apiToken>`, `<apiToken>${markup}</apiToken>`)
  })
})

describe("a name that describes something else", () => {
  it("its end says so", () => {
    for (const text of [
      '<add key="SecretName" value="kv-prod-secret-01"/>',
      '<add key="PasswordHashAlgo" value="PBKDF2-SHA256"/>',
      '<add key="PasswordResetUrl" value="/account/reset2"/>',
      '<add key="ApiKeyHeader" value="X-Api-Key2"/>',
      '<add key="AuthKeyPath" value="/etc/auth/key1"/>',
      '<input name="tokenizer" value="whitespace2">',
      '<input name="token_type" value="bearer12">',
      '<input id="password-field" class="x" value="Submit123">',
      '<button id="token-submit" value="Submit12">',
      '<add key="TokenEndpoint" value="/oauth2/v2/token"/>',
    ])
      assertLeft(text)
  })
  it("witness: names that go on being read", () => {
    for (const name of ["ApiToken", "SECRET_KEY_BASE", "DbPassword2", "ClientSecretValue", "ApiKeyAndroid"]) assertMasked(`<add key="${name}" value="${VALUE}"/>`, `<add key="${name}" value="${markup}"/>`)
  })
})

describe("an attribute in a JSON text", () => {
  it("escaped quotes, in both orders", () => {
    assertMasked(`<add key=\\"password\\" value=\\"${VALUE}\\"/>`, `<add key=\\"password\\" value=\\"${markup}\\"/>`)
    assertMasked(`<add value=\\"${VALUE}\\" key=\\"password\\"/>`, `<add value=\\"${markup}\\" key=\\"password\\"/>`)
    assertMasked(JSON.stringify({ a: `<add key="password" value="${VALUE}"/>` }), JSON.stringify({ a: `<add key="password" value="${markup}"/>` }))
  })
  it("witness: the plain forms stay as they were", () => {
    assertMasked(`<add key='password' value='${VALUE}'/>`, `<add key='password' value='${markup}'/>`)
    assertLeft(`<add key=\\"user\\" value=\\"${VALUE}\\"/>`)
  })
})

describe("a tag up to the bound of its beginning", () => {
  it("the name after a value, far away", () => {
    assertMasked(`<add key="password" value="${VALUE}" ${"a".repeat(9000)}>`, `<add key="password" value="${markup}" ${"a".repeat(9000)}>`)
    assertMasked(`<add value="${VALUE}" ${"a".repeat(9000)} key="password">`, `<add value="${markup}" ${"a".repeat(9000)} key="password">`)
  })
})

describe("an escaped placeholder", () => {
  it("is left", () => {
    assertLeft("<password>&lt;password&gt;</password>")
    assertLeft('<add key="token" value="&lt;abc123def&gt;"/>')
  })
  it("witness: an escape inside a value leaves it masked", () => {
    assert.equal(masked("<password>Fake&lt;Test-7391</password>").value, `<password>${markup}</password>`)
    assert.equal(masked("password=&lt;password&gt;").count, 0)
  })
})

describe("the name held elsewhere", () => {
  it("the attribute of an element with content", () => {
    assertMasked(`<entry key="password">${VALUE}</entry>`, `<entry key="password">${markup}</entry>`)
    assertMasked(`<property name="hibernate.connection.password">${VALUE}</property>`, `<property name="hibernate.connection.password">${markup}</property>`)
    assertMasked(`<prop key="db.password">\n  <![CDATA[${VALUE}]]>\n</prop>`, `<prop key="db.password">\n  <![CDATA[${markup}]]>\n</prop>`)
  })
  it("a sibling element: plist and Hadoop, on one or several lines", () => {
    assertMasked(`<key>password</key><string>${VALUE}</string>`, `<key>password</key><string>${markup}</string>`)
    assertMasked(`<key>password</key>\n\t<string>${VALUE}</string>`, `<key>password</key>\n\t<string>${markup}</string>`)
    assertMasked(`<name>javax.jdo.option.ConnectionPassword</name><value>${VALUE}</value>`, `<name>javax.jdo.option.ConnectionPassword</name><value>${markup}</value>`)
    assertMasked(`<property>\n  <name>fs.s3a.secret.key</name>\n  <value>${VALUE}</value>\n</property>`, `<property>\n  <name>fs.s3a.secret.key</name>\n  <value>${markup}</value>\n</property>`)
  })
  it("witness: a tag outside the list, a name without a word, a name that describes, a value that fails", () => {
    for (const text of [
      `<h4 id="token">${VALUE}</h4>`,
      `<a id="api-token" href="#x">${VALUE}</a>`,
      `<div id="token">${VALUE}</div>`,
      `<entry key="user">${VALUE}</entry>`,
      "<entry key=\"password\">changeme</entry>",
      "<entry key=\"password\">${DB_PASSWORD}</entry>",
      "<entry key=\"password\">two words</entry>",
      `<entry key="password"/>${VALUE}</entry>`,
      "<key>TokenLifetime</key><string>3600s1</string>",
      "<name>password.encoder</name><value>bcrypt12</value>",
      `<key>user</key><string>${VALUE}</string>`,
      "<key>password</key><string>${DB_PASSWORD}</string>",
    ])
      assertLeft(text)
  })
})

describe("the file of a key", () => {
  it("a path is left, for a name that ends in key", () => {
    for (const path of ["/home/deploy/.ssh/id_ed25519", "/home/user/.ssh/id_rsa2", "C:\\Users\\x1\\.ssh\\id_ed25519", ".ssh/id_ed25519"]) {
      assertLeft(`<privateKey>${path}</privateKey>`)
      assertLeft(`<add key="privateKey" value="${path}"/>`)
    }
  })
  it("an access key that starts with a slash, without + nor =, is a key", () => {
    const key = "/Fake0Test0Access0Key0Value0Only0Abcdef12"
    for (const text of [`<accessKey>${key}</accessKey>`, `<aws_secret_access_key>${key}</aws_secret_access_key>`, `<apiKey>${key}</apiKey>`, `<add key="accessKey" value="${key}"/>`])
      assert.ok(!masked(text).value.includes(key), text)
  })
  it("witness: paths that were left", () => {
    for (const path of ["/home/x/.ssh/id_rsa", "~/.ssh/id_rsa", "${user.home}/.ssh/id_rsa2"]) assertLeft(`<privateKey>${path}</privateKey>`)
  })
  it("witness: a key is masked, a PEM key whole, and a value of base64 that starts with a slash", () => {
    assertMasked(`<privateKey>${VALUE}</privateKey>`, `<privateKey>${markup}</privateKey>`)
    assertMasked("<apiKey>/x9Abc+def123==</apiKey>", `<apiKey>${markup}</apiKey>`)
    assertMasked("<password>/x9Abc+def123==</password>", `<password>${markup}</password>`)
    assertMasked("<secret>/x9Abc123def456</secret>", `<secret>${markup}</secret>`)
    const body = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo1234".repeat(2)
    const result = masked(`<privateKey>-----BEGIN RSA PRIVATE KEY-----\n${body}\n${body}\n-----END RSA PRIVATE KEY-----</privateKey>`)
    assert.ok(!result.value.includes(body))
  })
})

describe("the placeholder rule on an XML file read masked", () => {
  const read = masked(`<configuration>\n  <password>${VALUE}</password>\n  <timeout>30</timeout>\n</configuration>\n`).value
  it("the file is read masked", () => {
    assert.ok(read.includes(markup))
  })
  it("witness: an edit of another part of the file passes", () => {
    assert.equal(placeholderFinding("edit", { path: "c.xml", oldString: "<timeout>30</timeout>", newString: "<timeout>60</timeout>" }), undefined)
  })
  it("witness: in a patch, a context line that holds the marker is refused too", () => {
    const finding = placeholderFinding("patch", { patchText: `*** Begin Patch\n*** Update File: c.xml\n@@\n <password>${markup}</password>\n-  <timeout>30</timeout>\n+  <timeout>60</timeout>\n*** End Patch` })
    assert.equal(finding?.verdict, "deny")
    assert.equal(finding?.rule, "placeholder")
  })
  it("witness: an edit or a write that copies the marker is refused, with its guidance", () => {
    for (const [tool, input] of [
      ["edit", { path: "c.xml", oldString: `<password>${markup}</password>\n  <timeout>30</timeout>`, newString: `<password>${markup}</password>\n  <timeout>60</timeout>` }],
      ["edit", { path: "c.xml", oldString: "<timeout>30</timeout>", newString: `<timeout>60</timeout><password>${markup}</password>` }],
      ["write", { path: "c.xml", content: `<password>${markup}</password>` }],
    ] as const) {
      const finding = placeholderFinding(tool, input)
      assert.equal(finding?.verdict, "deny")
      assert.equal(finding?.rule, "placeholder")
      assert.match(finding!.reason, /writing it would destroy the real secret\. Make a targeted edit that does not include the placeholder/)
    }
  })
})

describe("a value recognized in a tool call", () => {
  const ctx = { redactor: redactor(), home: "/home/u" }
  const text = `<password>${VALUE}</password>`
  it("witness: refused in the arguments of MCP, execute, websearch and webfetch", () => {
    for (const [tool, input] of [
      ["mcp__notes__add", { body: text }],
      ["execute", { code: `const a = "${text}"` }],
      ["websearch", { query: text }],
      ["webfetch", { url: `https://example.org/?q=${text}` }],
    ] as const) {
      const finding = toolFinding(tool, input, ctx)
      assert.equal(finding?.verdict, "deny", tool)
      assert.equal(finding?.rule, "secret-network", tool)
    }
  })
})

describe("cost", () => {
  const SIZE = 1_000_000
  const fill = (unit: string) => unit.repeat(Math.ceil(SIZE / unit.length))
  const inputs: ReadonlyArray<[string, string]> = [
    ["<<<<", fill("<")],
    ["password= repeated", `<t>${fill("password=")}`],
    ["password=x< repeated", fill("password=x<")],
    ["open tags", fill("<password>")],
    ["open tags and text", fill("<password>abc")],
    ["closing tags", fill("</password>")],
    ["long element", `<password>${fill("x")}`],
    ["blanks in an element", `<password>${fill(" ")}`],
    ["blanks after an element", `<password>a</password${fill(" ")}`],
    ["long tag name", `<${fill("a")}`],
    ["long names repeated", fill(`<${"a".repeat(130)}`)],
    ["long attributes", `<add password="1" ${fill('a="b" ')}`],
    ["long attributes repeated", fill(`<add ${'a="b" '.repeat(1300)}`)],
    ["value= repeated, no end of tag", `<add ${fill(' value="x"')}`],
    ["value= repeated by tag, no end of tag", fill(`<add ${' value="x"'.repeat(800)}`)],
    ["value= repeated in a closed tag", fill(`<add ${' value="x"'.repeat(800)}>`)],
    ["value without a closing quote", fill(`<add key="password" value="${"x".repeat(5000)}`)],
    ["alternate quotes", `<add ${fill(` value="x value='y`)}`],
    ["key= repeated", fill(`<add ${' key="password"'.repeat(500)} value="${VALUE}"/>`)],
    ["CDATA repeated", fill("<password> <![CDATA[")],
    ["blanks before a CDATA", fill(`<password>${" ".repeat(64)}`)],
    ["a<b", fill("token a<b c ")],
    ["many elements", fill(`<password>${VALUE}</password>\n`)],
    ["many secret tags", fill(`<add key="password" value="${VALUE}"/>\n`)],
    ["value= first, end of tag beyond the bound of `after`", fill(`<add${' value="x"'.repeat(1000)}${" ".repeat(8300)}>`)],
    ["long name, the same tag", fill(`<${"a".repeat(128)}${' value="x"'.repeat(1000)}${" ".repeat(8300)}>`)],
    ["alternate quotes, the same tag", fill(`<add${" value=\"x value='y".repeat(500)}${" ".repeat(8300)}>`)],
    ["zero-width character, the same tag", `\u200b${fill(`<add${' value="x"'.repeat(1000)}${" ".repeat(8300)}>`)}`],
    ["long attributes of a named element", fill(`<entry ${"a".repeat(8000)}>${"x".repeat(2000)}`)],
    ["named elements left open", fill("<entry a")],
    ["key= repeated in a named element", fill(`<entry ${' key="password"'.repeat(500)}>${VALUE}</entry>`)],
    ["sibling elements left open", fill(`<key>${"a".repeat(250)}</key>${" ".repeat(64)}<string>${"x".repeat(2000)}`)],
    ["short sibling elements left open", fill("<key>a</key><string>")],
    ["blanks after a sibling name", fill(`<name>${" ".repeat(64)}`)],
    ["many sibling secrets", fill(`<key>password</key><string>${VALUE}</string>\n`)],
    ["open HTML tags", `password=${fill("a<td a")}`],
  ]
  for (const [name, text] of inputs) {
    it(`witness: bounded on ${name}`, () => {
      const r = redactor()
      // A secret word, as the patterns only run on a text with one.
      const start = performance.now()
      r.redactString(`token ${text}`)
      assert.ok(withinBudget(start, 3000), name)
    })
  }
})
