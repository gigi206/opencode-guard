import "./tmp.ts"
// Self-protection net: forms of write read by `writeTargets`, launchers and inline code, then the ask for a command that
// names a protected location and does more than read, whatever its form of write. Commands are only examined; nothing is
// run. Fake paths and values.
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { withinBudget } from "./budget.ts"
import { shellFinding } from "../src/rules/shell.ts"
import { createRedactor } from "../src/secrets/redact.ts"

const HOME = "/home/test"
const ctx = { redactor: createRedactor(), home: HOME, cwd: `${HOME}/project` }
type Context = Parameters<typeof shellFinding>[1]
const found = (command: string, context: Context = ctx) => {
  const finding = shellFinding(command, context)
  return finding ? `${finding.verdict}/${finding.rule}` : "none"
}
const decidable = (command: string, context: Context) => shellFinding(command, context)?.modelDecides !== undefined

const WRITE_REASON = "write to OpenCode's configuration or to the guard plugin (self-protection)"
const NAMED_REASON = "command that names OpenCode's configuration or the guard plugin and does more than read: it may write there in a form the plugin does not recognize (self-protection)"
const LIMIT_REASON = "command with too many paths to compare with OpenCode's configuration and the guard plugin: the plugin's limit on named paths was reached, so it could not be checked: confirmation required (self-protection)"

/** Commands of the pipeline switch: for a group, a quoted separator, `>(…)`, a heredoc, a text escape, `busybox sh`. */
const REGRESSIONS = [
  "for i in 1; do echo rm opencode.json; done | bash",
  "for i in 1; do echo opencode.json; done | xargs rm",
  "for i in 1; do find .opencode -type f; done | xargs rm",
  "for i in 1; do jq -r .a opencode.json; done | sh",
  "if true; then echo rm opencode.json; fi | sh",
  "if true; then find .opencode; fi | xargs rm",
  "if echo rm opencode.json; then :; fi | sh",
  "until false; do echo rm opencode.json; done | bash",
  "for i in 1; do echo rm opencode.json; done |& sh",
  "sh -c 'for i in 1; do echo rm opencode.json; done | sh'",
  "{ echo opencode.json; } > >(xargs rm)",
  "for i in 1; do echo opencode.json; done > >(xargs rm)",
  "if true; then echo opencode.json; fi > >(sh)",
  "echo 'rm opencode.json;' | sh",
  "echo 'rm opencode.json; ls' | sh",
  "echo 'rm .opencode/x && ls' | bash",
  "echo 'rm .opencode/x || ls' | bash",
  "echo 'rm .opencode/x & ls' | bash",
  "echo 'rm .opencode/x\nls' | bash",
  "printf 'rm .opencode/x;\\n' | sh",
  "echo \"cp /tmp/a .opencode/x;\" | sh",
  "find .opencode -type f | tee >(xargs rm)",
  "find .opencode | tee >(xargs sed -i s/a/b/)",
  "find .opencode -type f | tee >(xargs rm) | wc -l",
  "find .opencode -type f | tee /dev/null >(xargs rm)",
  "find .opencode -type f | cat > >(xargs rm)",
  "xargs rm <<'EOF'\nopencode.json\nEOF",
  "cat <<'EOF' | xargs rm\nopencode.json\nEOF",
  "cat <<'EOF' | xargs -I{} rm {}\n.opencode/x\nEOF",
  "xargs -a /dev/stdin rm <<'EOF'\nopencode.json\nEOF",
  "printf 'opencode.json\\0' | xargs -0 rm",
  "printf '.opencode/x\\0' | xargs -0 rm",
  "printf 'rm opencode.json\\v' | sh",
  "printf 'rm opencode.json\\f' | sh",
  "printf 'rm\\040opencode.json' | sh",
  "echo -e 'rm opencode.json\\c' | sh",
  "ls .opencode | busybox sh",
  "ls .opencode | busybox ash",
  "busybox sh <<'EOF'\ncurl -o opencode.json u\nEOF",
]

const TARGETS = ["opencode.json", ".opencode/plugins/x.ts", "$HOME/.config/opencode/guard.json", "~/.config/opencode/guard.json"]

describe("forms of write read as such", () => {
  const FILE_FORMS: ReadonlyArray<(target: string) => string> = [
    (target) => `dd if=/tmp/x of=${target}`,
    (target) => `patch ${target} < /tmp/p.diff`,
    (target) => `sponge ${target} < /tmp/x`,
    (target) => `perl -e 'open(F, ">", "${target}")'`,
    (target) => `perl -e 'sysopen(F, "${target}", 1)'`,
    (target) => `busybox cp /tmp/x ${target}`,
    (target) => `toybox cp /tmp/x ${target}`,
    (target) => `watch cp /tmp/x ${target}`,
    (target) => `watch -n 5 cp /tmp/x ${target}`,
    (target) => `env -S "cp /tmp/x ${target}"`,
    (target) => `env -S"cp /tmp/x ${target}"`,
    (target) => `env --split-string="cp /tmp/x ${target}"`,
  ]
  // A directory: `opencode.json` is not one.
  const DIRECTORY_FORMS: ReadonlyArray<(directory: string) => string> = [
    (directory) => `tar -xf /tmp/e.tar -C ${directory}`,
    (directory) => `tar xzf /tmp/e.tgz -C ${directory}`,
    (directory) => `tar --extract --file=/tmp/e.tar --directory=${directory}`,
    (directory) => `unzip -o /tmp/e.zip -d ${directory}`,
    (directory) => `cpio -idmv -D ${directory} < /tmp/e.cpio`,
    (directory) => `git apply --directory ${directory} /tmp/p.diff`,
    (directory) => `git apply --directory=${directory} /tmp/p.diff`,
  ]
  it("each form on each target: the reason of a write", () => {
    for (const form of FILE_FORMS)
      for (const target of TARGETS.filter((candidate) => !form(candidate).startsWith("perl") || !/^[$~]/.test(candidate))) {
        const finding = shellFinding(form(target), ctx)
        assert.equal(finding?.rule, "self-protection", form(target))
        assert.equal(finding?.reason, WRITE_REASON, form(target))
      }
    for (const form of DIRECTORY_FORMS)
      for (const directory of [".opencode", "~/.config/opencode"]) {
        const finding = shellFinding(form(directory), ctx)
        assert.equal(finding?.rule, "self-protection", form(directory))
        assert.equal(finding?.reason, WRITE_REASON, form(directory))
      }
  })
  it("a write through nested substitutions: the net asks, the location is named", () => {
    for (const command of ['cp /tmp/x "$(echo "$(echo .opencode)")/plugins/x.ts"', 'echo x > "$(echo "$(echo .opencode)")/plugins/x.ts"'])
      assert.equal(found(command), "ask/self-protection", command)
  })
  it("the same forms reach the other rules", () => {
    const unguarded = { ...ctx, active: { dangerousCommands: true, sensitiveFiles: false } }
    assert.equal(found("dd of=~/.ssh/authorized_keys", unguarded), "ask/protected-write")
    assert.equal(found("dd of=~/.bashrc"), "ask/protected-write")
    assert.equal(found("busybox cp /tmp/x /dev/sda"), "deny/write-device")
    assert.equal(found(`python3 -c 'open(".opencode/x.md","w")'`), "ask/self-protection")
  })
})

describe("net: names a protected location, form of write not read", () => {
  it("other programs and launchers ask", () => {
    for (const command of [
      "curl -o .opencode/x https://example.test/y",
      "wget -O opencode.json https://example.test/y",
      "sort -o opencode.json /tmp/x",
      "openssl enc -in /tmp/x -out .opencode/x",
      "gcc -o .opencode/x /tmp/a.c",
      "rsync /tmp/x .opencode/x",
      "ed opencode.json",
      "vim opencode.json",
      "git checkout-index --prefix=.opencode/ -a",
      "git -C .opencode apply /tmp/p.diff",
      "bsdtar -xf /tmp/e.tar -C .opencode",
      "gawk -i inplace '{print}' .opencode/x",
      `ruby -e 'File.write(".opencode/x.md", "x")'`,
      `php -r 'file_put_contents(".opencode/x.md", "x");'`,
      `python3 -c 'import shutil; shutil.copy("/tmp/x", ".opencode/x.md")'`,
      "nice cp /tmp/x .opencode/x",
      "timeout 5 cp /tmp/x .opencode/x",
      "xargs cp -t .opencode",
      "parallel cp {} .opencode/ ::: a",
      "systemd-run cp /tmp/x .opencode/x",
      "script -c 'cp /tmp/x .opencode/x' /dev/null",
      "stdbuf -o0 cp /tmp/x .opencode/x",
      "cd .opencode && npm install",
      "mkdir opencode.json",
      "somecmd --output=.opencode/x",
      "somecmd -C.opencode",
    ])
      assert.equal(found(command), "ask/self-protection", command)
  })
  it("the reason gives the cause, without a value", () => {
    assert.equal(shellFinding("somecmd .opencode/secret-name", ctx)?.reason, NAMED_REASON)
  })
  it("reads and naming commands ask nothing", () => {
    for (const command of [
      "cat opencode.json",
      "git diff opencode.json",
      "grep x .opencode/guard.json | head",
      "ls .opencode",
      "jq . opencode.json",
      "find .opencode -name x",
      "echo opencode.json",
      'printf "%s" .opencode/x',
      "nohup echo .opencode/x",
      "timeout 5 find .opencode -name x",
      "timeout -s KILL 5 find .opencode -name x",
      "nice -n 5 env A=1 jq . opencode.json",
      "test -f opencode.json",
      "[ -f opencode.json ]",
      "dd if=opencode.json of=/tmp/x",
      "head -5 ~/.config/opencode/opencode.json",
      "curl -o /tmp/x https://example.test/.opencode/x",
      "somecmd $DIR/opencode.json",
      "somecmd .opencode/*.md",
      "cat > /tmp/n.md <<'EOF'\nsomecmd .opencode/x\nEOF",
    ])
      assert.equal(found(command), "none", command)
  })
  it("a naming command that redirects or a find that acts is not left out", () => {
    for (const command of ["jq . opencode.json 2>/tmp/e", "find .opencode -fprint /tmp/x", "find .opencode -exec somecmd {} +", "nice find .opencode -exec somecmd {} +", "busybox echo .opencode/x", "A=1 echo .opencode/x", '"echo" .opencode/x'])
      assert.equal(found(command), "ask/self-protection", command)
    // Its own rule first.
    assert.equal(found("find .opencode -delete"), "ask/find-delete")
  })
  it("tar -c that names the location asks: wanted, it reads but no exemption exists for it", () => {
    assert.equal(found("tar -cf /tmp/a.tar -C .opencode ."), "ask/self-protection")
  })
  it("in a protected directory, bare words ask nothing, a path does", () => {
    const inside = { ...ctx, cwd: `${HOME}/.config/opencode` }
    assert.equal(found("npm install", inside), "none")
    assert.equal(found("npm install ./x", inside), "ask/self-protection")
  })
})

describe("net: place among the findings", () => {
  const byModel = { ...ctx, active: { dangerousCommands: true, sensitiveFiles: true, localAsksByModel: true, selfProtectionByModel: true } }
  it("settings stay with the user, another location goes like its neighbours", () => {
    assert.equal(found("somecmd opencode.json", byModel), "ask/self-protection")
    assert.equal(decidable("somecmd opencode.json", byModel), false)
    assert.equal(decidable("somecmd .opencode/x", byModel), true)
    assert.equal(decidable("cp /tmp/x .opencode/x", byModel), true)
    assert.equal(decidable("cp /tmp/x opencode.json", byModel), false)
    assert.equal(decidable("cp /tmp/x .opencode/x; somecmd opencode.json", byModel), false)
  })
  it("a deny is never lost, an earlier ask keeps its place", () => {
    assert.equal(found("rm -rf / opencode.json"), "deny/rm-critical")
    assert.equal(found("somecmd .opencode/x; echo x > /dev/sda"), "deny/redirect-device")
    assert.equal(found("guard rules off upload .opencode/x"), "ask/guard-cli")
    assert.equal(shellFinding("cp /tmp/x .opencode/x; somecmd opencode.json", ctx)?.reason, WRITE_REASON)
  })
  it("does not use the real paths budget, and a word reached through a link stays with the model (limit)", () => {
    let lookups = 0
    const realPaths: NonNullable<Context["realPaths"]> = () => {
      lookups++
      return [`${HOME}/.config/opencode/guard.json`]
    }
    assert.equal(found("somecmd sub/to-config", { ...ctx, realPaths }), "none")
    assert.equal(lookups, 0)
    assert.equal(found("cp /tmp/x sub/to-config", { ...ctx, realPaths }), "ask/self-protection")
  })
})

describe("net: bounds", () => {
  const paths = (count: number) => Array.from({ length: count }, (_, index) => `a/${index}`).join(" ")
  it("past the limit of distinct words: an ask, never left to the model", () => {
    assert.equal(found(`somecmd ${paths(1024)}`), "none")
    const finding = shellFinding(`somecmd ${paths(1025)}`, ctx)
    assert.equal(finding?.rule, "self-protection")
    assert.equal(finding?.reason, LIMIT_REASON)
    assert.equal(decidable(`somecmd ${paths(1025)}`, { ...ctx, active: { dangerousCommands: true, sensitiveFiles: true, localAsksByModel: true, selfProtectionByModel: true } }), false)
  })
  it("a word repeated counts once", () => {
    assert.equal(found(`somecmd ${"a/b ".repeat(5000)}`), "none")
  })
  it("cost: 64 KiB of words, segments and quotes: bounded", () => {
    const fill = (unit: string, size = 65536) => unit.repeat(Math.ceil(size / unit.length)).slice(0, size)
    for (const line of [
      `somecmd ${paths(9000)}`.slice(0, 65536),
      fill("somecmd a/b; "),
      fill("x/../"),
      fill("'\""),
      fill("echo a/b | "),
      `sudo ${fill("-1 1 ")}`,
      `sudo ${fill("env ")}a/b`,
      fill("sudo -1 1 a/b; "),
      `somecmd ${fill("-Ca/")}`,
      `somecmd ${fill("--o=a/b ")}`,
      fill("env -Sx "),
      fill('env -S"a b" '),
      fill("env -u "),
      `env -S${fill("env -S")}x`,
      fill("{ echo a/b; } | sh; "),
      `${fill("cat a/b | ")}xargs grep x`,
      `echo a/b ${fill("2>/dev/null ")}`,
      fill("env >a "),
      fill("env 2>&1 "),
      fill("env 'x "),
      `${fill("env >a ")}-Sx`,
      fill("export D=a/b; "),
      fill("x=$y "),
      fill("ls a/b | /usr/bin/x "),
      fill("jq . . "),
      fill("} > a; "),
      fill("| "),
      fill("|   /usr/local/bin/"),
      fill("D[0"),
      fill("a="),
      fill("\\0"),
      `xargs ${fill("cat a/b ")}`,
      `${fill("then if ! ")}echo a/b`,
    ]) {
      const start = performance.now()
      shellFinding(line, ctx)
      assert.ok(withinBudget(start, 1000), JSON.stringify(line.slice(0, 16)))
    }
  })
})

describe("net: data a shell reads", () => {
  it("a heredoc read by a shell is read as the commands it holds", () => {
    for (const command of ["sh <<'EOF'\ncurl -o opencode.json u\nEOF", "bash -s <<'EOF'\ncurl -o opencode.json u\nEOF", "cat <<'EOF' | bash\ncurl -o .opencode/x u\nEOF", "bash <<< 'curl -o opencode.json u'"])
      assert.equal(found(command), "ask/self-protection", command)
  })
  it("a heredoc no shell reads stays data", () => {
    for (const command of ["cat <<'EOF'\nsee opencode.json\nEOF", "cat > /tmp/x <<'EOF'\nopencode.json\nEOF", "python3 <<'EOF'\nprint('opencode.json')\nEOF"])
      assert.equal(found(command), "none", command)
  })
  it("in a heredoc a shell reads, a read asks too: no word is left out", () => {
    assert.equal(found("sh <<'EOF'\ncat opencode.json\nEOF"), "ask/self-protection")
  })
})

describe("net: a pipeline into a program that runs its input", () => {
  it("what feeds it is read, even a read or a naming command", () => {
    for (const command of [
      "find .opencode -type f | xargs sed -i s/a/b/",
      "find . -name opencode.json | xargs sed -i s/a/b/",
      "echo opencode.json | xargs rm",
      "cat opencode.json | xargs -I{} touch {}",
      "find .opencode | sort | xargs rm",
      "printf 'cp /tmp/x .opencode/x' | sh",
      "printf 'cp /tmp/x opencode.json\\n' | sh",
      "echo 'cp /tmp/x opencode.json' | bash",
      "ls .opencode | sh",
      "ls .opencode |& sh",
      'ls .opencode | "sh"',
      "ls .opencode | /bin/sh",
      "cat .opencode/x | zsh",
      "cat .opencode/x | dash",
      "cat .opencode/x | ksh",
      "cat .opencode/x | fish",
      "cat opencode.json | source /dev/stdin",
      "cat opencode.json | . /dev/stdin",
      "{ echo cp /tmp/x .opencode/x; } | sh",
      "(echo a; echo cp /tmp/x .opencode/x) | sh",
    ])
      assert.equal(found(command), "ask/self-protection", command)
  })
  it("eval, parallel and a bare xargs ask too, by their own rule", () => {
    assert.equal(found("ls .opencode | eval"), "ask/eval")
    assert.equal(found("cat .opencode/x | parallel"), "ask/parallel-dynamic-exec")
    assert.equal(found("find .opencode | xargs"), "ask/xargs-dynamic-exec")
  })
  it("a pipeline into a reader asks nothing, nor a statement outside the pipeline", () => {
    for (const command of [
      "cat opencode.json | jq .",
      "grep x opencode.json | head",
      "find .opencode -type f | sort",
      "ls .opencode | wc -l",
    ])
      assert.equal(found(command), "none", command)
  })
  it("the switch holds for the whole command, whatever the child of xargs, with these confirmations as its price", () => {
    for (const command of [
      "find .opencode -type f | xargs grep foo",
      "find .opencode | xargs cat",
      "find .opencode | xargs -0 -n1 grep foo",
      "find .opencode | xargs -I{} grep x {}",
      "find .opencode | xargs echo",
      "cat opencode.json; ls /tmp | sh",
      "grep xargs opencode.json",
      "cat opencode.json | awk '{print $1}'",
    ])
      assert.equal(found(command), "ask/self-protection", command)
  })
  it("non-regressions: every form that once passed the pipeline", () => {
    for (const command of REGRESSIONS) assert.equal(found(command), "ask/self-protection", command)
  })
  it("an interpreter reading its standard input", () => {
    for (const command of [
      "find .opencode | perl -lne unlink",
      "ls .opencode | python3 -c 'x'",
      "ls .opencode | python3.12 -c 'x'",
      'ls .opencode | "perl" -lne unlink',
      "ls .opencode | /usr/bin/ruby -ne x",
      "ls .opencode | env node x.js",
      "ls .opencode | timeout 5 php x.php",
      "ls .opencode | tee >(perl -lne unlink)",
      "ls .opencode | deno run x.ts",
      "ls .opencode | bun x.ts",
      "ls .opencode | gawk x",
    ])
      assert.equal(found(command), "ask/self-protection", command)
  })
  it("a program of the system by its path is no relaunch, any other path is", () => {
    for (const command of ["ls .opencode | /usr/bin/sort", "ls .opencode | /bin/sort", "ls .opencode | /usr/local/bin/sort", "ls .opencode; /usr/bin/true"])
      assert.equal(found(command), "none", command)
    for (const command of ["ls .opencode | ./sort", "ls .opencode | ../sort", "ls .opencode | ~/sort", "ls .opencode | /tmp/sort", "ls .opencode | /usr/bin/x/sort", "ls .opencode | /usr/bin/../../tmp/sort"])
      assert.equal(found(command), "ask/self-protection", command)
    // A shell or an interpreter stays one by its path; the exemption is the net's alone.
    for (const command of ["ls .opencode | /usr/bin/sh", "ls .opencode | /bin/bash", "ls .opencode | /usr/bin/env sh", "ls .opencode | /usr/bin/python3"])
      assert.equal(found(command), "ask/self-protection", command)
    assert.equal(found("/usr/bin/sort <<'EOF'\ncurl -o opencode.json u\nEOF\n./x"), "ask/self-protection")
  })
  it("a path inside quotes launches nothing, unlike one in a substitution", () => {
    for (const command of ["cat opencode.json | sed 's|/tmp|/x|g'", "ls .opencode | sed 's|/a|/b|'", 'cat opencode.json | sed "s|/tmp|/x|"'])
      assert.equal(found(command), "none", command)
    assert.equal(found('echo "$(ls .opencode | ./x)"'), "ask/self-protection")
  })
  it("a dot behind a word is an argument, a dot as a command is not", () => {
    for (const command of ["timeout 5 jq . opencode.json", "nice -n 5 jq . opencode.json", "env A=1 jq . opencode.json"]) assert.equal(found(command), "none", command)
    for (const command of ["ls .opencode | command . /dev/stdin", "ls .opencode; . /tmp/x"]) assert.equal(found(command), "ask/self-protection", command)
  })
  it("a group sent to a file reads every word", () => {
    for (const command of ["{ jq . opencode.json; } >/tmp/x", "(jq . opencode.json; echo a) >/tmp/x", "for i in 1; do jq . opencode.json; done > /tmp/x", "if true; then jq . opencode.json; fi >> /tmp/x"])
      assert.equal(found(command), "ask/self-protection", command)
    for (const command of ["{ jq . opencode.json; } 2>/dev/null", "for i in 1; do jq . opencode.json; done"]) assert.equal(found(command), "none", command)
  })
})

describe("net: what receives a pipe", () => {
  it("anything but a known reader reads every word", () => {
    for (const command of [
      "for i in 1; do echo rm opencode.json; done | csh",
      "for i in 1; do echo rm opencode.json; done | if true; then sh; fi",
      "echo rm opencode.json | csh",
      "! echo rm opencode.json | csh",
      "echo rm opencode.json 2>&1 | csh",
      "timeout -s KILL 5 echo rm opencode.json | csh",
      "env -u X echo rm opencode.json | csh",
      "exec -a x echo rm opencode.json | $SHELL",
      'find .opencode -type f | while read f; do curl -o "$f" u; done',
      'find .opencode -type f 2>/dev/null | while read f; do curl -o "$f" u; done',
      'for i in 1; do echo opencode.json; done | while read f; do curl -o "$f" u; done',
      "(echo opencode.json) | git rm --pathspec-from-file=-",
      "echo opencode.json | git rm --pathspec-from-file=-",
      "{ echo .opencode/x; } | rsync --files-from=- --remove-source-files . /tmp/y",
      "{ jq . opencode.json; } | tee /tmp/x",
      "ls .opencode | bin/apply",
      "ls .opencode | bin/jq .",
      "echo 'rm opencode.json' | /usr/bin/csh",
      "echo 'rm opencode.json' | /usr/bin/find . -delete",
      "ls .opencode | { cat; csh; }",
      "ls .opencode | (head; csh)",
      "ls .opencode | if cat; then csh; fi",
      "ls .opencode | head > /tmp/x",
      'echo rm opencode.json | "/tmp/e/"cat',
      'ls .opencode | "./"cat',
      "ls .opencode | 'x'cat",
      "ls .opencode | 'x'jq .",
      'ls .opencode | "$HOME/bin/"head',
      'for i in 1; do echo rm opencode.json; done | "./"cat',
      '! echo rm opencode.json | "./"sort',
      "ls .opencode | nice",
      "ls .opencode | {",
    ])
      assert.equal(found(command), "ask/self-protection", command)
  })
  it("a reader that writes is no known reader", () => {
    for (const command of ["ls .opencode | sed -i s/a/b/", "ls .opencode | sed 's/a/b/w x'", "ls .opencode | sed s/a/b/e", "ls .opencode | tee /tmp/x", "ls .opencode | sort -o x", "ls .opencode | sort -uo x", "ls .opencode | uniq - out", "ls .opencode | uniq a b"])
      assert.equal(found(command), "ask/self-protection", command)
  })
  it("a known reader asks nothing", () => {
    for (const command of [
      "cat opencode.json | jq .",
      "grep x opencode.json | head",
      "ls .opencode | wc -l",
      "cat opencode.json | sed s/a/b/",
      "cat opencode.json | sed 's/a|b/c/g'",
      "cat .opencode/x | sed -n 1,3p",
      "cat opencode.json | tr a b",
      "cat opencode.json | cut -d: -f1",
      "ls .opencode | /usr/bin/sort",
      "cat opencode.json | sort | uniq",
      "grep x opencode.json | sort -t: -k2 | uniq -c | head -5",
      "grep x opencode.json | grep -v sh",
      "find .opencode -type f 2>/dev/null | head 2>&1",
      "echo $(cat opencode.json | wc -l)",
      'cat opencode.json | "cat"',
      "cat opencode.json |\n  jq .",
      "cat opencode.json || ls",
    ])
      assert.equal(found(command), "none", command)
  })
  it("sed that substitutes reads, sort and uniq stay outside the readers of a file", () => {
    assert.equal(found("sed 's/a/b/g' opencode.json"), "none")
    for (const command of ["sed 's/a/b/w x' opencode.json", "sed -i s/a/b/ opencode.json", "sort opencode.json", "uniq opencode.json"]) assert.equal(found(command), "ask/self-protection", command)
  })
})

describe("net: assignments", () => {
  it("an assignment alone counts only if the command uses it", () => {
    for (const command of ["D=.opencode; ls foo", "D=.opencode", "export D=.opencode", "readonly D=.opencode; ls foo", "D+=.opencode; ls foo", "D[0]=.opencode; ls foo"])
      assert.equal(found(command), "none", command)
    for (const command of ["D=.opencode; curl -o $D/y u", "D=.opencode; curl -o ${D}/y u", "export D=.opencode; curl -o $D/y u", "readonly D=.opencode; curl -o ${D}/y u", "D=.opencode; ls $D", "D=.opencode; echo ${#D}"])
      assert.equal(found(command), "ask/self-protection", command)
  })
  it("in front of a program, or when every word is read, it counts", () => {
    for (const command of ["CONFIG=opencode.json node x.js", "DESTDIR=.opencode/x make install", "export D=.opencode; ./run.sh", "D=.opencode; ls foo | sh"])
      assert.equal(found(command), "ask/self-protection", command)
  })
  it("only a segment of dd reads if=, and every form of assignment is read", () => {
    for (const command of [
      "if=opencode.json; curl -o $if u",
      "export if=.opencode/x; curl -o $if u",
      "somecmd if=.opencode/x",
      "make if=.opencode/x",
      "D+=.opencode/x; curl -o $D u",
      "D[0]=.opencode/x; curl -o ${D[0]} u",
      "somecmd a=b=opencode.json",
      "somecmd --define=x=.opencode/y",
      "dd if=opencode.json | sh",
    ])
      assert.equal(found(command), "ask/self-protection", command)
    for (const command of ["dd if=opencode.json of=/tmp/x", "sudo dd if=opencode.json of=/tmp/x", "(dd if=opencode.json of=/tmp/x)"]) assert.notEqual(found(command), "ask/self-protection", command)
  })
})

describe("net: launchers, find and words", () => {
  it("the value of a launcher's option is not its program", () => {
    for (const command of [
      "env -u echo curl -o .opencode/x https://example.test/y",
      "env -u test wget -O opencode.json https://example.test/y",
      "env --unset echo curl -o .opencode/x https://example.test/y",
      "env -C jq curl -o .opencode/x https://example.test/y",
      "env --chdir jq curl -o .opencode/x https://example.test/y",
      "env -iu echo curl -o .opencode/x u",
      "exec -a echo curl -o .opencode/x https://example.test/y",
      "exec -a test gcc -o opencode.json /tmp/a.c",
      "timeout -s echo 5 curl -o .opencode/x u",
      "nice -n echo curl -o .opencode/x u",
    ])
      assert.equal(found(command), "ask/self-protection", command)
    // A long option not known may take a value: nothing benign behind it. Its own rule first.
    assert.equal(found("doas --user echo curl -o .opencode/x u"), "ask/privilege")
    for (const command of ["env -u FOO echo .opencode/x", "env --unset=FOO echo .opencode/x", "env --unset FOO jq . opencode.json", "exec -a x echo .opencode/x", "timeout 5 jq . opencode.json", "stdbuf -oL jq . opencode.json", "nice -n 5 jq . opencode.json"])
      assert.equal(found(command), "none", command)
  })
  it("an action of find quoted or escaped is an action", () => {
    for (const command of ["find . -name opencode.json '-exec' curl -o {} https://example.test/y ;", "find .opencode -name x \\-exec cp /tmp/x {} \;", 'find . "-fprint" .opencode/x', 'find . "-fls" .opencode/x', 'find .opencode -name x -de"le"te', "find .opencode $'-exec' rm {} ;"])
      assert.equal(found(command), "ask/self-protection", command)
    for (const command of ["find .opencode -name '*.json'", "find .opencode -name x -print", "find .opencode -executable"]) assert.equal(found(command), "none", command)
  })
  it("the literal value of a name=value word is read, not followed further", () => {
    for (const command of [
      "D=.opencode/plugins; curl -o $D/y u",
      "D=opencode.json; curl -o $D u",
      "export D=.opencode/x; curl -o $D u",
      'D=".opencode/x"; curl -o $D u',
      "D=~/.config/opencode; curl -o $D/x u",
      "make DESTDIR=.opencode/x install",
      "somecmd out=opencode.json",
      "X=opencode.json somecmd",
    ])
      assert.equal(found(command), "ask/self-protection", command)
    for (const command of ["dd if=opencode.json of=/tmp/x", "D=/tmp/x; curl -o $D u", "make DESTDIR=/tmp/x install", "somecmd out=/tmp/x", "URL=https://example.test/opencode.json somecmd", "D=opencode; somecmd $D"])
      assert.equal(found(command), "none", command)
  })
  it("a value keeps what follows its first = and its last", () => {
    for (const command of ["sort --output=.opencode/a=b x", "cp --target-directory=.opencode/a=b x", "wget --output-document=.opencode/a=b u", "tar --file=.opencode/a=b", "tar --file=.opencode/a=b -c x", "a=b=opencode.json somecmd"])
      assert.equal(found(command), "ask/self-protection", command)
  })
  it("escaped quotes hide no redirection, quoted text is no redirection", () => {
    for (const command of ['echo \\" >$(printf .opencode/x) \\"', "echo x >$(echo .opencode/x)", "echo 'a\\' >.opencode/x 'b'"])
      assert.equal(found(command), "ask/self-protection", command)
    for (const command of ["echo 'a > b' .opencode/x", 'echo "x > y" opencode.json']) assert.equal(found(command), "none", command)
  })
  it("a redirection without effect on a file changes nothing, a real one still asks", () => {
    for (const command of [
      "find .opencode -type f 2>/dev/null",
      "find .opencode -type f 2>/dev/null | head",
      "jq . opencode.json 2>/dev/null",
      "jq . opencode.json 2> /dev/null",
      "jq . opencode.json 2>&1",
      "jq . opencode.json 2>&-",
      "jq . opencode.json >/dev/null",
      "jq . opencode.json &>/dev/null",
      "test -f opencode.json 2>/dev/null",
      "echo .opencode/x 2>&1",
    ])
      assert.equal(found(command), "none", command)
    for (const command of ["jq . opencode.json 2>/tmp/e", "jq . opencode.json >/tmp/x", "jq . opencode.json 2>/dev/null >/tmp/x", "jq . opencode.json 2>&1 >/tmp/x", "echo x 2>opencode.json", "echo x >.opencode/x 2>&1", "find .opencode >/tmp/x 2>/dev/null"])
      assert.equal(found(command), "ask/self-protection", command)
    // Known false ask: an input redirection reads, but it is no exemption.
    assert.equal(found("jq . < opencode.json"), "ask/self-protection")
    assert.equal(found("jq . opencode.json >&/tmp/x"), "ask/self-protection")
  })
  it("structural words before a benign program change nothing, before another they do", () => {
    for (const command of [
      "if [ -f opencode.json ]; then echo yes; fi",
      "if test -f opencode.json; then echo yes; fi",
      "if ! [ -f opencode.json ]; then echo no; fi",
      "while [ ! -f opencode.json ]; do sleep 1; done",
      "until test -f opencode.json; do sleep 1; done",
      "! test -f opencode.json",
      "{ jq . opencode.json; }",
      "( find .opencode -type f )",
      "then echo .opencode/x",
    ])
      assert.equal(found(command), "none", command)
    for (const command of ["if cp /tmp/x .opencode/x; then echo; fi", "then somecmd opencode.json", "{ somecmd opencode.json; }", "( somecmd opencode.json )", "! somecmd opencode.json", "while somecmd .opencode/x; do sleep 1; done"])
      assert.equal(found(command), "ask/self-protection", command)
  })
})

describe("forms read for every rule", () => {
  it("sysopen for reading writes nothing, whatever the blanks", () => {
    for (const command of [`perl -e 'sysopen(F, ".opencode/x", 0)'`, `perl -e 'sysopen(F, "opencode.json", O_RDONLY)'`, `perl -e 'sysopen(F, ".opencode/x",0)'`, `perl -e 'sysopen(F, ".opencode/x", 0, 0644)'`])
      assert.equal(found(command), "none", command)
    for (const command of [`perl -e 'sysopen(F, ".opencode/x", 1)'`, `perl -e 'sysopen(F, ".opencode/x",1)'`, `perl -e 'sysopen(F, ".opencode/x", O_WRONLY)'`, `perl -e 'sysopen(F, "opencode.json", O_RDONLY|O_CREAT)'`, `perl -e 'sysopen(F, "opencode.json", O_RDONLY | O_CREAT)'`])
      assert.equal(found(command), "ask/self-protection", command)
  })
  it("the string of env -S reads as the separate form for every rule", () => {
    const expected: ReadonlyArray<readonly [string, string]> = [
      ["env -Srm -rf /", "deny/rm-critical"],
      ['env "-Srm -rf /"', "deny/rm-critical"],
      ['env -S "rm -rf /"', "deny/rm-critical"],
      ["env -S'rm -rf /'", "deny/rm-critical"],
      ['env -Srm" -rf /"', "deny/rm-critical"],
      ["env -iS'rm -rf /'", "deny/rm-critical"],
      ["env --split-string='rm -rf /'", "deny/rm-critical"],
      ["env -S'rm\\_-rf\\_/'", "deny/rm-critical"],
      ["env -i -Srm -rf /", "deny/rm-critical"],
      ["env -u X -Srm -rf /", "deny/rm-critical"],
      ["env --unset X -Srm -rf /", "deny/rm-critical"],
      ["sudo env -Srm -rf /", "deny/rm-critical"],
      ["/usr/bin/env -Srm -rf /", "deny/rm-critical"],
      ['"env" -Srm -rf /', "deny/rm-critical"],
      ['e"n"v -Srm -rf /', "deny/rm-critical"],
      ["env -Srm \\\n-rf /", "deny/rm-critical"],
      ["bash -c 'env -Srm -rf /'", "deny/rm-critical"],
      [`env -S "env -S 'rm -rf /'"`, "deny/rm-critical"],
      ['env -S"dd of=/dev/sda"', "deny/dd-device"],
      ["env -Ssudo ls", "ask/privilege"],
      ['env -S "opencode serve"', "ask/nested-opencode"],
      ["env -Sopencode serve", "ask/nested-opencode"],
      ['env -S "guard off"', "ask/guard-cli"],
      ["env -Sguard off", "ask/guard-cli"],
      ["env --split-string='guard off'", "ask/guard-cli"],
      ["env -Scp /tmp/x /etc/hosts", "ask/protected-write"],
      ["env -Scp /tmp/x .opencode/x", "ask/self-protection"],
    ]
    for (const [command, verdict] of expected) assert.equal(found(command), verdict, command)
    for (const command of ["env FOO=1 true", "env -i true", "ls -S", "git log -S foo", "sort -S 1M /tmp/x"]) assert.equal(found(command), "none", command)
  })
  it("strings of env -S read three levels deep, past that an ask never left to the model", () => {
    assert.equal(found("env -Senv -Senv -S true"), "none")
    assert.equal(found("env -Senv -Senv -Srm -rf /"), "deny/rm-critical")
    const deep = "env -Senv -Senv -Senv -S true"
    assert.equal(found(deep), "ask/nested-opencode")
    assert.equal(decidable(deep, { ...ctx, active: { dangerousCommands: true, sensitiveFiles: true, localAsksByModel: true, selfProtectionByModel: true } }), false)
  })
  it("the value of tar -I is no group of letters", () => {
    assert.equal(found("tar -cIxz -f a.tar -C /etc/x ."), "none")
    assert.equal(found("tar -xIxz -f a.tar -C /etc/x"), "ask/protected-write")
    assert.equal(found("tar -xIzstd -f a.tar -C .opencode"), "ask/self-protection")
  })
})

describe("words of launchers and structure", () => {
  it("a value skipped to find the program stays a word to classify", () => {
    for (const command of [
      "nice time -o .opencode/x echo hi",
      "env time -o opencode.json echo hi",
      "nohup time -ao .opencode/x echo hi",
      "timeout 5 time -o .opencode/x echo hi",
      "nice time -o .opencode/x jq . /tmp/a",
      "nice time -o opencode.json test -f x",
      "time -o .opencode/x find /tmp -type f",
      "nice time --output=.opencode/x echo hi",
    ])
      assert.equal(found(command), "ask/self-protection", command)
  })
  it("double brackets and an attached parenthesis are structure", () => {
    for (const command of [
      "[[ -f opencode.json ]]",
      "if [[ -f opencode.json ]]; then echo yes; fi",
      "while [[ ! -f opencode.json ]]; do sleep 1; done",
      "(find .opencode -type f)",
      "(jq . opencode.json)",
    ])
      assert.equal(found(command), "none", command)
    for (const command of ["(somecmd opencode.json)", "(jq . opencode.json) >/tmp/x"]) assert.equal(found(command), "ask/self-protection", command)
  })
})

describe("env -S not read to its end", () => {
  const padded = `${"env $(".repeat(31)}x${")".repeat(31)}`
  const BY_MODEL = { ...ctx, active: { dangerousCommands: true, sensitiveFiles: true, localAsksByModel: true, selfProtectionByModel: true } }
  it("a redirection before the option takes nothing from the reading", () => {
    for (const [command, expected] of [
      ["env 2>/dev/null -Srm -rf /", "deny/rm-critical"],
      ["env >/dev/null -Srm -rf /", "deny/rm-critical"],
      ["env </dev/null -Srm -rf /", "deny/rm-critical"],
      ["env -i 2>&1 -Srm -rf /", "deny/rm-critical"],
      ["env 2>/dev/null -Ssudo ls", "ask/privilege"],
      ["env 2>/dev/null -S'guard off'", "ask/guard-cli"],
      ["env 2>/dev/null -S'opencode serve'", "ask/nested-opencode"],
      ["env >/tmp/o -S 'sudo ls'", "ask/privilege"],
    ] as const)
      assert.equal(found(command), expected, command)
  })
  it("a line break in the string is a blank", () => {
    for (const command of ["env -S 'rm\n-rf\n/'", "env -S $'rm\\n-rf\\n/'", "env -S $'rm\\r-rf\\r/'"]) assert.equal(found(command), "deny/rm-critical", command)
  })
  it("a quoted string at the end of a -c string, or a spent budget: an ask the model cannot lift", () => {
    for (const command of [
      "bash -c 'env -S \"guard off\"'",
      "sh -c 'env -S\"guard off\"'",
      "bash -c \"env -S 'guard off'\"",
      "bash -c 'env -S \"opencode serve\"'",
      "bash -c \"env -S 'opencode serve'\"",
      'bash -c "env -S\\"guard off\\""',
      "bash -c 'env \"-Sguard off\"'",
      `${padded}; env -Srm -rf /`,
      `${padded}; env -Ssudo ls`,
      `${padded}; env -S'guard off'`,
    ]) {
      assert.equal(found(command), "ask/nested-opencode", command)
      assert.equal(decidable(command, BY_MODEL), false, command)
    }
  })
  it("the deny stays when the string is read, behind a word that is not", () => {
    assert.equal(found("bash -c 'env -Srm -rf /'"), "deny/rm-critical")
    assert.equal(found("bash -c 'env ls'; env -Srm -rf /"), "deny/rm-critical")
  })
  it("no ask for an env without a string", () => {
    for (const command of ["env > /tmp/x", "env 2>/dev/null | grep -c x", "bash -c 'env'; git log -S foo", "bash -c 'env ls'", "env ls -S"]) assert.equal(found(command), "none", command)
  })
})

describe("known limits, fixed as such", () => {
  it("left to the decision model: an output option of its own, a name built by the shell", () => {
    for (const command of [
      // `-o` with its value attached is not one of the attached options read as a word.
      "7z x /tmp/e.7z -o.opencode",
      // Brace expansion: the word is not literal.
      "dd if=/tmp/x of=.open{code,}/plugins/x.ts",
      // A name joined to a command substitution.
      "busybox cp /tmp/x $(printf .open)code/plugins/x.ts",
      // A substitution nested in a naming command: only the innermost one is a segment.
      'echo "$(somecmd $(other) opencode.json)"',
    ])
      assert.equal(found(command), "none", command)
  })
  it("a word in a comment of an executed script asks", () => {
    assert.equal(found("npm test\n# see .opencode/x", { ...ctx, executedScript: true }), "ask/self-protection")
  })
})
