// `guard-cli` and commands that only read files: the word `guard` in a quoted string, or a path of the plugin's command
// line only named by a reader, no longer asks; every form that may run it still does (reported 2026-10-31).
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { onlyReads } from "../src/rules/shell.ts"
import { toolFinding } from "../src/rules/tools.ts"
import { createRedactor } from "../src/secrets/redact.ts"

const ctx = { redactor: createRedactor(), home: "/home/test", cwd: "/opt/guard", protectedDirs: ["/opt/guard"], pluginDirs: ["/opt/guard"] }
const rule = (command: string) => toolFinding("shell", { command }, ctx)?.rule

describe("guard-cli: commands that only read", () => {
  it("GCR-1: the reported forms no longer ask: a grep pattern with \\| and the word guard, readers naming src/cli/ or bin/guard", () => {
    for (const command of [
      "grep -rn 'guard allow\\|rules allow\\|rules on\\|guard off\\|guard on\\|guard reset' README.md docs src test",
      "grep -rn 'x\\|guard off' README.md",
      "git show 872b43c -- bin/guard src/cli/write.ts src/cli/main.ts | head -180",
      "sed -n '1,80p' src/cli/main.ts",
      "cat src/cli/main.ts",
      "git -C /opt/guard log --oneline -- src/cli/help.ts",
      "rg -n guard src/cli/main.ts | wc -l",
      'grep "guard off" README.md 2>&1',
      "sed -n '1,30p' bin/guard; file bin/guard; ls -l bin/guard",
      "file -b --mime-type src/cli/main.ts",
    ])
      assert.notEqual(rule(command), "guard-cli", command)
  })
  it("GCR-2: every form that may run the command line still asks", () => {
    for (const command of [
      "guard rules off eval",
      "sh -c 'x; guard rules off eval'",
      "echo 'x; guard rules off eval' | sh",
      "sh <<< 'x; guard rules off eval'",
      "ssh localhost 'x; guard rules off eval'",
      "sed -n '1e x;guard rules off eval' f",
      `echo "it's" ; guard rules off ; echo "c'd"`,
      "echo a\\\\|guard rules off",
      'echo "$(guard rules off)"',
      "node src/cli/main.ts rules off eval",
      "bun /opt/guard/src/cli/main.ts",
      "./bin/guard rules",
      "ls src | xargs node src/cli/main.ts",
      "ln -s /opt/guard/bin/guard /tmp/g && /tmp/g rules off eval",
      "cat src/cli/main.ts | sh",
      "git -c core.pager=x show HEAD -- src/cli/main.ts",
      "LESSOPEN='|guard rules off %s' less src/cli/main.ts",
      "grep a src/cli/main.ts # ; guard off",
      "cat src/cli/main.ts && guard rules off eval",
      "cat src/cli/main.ts; /opt/guard/bin/guard rules",
      "file -z bin/guard",
      "file -m ./magic bin/guard",
      "file -C -m ./magic; cat bin/guard",
    ])
      assert.equal(rule(command), "guard-cli", command)
  })
  it("GCR-3: onlyReads: closed list of readers, options that run something, unmodelled constructions", () => {
    for (const command of ["cat a b", "head -n 5 x | tail -2", "git show HEAD -- a", "git diff --stat", "sed -n -e '3,$p' f", "ls -la 2>&1", "grep -E 'a|b' f"]) assert.ok(onlyReads(command), command)
    for (const command of ["sed -i 's/a/b/' f", "sed -n '1w out' f", "git show --ext-diff HEAD", "git -p log", "git commit -m x", "rg --pre=x a", "cat $F", "cat `x`", "cat <(x)", "cat << EOF", "less f", "sort f", "cat 'unclosed", "", "echo hi"])
      assert.ok(!onlyReads(command), command)
  })
})
