// Every command below is text given to the rules: none is ever run by a shell.
import "./tmp.ts"
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { shellFinding } from "../src/rules/shell.ts"
import { createRedactor } from "../src/secrets/redact.ts"

const context = { redactor: createRedactor(), home: "/home/test", cwd: "/project" }
const verdict = (command: string) => {
  const found = shellFinding(command, context)
  return found ? `${found.verdict}/${found.rule}` : "none"
}
const cases = (prefix: string, expected: string, commands: readonly string[]) => {
  for (const command of commands) it(`${prefix}${JSON.stringify(command)} → ${expected}`, () => assert.equal(verdict(command), expected))
}

describe("self-protection net: a separator between quotes cuts no segment", () => {
  cases("", "none", [
    String.raw`grep -n 'a\|b' opencode.json || true`,
    `grep -E "tool|state_read" opencode.json; echo done`,
    `grep 'a;b' opencode.json || true`,
    `jq '.a|.b' opencode.json`,
    `jq '.a;.b' .opencode/x && echo y`,
    `jq '.a\n.b' opencode.json`,
  ])
})

describe("self-protection net: a nested substitution outside quotes", () => {
  cases("", "ask/self-protection", [`echo $(rm $(ls .opencode/x))`, `jq . $(touch $(pwd)/.opencode/y)`])
  cases("witness: ", "ask/self-protection", [
    `echo 'a|b' $(rm $(ls .opencode/x))`,
    `jq '.a|.b' $(touch $(pwd)/.opencode/y)`,
    `echo 'a;b' $(cp x $(pwd)/opencode.json)`,
    `echo 'a|b' $(cp x .opencode/y; echo '(')`,
  ])
  cases("witness: ", "none", [`echo $(ls) opencode.json`, `jq . $(ls x) opencode.json`, `echo '$(a $(b))' opencode.json`, `echo $((1+2)) opencode.json`, `echo $(ls) $(ls) opencode.json`])
})

describe("self-protection net: what still asks", () => {
  cases("witness: ", "ask/self-protection", [
    // Quoted text handed to a program the net does not know.
    `vim -c "w .opencode/x"`,
    `mytool --cmd "mv a .opencode/x"`,
    `gdb -ex "dump .opencode/x" a`,
    `sed -i "s|a|b|" opencode.json`,
    // A real separator next to a quoted one.
    `jq '.a|.b' a; somecmd .opencode/x`,
    // Output of a left-out command given to a program.
    `jq '.a|.b' opencode.json | csh`,
    // Where quotes are not read, or a separator is escaped or is no quote's.
    `jq "$(x)|.b" opencode.json`,
    String.raw`echo a \; somecmd .opencode/x`,
    `[[ -f opencode.json && -d .opencode ]]`,
    // A comment right behind a group: the quote is in it and the next line runs.
    `(jq . a)#'\nsomecmd .opencode/x\n'`,
  ])
})
