// `guard completion bash|zsh`: the script is run by bash itself on simulated command lines (COMP_WORDS); zsh's script
// is checked for syntax when zsh is installed. Nothing else is run.
import "./tmp.ts"
import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { describe, it } from "node:test"
import { completionScript } from "../src/cli/completion.ts"
import { main } from "../src/cli/main.ts"

const available = (shell: string) => {
  try {
    execFileSync(shell, ["-c", "true"])
    return true
  } catch {
    return false
  }
}

/** Candidates bash offers for `guard <words…>`, the last word being completed. */
function complete(...line: string[]): string[] {
  const words = ["guard", ...line]
  const script = `${completionScript("bash")}
COMP_WORDS=(${words.map((word) => `'${word}'`).join(" ")}); COMP_CWORD=${words.length - 1}
_guard; printf '%s\\n' "\${COMPREPLY[@]}"`
  return execFileSync("bash", ["--norc", "--noprofile", "-c", script], { encoding: "utf8", env: { PATH: process.env.PATH ?? "/usr/bin:/bin" } }).split("\n").filter(Boolean)
}

describe("guard completion", { skip: !available("bash") && "bash not installed" }, () => {
  it("CMP-1: commands, rule settings and identifiers, formats, settings and their values, options", () => {
    assert.deepEqual(complete("st"), ["status"])
    assert.ok(complete("").includes("completion"))
    assert.deepEqual(complete("rules", "re"), ["reset", "remove"])
    assert.ok(complete("rules", "off", "").includes("rm"))
    assert.ok(complete("rules", "--explain", "").includes("secret-file-read"))
    assert.ok(complete("redaction", "off", "").includes("twilio_key"))
    assert.deepEqual(complete("set", "pro"), ["profile"])
    assert.deepEqual(complete("set", "profile", ""), ["standard", "credentials-only"])
    assert.deepEqual(complete("set", "scripts", "o"), ["on", "off"])
    assert.deepEqual(complete("set", "scripts", "true", "--a"), ["--agent"])
    assert.deepEqual(complete("status", ""), ["--offline"])
    assert.deepEqual(complete("up"), ["update"])
    assert.deepEqual(complete("update", ""), ["--check"])
    assert.deepEqual(complete("sett"), ["settings"])
    assert.ok(!complete("").includes("options"))
    assert.deepEqual(complete("test", "--m"), ["--model"])
    assert.deepEqual(complete("test", "--", "rm", "--"), [])
    assert.deepEqual(complete("rules", "off", "rm", "--agent", ""), [])
    assert.deepEqual(complete("completion", ""), ["bash", "zsh"])
  })
  it("CMP-2: the command prints the script; zsh's loads bashcompinit and is valid zsh; a missing or unknown shell is a usage error", () => {
    const out: string[] = []
    const run = (args: string[]) => main(args, { env: {}, cwd: "/", systemDir: "/nonexistent", out: (line) => out.push(line), err: () => {} }) as number
    assert.equal(run(["completion", "zsh"]), 0)
    assert.match(out.join("\n"), /bashcompinit/)
    assert.match(out.join("\n"), /complete -F _guard guard/)
    if (available("zsh")) execFileSync("zsh", ["-n"], { input: completionScript("zsh") })
    assert.equal(run(["completion"]), 2)
    assert.equal(run(["completion", "fish"]), 2)
  })
})
