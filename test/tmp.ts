// Private temporary directory for the suite: created on first import, it becomes the process TMPDIR (`os.tmpdir()` re-reads
// the variable on every call, under Node as under Bun; child processes inherit it), and it is removed on
// exit. Only this directory, created here, is removed. Node launches one process per test file, Bun a single one for all:
// the exit handler works for both. Import it first.
import { chmodSync, lstatSync, mkdtempSync, readdirSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"

// Absolute path: a test that changes directory does not move the deletion target.
const root = resolve(mkdtempSync(join(tmpdir(), "guard-tests-")))
process.env.TMPDIR = root

/** Restores write permission on directories (tests remove it), without following symbolic links. */
function writable(dir: string): void {
  try {
    chmodSync(dir, 0o700)
  } catch {}
  let names: string[] = []
  try {
    names = readdirSync(dir)
  } catch {
    return
  }
  for (const name of names) {
    const path = join(dir, name)
    try {
      if (lstatSync(path).isDirectory()) writable(path)
    } catch {}
  }
}

process.on("exit", () => {
  try {
    writable(root)
    rmSync(root, { recursive: true, force: true })
  } catch {}
})
