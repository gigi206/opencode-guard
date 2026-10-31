// Time budgets of the cost tests, robust to a loaded machine. A budget catches a quadratic or exponential case (seconds
// instead of milliseconds), not a slow machine: a run over budget is compared again with the budget scaled by how slow
// the machine is right now (a fixed reference workload, its median of three runs against its time on an unloaded
// machine). A cost that grows with the input stays over even the scaled budget.

/** Median time of the reference workload on an unloaded machine (measured on the development machine, 2026-10-31). */
export const REFERENCE_MS = 20

let sink = 0
function reference(): number {
  const start = performance.now()
  let total = 0
  for (let i = 0; i < 20_000; i++) total += `${"ab".repeat(40)}${i}`.replace(/(?:ab)+/g, "x").split("").length
  sink ^= total
  return performance.now() - start
}

// First run outside any measure (compilation of the workload).
reference()

/** How much slower than unloaded the machine is now (at least 1). */
export function slowness(): number {
  const runs = [reference(), reference(), reference()].sort((a, b) => a - b)
  return Math.max(1, runs[1]! / REFERENCE_MS)
}

/** Elapsed time within the budget, scaled by the machine's slowness when over it. */
export function fastEnough(elapsed: number, limitMs: number): boolean {
  if (elapsed < limitMs) return true
  return elapsed < limitMs * slowness()
}

/** Time since `start` (same clock as `now`) within the budget. */
export function withinBudget(start: number, limitMs: number, now: () => number = () => performance.now()): boolean {
  return fastEnough(now() - start, limitMs)
}
