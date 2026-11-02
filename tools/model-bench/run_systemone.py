"""Runs the bench of cases against a remote server of the System One API (POST <base>/systemone).

Same state and questions as run_local.py (the plugin's exact request). Writes a JSONL:
{"id", "ms", "answers", "usage"} per case, in case order.

Usage: python3 run_systemone.py --base <url/v1> --model <name> --out <out.jsonl>
           [--key-env <VAR>] [--cases <dir>] [--workers <n>]
`--key-env` names the environment variable that holds the key (sent as a Bearer token);
nothing is stored. `--workers` sends that many requests at once (default 4).
"""

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_local import CASE_DIR, QUESTIONS, STATE_NOTE, load_cases, post  # same cases, same questions


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="e.g. https://decision.example.com/v1")
    ap.add_argument("--model", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--key-env", help="environment variable containing the key (optional)")
    ap.add_argument("--cases", default=CASE_DIR, help="directory of cases*.json files (default: cases/, the 34 cases)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=120, help="max timeout per request in seconds")
    args = ap.parse_args()

    headers = {}
    if args.key_env:
        key = os.environ.get(args.key_env, "").strip()
        if not key:
            sys.exit(f"{args.key_env} is not set in the environment.")
        headers["Authorization"] = f"Bearer {key}"
    url = f"{args.base.rstrip('/')}/systemone"

    def run(case):
        state = {"note": STATE_NOTE, "tool": case["tool"], "input": case["input"],
                 "working_directory": case["working_directory"], "agent": case["agent"]}
        payload = {"model": args.model, "state": state, "questions": QUESTIONS}
        rec = {}
        for attempt in range(4):
            t0 = time.perf_counter()
            try:
                resp = post(url, payload, headers, timeout=args.timeout)
                return {"id": case["id"], "ms": round((time.perf_counter() - t0) * 1000),
                        "answers": resp.get("answers"), "usage": resp.get("usage")}
            except Exception as exc:  # noqa: BLE001
                rec = {"id": case["id"], "ms": round((time.perf_counter() - t0) * 1000), "error": str(exc)}
                time.sleep(2 * (attempt + 1))
        return rec

    cases = load_cases(args.cases)
    print(f"{len(cases)} cases against {url} (model {args.model}, {args.workers} at once)", flush=True)
    errors = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool, open(args.out, "w", encoding="utf-8") as out:
        for rec in pool.map(run, cases):
            errors += "error" in rec
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"done: {len(cases)} cases, {errors} errors", flush=True)


if __name__ == "__main__":
    main()
