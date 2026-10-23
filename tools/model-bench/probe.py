"""Latency probe: replays a few bench cases against a local llama-server.

Used to measure the effect of GPU offload (-ngl) without running all 34 cases.
Usage: python3 probe.py --alias d3-nano --port 8098 --ids b02,m06,d02,t05 --repeats 2
"""

import argparse
import json
import os
import statistics
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_local import QUESTIONS, STATE_NOTE, load_cases


def post(url, payload, timeout=600):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alias", required=True)
    ap.add_argument("--port", type=int, default=8098)
    ap.add_argument("--ids", default="b02,m06,d02")
    ap.add_argument("--repeats", type=int, default=2)
    args = ap.parse_args()

    cases = {c["id"]: c for c in load_cases()}
    url = f"http://127.0.0.1:{args.port}/v1/systemone"
    times = {}
    for cid in [s.strip() for s in args.ids.split(",") if s.strip()]:
        case = cases[cid]
        state = {
            "note": STATE_NOTE,
            "tool": case["tool"],
            "input": case["input"],
            "working_directory": case["working_directory"],
            "agent": case["agent"],
        }
        payload = {"model": args.alias, "state": state, "questions": QUESTIONS}
        runs = []
        for _ in range(args.repeats):
            t0 = time.perf_counter()
            try:
                post(url, payload)
                ms = round((time.perf_counter() - t0) * 1000)
            except Exception as exc:  # noqa: BLE001
                ms = None
                print(f"{cid}: ERROR {exc}", flush=True)
            if ms is not None:
                print(f"{cid}: {ms} ms", flush=True)
            runs.append(ms)
        times[cid] = [r for r in runs if r is not None]
    print("\nSummary:")
    for cid, runs in times.items():
        if runs:
            print(f"  {cid}: median {statistics.median(runs):.0f} ms (n={len(runs)})")


if __name__ == "__main__":
    main()
