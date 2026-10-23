"""Runs the bench of cases against a remote model, via the plugin's `chat` protocol.

Protocol (OpenAI-compatible gateway convention): POST <base>/chat/completions with
{"model", "messages": [{"role": "user", "content": JSON.stringify({state, questions})}]} ;
the response (JSON of {model, answers}) is read from choices[0].message.content.

Usage: python3 run_chat.py --base <url/v1> --model <name> --out <out.jsonl> [--key-env <VAR>]
Optional key: `--key-env` names the environment variable that contains it
(example: NOX_API_KEY); without it, no Authorization header is sent.
Works for any model served that way (example: nox-4b).
"""

import argparse
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_local import QUESTIONS, STATE_NOTE, load_cases  # same cases, same questions


def post(url, payload, headers, timeout=30):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", **headers}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="e.g. https://ai-gateway.example.com/v1")
    ap.add_argument("--model", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--key-env", help="environment variable containing the key (optional)")
    args = ap.parse_args()

    headers = {}
    if args.key_env:
        key = os.environ.get(args.key_env, "").strip()
        if not key:
            sys.exit(f"{args.key_env} is not set in the environment.")
        headers["Authorization"] = f"Bearer {key}"

    cases = load_cases()
    url = f"{args.base.rstrip('/')}/chat/completions"
    print(f"{len(cases)} cases against {url} (model {args.model})", flush=True)

    with open(args.out, "w", encoding="utf-8") as out:
        for case in cases:
            state = {
                "note": STATE_NOTE,
                "tool": case["tool"],
                "input": case["input"],
                "working_directory": case["working_directory"],
                "agent": case["agent"],
            }
            body = {
                "model": args.model,
                "messages": [{"role": "user", "content": json.dumps({"state": state, "questions": QUESTIONS})}],
            }
            t0 = time.perf_counter()
            try:
                resp = post(url, body, headers)
                content = resp["choices"][0]["message"]["content"]
                answers = json.loads(content)["answers"]
                rec = {"id": case["id"], "ms": round((time.perf_counter() - t0) * 1000), "answers": answers}
            except Exception as exc:  # noqa: BLE001
                rec = {"id": case["id"], "ms": round((time.perf_counter() - t0) * 1000), "error": str(exc)}
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            out.flush()
            tag = "ERR " + rec["error"] if "error" in rec else "ok"
            print(f"{rec['id']:<4} {rec['ms']:>6} ms  {tag}", flush=True)


if __name__ == "__main__":
    main()
