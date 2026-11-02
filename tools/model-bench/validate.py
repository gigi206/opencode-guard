#!/usr/bin/env python3
"""Validates bench500 case files: schema, sizes, unique ids, duplicates. Usage: validate.py file.json [...]"""
import json
import re
import sys
from collections import Counter

TOOLS = {"shell": {"command"}, "write": {"path", "content"}, "edit": {"path", "oldString", "newString"}}
CATS = {"benign", "medium", "dangerous", "tricky"}
VERDICTS = {"allow", "ask", "deny"}
FLAGS = {"destructive", "exfiltration", "credentials", "privilege_persistence"}
FIELDS = {"id", "cat", "family", "size", "tool", "input", "working_directory", "agent", "gt_verdict", "gt_flags", "note"}


def size_of(inp):
    n = len(json.dumps(inp, ensure_ascii=False))
    return "small" if n < 150 else "medium" if n <= 1200 else "large" if n <= 3800 else "too-large"


def norm(inp):
    return re.sub(r"\s+", " ", json.dumps(inp, ensure_ascii=False, sort_keys=True)).strip().lower()


errors, cases = [], []
for path in sys.argv[1:]:
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{path}: invalid JSON ({exc})")
        continue
    if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
        errors.append(f'{path}: expected {{"cases": [...]}}')
        continue
    for c in data["cases"]:
        cid = c.get("id", "?")
        if set(c) != FIELDS:
            errors.append(f"{path} {cid}: fields {sorted(set(c) ^ FIELDS)} missing or extra")
            continue
        if c["tool"] not in TOOLS or set(c["input"]) != TOOLS[c["tool"]]:
            errors.append(f"{path} {cid}: tool/input shape {c['tool']} {sorted(c['input'])}")
        elif not all(isinstance(v, str) and v for v in c["input"].values()) and c["tool"] != "edit":
            errors.append(f"{path} {cid}: empty input value")
        if c["cat"] not in CATS:
            errors.append(f"{path} {cid}: cat {c['cat']}")
        if c["gt_verdict"] not in VERDICTS:
            errors.append(f"{path} {cid}: verdict {c['gt_verdict']}")
        if not set(c["gt_flags"]) <= FLAGS:
            errors.append(f"{path} {cid}: flags {c['gt_flags']}")
        if c["agent"] != "build" or not c["working_directory"].startswith("/"):
            errors.append(f"{path} {cid}: agent/working_directory")
        actual = size_of(c["input"])
        if actual != c["size"]:
            errors.append(f"{path} {cid}: size says {c['size']}, input is {actual} ({len(json.dumps(c['input'], ensure_ascii=False))} chars)")
        if c["cat"] == "benign" and c["gt_verdict"] != "allow" or c["cat"] == "medium" and c["gt_verdict"] != "ask" or c["cat"] == "dangerous" and c["gt_verdict"] != "deny":
            errors.append(f"{path} {cid}: cat {c['cat']} with verdict {c['gt_verdict']}")
        cases.append((path, c))

ids = Counter(c["id"] for _, c in cases)
errors += [f"duplicate id {i} (x{n})" for i, n in ids.items() if n > 1]
seen = {}
for path, c in cases:
    key = norm(c["input"])
    if key in seen:
        errors.append(f"duplicate input: {c['id']} = {seen[key]}")
    seen[key] = c["id"]

print(f"{len(cases)} cases")
for field in ("gt_verdict", "cat", "size", "tool", "family"):
    print(f"  {field}: {dict(Counter(c[field] for _, c in cases).most_common())}")
for e in errors:
    print("ERROR", e)
sys.exit(1 if errors else 0)
