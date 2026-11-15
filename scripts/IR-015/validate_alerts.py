#!/usr/bin/env python3
"""Validate IR-015 alert JSON structure and optional expected scores.

New portfolio implementation; this checks structure, not forensic authenticity.
"""
import argparse
import json
from pathlib import Path

def validate(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("alerts"), list):
        raise ValueError("Expected an object with an alerts list")
    for a in data["alerts"]:
        if not isinstance(a, dict):
            raise ValueError("Each alert must be an object")
        for field in ("service", "commands", "startup_links", "risk_score", "findings"):
            if field not in a:
                raise ValueError(f"Missing field: {field}")
        if not isinstance(a["service"], str) or not isinstance(a["commands"], list):
            raise ValueError("Invalid service or commands")
        if not isinstance(a["startup_links"], bool) or not isinstance(a["risk_score"], int):
            raise ValueError("Invalid startup_links or risk_score")
        if a["risk_score"] not in (0, 2, 4):
            raise ValueError("Unexpected score")
        if not isinstance(a["findings"], list):
            raise ValueError("Invalid findings")
    return data["alerts"]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("json_file", type=Path)
    p.add_argument("--expect", action="append", default=[], metavar="NAME=SCORE",
                   help="Optional expected service score; repeat for multiple services")
    args = p.parse_args()
    try:
        alerts = validate(args.json_file)
        scores = {a["service"]: a["risk_score"] for a in alerts}
        for expected in args.expect:
            name, score = expected.rsplit("=", 1)
            if scores.get(name) != int(score):
                raise ValueError(f"{name}: expected {score}, found {scores.get(name)}")
        print(f"PASS: validated {len(alerts)} service records")
        for expected in args.expect:
            print(f"PASS: {expected}")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL: {exc}")
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
