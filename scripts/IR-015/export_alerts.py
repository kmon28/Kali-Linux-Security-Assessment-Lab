#!/usr/bin/env python3
"""Export IR-015 read-only detector results as a timestamped JSON snapshot.

New portfolio implementation, not a recovered copy of the original lab file.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from user_service_detector import scan

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--config-root", type=Path, default=Path.home() / ".config")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    alerts = scan(args.config_root.expanduser())
    record = {
        "schema_version": 1,
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": "IR-015 portfolio detector",
        "alerts": alerts,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"Exported {len(alerts)} service records to {args.output}")

if __name__ == "__main__":
    main()
