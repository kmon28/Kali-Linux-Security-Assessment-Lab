#!/usr/bin/env python3
"""IR-013: systemd service inventory comparison.

Reconstructed from the documented lab detection logic; this is NOT a
word-for-word copy of the original Kali detector. Place service-before.txt
and service-after.txt in the same directory as this script.
"""
from pathlib import Path

evidence = Path(__file__).resolve().parent
before = evidence / "service-before.txt"
after = evidence / "service-after.txt"

def load_services(path: Path) -> set[str]:
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()}

def main() -> None:
    old_services = load_services(before)
    new_services = load_services(after)
    print("=== IR-013 SERVICE DETECTION ===")
    added = sorted(new_services - old_services)
    if not added:
        print("[INFO] No new services detected")
    for service in added:
        print(f"[ALERT] New service detected: {service}")

if __name__ == "__main__":
    main()
