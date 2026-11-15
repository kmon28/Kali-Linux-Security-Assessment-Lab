#!/usr/bin/env python3
"""IR-015: read-only detection of suspicious systemd user-service configuration.

New portfolio implementation based on the documented lab logic; not a recovered
copy of the original VM script. Uses only Python standard library.
"""
import argparse
import json
import os
from pathlib import Path

def scan(root: Path):
    """Inspect .service units and enablement symlinks under a supplied user config root."""
    service_dir = root / "systemd" / "user"
    if not service_dir.is_dir():
        return []
    enabled_targets = set()
    for link in service_dir.rglob("*.wants/*.service"):
        if link.is_symlink():
            try:
                enabled_targets.add(link.resolve(strict=False).name)
            except OSError:
                pass
            enabled_targets.add(link.name)
    results = []
    for unit in sorted(service_dir.rglob("*.service")):
        if not unit.is_file() or unit.is_symlink():
            continue
        # Only inspect actual unit files, not .wants links.
        if ".wants" in unit.parts:
            continue
        try:
            lines = unit.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        commands = []
        for line in lines:
            s = line.strip()
            if s.startswith("#") or "=" not in s:
                continue
            key, val = s.split("=", 1)
            if key.strip() == "ExecStart":
                commands.append(val.strip())
        enabled = unit.name in enabled_targets
        # The heuristic matches absolute /home or /tmp path references.
        suspicious_path = any("/home/" in c or "/tmp/" in c for c in commands)
        findings = []
        if enabled:
            findings.append("Enabled startup symlink found (+2)")
        if suspicious_path:
            findings.append("ExecStart references /home/ or /tmp/ (+2)")
        results.append({
            "service": unit.name,
            "unit_path": str(unit),
            "commands": commands,
            "startup_links": enabled,
            "risk_score": (2 if enabled else 0) + (2 if suspicious_path else 0),
            "findings": findings,
        })
    return results

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config-root", type=Path,
                   default=Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))),
                   help="Root containing systemd/user (default: XDG_CONFIG_HOME or ~/.config)")
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = p.parse_args()
    result = scan(args.config_root.expanduser())
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if not result:
            print("No user-service unit files found.")
        for item in result:
            print(f"{item['service']}: {item['risk_score']}/4 | {', '.join(item['findings']) or 'No heuristic indicators'}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
