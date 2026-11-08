from pathlib import Path

folder = Path(__file__).resolve().parent

before = (folder / "service-before.txt").read_text().splitlines()
after = (folder / "service-after.txt").read_text().splitlines()

old_services = {line.split()[0] for line in before if line.endswith(".service") or ".service " in line}

new_services = {line.split()[0] for line in after if line.endswith(".service") or ".service " in line}

added = sorted(new_services - old_services)

print("=== IR-013 SERVICE DETECTION ===")

for service in added:
    print(f"[ALERT] New service detected: {service}")

if not added:
    print("[OK] No new services detected")
