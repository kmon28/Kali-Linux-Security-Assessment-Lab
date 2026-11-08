
from pathlib import Path
import re
from collections import Counter

LOG_FILE = Path(__file__).with_name("ssh-evidence.log")

def analyze_ssh_logs():
    if not LOG_FILE.exists():
        print("ERROR: ssh-evidence.log not found")
        return

    logs = LOG_FILE.read_text(errors="replace").splitlines()
    findings = []

    for line in logs:
        if re.search(
            r"Invalid user|Failed password|authentication failure",
            line,
            re.IGNORECASE
        ):
            findings.append(line)

    print("=== IR-012 SSH AUTHENTICATION DETECTOR ===")
    print(f"Log entries analyzed: {len(logs)}")
    print(f"Suspicious authentication events: {len(findings)}")

    for event in findings:
        print(f"[ALERT] {event}")

    if findings:
        print("\nRESULT: Suspicious SSH authentication activity detected")
    else:
        print("\nRESULT: No matching authentication failures found")

if __name__ == "__main__":
    analyze_ssh_logs()


