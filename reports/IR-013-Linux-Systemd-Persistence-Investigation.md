<div align="center">

# 🛡️ IR-013 | Linux Persistence Investigation

### 🔎 Detect · 🧪 Investigate · 🛑 Contain · 📋 Document

![Linux](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![Technique](https://img.shields.io/badge/MITRE-T1543.002-6F42C1?style=for-the-badge)
![Detection](https://img.shields.io/badge/Python-Baseline%20Detection-0969DA?style=for-the-badge&logo=python&logoColor=white)
![Outcome](https://img.shields.io/badge/Containment-Verified-238636?style=for-the-badge)

**A documented, benign adversary-technique simulation with original terminal evidence.**

[Investigation](#1-establish-a-baseline-and-identify-the-new-service) · [Detection](#5-detection-engineering) · [Response](#6-containment-and-verification) · [Interview prep](#interview-preparation--explain-your-decisions)

</div>

---

**Environment:** Isolated, authorized Kali Linux VirtualBox lab  
**Technique:** MITRE ATT&CK T1543.002 — Create or Modify System Process: Systemd Service  
**Classification:** Benign adversary-technique simulation; no real compromise asserted  
**Status:** Detection, investigation and containment completed

## Executive summary

This exercise simulated persistence using a harmless Bash script and a systemd unit named `ir013-agent.service`. The investigation compared service inventories before and after installation, inspected service configuration and execution evidence, recorded a script SHA-256 hash, and tested a Python detector that flags newly introduced systemd service units. The service was subsequently disabled and removed, followed by verification checks.

The screenshots below are **original uploaded lab evidence**, embedded inline so readers can inspect the observed results while reading the report.

## 1. Establish a baseline and identify the new service

Saved systemd unit inventories before and after the simulation were compared. The inventory increased from 287 to 288 entries, with `ir013-agent.service` identified as the added service. A new service is a lead for investigation, not proof of malicious intent.

![IR-013 screenshot 01 — systemd service baseline comparison](../screenshots/IR013_01_Service_Baseline_Comparison.png)

## 2. Investigate the persistence mechanism

The test service was installed under `/etc/systemd/system/` and enabled to model boot-persistent execution. Its `ExecStart` referenced a harmless local Bash script, `~/IR013/simulation/agent.sh`, which wrote a timestamp to `/tmp/ir013-agent.log`. This demonstrates the mechanism without deploying malware.

![IR-013 screenshot 02 — systemd service persistence configuration](../screenshots/IR013_02_Systemd_Service_Persistence.png)

## 3. Record file integrity evidence

The investigation captured a SHA-256 hash for the simulated agent and reviewed file metadata. A hash is useful for tracking a specific file's content and comparing copies; it does not, on its own, determine whether a file is malicious.

![IR-013 screenshot 03 — SHA-256 evidence](../screenshots/IR013_03_Agent_SHA256_Evidence.png)

## 4. Reconstruct the execution timeline

Systemd journal evidence and the script's timestamped output supported a timeline of simulated execution. Journal records provide context for service starts and stops, but interpretation still requires configuration and process evidence.

![IR-013 screenshot 04 — agent execution timeline](../screenshots/IR013_04_Agent_Execution_Timeline.png)

## 5. Detection engineering

A Python comparison of the saved before-and-after service inventories produced:

```text
[ALERT] New service detected: ir013-agent.service
```

The detector performs **snapshot comparison**, not continuous monitoring, and would require enrichment and allowlisting in a production environment. The original detection-alert screenshot is embedded below, showing the detector's output during the controlled test.

![IR-013 screenshot 05 — Python service detection alert](../screenshots/IR013_05_Python_Service_Detection_Alert.png)

## 6. Containment and verification

The simulated service was disabled and stopped with `systemctl disable --now`, its unit file was removed, and systemd configuration was reloaded. Follow-up checks showed `systemctl is-enabled ir013-agent.service` returning `not-found`, no matching persistence unit paths, and no unexpected listeners attributable to this simulation. The benign script was intentionally retained as lab material.

![IR-013 screenshot 06 — containment verification](../screenshots/IR013_06_Containment_Verification.png)

## Findings and limitations

- **Observed:** A new systemd service appeared in the inventory, executed the benign simulation, and triggered the snapshot-based Python alert.
- **Observed:** The simulated persistence unit was disabled and removed; follow-up checks did not find the installed unit.
- **Not established:** A real attacker, malicious binary, production compromise, or continuous detection capability.
- **Improvement opportunities:** Automate periodic inventory capture, record unit metadata, correlate journal events, baseline approved services, and test alerting on suspicious service changes.

## Evidence and reproducibility

The screenshots are stored in the repository's [shared screenshot archive](../screenshots/). The locally prepared Python detector, before/after inventories, and longer incident report should be uploaded separately for complete reproducibility. This report summarizes the verified exercise and does not substitute reconstructed source code for the original files.

---

## 🧠 Why each investigative decision mattered

| Action | Technical reason | How to explain it simply |
|---|---|---|
| Capture a **before** inventory | Establish a reference state for change detection | “I needed to know what normal looked like before looking for anomalies.” |
| Capture an **after** inventory | Identify service registration changes | “I compared snapshots instead of guessing which service was new.” |
| Inspect the systemd unit | Determine the configured execution path and startup mechanism | “A suspicious service name alone is not enough; I checked what it runs.” |
| Examine journal and timestamps | Correlate configuration with observed execution | “I wanted evidence that the service actually ran, not just that it existed.” |
| Record SHA-256 | Fingerprint the script for later integrity comparison | “The hash identifies file contents; it does not prove malware.” |
| Build a Python set-difference detector | Reproducibly flag new service names | “The script finds entries present after the change but absent before.” |
| Preserve the unit file before removal | Retain the configuration for later review | “I kept evidence before changing the system.” |
| Disable, remove, and verify | Stop the test service, remove startup registration, confirm absence | “Containment isn't complete until the control is checked afterward.” |

## ⚙️ Technical command reference

These commands illustrate the investigation and response workflow; they are **not a transcript of every exact command entered**. Run them only in an authorized lab.

```bash
# Inspect the installed service and its execution configuration
systemctl cat ir013-agent.service
systemctl status ir013-agent.service --no-pager

# Review service journal evidence
journalctl -u ir013-agent.service --no-pager

# Examine service metadata and script integrity
sudo stat /etc/systemd/system/ir013-agent.service
sha256sum ~/IR013/simulation/agent.sh

# Reproduce the locally developed snapshot detector
python3 ~/IR013/detect_services.py

# Controlled containment after preserving evidence
sudo systemctl disable --now ir013-agent.service
sudo rm /etc/systemd/system/ir013-agent.service
sudo systemctl daemon-reload
systemctl is-enabled ir013-agent.service
```

**Interpretation notes:** `systemctl disable --now` removes enablement and stops the running unit; `daemon-reload` refreshes systemd's view after changing unit files. A `not-found` result supports removal of this specific service registration. It does **not** establish that every possible persistence mechanism or malicious process is absent.

## 🎯 Interview preparation — explain your decisions

<details>
<summary><strong>Q1. What was the security problem you investigated?</strong></summary>

A harmless Bash agent was registered as a systemd service to simulate a common Linux persistence technique (MITRE ATT&CK T1543.002). I investigated how a service could be configured to start automatically, how to detect its introduction, and how to verify removal. It was a simulation, not a real breach.

</details>

<details>
<summary><strong>Q2. Why did you collect two service inventories?</strong></summary>

A single inventory shows what exists; two snapshots show **what changed**. I compared the baseline of 287 entries against a later inventory of 288 entries and identified `ir013-agent.service`. That is change detection, not a malware verdict.

</details>

<details>
<summary><strong>Q3. How does your Python detector work?</strong></summary>

It reads saved service inventories, splits them into entries, converts them into sets, and calculates `new_services - old_services`. This flags newly registered entries. The original lab detector used files in `~/IR013/evidence/`; a portable GitHub copy was tested locally. The raw source files still need separate publication for external reproducibility.

</details>

<details>
<summary><strong>Q4. How did you distinguish configuration from execution?</strong></summary>

I inspected the systemd unit and its `ExecStart` path, then correlated service journal events with the agent's timestamped log. A unit file demonstrates configuration; execution records provide separate evidence that the simulation ran.

</details>

<details>
<summary><strong>Q5. Why hash the agent?</strong></summary>

SHA-256 provides a reproducible content fingerprint to compare files or detect changes. It does not identify a file as malicious without further context.

</details>

<details>
<summary><strong>Q6. How did you verify containment?</strong></summary>

After preserving the configuration, I disabled and stopped the service, removed its unit file, reloaded systemd, and checked its registration. The observed `not-found` response verified removal of this specific systemd persistence mechanism. I did not claim full-host forensic clearance.

</details>

<details>
<summary><strong>Q7. What would you improve in a production SOC?</strong></summary>

I would add scheduled or event-driven collection, service metadata enrichment, known-good allowlists, process and network correlation, central log retention, alert severity rules, and testing for false positives and alternate persistence paths. I would also preserve collection times and hashes in a formal evidence manifest.

</details>

## 📌 Analyst takeaways

**Detection is not attribution.** A newly registered service deserves investigation but can be legitimate. **Evidence should precede remediation.** Preserving the unit and timeline makes the response defensible. **Verification is part of response.** Removing a file without checking systemd state leaves the outcome uncertain.

> **Portfolio scope:** This report documents a controlled simulation with six inline original screenshots. The locally created Python source, inventories, and full raw evidence are not represented as published until they are actually uploaded.

