# IR-014 — Python Network Connection Detection and Containment Verification

**Date:** 2026-11-12  
**Environment:** Authorized Kali Linux home lab (VirtualBox)  
**Classification:** Simulated detection-engineering exercise; no confirmed malicious compromise

## Objective
Build and validate a Python network-connection detector that identifies connections involving a lab-monitored TCP port, attributes activity to processes, assigns a triage label, and verifies alert behavior after the test connection ends.

## Tools
- Python 3 and psutil 7.1.0
- Netcat (`nc.traditional`) for controlled loopback traffic
- Kali Linux terminal and standard Linux process/network facilities

## Procedure and verified observations
1. Created `~/IR014/scripts/network_detector.py` using `psutil.net_connections(kind="inet")`. The detector prints scan time, connection count, local/remote endpoints, TCP state, and PID.
2. Started a Netcat listener on `127.0.0.1:9090` and connected a second local Netcat process. The initial scanner found **three network connection records**.
3. An initial local-port-only rule flagged the listener but missed the client. Revised the rule to match port 9090 on **either the local or remote endpoint**. This produced **two alerts**, representing the two local process endpoints of one TCP conversation—not two attacks.
4. Added process attribution using `psutil.Process(pid)`: process name `nc`, executable `/usr/bin/nc.traditional`, and parent PID. Added a lab-defined `MEDIUM` triage label with the reason `Connection uses monitored port 9090`. This label alone does not establish maliciousness.
5. Preserved active-detection output using `tee` to `~/IR014/evidence/final-detection-results.txt`.
6. Stopped the Netcat test processes. A subsequent scan showed **two records**, including one port-9090 `TIME_WAIT` record with `PID: None`, which still triggered the port-only rule. This was a recently closed TCP connection, not proof of an active process.
7. After the `TIME_WAIT` record expired, a new scan showed **one remaining record and zero port-9090 alerts**. The remaining record was DHCP traffic (`192.168.56.105:68` to `192.168.56.100:67`). Preserved this post-test result in `~/IR014/evidence/post-containment-results.txt`.

## Detection logic and limitations
- Matches port 9090 on either endpoint; this is a **lab-specific indicator**, not a universal malware signature.
- A connection record is not necessarily a distinct remote session or attack.
- `TIME_WAIT` can produce a stale alert after a process exits; an improvement would classify TCP state separately and prioritize `ESTABLISHED` and `LISTEN` activity.
- `PID: None` may reflect a connection state without an owning process or limited attribution; it is not evidence of stealth malware.
- The script provides a **point-in-time snapshot**, not continuous monitoring, packet capture, or historical logging.
- No comprehensive persistence search, malware analysis, data-exfiltration assessment, or full-host compromise clearance was established in IR-014.

## Outcome
The detector correctly identified both endpoints of the controlled Netcat connection, enriched alerts with process metadata, and stopped alerting after the simulated activity and TCP cleanup completed. The exercise demonstrates detection rule iteration, process attribution, false-positive awareness, evidence preservation, and post-activity validation.

## Evidence inventory
- Local screenshot confirmed saved: `IR014_74_Python_Network_Detection.png` (not yet confirmed uploaded to GitHub).
- Local text evidence: `final-detection-results.txt` and `post-containment-results.txt` (not yet confirmed uploaded to GitHub).
- Python script: `~/IR014/scripts/network_detector.py` (local Kali file; do not substitute reconstructed source for the original without verification).

## Analyst decision
Close the **controlled lab test** as successful. Do not interpret a disappearing alert as proof of host safety in a real incident. A real SOC case would also investigate process ancestry, user activity, persistence, destination reputation, data transfer, and reappearance before incident closure.
