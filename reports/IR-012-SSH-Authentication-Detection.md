# IR-012 — SSH Authentication Failure Detection and Clean-Log Validation

**Date:** November 5, 2026  
**Environment:** Authorized Kali Linux lab, VirtualBox  
**Status:** Positive and negative test cases completed

## Objective
Build and validate a lightweight Python detector for SSH authentication-failure messages, using controlled log evidence. Distinguish matching log lines from unique login attempts and test for false alerts on a benign sample.

## Method
1. Collected a five-line SSH authentication evidence sample from a controlled local test (source `127.0.0.1`, invalid account `invaliduser`).
2. Wrote `ssh_detector.py` to read `ssh-evidence.log` beside the script, scan each line case-insensitively for `Invalid user`, `Failed password`, or `authentication failure`, and print matching lines.
3. Ran the detector on the original evidence.
4. Created a separate two-line benign sample containing an accepted SSH login and a session-open event. Temporarily substituted it for the input log and reran the detector.
5. Restored the original evidence file after testing.

## Observed results

| Test | Log lines | Matching lines | Result |
| --- | ---: | ---: | --- |
| Controlled failed-authentication sample | 5 | 4 | Suspicious SSH authentication activity detected |
| Benign login/session sample | 2 | 0 | No matching authentication failures found |

**Interpretation:** Four matches do **not** mean four distinct failed login attempts. A connection-closure line also contained the phrase `invalid user` and matched the broad regex. The benign test demonstrates zero matches for the two supplied normal lines, not a measured production false-positive rate.

## Reproduce
Place the detector and an SSH sample named `ssh-evidence.log` in the same directory, then run:

```bash
python3 ssh_detector.py
```

The script does not automatically ingest system journals or accept an arbitrary input path. To run against another sample, replace the local `ssh-evidence.log` file (after backing up the original).

## Evidence
- [64 — Failed SSH authentication evidence](../screenshots/64-IR012-SSH-Failed-Authentication-Evidence.png)
- [65 — SSH authentication timeline](../screenshots/65-IR012-SSH-Authentication-Timeline.png)
- [66 — Detector positive test](../screenshots/66-IR012-SSH-Authentication-Detection.png)
- [67 — Clean-log negative test](../screenshots/67-IR012-Clean-Log-Validation.png)
- [Python detector](../scripts/ssh_detector.py)

## Limitations and next improvements
- Regex matches individual lines, not unique sessions; deduplicate by process ID, source, account, and time window.
- No rate threshold, aggregation, severity classification, structured JSON output, or automated tests yet.
- Only a tiny controlled sample and two benign lines were validated; broader real-world SSH log formats may behave differently.
- The localhost test is a simulation, **not** evidence of an external intrusion or compromised host.
- Raw log evidence is retained locally; the repository documents screenshots and source code.

## Skills demonstrated
Python log parsing, regex-based detection, controlled test design, positive/negative validation, evidence preservation, and explicit detection limitations.
