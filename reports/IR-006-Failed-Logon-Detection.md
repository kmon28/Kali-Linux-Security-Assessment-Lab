# IR-006 — PowerShell Failed-Logon Detection Engineering

**Environment:** Isolated Windows Server 2022 Active Directory lab  
**Scope:** Controlled Windows Security Event 4625 analysis and detection testing  
**Status:** Script execution validated; historical threshold alert observed separately; additional live positive-test validation recommended

## Executive summary
Investigated repeated failed SMB authentication events for `LAB\socuser` from Kali Linux (`192.168.56.105`) against DC02 (`192.168.56.101`). The analyst correlated Windows Security Event ID **4625** timestamps, account identity, and source IP, then evaluated a five-minute threshold rule. Historical events on October 23, 2026 at 10:58:49, 10:58:53, and 10:58:58 met the three-failures-in-five-minutes threshold. A separate reusable PowerShell detection script was executed in a later no-alert window.

## Investigative method
1. Generate authorized authentication failures in the isolated test network.
2. Query DC02 Security Event **4625** and verify `socuser` and `192.168.56.105`.
3. Group events by source and five-minute time window; compare counts with a threshold of three.
4. Differentiate a **historical positive test** from a **current rolling-window no-alert result**.
5. Preserve screenshots and document alert logic, assumptions, and false positives.

## Evidence and results
- **Screenshot 45:** Historical threshold alert — three failed logons within five minutes (historical-event validation).
- **Screenshot 48:** Reusable PowerShell script execution, reporting `OK: No threshold reached` during that run.
- A positive result from a historical query **does not by itself prove** the scheduled or rolling-window script will alert during a new live burst.
- Failed authentication can be caused by mistyped credentials, expired passwords, service misconfiguration, or password guessing. Intent cannot be inferred from the event ID alone.

### Screenshot 48 — Script validation
[Open original image](https://raw.githubusercontent.com/kmon28/Kali-Linux-Security-Assessment-Lab/main/screenshots/48-IR006-Reusable-Detection-Script.png)

![IR-006 PowerShell failed-logon detection screenshot](https://raw.githubusercontent.com/kmon28/Kali-Linux-Security-Assessment-Lab/main/screenshots/48-IR006-Reusable-Detection-Script.png)

## Detection considerations
For production-grade correlation, parse event XML by named fields, retain account, IP, logon type, status/substatus, event record ID, and timestamps; deduplicate repeated collection; and use explicit lookback boundaries. Validate both alert and no-alert paths. Tune the threshold against normal account activity before escalation.

## Interview explanation
> I analyzed failed Windows authentication events from a known Kali test host, built threshold-based PowerShell detection logic, verified a historical alert condition, and separately tested the script's no-alert path. I documented what was validated and what still requires a live positive test.

**Related Windows SOC report:** [IR-006 in Windows-SOC-Detection-Lab](https://github.com/kmon28/Windows-SOC-Detection-Lab/blob/main/incident-reports/IR-006-failed-logon-script.md).
