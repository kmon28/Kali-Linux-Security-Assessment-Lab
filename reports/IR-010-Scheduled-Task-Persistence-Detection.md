# IR-010 — Scheduled Task Persistence Simulation and Windows Event Correlation

**Date:** November 1, 2026  
**Host:** CLIENT01 (Windows 10, `lab.local`)  
**Scope:** Authorized, isolated VirtualBox defensive lab  
**ATT&CK:** [T1053.005 — Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)  
**Disposition:** Benign simulation; successful detection/verification and cleanup

## Executive summary
Created a deliberately benign Windows scheduled task named `IR010-Lab-Persistence` to study how task-based persistence appears in Windows telemetry. The task launched `powershell.exe` with `-NoProfile -Command "Write-Output IR010-Test"`. Investigated task configuration, execution identity, Scheduler Operational events, and return codes. After correcting execution context, the task completed successfully under `NT AUTHORITY\SYSTEM`. The task was subsequently unregistered, and a `Get-ScheduledTask` lookup returned no result.

**No malicious payload, actual compromise, or unauthorized persistence is claimed.** The task was manually invoked for validation; an automatic recurring trigger was not demonstrated.

## Lab methodology
1. Registered the named task with a harmless PowerShell output action.
2. Inspected its `Actions`, `Triggers`, `Settings`, and `Principal` using `Get-ScheduledTask`.
3. Attempted execution and inspected `LastRunTime`, `LastTaskResult`, and the Task Scheduler Operational log.
4. Investigated Event **332**, which stated that the configured user was not logged on when the task's launch conditions required an interactive session.
5. Changed the task principal to `SYSTEM` / `ServiceAccount` / `Limited`, then reran the task.
6. Confirmed `LastTaskResult: 0`, correlated events, unregistered the task, and verified absence.

## Observed evidence

| Observation | Result |
|---|---|
| Task name | `\IR010-Lab-Persistence` |
| Action | `powershell.exe -NoProfile -Command "Write-Output IR010-Test"` |
| Final principal | `SYSTEM`; `ServiceAccount`; `Limited` |
| Earlier failure | Task Scheduler Event **332**: user not logged on; launch conditions unmet |
| Successful task start | Event **100**, Nov 1 at **01:30:44** |
| Action launch | Event **200**, `powershell.exe`, **01:30:44** |
| Action completion | Event **201**, return code **0**, **01:30:55** |
| Task completion | Event **102**, **01:30:55**, user `NT AUTHORITY\SYSTEM` |
| Task status after run | `Ready`; `LastTaskResult: 0` |
| Cleanup | `Unregister-ScheduledTask` succeeded; subsequent lookup yielded no task |

**Timing note:** `Get-ScheduledTaskInfo` displayed `LastRunTime: 01:30:30`, while the detailed Operational log showed start/action events at 01:30:44. The event timestamps are used for the execution timeline; this discrepancy is retained rather than silently reconciled.

## Detection and forensic approach
Task Scheduler's **Microsoft-Windows-TaskScheduler/Operational** channel provides execution telemetry:
- **100**: task started
- **200**: task action launched
- **201**: action completed with exit code
- **102**: task completed
- **332**: task launch blocked by logon conditions (observed during troubleshooting)

The task name, execution identity, action path, and event times should be correlated with Security task-creation/change events (where enabled), Sysmon process creation, and approved task inventory. These events alone are not proof of malicious activity.

### Reproducible defensive queries
```powershell
Get-ScheduledTask -TaskName 'IR010-Lab-Persistence' |
  Select-Object -ExpandProperty Principal |
  Format-List UserId,LogonType,RunLevel

Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-TaskScheduler/Operational'
  Id=100,102,200,201
  StartTime='2026-11-01 01:30:00'
  EndTime='2026-11-01 01:32:00'
} | Select-Object TimeCreated,Id,Message | Format-List
```

### Cleanup
```powershell
Unregister-ScheduledTask -TaskName 'IR010-Lab-Persistence' -Confirm:$false
Get-ScheduledTask -TaskName 'IR010-Lab-Persistence' -ErrorAction SilentlyContinue
```
The second command produced no task object, supporting removal of the registered task. Historical events remain available for investigation.

## Evidence inventory (screenshots 57–60)

The following four screenshots were reported uploaded after the investigation. Their exact repository paths have not been independently verified, so direct image links are withheld rather than risking broken references.

| Number | Evidence | Investigative value |
|---|---|---|
| 57 | Scheduled task execution events | Operational Events 100, 200, 201, and 102 establish successful task execution and completion |
| 58 | Scheduled task creation, Security Event 4698 | Documents task registration in Windows Security telemetry |
| 59 | Persistence removal verification | Shows task unregistration and absence on subsequent lookup |
| 60 | Scheduled task registration, Operational Event 106 | Corroborates task registration in Task Scheduler telemetry |

**Evidence handling:** The Event 4698 and Event 106 records represent different Windows logging channels, not duplicate screenshots. Execution and removal evidence are distinct. These observations support a benign lab simulation and do not establish malicious persistence.

## Detection engineering and SOC triage

**Analytic hypothesis:** A newly registered scheduled task invoking a script interpreter can indicate persistence when the creator, command, execution identity, or timing deviates from an approved baseline. Task registration or SYSTEM execution alone is insufficient to label an incident malicious.

**Investigation workflow:**
1. Identify task registration through Security **4698** and TaskScheduler/Operational **106**, when available. Preserve task XML and identify creator, task name, action, trigger, and principal.
2. Correlate task instance events **100** (start), **200** (action launch), **201** (action return), and **102** (task completion). Use task instance GUID and timestamps rather than event proximity alone.
3. Review the failed execution context via **332**, then distinguish misconfiguration from evasion or malicious activity.
4. Enrich with Sysmon **1** or Security **4688** process creation (where configured), command line, signer, user, and parent process. Look for unexpected network, file, and registry activity.
5. Compare against known-good IT automation and Windows tasks. Escalate only with corroborating evidence; document disposition and verify remediation.

### Read-only hunting queries

```powershell
$taskName = 'IR010-Lab-Persistence'
$start = [datetime]'2026-11-01 01:20:00'
$end = [datetime]'2026-11-01 01:40:00'

Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-TaskScheduler/Operational'
    Id = 100,102,106,200,201,332
    StartTime = $start
    EndTime = $end
} | Where-Object { $_.Message -like "*$taskName*" } |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, Message

# Requires task creation auditing; absence of records is not proof of no activity.
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4698
    StartTime = $start
    EndTime = $end
} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -like "*$taskName*" } |
    Select-Object TimeCreated, Id, Message
```

### Production detection considerations

A stronger analytic combines **task creation or modification** with unusual actions (script interpreters, encoded arguments, executables in user-writable paths), anomalous principals, and observed follow-on execution. Common false positives include Windows Update, endpoint agents, and approved administrative scripts. Task Scheduler event retention and Security audit policy affect visibility. A zero action exit code means the process reported success, not that persistence survived reboot or that an attacker achieved objectives.

## Analyst assessment and limitations
This simulation demonstrates task configuration analysis, troubleshooting logon-context failure, process-action event correlation, return-code validation, and safe cleanup. It does **not** establish a stealthy persistence mechanism, automatic execution after reboot, elevated `RunLevel`, or malicious PowerShell behavior. `SYSTEM` identity alone is not an indicator of compromise. In production, triage should assess task provenance, author, executable signature/path, command line, creation/modification time, and expected administrative activity.
