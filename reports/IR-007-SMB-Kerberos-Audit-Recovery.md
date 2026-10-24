# IR-007 — SMB Authentication Investigation and Kerberos Audit Recovery

**Environment:** VirtualBox `lab.local` Active Directory lab  
**Scope:** Network authentication attribution, Windows auditing, and GPO remediation  
**Status:** Controlled investigation and telemetry remediation validated

## Executive summary
A controlled SMB IPC$ connection from CLIENT01 (`192.168.56.102`) to DC02 (`192.168.56.101`) using `LAB\socuser` was correlated with Windows Security Event **4624, Logon Type 3**. During subsequent Kerberos investigation, new **4769** events were absent even though service-ticket operations were being tested. The analyst identified effective audit policy reverting to **No Auditing** after Group Policy refresh, configured the domain-controller GPO to audit **Success and Failure**, refreshed policy, and confirmed three fresh **4769** events on October 24.

## Evidence-driven workflow
1. **Simulate authorized SMB authentication.** From CLIENT01, run `net use \\192.168.56.101\IPC$ /user:LAB\socuser *`.
2. **Attribute the logon.** Investigate Security 4624 on DC02; distinguish *New Logon* identity from *Subject*. Confirm `socuser`, Logon Type **3**, and source `192.168.56.102`.
3. **Investigate Kerberos visibility.** Query Security 4769; initially only older October 17 records were present.
4. **Check effective audit policy.** `auditpol /get /subcategory:"Kerberos Service Ticket Operations"` showed **No Auditing** after policy refresh.
5. **Remediate at policy source.** Edit the **Default Domain Controllers Policy** under Advanced Audit Policy Configuration → Account Logon → **Audit Kerberos Service Ticket Operations**, enable **Success** and **Failure**, then run `gpupdate /force`.
6. **Retest.** Request a Kerberos service ticket for the DC's actual host principal. Three new 4769 records appeared on October 24, two at 01:55:57 and one at 01:56:54.

## Security interpretation
The SMB connection shows authenticated network access, **not** malicious lateral movement or remote code execution. The Kerberos service-ticket retest was performed as `LAB\Administrator` on DC02, so those later 4769 records must **not** be attributed to the earlier `socuser` session on CLIENT01.

## Analyst commands
```powershell
# Verify effective auditing on the domain controller
auditpol /get /subcategory:"Kerberos Service Ticket Operations"

# Inspect recent successful network logons
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 100 |
  Select-Object TimeCreated, Id, Message

# Inspect Kerberos service-ticket events
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} -MaxEvents 10 |
  Select-Object TimeCreated, Id
```

## Screenshots

### Screenshot 49 — SMB network-logon attribution
[Open original image](https://raw.githubusercontent.com/kmon28/Kali-Linux-Security-Assessment-Lab/main/screenshots/49-IR007-SMB-Network-Logon.png)

![IR-007 SMB network logon evidence](https://raw.githubusercontent.com/kmon28/Kali-Linux-Security-Assessment-Lab/main/screenshots/49-IR007-SMB-Network-Logon.png)

### Screenshot 50 — Kerberos 4769 auditing validated
[Open original image](https://raw.githubusercontent.com/kmon28/Kali-Linux-Security-Assessment-Lab/main/screenshots/50-IR007-Kerberos-4769-Audit-Validation.png)

![IR-007 Kerberos audit validation evidence](https://raw.githubusercontent.com/kmon28/Kali-Linux-Security-Assessment-Lab/main/screenshots/50-IR007-Kerberos-4769-Audit-Validation.png)

## Engineering takeaways
- Effective Group Policy can override local audit configuration.
- Missing telemetry must be investigated before interpreting absence of events as absence of activity.
- Verify remediation by generating fresh test activity and checking new event timestamps.
- For a mature detector, correlate account, client address, ticket service, logon type, and event record ID; distinguish routine administrative behavior from anomalies.

## Interview explanation
> I investigated authenticated SMB traffic, traced the originating workstation and account through Event 4624, identified why Kerberos service-ticket events were missing, corrected the effective domain-controller audit policy, and verified the fix with newly generated Event 4769 records.

**Related Windows SOC report:** [IR-007 in Windows-SOC-Detection-Lab](https://github.com/kmon28/Windows-SOC-Detection-Lab/blob/main/incident-reports/IR-007-smb-kerberos-audit-recovery.md).
