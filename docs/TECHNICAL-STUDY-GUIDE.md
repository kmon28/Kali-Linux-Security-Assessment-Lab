# Kali Security Assessment — Technical Interview Guide

**Scope:** These are authorized, controlled investigations. Distinguish historical lab execution, screenshots, and later reconstructed reference code. Use the [repository overview](../README.md) and original [incident reports](../reports/) to defend each claim.

## 60-second portfolio explanation

I built a controlled Windows Active Directory and Kali Linux lab to practice both attack-surface assessment and defensive investigation. I enumerated services and directory objects, examined SMB/NTLM and Kerberos authentication, correlated Windows security events, and tested detection and remediation workflows. I then investigated Linux SSH failures, systemd persistence, and network connections using Python and native system tools. I documented evidence, verified selected remediation outcomes, and explicitly separated observations from hypotheses.

## What each hiring audience should see

| Reviewer | Relevant investigation | What is demonstrated | Important limitation |
| --- | --- | --- | --- |
| SOC analyst / team lead | [IR-008](../reports/IR-008-Failed-to-Successful-Authentication-Correlation.md), [IR-012](../reports/IR-012-SSH-Authentication-Detection.md) | Failed-to-successful authentication correlation and SSH log triage | Authorized simulations, not live incidents |
| SOC manager / incident responder | [IR-015](../reports/IR-015-Linux-User-Systemd-Persistence-Investigation.md) | Timeline, detection, evidence integrity, containment and recovery verification | Removal of tested persistence does not clear the entire host |
| Windows security / IAM analyst | [IR-002](../reports/IR-002-kerberos-rc4-aes256-hardening.md), [IR-005](../reports/IR-005-AD-Privilege-Escalation-Investigation.md) | Kerberos encryption review and privileged-group change evidence | Lab account changes are not proof of an external attacker |
| Detection engineer | [IR-011](../reports/IR-011-PowerShell-Account-Discovery-Detection.md), [IR-014](../reports/IR-014-python-network-detection.md), [IR-015](../reports/IR-015-Linux-User-Systemd-Persistence-Investigation.md) | Rule logic, source attribution, controlled alerts and false-positive considerations | Some GitHub scripts are reconstructed references, not original VM files |
| Network security analyst | [IR-004](../reports/IR-004-SMB-NTLM-Network-Forensics.md) | TCP and SMB2/NTLMSSP packet interpretation | Packet observations do not by themselves establish compromise |
| Hiring manager | [Featured investigations](../README.md#featured-investigations--60-second-review) | Clear problem → evidence → response → outcome storytelling | Hands-on labs are not equivalent to production employment |

## Interview questions to practice

### Why is a failed logon not automatically an attack?
Event 4625 confirms a failed authentication attempt, not intent. Investigate account, source IP, logon type, status codes, frequency, timing, and related successful logons before making an incident determination.

### What makes the Kerberos investigation security-relevant?
Encryption types and ticket-service activity can indicate legacy configuration or potential risk. Compare the recorded RC4 and AES256 observations, policy settings, and post-change evidence. Do not label a ticket request as Kerberoasting without additional evidence.

### How do you distinguish suspicious systemd persistence from a normal service?
Review the unit's location, ExecStart, enablement links, process ancestry, owner, timestamps, journal history, and expected business purpose. A service launched from a user-writable path is a lead, not proof of malware.

### What is the difference between containment, eradication, and recovery?
Containment limits active behavior. Eradication removes the identified mechanism. Recovery checks the intended system function and control state afterward. IR-015 verifies removal of a specific test service, **not** complete host cleanliness.

### What are the limits of a Python port-based detector?
A port match is a triage signal. TCP TIME_WAIT may remain after a process exits, and missing PID attribution does not prove stealth. Validate process ownership, connection state, context, and baseline before escalating.

### How do you explain a reconstructed detection script?
The original lab screenshots and reports establish historical observations. A later reference implementation documents the detection idea but must be labeled separately until its own execution and tests are demonstrated.

## Five-minute preparation routine

1. Pick one [incident report](../reports/).
2. State the initial question, data source, and the strongest **specific** observation.
3. Explain the command or filter and why it was used.
4. Describe a competing benign explanation and what would disprove it.
5. State the containment or remediation and the exact verification, if any.
6. Name the evidence limitation and one next step without claiming it happened.

**Interview principle:** Evidence → interpretation → validation → response → verification → remaining uncertainty.
