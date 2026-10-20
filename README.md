# Kali Linux Security Assessment & Blue-Team Investigation

> **Hands-on security engineering portfolio:** authorized Kali reconnaissance, Active Directory enumeration, SMB security validation, Windows event correlation, and defensive retesting in an isolated VirtualBox lab.

![Kali Linux](https://img.shields.io/badge/Platform-Kali_Linux-2874A6?style=flat-square)
![Nmap](https://img.shields.io/badge/Tool-Nmap-1679A7?style=flat-square)
![Active Directory](https://img.shields.io/badge/Target-Active_Directory-4B5563?style=flat-square)
![Windows Event Logs](https://img.shields.io/badge/Detection-Event_4625-2874A6?style=flat-square)
![Evidence](https://img.shields.io/badge/Evidence-26_Screenshots-218838?style=flat-square)
![Status](https://img.shields.io/badge/Project-Documented-218838?style=flat-square)

**Quick navigation:** [Results](#investigation-results) · [Environment](#lab-environment) · [Evidence](#evidence-index) · [Detailed report](reports/assessment-findings.md) · [Command refresher](commands/command-reference.md) · [Kerberos report](reports/IR-002-kerberos-rc4-aes256-hardening.md) · [Kerberos detection guide](docs/kerberos-detection-engineering.md) · [IR-003 SMB authentication report](reports/IR-003-SMB-Authentication-Failure.md)

## Executive Summary

Conducted a controlled Kali Linux security assessment against Windows lab systems on `192.168.56.0/24`. The workflow progressed from **workstation validation → host discovery → service enumeration → SMB and LDAP review → privileged group inspection → controlled failed authentication → Windows log correlation → SMB access retest**.

**Key verified outcomes:** Nmap discovered four active hosts; DC02 exposed typical Active Directory services and **required SMB signing**; LDAP queries returned directory and group membership data; a deliberately unsuccessful SMB authentication attempt against CLIENT01 corresponded with **Security Event 4625 (network logon, source 192.168.56.105)**; a later scan found CLIENT01 TCP/445 **filtered**.

These are **lab observations, not proof of exploitation or a production security incident**.

## Investigation Results

| Investigation | Evidence-backed result | Security significance |
|---|---|---|
| Kali baseline | Kali Linux on `eth1`, `192.168.56.105/24` | Confirms assessment source and network context |
| Host discovery | `nmap -sn 192.168.56.0/24`: **4 hosts up** | Establishes reachable lab assets |
| DC02 service inventory | DNS, Kerberos, RPC, LDAP, SMB, LDAPS, Global Catalog and WinRM-related ports visible | Inventory for access-control and hardening review; **not** automatically vulnerabilities |
| SMB signing | `smb2-security-mode`: **signing enabled and required** | Positive integrity control observed |
| LDAP | RootDSE and directory account/group results returned | Shows directory metadata and account visibility |
| Privileged access | `Domain Admins` listed `Administrator` and `socuser` | Least-privilege review recommended; no claim of unauthorized membership |
| SMB authentication | `NT_STATUS_LOGON_FAILURE` for a controlled attempt | No successful access established |
| Defensive telemetry | CLIENT01 **4625**, Type 3, source Kali `192.168.56.105` | Correlates endpoint evidence with the test |
| SMB retest | CLIENT01 `445/tcp filtered` from Kali | Consistent with restricted reachability; exact firewall rule not independently shown |

## Lab Environment

```text
               VirtualBox host-only network 192.168.56.0/24
             ┌─────────────────────────────────────────────┐
             │ Kali Linux         DC02            CLIENT01 │
             │ 192.168.56.105     192.168.56.101  192.168.56.102
             │ Recon / testing    AD DS / DNS     Windows 10
             └─────────────────────────────────────────────┘
```

**Domain:** `lab.local`. The network and target identities are drawn from the captured evidence. See [scope, architecture and limitations](docs/lab-scope-and-topology.md).

## Investigation Walkthrough

### 1. Establish the Kali baseline and discover hosts

The Kali screenshot shows `hostnamectl && echo && ip -br addr`, identifying the Kali guest and `eth1` at `192.168.56.105/24`. A ping to DC02 returned four replies. `nmap -sn 192.168.56.0/24` reported **four hosts up** from 256 scanned addresses.

[Baseline](screenshots/01-Kali-Attacker-Workstation-Baseline.png) · [Host discovery](screenshots/02-Nmap-Host-Discovery.png)

### 2. Enumerate domain-controller services

The DC02 scan reported open TCP ports **53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, and 5985**, among others; the output also noted **988 filtered TCP ports**. The exposed services align with Windows Active Directory functionality. Exposure should be assessed against the intended network trust boundary; a listening port is not itself a confirmed weakness.

[Service enumeration screenshot](screenshots/03-DC02-Service-Enumeration.png)

### 3. Validate SMB security posture

The observed command was:

```bash
nmap -p 445 --script smb2-security-mode,smb2-time 192.168.56.101
```

Nmap reported **SMB 3.1.1 signing enabled and required**. This is a **positive defensive finding**, not a missing-signing vulnerability.

[SMB security-mode screenshot](screenshots/04-DC02-SMB-Security-Mode.png)

### 4. Examine LDAP directory information and privileges

LDAP rootDSE returned `DC=lab,DC=local` and naming contexts. A later directory search displayed `socuser` and a workstation account. The Domain Admins group output included `Administrator` and `socuser`.

**Analyst interpretation:** Privileged membership warrants periodic authorization review. The screenshots do not prove a misconfiguration or compromise. The exact LDAP bind/command used for each query is not visible; do not assume an anonymous bind or credential exposure.

[LDAP rootDSE](screenshots/05-Active-Directory-LDAP-Enumeration.png) · [Account enumeration](screenshots/06-Authenticated-AD-User-Enumeration.png) · [Group membership](screenshots/07-Privileged-Group-Enumeration.png)

### 5. Correlate a controlled failed login with Windows telemetry

A single captured `smbclient` attempt against CLIENT01 returned **`NT_STATUS_LOGON_FAILURE`**. On CLIENT01, Windows Event **4625**, Logon Type **3**, recorded account `labattacktest`, source workstation `KALI`, source IP `192.168.56.105`, and status `0xC000006D` / substatus `0xC000006A`.

**Detection lesson:** A failed network login is observable on the defender and should be interpreted with account, source, timing, and baseline context. One controlled failure does **not** establish password spraying, brute force, or successful intrusion.

[Failed SMB login](screenshots/08-Controlled-SMB-Authentication-Failure.png) · [Windows 4625 event](screenshots/09-Windows-Event-4625-Investigation.png)

### 6. Verify restricted SMB reachability

The observed retest:

```bash
nmap -Pn -p 445 192.168.56.102
```

returned **`445/tcp filtered`**. This is consistent with blocked or otherwise filtered access from Kali at that point in time. To attribute it to a specific firewall change, a reviewer would need rule configuration and a before/after policy record.

[SMB retest screenshot](screenshots/10-SMB-Firewall-Hardening-Retest.png)

## Evidence Index

| # | Artifact | Link |
|---|---|---|
| 01 | Kali baseline: eth1 192.168.56.105/24 | [View screenshot](screenshots/01-Kali-Attacker-Workstation-Baseline.png) |
| 02 | Nmap host discovery: 4 hosts up | [View screenshot](screenshots/02-Nmap-Host-Discovery.png) |
| 03 | DC02 AD-associated services | [View screenshot](screenshots/03-DC02-Service-Enumeration.png) |
| 04 | SMB signing enabled and required | [View screenshot](screenshots/04-DC02-SMB-Security-Mode.png) |
| 05 | LDAP rootDSE and naming contexts | [View screenshot](screenshots/05-Active-Directory-LDAP-Enumeration.png) |
| 06 | LDAP directory account results | [View screenshot](screenshots/06-Authenticated-AD-User-Enumeration.png) |
| 07 | Domain Admins membership | [View screenshot](screenshots/07-Privileged-Group-Enumeration.png) |
| 08 | Controlled SMB login failure | [View screenshot](screenshots/08-Controlled-SMB-Authentication-Failure.png) |
| 09 | CLIENT01 Security Event 4625 | [View screenshot](screenshots/09-Windows-Event-4625-Investigation.png) |
| 10 | CLIENT01 TCP/445 filtered on retest | [View screenshot](screenshots/10-SMB-Firewall-Hardening-Retest.png) |

## Technical Documentation and Refresher Notes

- **[Assessment findings report](reports/assessment-findings.md):** findings matrix, risk interpretation, correlation, and next validation steps.
- **[Command reference and interview refresher](commands/command-reference.md):** observed commands vs reproducible examples, protocol concepts, Windows event interpretation, and self-test questions.
- **[Lab scope and topology](docs/lab-scope-and-topology.md):** network architecture, chronological evidence, and what cannot be concluded from the screenshots.


## Kerberos Service Ticket Investigation — RC4 to AES-256

**Completed October 17, 2026.** Extended the authorized Windows/AD assessment with Kerberos service-account configuration, Event ID 4769 auditing, legacy-encryption identification, and an AES-256 hardening retest.

- **Before:** 9:20:12 PM, `svc-kerberos-lab` service ticket issued using **RC4 (`0x17`)**, success `0x0`.
- **After:** account configured with supported encryption types **24 decimal (`0x18`, AES-128 + AES-256)**; fresh ticket requested; 10:16:40 PM Event 4769 showed **AES-256 (`0x12`)**, success `0x0`.
- **Disposition:** scoped legacy-encryption hardening validation, **not** evidence of a Kerberoasting attack or compromise. Local client address `::1`.
- **Tooling:** Windows Security Event Logs, Active Directory PowerShell, and `klist`; **no active Splunk access** (earlier trial expired).

**[Read the complete Kerberos investigation report](reports/IR-002-kerberos-rc4-aes256-hardening.md)** · [Command reference](commands/kerberos-command-reference.md) · [Detection engineering and MITRE mapping](docs/kerberos-detection-engineering.md) · [Evidence index (11–23)](docs/kerberos-evidence-index.md) · [RC4 investigation screenshot 22](screenshots/22-Kerberos-RC4-Investigation.png) · [AES-256 verification screenshot 23](screenshots/23-Kerberos-AES256-Final-Verification.png)

The evidence set now contains **26 numbered screenshots**, with screenshots 11–23 covering Kerberos setup, auditing, event investigation, and encryption verification, and screenshots 24–26 covering DC02 failed authentication triage. See the full [screenshots directory](screenshots/).

## IR-003 — DC02 SMB Authentication Failure Investigation

**Completed October 18, 2026.** Investigated four controlled failed network logons on **DC02** originating from Kali (`192.168.56.105`) against `LAB\\socuser`. Windows Event ID **4625** recorded Logon Type **3**, status `0xC000006D`, substatus `0xC000006A` (incorrect password), and MSV1_0 authentication-package information. The four events were logged between **02:42:55 and 02:47:08 AM**. This is a controlled lab simulation, **not** evidence of brute force or compromise.

**[Read the IR-003 incident report](reports/IR-003-SMB-Authentication-Failure.md)** · [Screenshot 24: failed login](screenshots/24-SMB-Failed-Logon-4625-Kali-to-DC02.png) · [Screenshot 25: timeline](screenshots/25-Failed-Logon-Event-Timeline.png) · [Screenshot 26: authentication details](screenshots/26-SMB-Authentication-Protocol-4625.png)

## Engineering Takeaways

1. **Reconnaissance is not exploitation:** host discovery and open ports establish an attack surface, not a compromise.
2. **Validate controls, including positive findings:** DC02 required SMB signing.
3. **Treat identity data carefully:** privileged group membership needs business context before calling it a finding.
4. **Correlate both sides:** Kali's authentication failure and CLIENT01's 4625 event support one investigation narrative.
5. **Verify remediation cautiously:** `filtered` is an observed network state, not a complete firewall policy audit.

## Scope and Limitations

All activity shown was performed against controlled lab hosts. Screenshots are the original evidence; raw Nmap/LDAP output files, a complete Kali packet capture, and firewall-rule exports are not included. No vulnerability exploitation, credential compromise, lateral movement, or production incident is asserted.

**Related projects:** [Windows SOC Detection & Threat Hunting](https://github.com/kmon28/Windows-SOC-Detection-Lab) · [Network Traffic Analysis & Active Directory Investigation](https://github.com/kmon28/Network-Traffic-Analysis-Lab)
