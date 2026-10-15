# Lab Topology, Authorization & Evidence Scope

## Objective
Assess exposed services and identity-related behavior in an **isolated, personally controlled VirtualBox Active Directory lab**. Correlate a deliberately failed network authentication attempt with Windows Security telemetry, then validate a firewall change from the Kali workstation.

## Systems observed

| Asset | Role | Host-only IPv4 | Evidence |
|---|---|---|---|
| Kali Linux | Assessment workstation | `192.168.56.105/24` on `eth1` | [01](../screenshots/01-Kali-Attacker-Workstation-Baseline.png) |
| DC02 | Windows Server 2022 domain controller, AD DS/DNS | `192.168.56.101` | [03](../screenshots/03-DC02-Service-Enumeration.png) |
| CLIENT01 | Windows 10 domain client, SMB test destination | `192.168.56.102` | [08](../screenshots/08-Controlled-SMB-Authentication-Failure.png), [09](../screenshots/09-Windows-Event-4625-Investigation.png) |
| VirtualBox host | Host-only adapter | `192.168.56.1` | [02](../screenshots/02-Nmap-Host-Discovery.png) |

AD domain: `lab.local`; host-only segment: `192.168.56.0/24`. Kali's `hostnamectl` shows Kali GNU/Linux Rolling, kernel `6.19.14+kali-amd64`, running as a VirtualBox VM. These are lab snapshot details, not a claim about a production deployment.

```text
                    VirtualBox host-only: 192.168.56.0/24
  +-------------------+   +---------------------+   +---------------------+
  | Kali workstation  |   | DC02                |   | CLIENT01            |
  | 192.168.56.105    |-->| 192.168.56.101      |   | 192.168.56.102      |
  | Nmap / ldapsearch |   | AD DS / DNS / SMB   |   | SMB test / Event 4625|
  | smbclient         |   +---------------------+   +---------------------+
  +-------------------+              |                         ^
              |                      | LDAP/SMB discovery      |
              +-----------------------------------------------+
                          Controlled SMB failure / retest
```

## Scope and constraints
- Target only owned, authorized lab VMs and the isolated host-only subnet.
- Discovery and enumeration do not establish exploitability.
- Authenticated LDAP reads demonstrate access to directory information; they do **not** demonstrate privilege escalation.
- A failed SMB login is a controlled simulation, not a password-spraying campaign.
- Firewall validation is limited to the observed TCP/445 state; the screenshot does not prove the exact firewall rule, its scope, or continued enforcement.
- Screenshots are the original evidence artifacts; raw Nmap/LDAP output and Windows EVTX exports have not been supplied.
- Dates shown in screenshots span October 11 and October 15, 2026. Do not present all ten screenshots as one continuous same-day capture.

## Evidence-handling principles
Record tool version, target, command, time, result, and interpretation. Avoid uploading credentials, passwords, sensitive domain exports, or personal identifiers. Keep any future redacted logs alongside their unmodified local originals and record hashes when available.
