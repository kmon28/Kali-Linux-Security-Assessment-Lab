# Study Notes — Kali, Active Directory & Defensive Correlation

Use this as a **quick refresher before interviews**. Read each answer, then hide it and explain the concept from memory.

## 60-second project explanation
> I built a Kali workstation on an isolated VirtualBox host-only network and assessed a Windows Active Directory lab. I used Nmap to discover hosts and enumerate the domain controller, confirmed SMB signing was required, queried LDAP directory information and Domain Admins membership, then generated a single controlled SMB login failure against a Windows client. I correlated that attempt to Windows Security Event 4625 and retested TCP/445 after firewall hardening. I documented what the screenshots prove and what still requires validation.

## Core concepts

### 1. What is the difference between host discovery and port enumeration?
`nmap -sn` identifies responsive hosts without performing a port scan. Service detection (`-sV`) probes services on selected ports to estimate software or protocol. A host being up does not imply a service is accessible.

### 2. What do open, closed and filtered mean?
- **Open:** an application appears to accept connections on that port.
- **Closed:** host responds, but no application is listening.
- **Filtered:** a network device or firewall prevents Nmap from determining open versus closed. **Filtered does not identify the exact rule.**

### 3. What does SMB signing do?
SMB signing provides message integrity and helps prevent tampering and certain relay attacks. The DC02 result showed **enabled and required** for SMB 3.1.1. It does not mean SMB is immune to every attack.

### 4. What are LDAP and Kerberos used for?
LDAP is used to query and manage directory objects. Kerberos supplies ticket-based authentication in Active Directory. LDAP enumeration is not synonymous with credential compromise.

### 5. What is RootDSE?
A special LDAP base entry exposing server metadata such as naming contexts and capabilities. Returning RootDSE does not mean an anonymous user can read all directory objects.

### 6. Why is Domain Admins membership important?
It is highly privileged within the domain. The lab's `socuser` membership is a **review target**. You must confirm authorization before calling it a misconfiguration.

### 7. What does Event ID 4625 indicate?
A **failed logon**. Here: Type 3 (network), source `192.168.56.105`, account `labattacktest`, NTLM, status `0xC000006D` and substatus `0xC000006A` (bad password). One failure is not a brute-force attack.

### 8. Why correlate Kali and Windows evidence?
A Kali-side failure establishes what the test tool saw; a Windows 4625 independently establishes the target recorded a corresponding attempt. Matching IP, user, target and time strengthens confidence.

### 9. What does a TCP/445 filtered retest establish?
From that scanning position, Nmap could not establish whether the service was open or closed. It is **consistent with filtering**. Verify firewall rules and approved access paths before claiming the control is complete.

### 10. What would make this a stronger enterprise-quality assessment?
Sanitized raw scan outputs, command logs, timestamps with timezone, rule exports, Event Viewer EVTX, detection queries, change approval, false-positive tests, and a retest matrix.

## Quick-reference commands

| Purpose | Command |
|---|---|
| Kali address | `ip -br addr` |
| Host discovery | `nmap -sn 192.168.56.0/24` |
| Service fingerprinting | `nmap -sV 192.168.56.101` |
| SMB signing | `nmap -p 445 --script smb2-security-mode,smb2-time 192.168.56.101` |
| LDAP RootDSE | `ldapsearch -x -H ldap://192.168.56.101 -s base -b "" namingContexts dnsHostName` |
| Windows failures | `Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625}` |
| Post-change probe | `nmap -Pn -p 445 192.168.56.102` |

## Interview challenge questions
1. What would you need to prove a firewall change caused a port to become filtered?
2. How would you distinguish a typo from a password-spraying campaign?
3. Why is an authenticated LDAP group query not proof of escalation?
4. Which network controls should limit access to a domain controller's administrative services?
5. How would you test an SMB-signing policy change without disrupting legitimate clients?

## Next hands-on exercises
- Export and sanitize Windows Event 4625 records; write a basic Splunk detection with false-positive notes.
- Save Nmap XML output and a redacted command transcript; compare before/after results.
- Export the effective Windows Firewall rules governing TCP/445; document allowlist and deny cases.
- Audit privileged AD memberships with explicit authorization and create a remediation checklist.

**Evidence discipline:** Exercises in this section are proposed future work, not completed tasks.
