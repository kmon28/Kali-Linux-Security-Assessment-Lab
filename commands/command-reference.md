# Kali and Windows Command Reference — Refresher Notes

These commands are for **authorized, isolated lab assets only**. Commands explicitly visible in screenshots are labeled **Observed**; examples reconstructed for future practice are labeled **Reference**, not evidence of execution.

| Command | Status | Why it matters |
|---|---|---|
| `hostnamectl && echo && ip -br addr` | Observed | Identify Kali host, OS, kernel and interface address |
| `ping -c 4 192.168.56.101` | Reference (output observed) | Establish ICMP reachability; ping output showed four replies |
| `nmap -sn 192.168.56.0/24` | Observed | Discover responding hosts without a port scan |
| `nmap -p 445 --script smb2-security-mode,smb2-time 192.168.56.101` | Observed | Inspect SMB signing posture and server time |
| `smbclient -L //192.168.56.102 -U 'CLIENT01\\labattacktest'` | Observed | Controlled SMB authentication test; screenshot showed failure |
| `nmap -Pn -p 445 192.168.56.102` | Observed | Retest SMB port reachability; result was filtered |
| `ldapsearch -x -H ldap://192.168.56.101 -s base -b '' namingContexts dnsHostName` | Reference | Example rootDSE query matching displayed attributes; exact original invocation not visible |
| `ldapsearch -x -H ldap://192.168.56.101 -b 'DC=lab,DC=local' '(sAMAccountName=socuser)' dn sAMAccountName` | Reference | Example scoped account lookup; access depends on directory permissions |
| `ldapsearch -x -H ldap://192.168.56.101 -b 'DC=lab,DC=local' '(cn=Domain Admins)' cn member` | Reference | Review privileged group membership; exact original invocation not visible |

## Windows event review

**Observed on CLIENT01:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddMinutes(-30)} -MaxEvents 10 | Format-List TimeCreated,Id,Message
```

**How to interpret:** Event 4625 means a logon attempt failed. Logon Type 3 indicates network access. Correlate `IpAddress`, `TargetUserName`, `Status`, `SubStatus`, and timestamps. `0xC000006D` indicates logon failure; `0xC000006A` indicates an incorrect password for the supplied account context. These codes alone do not establish malicious intent.

## Important concepts to recall

- **Host discovery vs port scan:** `-sn` detects hosts; a service scan evaluates ports and possibly versions.
- **Open vs filtered:** `open` means Nmap received evidence a service accepts connections; `filtered` means filtering or non-response prevents a definitive open/closed determination.
- **SMB signing required:** Helps protect SMB message integrity; not a blanket guarantee against all SMB threats.
- **LDAP rootDSE:** Provides directory metadata such as naming contexts; the bind context affects what can be queried.
- **Domain Admins:** Highly privileged AD group; membership should be intentional and reviewed.
- **Event 4625:** Failed logon, not evidence of successful access.
- **Correlation:** Compare attacker-side output with defender-side event logs and network state before attributing a cause.

## Interview self-test

1. Why does an open port not automatically constitute a vulnerability?
2. What does `Message signing enabled and required` imply for SMB integrity?
3. Why might LDAP directory information be visible even without a demonstrated exploit?
4. What is the difference between Event 4625 and 4624?
5. How do source IP, Logon Type 3, and status codes support event correlation?
6. What additional evidence would prove a firewall rule caused a filtered TCP/445 result?
7. What would you check before removing a user from Domain Admins?

**Suggested answers:** (1) Exposure alone does not prove an exploitable weakness. (2) The server requires signed SMB messages for relevant sessions. (3) Directory metadata/query access is governed by directory policy and permissions. (4) 4625 failed; 4624 successful logon. (5) They establish where a network login attempt originated and why it failed. (6) Rule configuration, policy precedence, and before/after tests. (7) Business justification, dependencies, alternative privileges, approval, and retest.
