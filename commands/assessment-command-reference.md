# Kali Assessment Command Reference

Commands are reconstructed only where legible in the screenshots or explicitly identified as examples. Execute **only against your own authorized lab systems**. Replace credentials with interactive prompts; never commit secrets.

## 1. Workstation baseline
```bash
hostnamectl
ip -br addr
```
**Observed:** Kali Rolling on VirtualBox; `eth1` UP at `192.168.56.105/24`. The terminal screenshot also shows `lo` and `eth0` (eth0's IPv4 details are not visible).

## 2. Reachability and host discovery
```bash
ping -c 4 192.168.56.101
nmap -sn 192.168.56.0/24
```
**Observed:** four ICMP replies from DC02, 0% packet loss. Nmap 7.99 reports **4 hosts up** across 256 IP addresses in 2.06 seconds. The visible entries include `.1`, `.100`, `.101`, and `.105`. A discovery response alone does not prove the host is trustworthy or enumerate its services.

## 3. Domain-controller service enumeration
The screenshot shows service detection output but the **full original command is not visible**. A representative command for repeating the technique in this authorized lab is:
```bash
nmap -sV 192.168.56.101
```
**Observed:** 12 open TCP ports in the captured output: `53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985`. Nmap reports 988 filtered ports. The scan is not a full 65,535-port assessment.

## 4. SMB security posture
```bash
nmap -p 445 --script smb2-security-mode,smb2-time 192.168.56.101
```
**Observed:** SMB dialect 3.1.1; `Message signing enabled and required`. The `smb2-time` script reports server time. Required signing is a useful mitigation against certain SMB relay/tampering scenarios, not a guarantee of complete SMB security.

## 5. LDAP RootDSE discovery
The original `ldapsearch` command is not fully visible. The screenshot shows a base-object search requesting `namingContexts` and `dnsHostName`. An illustrative command is:
```bash
ldapsearch -x -H ldap://192.168.56.101 -s base -b "" namingContexts dnsHostName
```
**Observed:** `dnsHostName: WIN-QDGUB4SSHAG.lab.local`; naming context `DC=lab,DC=local` plus configuration, schema and DNS partitions; LDAP `result: 0 Success`. RootDSE availability is not proof of anonymous access to all directory objects.

## 6. Authenticated directory and group reads
The screenshots show `sAMAccountName` results and a `Domain Admins` group membership query, but not the full authentication invocation. Reproduce with a **dedicated least-privileged lab account**, using a prompt rather than a command-line password:
```bash
ldapsearch -x -H ldap://192.168.56.101 -D 'LAB\\lab-reader' -W \
  -b 'DC=lab,DC=local' '(objectClass=user)' sAMAccountName
ldapsearch -x -H ldap://192.168.56.101 -D 'LAB\\lab-reader' -W \
  -b 'DC=lab,DC=local' '(cn=Domain Admins)' cn member
```
**Note:** Depending on LDAP bind format, environment, and domain policy, use a UPN or distinguished name instead of the example bind identifier; plain LDAP credentials should not be used on untrusted networks. Prefer LDAPS with certificate validation for credential-bearing queries.

**Observed:** the user-enumeration output includes `socuser` and a computer account; the group query lists `socuser` and `Administrator` as members of `Domain Admins`. This indicates a **high-impact privileged group membership requiring review**, not proof that the account was abused.

## 7. Controlled SMB failure
```bash
smbclient -L //192.168.56.102 -U 'CLIENT01\\labattacktest'
```
Enter a deliberately incorrect test password interactively.
**Observed:** `NT_STATUS_LOGON_FAILURE`; no successful SMB session is demonstrated.

## 8. Windows event correlation (run on CLIENT01)
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-30)} |
  Select-Object -First 10 TimeCreated,Id,Message
```
**Observed:** event `4625`, `Logon Type 3`, `labattacktest`, source `192.168.56.105`, workstation `KALI`, `NtLmSsp`, `NTLM`, status `0xC000006D`, substatus `0xC000006A`. The combination supports a bad-password attempt against an account name, not a successful intrusion.

## 9. Firewall retest
```bash
nmap -Pn -p 445 192.168.56.102
```
**Observed:** TCP/445 is `filtered` after the hardening step. `-Pn` skips host discovery; `filtered` indicates Nmap did not obtain a definitive open/closed response, not proof of a specific Windows Firewall rule.

## Study check
Explain why `open`, `closed`, and `filtered` differ; why `4625` alone is not evidence of brute force; and why authenticated LDAP enumeration does not imply privilege escalation.
