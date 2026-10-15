# Lab scope, topology, and evidence boundaries

## Authorized scope
This exercise was conducted on isolated, personally controlled VirtualBox hosts. The captured targets were `192.168.56.101` (DC02, Windows Server/AD DS) and `192.168.56.102` (CLIENT01, Windows 10). Kali used `192.168.56.105/24` on `eth1`; the host-only network was `192.168.56.0/24`. Host `192.168.56.1` was also visible. These addresses are private lab addresses, **not** public scan targets.

```text
                     VirtualBox host-only LAN
                          192.168.56.0/24
     Kali Linux             DC02 / AD DS             CLIENT01
     192.168.56.105  ----  192.168.56.101  ----     192.168.56.102
        eth1                 lab.local                Windows 10
                              |                            |
                    TCP 53/88/135/139/389/445       SMB test + 4625
                    464/593/636/3268/3269/5985     firewall retest
```

The diagram is conceptual; the screenshots do not establish a physical traffic path or a complete inventory.

## Evidence chronology
1. Kali host identity and network interface verified.
2. `ping` and Nmap `-sn` showed connectivity and four live hosts on the host-only subnet.
3. Service/version scan identified AD-related services on DC02.
4. SMB security-mode NSE check showed signing enabled **and required** on DC02.
5. LDAP rootDSE query returned `DC=lab,DC=local` and directory naming contexts.
6. LDAP directory query returned account entries, including `socuser`.
7. Domain Admins membership query returned `Administrator` and `socuser`.
8. One controlled SMB logon attempt against CLIENT01 failed.
9. CLIENT01 Security Event 4625 documented a network logon failure from Kali.
10. Retest showed CLIENT01 TCP/445 as `filtered` from Kali's vantage point.

## Evidence limitations
- Screenshots are point-in-time terminal output, not complete command transcripts or full packet captures.
- The precise Nmap version-detection command for the service scan is not visible; do not assert flags that cannot be read.
- An LDAP result does not by itself establish whether the bind was anonymous or authenticated; the screenshot for user enumeration is labeled authenticated, but the bind command is not visible.
- Domain Admins membership is a **lab exposure/privilege review finding**, not evidence of compromise.
- `445/tcp filtered` is consistent with firewall filtering but does not independently prove the exact firewall rule, direction, profile, or policy that caused it.
- Event 4625 demonstrates a failed network authentication event; the displayed account domain `CLIENT01` should not be silently relabeled `lab.local`.
- No credential compromise, exploitation, lateral movement, or production system activity is claimed.
