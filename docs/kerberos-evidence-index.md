# Kerberos Evidence Index — Screenshots 11–23

**Case:** [IR-002 — Kerberos RC4 to AES-256 hardening](../reports/IR-002-kerberos-rc4-aes256-hardening.md)  
**Environment:** DC02 / `lab.local`; authorized, isolated Active Directory test.  
**Important:** These screenshots document configuration, logging, detection review, and scoped hardening. They do **not** prove a Kerberoasting attack.

| # | File | Analyst significance |
|---|---|---|
| 11 | [Kerberos SPN Configuration](../screenshots/11-Kerberos-SPN-Configuration.png) | Test service principal setup |
| 12 | [Kerberos Auditing Enabled](../screenshots/12_Kerberos_Auditing_Enabled.png) | Service-ticket audit visibility |
| 13 | [Kerberos Test Account Configured](../screenshots/13_Kerberos_Test_Account_Configured.png) | Controlled service-account context |
| 14 | [Kerberos Event 4769 Ticket Detection](../screenshots/14-Kerberos-Event4769-Ticket-Detection.png) | Ticket event identification |
| 15 | [Service Account Security Assessment](../screenshots/15-Kerberos-Service-Account-Security-Assessment.png) | Account encryption/security review |
| 16 | [AES-256 Ticket Verified](../screenshots/16-Kerberos-AES256-Ticket-Verified.png) | Client-side ticket validation |
| 17 | [AES-256 Event 4769](../screenshots/17-Kerberos-AES256-Event4769.png) | Windows Security log validation |
| 18 | [RC4 Event 4769](../screenshots/18-Kerberos-RC4-Event4769.png) | Historical RC4 ticket evidence |
| 19 | [AES-256 Comparison](../screenshots/19-Kerberos-AES256-Comparison.png) | Encryption setting comparison |
| 20 | [RC4 Detection](../screenshots/20-Kerberos-RC4-Detection.png) | Manual Event 4769 RC4 search |
| 21 | [RC4 Investigation](../screenshots/21-Kerberos-RC4-Investigation.png) | Follow-up RC4 analysis |
| 22 | [RC4 Investigation — Final](../screenshots/22-Kerberos-RC4-Investigation.png) | Confirmed 4769, `0x17`, `0x0`, `svc-kerberos-lab`, source `::1` |
| 23 | [AES-256 Final Verification](../screenshots/23-Kerberos-AES256-Final-Verification.png) | Confirmed later 4769, `0x12`, `0x0` |

## Evidence Standard

- Original screenshots remain unchanged.
- Files 11–23 are linked using their exact GitHub filenames (including underscores in 12 and 13).
- 4769 **9:20:12 PM** shows RC4; **10:16:40 PM** shows AES-256, both October 17, 2026.
- Account setting `24` decimal (`0x18`) means AES-128 + AES-256 **supported**; observed `0x12` proves AES-256 used for the specific retest.
- Earlier screenshots may contain overlapping stages; they are retained for audit trail rather than counted as 13 independent tests.
- No Splunk access is required to reproduce the Windows-side analysis.

**Supporting docs:** [Commands](../commands/kerberos-command-reference.md) · [Detection guide](../docs/kerberos-detection-engineering.md) · [Case report](../reports/IR-002-kerberos-rc4-aes256-hardening.md).
