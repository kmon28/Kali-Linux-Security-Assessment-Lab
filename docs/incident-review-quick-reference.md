# Security investigation review guide

A short entry point to the controlled Linux and Windows identity investigations.

| Case | Question | Evidence focus |
|---|---|---|
| [IR-004](../reports/IR-004-SMB-NTLM-Network-Forensics.md) | What SMB/NTLM authentication activity is visible? | Wireshark protocol status and context |
| [IR-006](../reports/IR-006-Failed-Logon-Detection.md) | Can failed logons be detected? | Event 4625 and PowerShell output |
| [IR-008](../reports/IR-008-Failed-to-Successful-Authentication-Correlation.md) | Do failures precede success from the same source? | Events 4625/4624, account and timestamp |
| [IR-013](../reports/IR-013-Linux-Systemd-Persistence-Investigation.md) | How is systemd persistence investigated? | Service configuration and state |
| [IR-015](../reports/IR-015-Linux-User-Systemd-Persistence-Investigation.md) | Can user-level service indicators be scored and validated? | Documented suspicious 4/4 and benign 0/4 tests |

## Analyst workflow
1. State the hypothesis and initial observation.
2. Identify each artifact: log, command output, screenshot or source file.
3. Distinguish observed evidence from inference and unknowns.
4. Check benign explanations and false positives.
5. Verify containment and recovery where performed.

Historical hands-on lab tests count. [IR-015 published reference code](../scripts/IR-015/) was reconstructed later and should not be represented as byte-for-byte original VM code. These are authorized simulations, not production incidents.
