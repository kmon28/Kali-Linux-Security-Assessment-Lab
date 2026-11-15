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

## Five-minute hiring-panel review path

1. **SOC triage:** [IR-008 authentication correlation](../reports/IR-008-Failed-to-Successful-Authentication-Correlation.md) — identify failed and successful Windows logons by account, source, and time; distinguish a detected sequence from confirmed compromise.
2. **Incident response:** [IR-015 user-level persistence](../reports/IR-015-Linux-User-Systemd-Persistence-Investigation.md) — examine the test service, detection scores, journal evidence, hash verification, containment, and removal checks.
3. **Network investigation:** [IR-004 SMB/NTLM forensics](../reports/IR-004-SMB-NTLM-Network-Forensics.md) — interpret packet outcomes without inferring an attacker from normal protocol fields.
4. **Security engineering:** [IR-002 Kerberos hardening](../reports/IR-002-kerberos-rc4-aes256-hardening.md) — discuss RC4/AES256 event evidence and control validation.
5. **Code provenance:** [IR-015 scripts](../scripts/IR-015/) — review the clearly labeled later reference implementation separately from original screenshot evidence.

**Recruitment framing:** This is a hands-on lab portfolio relevant to SOC, security operations, identity security, and junior detection engineering. It does not demonstrate production incident ownership, enterprise-scale deployment, or a guaranteed level of job seniority.
