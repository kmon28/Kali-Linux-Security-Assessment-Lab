# IR-003 Interview Review — SOC / Help Desk / Junior Security Analyst

> **Practice guide** for the [IR-003 investigation](../reports/IR-003-SMB-Authentication-Failure.md). Answers are deliberately concise enough to say aloud. **Do not claim tools or telemetry you did not use.**

## Your 30-second project pitch

“I built an isolated Kali and Active Directory lab, generated controlled failed SMB logins, and investigated the Windows Server Security log. I identified four Event 4625 records over about four minutes, correlated the timestamps, and examined the source IP, targeted account, network logon type, and bad-password status codes. I documented the results in an incident report and proposed monitoring improvements. The key lesson was distinguishing a useful security signal from a confirmed attack.”

## Foundational questions

### 1. What is Windows Event ID 4625?
**Answer:** A failed logon recorded in the Windows Security log. I inspect the target account, source address, logon type, timestamp, and failure codes to understand the event.

### 2. What does Logon Type 3 mean?
**Answer:** A network logon, such as access to a network resource. It is different from Type 2 (interactive/local) and Type 10 (remote interactive, commonly RDP).

### 3. What is SMB?
**Answer:** Server Message Block, a Windows network protocol used for file and printer sharing and related resource access, commonly over TCP port 445.

### 4. What is a domain controller?
**Answer:** A server providing Active Directory identity and authentication services. Because it is security-critical, unexpected authentication events deserve careful review.

### 5. What is the difference between authentication and authorization?
**Answer:** Authentication verifies identity; authorization determines permissions after identity is established.

### 6. What do 0xC000006D and 0xC000006A mean?
**Answer:** The first indicates a general logon failure; the second specifies an incorrect password.

### 7. What is NTLM versus Kerberos?
**Answer:** NTLM is a Windows challenge-response authentication family; Kerberos uses tickets. Both may appear in Windows environments, but the observed event alone does not prove a specific NTLM version.

### 8. What does MSV1_0 tell you?
**Answer:** Windows used an authentication package associated with NTLM-family processing. It is useful context but does not independently prove NTLMv1 versus NTLMv2 or reveal the complete network exchange.

## Investigation and scenario questions

### 9. You see four failed logons in five minutes. Is that brute force?
**Answer:** Not automatically. I would investigate the account, source, expected activity, and whether the pattern continues or targets other identities. In my lab, the failures were controlled tests.

### 10. What would you investigate first in a 4625 event?
**Answer:** Timestamp, computer, username, source IP, logon type, status, and substatus. Then I'd compare neighboring events.

### 11. What if a successful Event 4624 appears after the failures?
**Answer:** Check whether it involves the same account, source, destination, and logon context. A nearby success alone does not prove the earlier failures led to compromise.

### 12. What if 20 different usernames fail from one source?
**Answer:** Consider password spraying or automated enumeration as hypotheses, investigate source ownership and rate, and correlate with other logs. Don't label it confirmed without evidence.

### 13. What if one account fails hundreds of times from one source?
**Answer:** Consider repeated password guessing, a stale service credential, or a broken application. Assess rate, timing, system role, and legitimate operational explanations.

### 14. What if the targeted account is a Domain Admin?
**Answer:** Prioritize context and impact assessment because a privileged account raises risk. Confirm whether the membership is intended and follow least-privilege change procedures rather than removing access blindly.

### 15. Which other Windows events help?
**Answer:** 4624 for successes; 4776 for relevant NTLM credential validation; 4771 for Kerberos pre-authentication failures; and 4768/4769 for ticket context, where applicable and logged.

### 16. How would you build a detection rule?
**Answer:** Start with 4625 and Logon Type 3, group by host, username, and source IP within a time window, and alert above a tuned threshold. Add privilege and success correlation to reduce noise.

### 17. What are false positives in this detection?
**Answer:** Mistyped passwords, stale mapped-drive credentials, outdated service passwords, or authorized testing. Baselines and context reduce false alerts.

### 18. What would Wireshark add?
**Answer:** Network packet evidence about protocol negotiation and traffic timing. I'd capture only authorized lab traffic and avoid claiming a protocol version until the packet evidence supports it.

## Questions about *your actual work*

### 19. What did you personally do?
**Answer:** Used Kali to initiate controlled failed SMB authentication, queried DC02 Windows Security logs with PowerShell, identified the four-event timeline, inspected Event 4625 details, and documented screenshots 24–26.

### 20. What was your conclusion?
**Answer:** The failures were real, logged, and traceable to the lab source in inspected evidence. No successful access or malicious activity was established. The exercise demonstrated monitoring and investigation, not exploitation.

### 21. What was the hardest part?
**Suggested authentic answer:** “Understanding what each event field could prove—and what it could not. I learned to separate observations from assumptions, especially around authentication protocols and brute-force claims.”

### 22. What would you improve next time?
**Answer:** Export the EVTX records, preserve each event's complete fields, correlate 4624 and relevant domain authentication logs, and collect an authorized packet capture for protocol-level validation.

## Hands-on troubleshooting prompts

**Scenario A:** “A user says the password is correct, but the network share keeps failing.”  
**Approach:** Confirm username/domain and connectivity, inspect 4625 status/substatus, check account state and cached/stale credentials, validate share/NTFS permissions only after authentication works.

**Scenario B:** “You find 4625 but no source IP.”  
**Approach:** Check other event fields and log sources; some authentication pathways lack useful IP attribution. Do not invent an origin.

**Scenario C:** “Your SIEM trial expired.”  
**Approach:** Continue with native Windows Event Viewer/PowerShell and preserve evidence. A SIEM improves aggregation but is not required to interpret individual Windows events.

## Quick self-test

Try answering these without notes:

- Explain **4625 vs 4624** in one sentence.
- Decode **Logon Type 3** and **0xC000006A**.
- Explain **why four failures do not prove brute force**.
- Name **two next evidence sources** and why you would check them.
- Deliver your **30-second project pitch** confidently.

**Scoring guide:** 5/5 = interview-ready for this case; 3–4/5 = review weak topics; 0–2/5 = revisit the [study notes](IR-003-Study-Notes.md).

## Resume bullet (adapt to your own experience)

- Investigated controlled SMB authentication failures in an isolated Active Directory lab; correlated Windows Security Event 4625 timelines, source IPs, logon types, and authentication failure codes; documented evidence and proposed detection and least-privilege improvements.

**Remember:** Clear reasoning and accurate scope beat exaggerated claims.
