# Kerberos Service Ticket Detection Engineering — Event 4769

**Use case:** Identify legacy RC4 Kerberos service-ticket issuance and triage potentially suspicious ticket-request patterns. **Platform used in this case:** Windows Security Event Logs and PowerShell, not Splunk. The prior Splunk trial has expired.

## Detection Hypothesis

An Event **4769** with the named field `TicketEncryptionType = 0x17` identifies a Kerberos service ticket issued using RC4. This may reflect a legacy application, compatibility behavior, or a potential Kerberoasting-related lead. It is **not** sufficient to declare an attack.

### Telemetry prerequisites

- Collect domain-controller **Security** Event 4769.
- Enable the **Kerberos Service Ticket Operations** audit subcategory through appropriate policy.
- Retain event XML or parsed fields including `ServiceName`, `TargetUserName` (when present), `IpAddress`, `TicketEncryptionType`, `Status`, and event timestamp.
- Confirm field names in the actual OS/event schema; some Windows versions differ.

### Detection logic

```text
WHEN EventID = 4769
 AND TicketEncryptionType = 0x17
THEN record RC4 service-ticket issuance
 AND enrich with service account/SPN, requester, source address, volume, and history
 AND triage rather than automatically classify as malicious
```

**PowerShell example:** See [field-specific query](../commands/kerberos-command-reference.md#event-4769-hunting).

## Triage Playbook

1. **Validate the event:** confirm 4769, `TicketEncryptionType=0x17`, and `Status/Failure Code=0x0`; identify the DC and time.
2. **Attribute:** examine requesting account, service/SPN, source address, and whether the source is a known workstation or the DC itself.
3. **Baseline:** compare RC4 use for this service and client over time. Check whether a legacy service requires RC4.
4. **Look for patterns:** bursts of service-ticket requests across many SPNs, unusual account/client combinations, off-hours anomalies, or nearby identity/endpoint events. Thresholds should be tuned to the environment, not invented from one lab sample.
5. **Correlate:** use Event 4768, 4624/4625, directory changes, Sysmon process/network data, and any available packet captures to support or reject hypotheses.
6. **Respond proportionally:** review service-account configuration, rotate exposed credentials if independently justified, prefer AES where supported, and verify functionality after changes.
7. **Close with evidence:** record finding, confidence, actions, remaining unknowns, and retest output.

## False Positives and Blind Spots

- Legitimate legacy services/clients can use RC4.
- A **single** successful RC4 ticket does not demonstrate cracking, extraction, or compromise.
- A string search for `0x17` anywhere in a message can match the wrong field; parse `TicketEncryptionType` specifically.
- Missing auditing, short retention, incomplete endpoint telemetry, and time skew can impair correlation.
- An AES-256 retest for one SPN does **not** establish that RC4 is eliminated throughout the domain.

## MITRE ATT&CK Mapping

| Technique | Relationship to this case |
|---|---|
| [T1558.003 — Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) | **Relevant hypothesis only.** RC4 service tickets can matter in Kerberoasting investigations, but no ticket cracking or adversary action was demonstrated. |
| [T1558 — Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/) | Broader contextual technique family; **not observed** in this exercise. |

## Lab Validation — October 17, 2026

| Test | Evidence | Outcome |
|---|---|---|
| Baseline service-ticket request | [Screenshot 22](../screenshots/22-Kerberos-RC4-Investigation.png) | 4769, service `svc-kerberos-lab`, `0x17` (RC4), `0x0` success, source `::1` |
| Encryption hardening / fresh ticket | [Screenshot 23](../screenshots/23-Kerberos-AES256-Final-Verification.png) | 4769, same service, `0x12` (AES-256), `0x0` success |
| Account encryption support | [Screenshot 19](../screenshots/19-Kerberos-AES256-Comparison.png) | `msDS-SupportedEncryptionTypes=24` (decimal), AES-128 + AES-256 |

**Disposition:** Verified scoped improvement in ticket encryption; **no confirmed attack**. This document is a detection design and investigation guide, not a claim that an automated alert was deployed.

## Next Iteration

Implement the field-parsed analytic in an accessible SIEM such as Wazuh or Elastic, **after** validating installation and log ingestion. Generate controlled baseline and noisy events, measure false positives, and document alert-to-investigation-to-response. Do not depend on the expired Splunk trial.

**Related:** [IR-002 case study](../reports/IR-002-kerberos-rc4-aes256-hardening.md).
