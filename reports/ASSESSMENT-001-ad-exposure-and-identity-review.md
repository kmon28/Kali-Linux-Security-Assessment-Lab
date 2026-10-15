# ASSESSMENT-001 — Domain Controller Exposure and Identity Review

**Type:** Authorized Active Directory lab enumeration and configuration review  
**Target:** DC02, `192.168.56.101`, `lab.local`  
**Evidence:** [03 — service enumeration](../screenshots/03-DC02-Service-Enumeration.png), [04 — SMB signing](../screenshots/04-DC02-SMB-Security-Mode.png), [05 — LDAP RootDSE](../screenshots/05-Active-Directory-LDAP-Enumeration.png), [06 — directory identities](../screenshots/06-Authenticated-AD-User-Enumeration.png), [07 — Domain Admins](../screenshots/07-Privileged-Group-Enumeration.png)

## Summary
The domain controller exposes expected Active Directory services within the lab subnet. SMB signing is **enabled and required** in the observed SMB 3.1.1 response. LDAP queries return domain naming contexts and, in a separately authenticated query, directory identity and privileged group information.

A privileged-group query lists `socuser` and `Administrator` as `Domain Admins` members. This is a **privilege review finding**, not evidence of exploitation or unauthorized membership.

## Findings matrix

| ID | Observation | Security significance | Confidence |
|---|---|---|---|
| AD-01 | TCP ports `53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985` shown open; 988 default-scan ports filtered | Expected AD service footprint; access should be scoped to appropriate hosts | High for observed scan, not full port coverage |
| AD-02 | SMB 3.1.1 signing enabled **and required** | Positive hardening control that mitigates certain SMB relay/tampering scenarios | High for scanned DC02 endpoint |
| AD-03 | LDAP RootDSE returns `DC=lab,DC=local` and naming partitions | Directory service discoverability; not proof of unrestricted anonymous object reads | High |
| AD-04 | Authenticated LDAP output includes user `socuser` and a computer account | Demonstrates authenticated directory enumeration | High for visible entries; not a complete inventory |
| AD-05 | `Domain Admins` members include `socuser` and `Administrator` | Review whether `socuser` genuinely requires Tier-0 privileges | High for membership at capture time; authorization unknown |

## Recommended follow-up validation
1. Compare exposed services against the DC's intended role and restrict access by network segment, host firewall, and administrative policy.
2. Verify SMB signing settings via Group Policy and effective configuration on both clients and servers.
3. Review `socuser` membership with a documented business justification; if unnecessary, remove elevated membership through an approved change and retest.
4. Assess LDAPS certificate validation, LDAP signing/channel-binding configuration, and credential handling in the lab.
5. Capture and retain sanitized Nmap XML, LDAP LDIF excerpts, and configuration exports to strengthen reproducibility.

## Boundaries
No password extraction, successful exploitation, privilege escalation, or unauthorized access is demonstrated. Nmap's version/service labels are fingerprints that may require corroboration. An open port is not itself a vulnerability.
