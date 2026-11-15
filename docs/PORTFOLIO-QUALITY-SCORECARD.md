# Security Portfolio Quality Scorecard

**Assessment date:** November 2026  
**Scope:** The public `kmon28/Kali-Linux-Security-Assessment-Lab` repository.  
**Important:** This is an **internal editorial assessment**, not a score from an applicant tracking system, an external recruiter, a hiring manager, or a cybersecurity certification body. It does not predict hiring outcomes.

## Standard for every case study

A strong report should let three readers find what they need:

1. **Recruiter (30 seconds):** Plain-English problem, tools/skills, measured result, and honest scope.
2. **SOC hiring manager (3 minutes):** Triage question, data sources, event sequence, evidence, response, and disposition.
3. **Security engineer (10 minutes):** Original screenshots and source artifacts, detection logic, reproducible commands, validation, false positives, limitations, and accurate security claims.

## Weighted rubric (100 points)

| Category | Weight | What earns full credit |
| --- | ---: | --- |
| Plain-English project overview | 15 | Problem, approach, findings, scope and outcomes understood without specialist knowledge |
| Technical accuracy and claim discipline | 20 | Observations vs interpretations separated; no invented attacker, compromise, or validation |
| Original evidence and accessibility | 20 | Legible screenshots beside analysis, working clickable links, timestamps and evidence provenance |
| Detection and investigation depth | 15 | Explainable methods, commands, data sources, results and false-positive reasoning |
| Reproducibility and source availability | 15 | Original safe scripts, sample inputs, setup, expected output, limitations |
| Response and outcome verification | 10 | Containment/remediation checks and documented result |
| Navigation and presentation | 5 | Consistent titles, summaries, readable mobile GitHub Markdown |
| **Total** | **100** | |

## Current editorial assessment

**Provisional repository score: 78/100 (strong presentation foundation; incomplete reproducibility).**

This is a **judgment-based working estimate** based on inspecting report text and the GitHub screenshot inventory, **not** an independently validated score. The audit has not executed every script, reviewed each screenshot pixel-by-pixel, verified every external link, or tested every procedure. Those gaps prevent a defensible “perfect” rating.

| Area | Provisional score | Rationale |
| --- | ---: | --- |
| Plain-English overview | 14/15 | All 16 IR reports now include a recruiter-oriented overview or equivalent |
| Technical accuracy | 17/20 | Reports frequently distinguish controlled tests from actual compromise; full expert peer review remains pending |
| Evidence | 15/20 | Multiple reports now embed clickable original images; screenshot content and all links still require detailed review |
| Investigation depth | 12/15 | Case reports document event correlation, process attribution and detection, with varying detail |
| Reproducibility | 7/15 | Original source and raw artifacts are not consistently published or independently tested |
| Response verification | 9/10 | Many cases document validation; depth varies by project |
| Navigation and presentation | 4/5 | Plain-English overviews added across IR-001 through IR-015; root navigation can be simplified |
| **Total** | **78/100** | **Internal provisional assessment** |

## Inventory and remaining work

- **16 numbered IR reports** exist (IR-001 through IR-015, with two separate IR-005 reports).
- All 16 now contain a plain-English project overview or equivalent.
- Screenshot galleries were added to reports that previously linked images without displaying them (IR-001, IR-002, IR-003 and IR-008).
- Other reports' existing screenshot images were made clickable when the corresponding repository filename was verified.
- **Next:** Review screenshots individually for legibility, context and private details; add captions with specific observed values and limitations where generic.
- **Next:** Upload and test the **original** scripts and safe evidence files, including IR-015; do not reconstruct source code from screenshots and present it as original.
- **Next:** Audit every report link and Markdown render on mobile and desktop; remove duplicate or outdated navigation.
- **Next:** Complete a technical review for factual accuracy and reproducibility, including case-by-case MITRE ATT&CK mappings where supported.
- **Next:** Add a short recruiter-facing featured-project index to the root README and align the other related repositories.

## Publishing rules

- Never claim a real compromise when the evidence is a controlled simulation.
- Never describe a heuristic risk score as a malware probability.
- Never publish credentials, NTLM challenge-response captures, personal identifiers, or raw sensitive evidence.
- Never claim source code or artifacts were uploaded before verifying they exist.
- Screenshots should be original, relevant, readable, clickable, and accompanied by **what the image shows**, **why it matters**, and **what it does not prove**.
- The goal is a credible, verifiable portfolio—not maximizing a made-up score.
