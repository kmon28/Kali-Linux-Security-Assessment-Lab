# Kali Linux Security Assessment & Investigation Lab

> **Hands-on security assessment portfolio:** a controlled Kali Linux lab for developing repeatable network reconnaissance, service-enumeration, validation, and defensive investigation skills.

![Kali Linux](https://img.shields.io/badge/Platform-Kali_Linux-2874A6?style=flat-square)
![Network Security](https://img.shields.io/badge/Focus-Network_Security-1679A7?style=flat-square)
![Methodology](https://img.shields.io/badge/Methodology-Evidence_Driven-4B5563?style=flat-square)
![Status](https://img.shields.io/badge/Status-Evidence_Review_Pending-D69E2E?style=flat-square)

## Executive Summary

This repository documents a **controlled, authorized Kali Linux practice environment**. Its purpose is to show not only how security tools are used, but also how results are interpreted, corroborated, and communicated to defenders.

**Current evidence status:** The repository structure and documentation are prepared. Four previously captured Kali screenshots are awaiting upload and review. No scan results, open ports, vulnerabilities, successful exploits, or completed remediation are claimed here until verified from the actual evidence.

## Assessment Workflow

| Phase | Analyst objective | Evidence to preserve |
|---|---|---|
| 1. Scope | Define authorized targets, boundaries, and test purpose | Lab topology and target inventory |
| 2. Discovery | Identify live hosts in the isolated environment | Commands, output, timestamps |
| 3. Enumeration | Identify exposed services and versions | Service/port evidence |
| 4. Validation | Corroborate findings and assess risk without assuming exploitation | Screenshots, raw output, limitations |
| 5. Defensive analysis | Explain relevant detection opportunities and investigation steps | Logs, network observations, hypotheses |
| 6. Reporting | Document observations, impact, remediation, and verification | Reproducible technical report |

## Repository Structure

```text
Kali-Linux-Security-Assessment-Lab/
├── README.md
├── screenshots/    # Original evidence images
├── reports/        # Assessment findings and case reports
├── commands/       # Reproducible commands with explanations
└── docs/           # Scope, topology, methodology, limitations
```

## Evidence and Findings

**Evidence review pending.** Once the original Kali screenshots are uploaded, this section will identify each artifact, the tool or command shown, the target and result (where visible), and the justified technical conclusion.

Findings will be classified as:
- **Observed:** directly supported by tool output, packet evidence, or a screenshot.
- **Inferred:** plausible interpretation requiring further validation.
- **Not established:** conclusions that cannot be supported by the available evidence.

## Defensive Relevance

The objective is to connect assessment activity to practical blue-team questions: What would the traffic or host logs show? Which behaviors might merit investigation? What corroborating telemetry is missing? What change would reduce exposure, and how would it be verified?

This project complements the [Windows SOC Detection & Threat Hunting Lab](https://github.com/kmon28/Windows-SOC-Detection-Lab) and [Network Traffic Analysis & Active Directory Investigation](https://github.com/kmon28/Network-Traffic-Analysis-Lab).

## Safety and Scope

Only isolated lab assets or systems explicitly authorized for testing are in scope. This repository is not evidence of a production engagement. Any future exploit-validation exercise will be documented as a controlled simulation, with limitations clearly stated.

## Next Documentation Steps

1. Upload the original Kali screenshots to `screenshots/`.
2. Identify the exact commands, tools, hosts, and results shown in each image.
3. Populate `reports/`, `commands/`, and `docs/` using only confirmed details.
4. Add screenshot links and an evidence-to-finding matrix to this README.
