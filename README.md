# Enterprise DevSecOps Pipeline Framework
### Architect: Kehinde (Kenny) Samson Ogunlowo | Principal AI Infrastructure & Security Architect

## Overview

A production-grade, end-to-end **DevSecOps pipeline** integrating security at every stage of the software delivery lifecycle (SDLC). Built from real-world experience across healthcare (HIPAA), defense (CMMC Level 2), and energy sectors. Implements **shift-left security**, automated compliance gates, container hardening, and infrastructure-as-code with full observability.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEVELOPER WORKSTATION                        │
│  pre-commit hooks → SAST (Semgrep) → Secret Scan (Gitleaks)   │
└─────────────────────────┬───────────────────────────────────────┘
                          │ git push
┌─────────────────────────▼───────────────────────────────────────┐
│                    GITHUB ACTIONS CI/CD                         │
│  Build → SAST → DAST → SCA/SBOM → Container Hardening          │
│       → Policy Check → Approval Gate → Deploy                  │
└─────────────────────────┬───────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│              DEV → STAGING → PROD (with approval gates)        │
└─────────────────────────┬───────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│         Prometheus + Grafana | ELK Stack | Azure Sentinel       │
└─────────────────────────────────────────────────────────────────┘
```

## Security Controls

| Control | Tool | Standard |
|---------|------|----------|
| SAST | Semgrep, SonarQube | OWASP ASVS |
| DAST | OWASP ZAP | OWASP Top 10 |
| Container Scan | Trivy, Grype | CIS Docker |
| Secret Detection | Gitleaks, TruffleHog | NIST 800-53 |
| IaC Scanning | Checkov, tfsec | CIS Benchmarks |
| SBOM | Syft, CycloneDX | EO 14028 |
| Policy as Code | Open Policy Agent | NIST CSF |
| Runtime Security | Falco | MITRE ATT&CK |

## Compliance Frameworks
- HIPAA, CMMC Level 2, NIST CSF, SOC 2 Type II, FedRAMP Moderate, CIS Benchmarks

## Quick Start

```bash
pre-commit install
./scripts/pre-commit-checks.sh
checkov -d terraform/ --framework terraform
cd terraform/environments/prod && terraform init && terraform plan
```

## Author
**Kehinde (Kenny) Samson Ogunlowo** — Principal AI Infrastructure & Security Architect | Active Secret Clearance
