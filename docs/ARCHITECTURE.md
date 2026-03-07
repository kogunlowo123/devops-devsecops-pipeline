# Architecture Documentation
## Enterprise DevSecOps Pipeline Framework
**Architect:** Kehinde (Kenny) Samson Ogunlowo  
**Last Updated:** March 2026  

## Design Principles
1. **Shift-Left Security** — Catch vulnerabilities at the developer workstation, not in production
2. **Compliance as Code** — HIPAA/CMMC controls enforced programmatically, not manually
3. **Zero Long-Lived Credentials** — OIDC-based cloud auth everywhere, no static keys
4. **Defense in Depth** — Multiple independent security layers (SAST → DAST → Container → Runtime)
5. **Fail Closed** — Pipeline blocks on ANY critical security finding

## Technology Decisions

### Why GitHub Actions over Jenkins?
GitHub Actions eliminates the need to manage Jenkins infrastructure, offers native OIDC integration
with AWS/Azure, and has first-class secret scanning via GitHub Advanced Security. At Cigna, 
Jenkins maintenance overhead consumed ~15% of platform team capacity.

### Why Semgrep over SonarQube for SAST?
Semgrep supports custom rules in YAML (no Java required), runs in CI in <60s for most repos, 
and has community rule packs for OWASP Top 10, Terraform, and Kubernetes. SonarQube is still
used for long-running quality gates but not the critical security blocking path.

### Why Trivy over Snyk for container scanning?
Trivy is open-source, self-hosted (no SaaS dependency), covers OS packages + app dependencies 
+ IaC + SBOM generation in a single tool. Snyk's cost at enterprise scale ($80k+/year) was 
prohibitive. Trivy achieves equivalent critical/high CVE detection rates.

### Why OPA/Rego for compliance gates?
Open Policy Agent decouples policy from pipeline logic. Compliance rules (HIPAA §164.312, 
CMMC AC-2) are version-controlled, auditable Rego files rather than opaque CI scripts. 
This was directly applicable to the Connecticut BITS Flexera implementation.

### Why OIDC over IAM Access Keys for AWS/Azure auth?
OIDC eliminates the biggest attack surface in CI/CD: stored cloud credentials. If a token is 
compromised, it's scoped to a single job run and expires in minutes. This aligns with CMMC L2 
IA.L2-3.5.3 (multi-factor authentication) and NIST 800-53 IA-5 (authenticator management).

## Pipeline Stage Timing
| Stage | Avg Duration | Parallelized |
|-------|-------------|--------------|
| Secret Detection | 45s | No (fail-fast) |
| SAST (Semgrep) | 2m 30s | Yes |
| SCA (OWASP DC) | 4m 00s | Yes |
| IaC Scan (Checkov) | 1m 15s | Yes |
| Container Build | 5m 00s | Sequential |
| Trivy Scan | 2m 00s | No |
| OPA Gate | 30s | No |
| DEV Deploy | 4m | Sequential |
| STAGING Deploy | 6m | Sequential |
| PROD Deploy | 8m | Manual gate |
| **Total (happy path)** | **~20 min** | — |

## Compliance Evidence Collection
Every pipeline run generates a `compliance-evidence.json` artifact containing:
- SBOM (Software Bill of Materials) — EO 14028 requirement
- Vulnerability scan results with remediation status
- IaC compliance check outputs mapped to NIST/CIS controls
- Deployment approval chain with actor identity
- Cosign image signature verification record

This evidence package is retained for 7 years (HIPAA §164.312(b) audit control requirement).
