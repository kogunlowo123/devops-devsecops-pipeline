#!/bin/bash
# Pre-commit Security Checks — Enterprise DevSecOps
# Architect: Kehinde (Kenny) Samson Ogunlowo
# Runs locally before any git push to catch issues shift-left
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0

log_pass() { echo -e "${GREEN}✅ PASS${NC}: $1"; ((PASS++)); }
log_fail() { echo -e "${RED}❌ FAIL${NC}: $1"; ((FAIL++)); }
log_warn() { echo -e "${YELLOW}⚠️  WARN${NC}: $1"; }

echo "============================================================"
echo "  Enterprise DevSecOps Pre-Commit Security Checks"
echo "  Architect: Kehinde (Kenny) Samson Ogunlowo"
echo "============================================================"

# 1. Secret Detection (Gitleaks)
echo -e "\n[1/6] Running Gitleaks secret scan..."
if command -v gitleaks &>/dev/null; then
  if gitleaks detect --source . --no-git -q 2>/dev/null; then
    log_pass "No secrets detected"
  else
    log_fail "SECRETS DETECTED — commit blocked. Run: gitleaks detect --report-format json"
    exit 1
  fi
else
  log_warn "gitleaks not installed. Install: brew install gitleaks"
fi

# 2. Semgrep SAST
echo -e "\n[2/6] Running Semgrep SAST..."
if command -v semgrep &>/dev/null; then
  if semgrep --config=auto --quiet --error . 2>/dev/null; then
    log_pass "Semgrep: No critical issues"
  else
    log_fail "Semgrep found security issues. Run: semgrep --config=auto ."
  fi
else
  log_warn "semgrep not installed: pip install semgrep"
fi

# 3. Terraform Format Check
echo -e "\n[3/6] Checking Terraform formatting..."
if command -v terraform &>/dev/null; then
  if terraform fmt -check -recursive terraform/ 2>/dev/null; then
    log_pass "Terraform formatting OK"
  else
    log_fail "Terraform not formatted. Run: terraform fmt -recursive terraform/"
  fi
fi

# 4. Checkov IaC Scan
echo -e "\n[4/6] Running Checkov IaC scan..."
if command -v checkov &>/dev/null; then
  if checkov -d terraform/ --framework terraform --quiet 2>/dev/null; then
    log_pass "Checkov: No critical IaC misconfigurations"
  else
    log_warn "Checkov found issues — review before push"
  fi
fi

# 5. Dockerfile Lint
echo -e "\n[5/6] Linting Dockerfiles..."
if command -v hadolint &>/dev/null; then
  find . -name "Dockerfile*" | while read f; do
    if hadolint "$f" 2>/dev/null; then
      log_pass "Dockerfile OK: $f"
    else
      log_warn "Dockerfile issues in: $f"
    fi
  done
fi

# 6. Python Bandit Security Scan
echo -e "\n[6/6] Running Bandit Python security scan..."
if command -v bandit &>/dev/null; then
  if bandit -r . -ll -q 2>/dev/null; then
    log_pass "Bandit: No high-severity Python security issues"
  else
    log_fail "Bandit found high-severity issues"
  fi
fi

echo ""
echo "============================================================"
echo "  Results: ${PASS} PASSED | ${FAIL} FAILED"
echo "============================================================"
[[ $FAIL -eq 0 ]] && echo -e "${GREEN}✅ All checks passed — safe to push${NC}" || { echo -e "${RED}🚫 Fix failures before pushing${NC}"; exit 1; }
