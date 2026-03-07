# HIPAA Technical Safeguard Compliance Policy
# Architect: Kehinde (Kenny) Samson Ogunlowo
# OPA Rego policy for automated HIPAA compliance validation

package compliance.hipaa

import future.keywords.in

default allow = false

# Allow deployment only when all HIPAA controls pass
allow {
    encryption_at_rest_compliant
    encryption_in_transit_compliant  
    audit_logging_enabled
    access_controls_compliant
    no_critical_vulnerabilities
}

# §164.312(a)(2)(iv) - Encryption and Decryption
encryption_at_rest_compliant {
    input.controls["HIPAA-164.312-a-2-iv"].status == "PASS"
}

# §164.312(e)(2)(ii) - Encryption in Transit
encryption_in_transit_compliant {
    input.infrastructure.tls_version >= "1.2"
    input.infrastructure.certificate_valid == true
}

# §164.312(b) - Audit Controls
audit_logging_enabled {
    input.controls["HIPAA-164.312-b"].status == "PASS"
    input.infrastructure.cloudtrail_enabled == true
    input.infrastructure.log_retention_days >= 2557  # 7 years
}

# §164.312(a)(1) - Access Control
access_controls_compliant {
    input.controls["HIPAA-164.312-a-1"].status == "PASS"
    input.infrastructure.mfa_enabled == true
}

# Zero tolerance for critical vulnerabilities in PHI environments
no_critical_vulnerabilities {
    count([v | v := input.vulnerabilities[_]; v.severity == "CRITICAL"]) == 0
}

# Violations report
violations[msg] {
    not encryption_at_rest_compliant
    msg := "HIPAA §164.312(a)(2)(iv): Encryption at rest not validated"
}

violations[msg] {
    not audit_logging_enabled
    msg := "HIPAA §164.312(b): Audit logging not compliant (requires 7-year retention)"
}

violations[msg] {
    not no_critical_vulnerabilities
    count_critical := count([v | v := input.vulnerabilities[_]; v.severity == "CRITICAL"])
    msg := sprintf("HIPAA: %v critical vulnerabilities found - PHI environments require zero", [count_critical])
}
