# =============================================================================
# OPA Rego Policy — Container Security
# Author: Kehinde (Kenny) Samson Ogunlowo
# Enforces CIS Docker Benchmark + HIPAA + NIST 800-53 controls
# =============================================================================

package container.security

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# ── Deny running as root ──────────────────────────────────────────────────────
deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.securityContext.runAsNonRoot == true
    msg := sprintf("Container '%v' must not run as root (NIST SI-3, CIS 4.1)", 
                   [container.name])
}

deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.runAsUser == 0
    msg := sprintf("Container '%v' is configured to run as UID 0 (root)", 
                   [container.name])
}

# ── Deny privileged containers ────────────────────────────────────────────────
deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("Container '%v' must not be privileged (CIS 4.2, NIST SC-7)", 
                   [container.name])
}

# ── Require read-only root filesystem ─────────────────────────────────────────
deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf("Container '%v' must use read-only root filesystem (CIS 4.4)", 
                   [container.name])
}

# ── Deny privilege escalation ─────────────────────────────────────────────────
deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container '%v' must set allowPrivilegeEscalation=false (CIS 4.5)", 
                   [container.name])
}

# ── Require resource limits (prevent DoS) ─────────────────────────────────────
deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("Container '%v' must have memory limits set (NIST SC-5)", 
                   [container.name])
}

deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.resources.limits.cpu
    msg := sprintf("Container '%v' must have CPU limits set", [container.name])
}

# ── Require security labels ───────────────────────────────────────────────────
required_labels := {
    "app.kubernetes.io/name",
    "app.kubernetes.io/version",
    "security.scan",
    "compliance"
}

deny contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet"]
    label := required_labels[_]
    not input.metadata.labels[label]
    msg := sprintf("Resource '%v' missing required label: %v", 
                   [input.metadata.name, label])
}

# ── Deny latest image tag ──────────────────────────────────────────────────────
deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    endswith(container.image, ":latest")
    msg := sprintf("Container '%v' must not use ':latest' tag — pin to digest (NIST CM-6)", 
                   [container.name])
}

deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not contains(container.image, ":")
    msg := sprintf("Container '%v' must specify an explicit image tag", [container.name])
}

# ── Require image from trusted registry ───────────────────────────────────────
trusted_registries := [
    "ghcr.io/",
    "our-registry.azurecr.io/",
    "our-registry.dkr.ecr.us-east-1.amazonaws.com/"
]

deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not any_trusted_registry(container.image)
    msg := sprintf("Container '%v' image must come from a trusted registry", 
                   [container.name])
}

any_trusted_registry(image) if {
    registry := trusted_registries[_]
    startswith(image, registry)
}

# ── Require network policies ──────────────────────────────────────────────────
warn contains msg if {
    input.kind == "Namespace"
    not has_network_policy(input.metadata.name)
    msg := sprintf("Namespace '%v' should have a NetworkPolicy (NIST SC-7)", 
                   [input.metadata.name])
}

has_network_policy(namespace) if {
    # This would check against the cluster state in a real implementation
    namespace != "kube-system"
}

# ── Deny hostNetwork / hostPID / hostIPC ──────────────────────────────────────
deny contains msg if {
    input.kind == "Pod"
    input.spec.hostNetwork == true
    msg := "Pod must not use host network namespace (CIS 5.2.4)"
}

deny contains msg if {
    input.kind == "Pod"
    input.spec.hostPID == true
    msg := "Pod must not share host PID namespace (CIS 5.2.2)"
}

deny contains msg if {
    input.kind == "Pod"
    input.spec.hostIPC == true
    msg := "Pod must not share host IPC namespace (CIS 5.2.3)"
}

# ── Require seccomp profile ───────────────────────────────────────────────────
deny contains msg if {
    input.kind == "Pod"
    not input.metadata.annotations["seccomp.security.alpha.kubernetes.io/pod"]
    not input.spec.securityContext.seccompProfile
    msg := "Pod must have seccomp profile defined (NIST SI-3)"
}
