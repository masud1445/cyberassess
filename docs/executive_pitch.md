# Executive Pitch — CyberAssess

CyberAssess is a lightweight automated cybersecurity baseline assessment tool for SMEs, IT teams, analysts, training providers and students. It performs read-only evidence collection from authorized Ubuntu/Linux systems over SSH, evaluates 15 security controls, maps findings to NIST SP 800-53 references, and generates prioritized remediation guidance.

## Business value
- **Faster checks:** replaces repetitive manual baseline inspection with a repeatable automated workflow.
- **Consistent evidence:** the same controls and operators are applied on each run.
- **Risk prioritization:** findings are grouped by severity and category.
- **Clear remediation:** reports show expected state, observed state, evidence and suggested next action.
- **Measurable improvement:** teams can remediate approved gaps and rerun the assessment to demonstrate progress.

## Current capabilities
CyberAssess checks SSH hardening, firewall status, sensitive file permissions, local accounts, password policy, audit logging, unattended security updates, time synchronization and Telnet exposure. It generates machine-readable JSON plus a client-ready HTML/PDF-friendly report.

## Scope
CyberAssess is an entry-level compliance-readiness and teaching tool. It supports internal hardening and awareness workflows but does not replace a formal certified audit, vulnerability assessment or penetration test.
