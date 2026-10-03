# CyberAssess — Ubuntu Security Baseline Control Master Table

| ID | Control | Severity | Source | Key | Operator | Expected | NIST |
|---|---|---|---|---|---|---|---|
| SSH-001 | Disable direct SSH root login | HIGH | sshd | PermitRootLogin | EQUALS | no | AC-6 |
| SSH-002 | Disable SSH password authentication | HIGH | sshd | PasswordAuthentication | EQUALS | no | IA-2 |
| SSH-003 | Limit SSH MaxAuthTries to 4 or lower | MEDIUM | sshd | MaxAuthTries | LESS_OR_EQUAL | 4 | AC-7 |
| SSH-004 | Disable SSH X11 forwarding | LOW | sshd | X11Forwarding | EQUALS | no | CM-7 |
| SSH-005 | Configure SSH idle timeout | MEDIUM | sshd | ClientAliveInterval | GREATER_OR_EQUAL | 1 | AC-12 |
| NET-001 | Host firewall is active | HIGH | firewall | status | EQUALS | active | SC-7 |
| FILE-001 | /etc/shadow permissions are 640 or stricter | HIGH | files | shadow_mode | MODE_AT_MOST | 640 | AC-6 |
| FILE-002 | /etc/passwd permissions are 644 or stricter | MEDIUM | files | passwd_mode | MODE_AT_MOST | 644 | CM-6 |
| AUTH-001 | No local accounts have an empty password field | HIGH | accounts | empty_password_count | EQUALS | 0 | IA-5 |
| AUTH-002 | Only root has UID 0 | HIGH | accounts | uid0_nonroot_count | EQUALS | 0 | AC-6 |
| AUTH-003 | Minimum password length is 14 or more | MEDIUM | password_policy | minimum_length | GREATER_OR_EQUAL | 14 | IA-5 |
| LOG-001 | Audit service is active | MEDIUM | auditd | status | EQUALS | active | AU-12 |
| UPD-001 | Automatic security updates are enabled | MEDIUM | updates | enabled | EQUALS | true | SI-2 |
| TIME-001 | Time synchronization is active | LOW | time_sync | status | EQUALS | active | AU-8 |
| SVC-001 | Telnet server is not installed | HIGH | services | telnet_installed | EQUALS | false | CM-7 |

## Evaluation Semantics

- PASS: Live evidence was collected successfully and satisfies the configured baseline rule.
- FAIL: Live evidence was collected successfully but does not satisfy the baseline rule.
- ERROR: CyberAssess could not reliably determine the control state because evidence collection or parsing failed.
- GAP: Any control with a FAIL result is included in the remediation/gap report.

## Assessment Scope

This baseline evaluates 15 selected Ubuntu security controls. A 100% compliance score means that all 15 configured controls passed at scan time. It does not mean that the target system is completely secure or certified against the full CIS Benchmark.
