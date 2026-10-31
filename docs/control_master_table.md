# CyberAssess — Baseline Control Coverage and NIST References

There are **40 defined checks across three separate profiles**: 15 Ubuntu,
13 Windows and 12 macOS. One assessment evaluates only its selected profile.
These are configuration checks associated with relevant controls in
[NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final), not
complete implementations of those controls or a full CIS Benchmark. NIST
references are a traceability aid; a PASS is not a framework certification.
Values such as 14 characters, 900 seconds and four attempts are selected
CyberAssess baseline thresholds, not universal NIST mandates; approve their
applicability with the system owner before using them for grading.

## Ubuntu v1 — 15 controls

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

- PASS: Reliable evidence satisfies the configured baseline rule. Demonstration results use explicitly labelled sample evidence.
- FAIL: Reliable evidence does not satisfy the configured baseline rule; this is distinct from an unavailable read.
- ERROR: CyberAssess could not reliably determine the control state because evidence collection or parsing failed.
- GAP: Any control with a FAIL result is included in the remediation/gap report.

## Assessment Scope

The Ubuntu profile evaluates the 15 rules above; Windows and macOS use their own rules below. A 100% score means all configured rules in the selected profile passed at collection time. It does not establish complete security, clock accuracy, full framework coverage or certification. ERROR retains its weight in the score denominator; review evidence limitations even when the numerical verdict is Compliant.


## Windows v1 — 13 controls

| ID | Control | Severity | Evidence key | Rule / expected | NIST |
| --- | --- | --- | --- | --- | --- |
| WIN-DEF-001 | Microsoft Defender antivirus is enabled | HIGH | `defender.antivirus_enabled` | `EQUALS true` | SI-3 |
| WIN-DEF-002 | Microsoft Defender real-time protection is enabled | HIGH | `defender.realtime_enabled` | `EQUALS true` | SI-3 |
| WIN-NET-001 | All three Windows firewall profiles are enabled | HIGH | `firewall.all_profiles_enabled` | `EQUALS true` | SC-7 |
| WIN-ENC-001 | BitLocker OS-volume protection is on | HIGH | `bitlocker.protection_enabled` | `EQUALS true` | SC-28 |
| WIN-RDP-001 | Remote Desktop connections are disabled | HIGH | `rdp.disabled` | `EQUALS true` | CM-7 |
| WIN-RDP-002 | Remote Desktop Network Level Authentication is required | MEDIUM | `rdp_nla.required` | `EQUALS true` | IA-2 |
| WIN-ACC-001 | The built-in local Guest account is disabled | HIGH | `guest.disabled` | `EQUALS true` | AC-2 |
| WIN-ACC-002 | User Account Control is configured as enabled | HIGH | `uac.enabled` | `EQUALS true` | AC-6 |
| WIN-SMB-001 | The SMBv1 server protocol is disabled | HIGH | `smb.smb1_disabled` | `EQUALS true` | CM-7 |
| WIN-LOCK-001 | Machine inactivity limit is explicitly non-zero | MEDIUM | `inactivity.timeout_seconds` | `GREATER_OR_EQUAL 1` | AC-11 |
| WIN-LOCK-002 | Machine inactivity limit is at most 900 seconds | MEDIUM | `inactivity.timeout_seconds` | `LESS_OR_EQUAL 900` | AC-11 |
| WIN-BOOT-001 | UEFI Secure Boot is enabled | MEDIUM | `secure_boot.enabled` | `EQUALS true` | SI-7 |
| WIN-LOG-001 | The Windows Event Log service is running | MEDIUM | `eventlog.running` | `EQUALS true` | AU-12 |


## macOS v1 — 12 controls

| ID | Control | Severity | Evidence key | Rule / expected | NIST |
| --- | --- | --- | --- | --- | --- |
| MAC-001 | FileVault is enabled | HIGH | `filevault.enabled` | `EQUALS true` | SC-28 |
| MAC-002 | Application Firewall is enabled | HIGH | `application_firewall.enabled` | `EQUALS true` | SC-7 |
| MAC-003 | System Integrity Protection is fully enabled | HIGH | `system_integrity.enabled` | `EQUALS true` | SI-7 |
| MAC-004 | Gatekeeper assessments are enabled | HIGH | `gatekeeper.enabled` | `EQUALS true` | CM-7 |
| MAC-005 | Automatic update checking preference is enabled | MEDIUM | `update_check.enabled` | `EQUALS true` | SI-2 |
| MAC-006 | Automatic update download preference is enabled | MEDIUM | `update_download.enabled` | `EQUALS true` | SI-2 |
| MAC-007 | Critical update installation preference is enabled | HIGH | `security_updates.enabled` | `EQUALS true` | SI-2 |
| MAC-008 | System data update installation preference is enabled | MEDIUM | `system_data_updates.enabled` | `EQUALS true` | SI-2 |
| MAC-009 | Remote Login is disabled | MEDIUM | `remote_login.enabled` | `EQUALS false` | CM-7 |
| MAC-010 | Current-user screen saver password preference is enabled | MEDIUM | `screen_lock.password_required` | `EQUALS true` | AC-11 |
| MAC-011 | Current-user screen saver password delay preference is zero | MEDIUM | `screen_lock_delay.seconds` | `LESS_OR_EQUAL 0` | AC-11 |
| MAC-012 | Network time configuration is enabled | LOW | `network_time.enabled` | `EQUALS true` | AU-8 |


## Source and interpretation limits

- Ubuntu SSH-005 checks a non-zero `ClientAliveInterval`. Despite its historical
  idle-timeout title, SSH keepalives do not by themselves enforce an interactive
  idle-session timeout or satisfy all of AC-12. No control condition was changed.
- AUTH-003 checks explicit password-quality configuration, not every PAM stack,
  application, identity provider or possible password-enforcement path. Unreadable
  or contradictory configured evidence cannot establish a stronger minimum.
- Windows checks the native properties named in `config/profiles/windows.json`;
  for example, SMBv1 server state does not cover every SMB client feature, and
  Defender flags do not attest an approved third-party antivirus product.
- macOS control descriptions retain their original baseline wording. Actual
  MAC-005/009/010/011/012 collection now prefers bounded native effective status,
  scoped CoreFoundation values and independently verified managed policy where
  available. See the [source-of-truth table](macos-remaining-four.md#evidence-used-by-each-control)
  and [macOS read-only prerequisites](macos-live-collection.md).
- MAC-005 can legitimately remain ERROR when modern macOS exposes no reliable
  automatic-check scalar. MAC-012 requires native On/Off or a verified forced
  automatic-time policy; a running `timed` process, server name or missing key
  does not establish it. Permission denial stays ERROR, with no automatic sudo.
- A configured delay or update flag is not proof of current screen lock, clock
  synchronization success, installed patches, exploitation resistance or full
  policy enforcement. The report labels configured versus effective evidence.

The JSON control files are authoritative for IDs, conditions, expected values,
severity and NIST associations. The shared evaluator and severity weights remain
unchanged. Review the [requirement map and acceptance checklist](HANDOVER.md)
with a supervisor before adopting a profile as an organization's grading policy.
