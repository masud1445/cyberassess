# macOS live collection troubleshooting

An operator reported MAC-005, MAC-009, MAC-010, MAC-011 and MAC-012 as ERROR on
an Apple M1 running macOS Tahoe 26.5.1. The development environment is Linux:
the fixes below are covered by injected native-command tests, but have not
been validated on that Mac. The OS version alone does not establish whether
each original error was a missing preference, denied read or unsupported output.

The collector retains every successful original read. If a read fails, it tries
only the following read-only alternatives. It does not use sudo, prompt for
credentials, change settings or change user accounts. Each command has a
10-second timeout; missing tools and denied reads stay unavailable.

| Control | Original read | Fallback and limits |
| --- | --- | --- |
| MAC-005 | Machine `com.apple.SoftwareUpdate` / `AutomaticCheckEnabled` | `plutil -extract AutomaticCheckEnabled xml1 -o - /Library/Preferences/com.apple.SoftwareUpdate.plist`. Only an explicit Boolean or 0/1 integer is accepted. |
| MAC-009 | `systemsetup -getremotelogin` | `launchctl print-disabled system`. Exactly one `com.openssh.sshd` entry is required. `disabled` / `true` means Remote Login disabled; `enabled` / `false` means enabled. Missing, duplicate or ambiguous entries are ERROR, even when no SSH process is running. |
| MAC-010 | Invoking-user `com.apple.screensaver` / `askForPassword` | `plutil` extracts that exact key from the invoking user's `Library/Preferences/com.apple.screensaver.plist`. Only an explicit Boolean or 0/1 integer is accepted. |
| MAC-011 | Invoking-user `com.apple.screensaver` / `askForPasswordDelay` | `plutil` extracts that exact key from the same plist. Only a finite, nonnegative numeric scalar within the supported range is accepted. Zero passes; a positive delay fails. An absent value is never treated as zero. |
| MAC-012 | `systemsetup -getusingnetworktime` | `defaults read /Library/Preferences/com.apple.timed TMAutomaticTimeOnlyEnabled`, then exact-key `plutil` extraction if needed. This establishes an explicit automatic-time configuration, not successful synchronization, server accuracy or MDM enforcement. |

The user plist path comes from the process user's account record. `HOME`,
`SUDO_USER` and the console user's identity do not select another user's plist.
The collector does not read ByHost or managed preference stores as substitutes
for the existing current-user controls. Raw command output and private paths
are discarded; retained diagnostics identify the limitation without copying
native stderr into reports.

## Missing preferences and permissions

MAC-005, MAC-010 and MAC-011 explicitly assess named preference keys. Those
keys can be absent even when System Settings shows a secure effective policy.
That remains ERROR under this baseline. In particular, `softwareupdate
--schedule` can report a resolved automatic-check setting and `sysadminctl`
can report a lock state, but neither establishes that the required explicit
key exists. The collector must not turn those different observations into a
PASS for the existing controls.

Review an unavailable key with the device owner; do not create preferences or
change security settings just to eliminate an assessment error. If a native
query remains permission denied, arrange approved read access for that specific
query or retain the limitation. Running the whole assessment with sudo changes
the screen-saver user scope and is not a general solution.

## Acceptance on the reported Mac

Run as the intended assessment user from the repository root:

```bash
.venv/bin/python -m pytest tests/test_macos_collector.py -q
.venv/bin/python main.py --profile macos --local --output reports/macos-live-validation
```

The first command tests fixtures; it does not validate native security reads.
The second performs the authorized live read. Record macOS release, architecture,
whether the terminal was elevated, and the five control statuses and collection
diagnostics. Review the matching JSON as well as HTML. Confirm the intended user
scope and independently compare any recovered scalar with its source before
acceptance. Share only redacted diagnostics if an error persists.

The UI, control definitions, evaluator, scoring and report/JSON structure are
unchanged. An observed insecure value remains FAIL; unavailable evidence remains
ERROR; no missing value receives a favorable default.

Reference checks in NIST's macOS Security Compliance Project use the explicit
[SSH launchd state](https://raw.githubusercontent.com/usnistgov/macos_security/sequoia/rules/system_settings/system_settings_ssh_disable.yaml)
and [automatic-time preference](https://raw.githubusercontent.com/usnistgov/macos_security/sequoia/rules/system_settings/system_settings_time_server_enforce.yaml).
These are command/source references, not proof of live acceptance on Tahoe.
