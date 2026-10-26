# Remaining macOS collection errors: evidence sources and diagnostics

## Current investigation

The latest supplied live summary reports MAC-009 PASS with `actual=false` and
MAC-005/010/011/012 ERROR. A previous summary reported MAC-010 PASS and MAC-011
FAIL. The current screen-lock getter, decoder and user-context guard have not
changed since commit `48c07fc`; the exact running revision, latest JSON and
native getter output have been requested to distinguish execution-context
differences from a native-output compatibility problem. No latest live JSON is
available in this checkout, so its cause cannot yet be established.

Before changes, the full suite passed **946 tests**. Inspection found three
reproducible gaps, corrected in this revision:

1. Screen-lock ERROR evidence reported only the preference failure, hiding
   whether the modern status getter was skipped, denied, unavailable, empty,
   unsuccessful or unrecognized. It now includes a fixed sanitized native-stage
   reason. The current-user/console guard and supported status formats remain
   unchanged.
2. The managed-machine cross-check rejected legacy Boolean strings accepted by
   the native CoreFoundation probe. Only those update/time policy checks now
   accept bounded ASCII `true`/`YES` and `false`/`NO`, case-insensitively, with
   no whitespace, numeric-string or missing-value coercion. Both the forced
   effective scalar and independently read machine policy must agree.
3. A native getter reporting two different known states could be discarded as
   unrecognized output, allowing a preference fallback to produce PASS. A
   forced preference disagreeing with the separately read managed machine key
   could also be discarded. Both proven contradictions now remain ERROR,
   including when another source supplies a known value. Unknown text alone
   proves neither a conflict nor a security value.

These changes add no native commands, new status formats, private framework
dependencies, privilege elevation, settings changes or remediation. They do
not establish that any of the receiving Mac's four errors is resolved.

## Evidence used by each control

| Control | Reliable sources, in order of preference | PASS/FAIL evidence | ERROR conditions |
| --- | --- | --- | --- |
| MAC-005 | `softwareupdate --schedule`; forced CoreFoundation value verified against the matching managed machine key; otherwise typed machine current-host/any-host CoreFoundation configuration with known unforced management status. | Explicit on/true is PASS; off/false is FAIL. Configured fallback is labelled as configuration, not proof of daemon runtime state. | No check-specific scalar, denied/unsupported getter, unreadable higher-priority machine scope, unresolved management or contradictory reliable observations. |
| MAC-010 | `sysadminctl -screenLock status` when invoking and console identities safely match; otherwise invoking-user CoreFoundation preferences, including ByHost/managed resolution. | Explicit immediate/numeric native lock delay establishes a password requirement (PASS); native Off establishes no requirement (FAIL). A reliable own-user Boolean can also assess the preference. | No reliable requirement, unsafe native user context with no own-user fallback, denied/unsupported/unrecognized getter or conflicting policy. Absent legacy keys never imply PASS. |
| MAC-011 | The same safely scoped native getter, or a reliable invoking-user resolved numeric delay. | An explicit zero/immediate delay is PASS; a known positive delay is FAIL under the unchanged control. | No numeric delay, native Off without a delay, unsupported/denied evidence, unsafe context with no own-user fallback or contradiction. No zero is invented. |
| MAC-012 | `systemsetup -getusingnetworktime`, then `sysadminctl -automaticTime status`, then an independently verified forced-positive machine `TMAutomaticTimeOnlyEnabled` policy. | Explicit native On is PASS and Off is FAIL. Verified enforced automatic time can establish PASS. | Denied/unsupported/unrecognized native status with no enforced policy, or contradiction. False/unforced enforcement, a server name, cached data or a running time daemon cannot establish the automatic-time state. |

Modern screen-lock state may have migrated away from `com.apple.screensaver`;
the native status route deliberately does not depend on those keys. It never
switches accounts, reads another user's home, or equates the current screen's
locked state or an account password policy with the configured lock requirement.

MAC-005 has a real platform limit: the separate check-for-updates toggle was
removed on recent macOS, and Apple's declarative update settings expose
download/install actions without an equivalent check-specific Boolean. See
[NIST's discussion](https://github.com/usnistgov/macos_security/issues/437),
[Apple's legacy payload](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.SoftwareUpdate.yaml)
and [its replacement](https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/softwareupdate.settings.yaml).
Those other settings cannot substitute for the unchanged MAC-005 definition.

MAC-012 may genuinely require local privileges; the
[systemsetup manual](https://raw.githubusercontent.com/keith/xcode-man-pages/main/docs/systemsetup.8.html)
documents administrative requirements. No additional trustworthy unprivileged
enabled-state source was identified. Unknown evidence remains ERROR rather
than triggering elevation or deriving a setting from service activity.

## Re-run the latest live assessment

From the repository root, as the intended logged-in assessment user, without
sudo:

```bash
git switch feature/multiplatform-cyberassess
git pull --ff-only origin feature/multiplatform-cyberassess
git rev-parse HEAD
.venv/bin/python main.py --profile macos --local --output reports/macos-remaining-four
```

If an ERROR remains, share its sanitized `raw_evidence`, the running commit
SHA, and the relevant getter output/exit status. These additional commands
are fixed read-only queries; do not add sudo:

```bash
/usr/sbin/softwareupdate --schedule
printf 'softwareupdate exit=%s\n' "$?"
/usr/sbin/sysadminctl -screenLock status
printf 'screen-lock exit=%s\n' "$?"
/usr/sbin/systemsetup -getusingnetworktime
printf 'systemsetup time exit=%s\n' "$?"
/usr/sbin/sysadminctl -automaticTime status
printf 'automatic-time exit=%s\n' "$?"
```

Regression fixtures cover native and preference PASS/FAIL, missing/denied
evidence, managed legacy representations, malformed output, conflicts, user
context restrictions and multiple user/home layouts. They do not execute native
Mac commands or establish real live success. MAC-009, UI, CLI, profiles, scoring,
public JSON schema, Ubuntu and Windows collectors remain unchanged.

## Native source references and safety boundaries

- [Apple CF preference implementation](https://github.com/apple-oss-distributions/CF/blob/main/CFApplicationPreferences.c)
  documents the legacy Boolean representations. No absent-value getter default
  is used, and the separate XML scalar reader remains structurally validated.
- [Older sysadminctl native help](https://github.com/microsoft/macos-cookbook/issues/32)
  and [recent captured help](https://github.com/xfreebird/kcpassword/issues/5)
  document the status-only commands. Help establishes getter availability,
  not a stable output format across every OS release.
- Captured screen-lock outputs include
  [immediate](https://github.com/sametsazak/mergen/issues/39),
  [numeric delay](https://github.com/iamivanhx/macos-setup/issues/30), and
  [Off](https://github.com/openai/codex/issues/55615).
  Unknown wording remains ERROR when no reliable fallback exists.
- [osquery's screen-lock source](https://github.com/osquery/osquery/blob/master/osquery/tables/system/darwin/screenlock.mm)
  illustrates migration to MobileKeyBag state. This collector does not add that
  private framework dependency.
- [NIST automatic-time enforcement](https://github.com/usnistgov/macos_security/blob/main/rules/system_settings/system_settings_time_server_enforce.yaml)
  checks forced automatic-time policy. A server configuration or running daemon
  is not equivalent evidence; this collector does not claim clock accuracy or
  successful synchronization.

All native commands use fixed argument lists, closed stdin and a ten-second
execution timeout. Only sanitized selected scalars and fixed provenance/reason
labels enter reports. Identities, home paths, timestamps, process IDs and raw
command diagnostics are not added to evidence summaries.

The existing explicit `--allow-elevated-read` contract and exact sudo allowlist
remain unchanged. The commands above use normal mode, which never invokes
sudo. No user switching, interactive password request, setting change or
remediation is introduced. No other user's preferences are read.
