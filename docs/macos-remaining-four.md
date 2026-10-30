# Remaining macOS collection errors: evidence sources and diagnostics

## Current investigation

The latest follow-up concerns MAC-010/011/012. See the
[sanitized macOS diagnostic utility](macos-diagnostics.md) for a reproducible
native-stage report and source-file identification; the earlier four-control
investigation and collection changes below provide the source-selection context.

The latest supplied live summary reports MAC-009 PASS and MAC-005/010/011/012
ERROR. No latest live JSON or exact getter output is available in this checkout.
The running revision and sanitized native diagnostics have been requested;
the receiving Mac's exact failure cause is not yet established.

These changes were reviewed against
`8ddacee468d991ee1f3ec334959e91ed600c38bd` (1,114 tests). The combined suite
passes **1,266 tests**, including scoped-preference, console-policy,
privilege-guidance, diagnostic and native-path regressions. Native getters,
supported output formats, CLI and the existing explicit elevation contract
are unchanged.

The latest requirement targets the **current console user**. Previously only
the native getter required the invoking user to match the console; a readable
invoking-user preference could still assess another session's configuration.
The entire MAC-010/011 collection now checks that the non-root invoking user
matches the console before reading preferences or native status, and checks
again before accepting any known result. No account is substituted. Root,
headless, redirected-home or different-user contexts produce actionable ERROR
and are directed to run as the logged-in console user without sudo.

[NIST issue 635](https://github.com/usnistgov/macos_security/issues/635) records
Tahoe systems where non-host screen-saver preference resolution is empty while
ByHost or managed observations remain readable. The discussion also records
management conflicts and execution-context differences; it does not prove that
any one stored key is the effective policy on every affected system.

Inspection found a specific evidence-loss gap: the helper already reads exact
invoking-user/current-host and any-host values, but the parent discards them
when the composite application value is NULL. This review preserves those
observations as a final **explicit configured current-user preference** fallback
for MAC-010/011, after native current state and resolved application preference.
It requires a successful safe-context probe and readable management status
showing no forced value. Current-host takes precedence over any-host; an
unreadable or invalid higher-priority value prevents fallback. Machine-scope
values never establish another user's preference. Missing values supply no
Boolean and no zero delay.

This fallback does not claim effective runtime enforcement. Forced or unknown
management with no resolved value remains ERROR. Readable native state retains
precedence over stale unforced configuration, and proven native/managed
contradictions remain ERROR.

No additional authoritative unprivileged source was found for MAC-005 or
MAC-012. Their source selection is unchanged. If the allowlisted native getter
is denied and no reliable ordinary fallback exists, standard-mode ERROR now
explains the existing optional `--allow-elevated-read` path and its requirement
for operator authorization and administrator-approved passwordless access.
The guidance is not added for empty/unsupported output, does not run sudo, and
does not imply that privilege can fix an unavailable native scalar. No native
commands, speculative output formats, private APIs, automatic escalation,
settings changes or remediation are added. These are not confirmed live fixes.

## Evidence used by each control

| Control | Reliable sources, in order of preference | PASS/FAIL evidence | ERROR conditions |
| --- | --- | --- | --- |
| MAC-005 | `softwareupdate --schedule`; forced CoreFoundation value verified against the matching managed machine key; otherwise typed machine current-host/any-host CoreFoundation configuration with known unforced management status. | Explicit on/true is PASS; off/false is FAIL. Configured fallback is labelled as configuration, not proof of daemon runtime state. | No check-specific scalar, denied/unsupported getter, unreadable higher-priority machine scope, unresolved management or contradictory reliable observations. |
| MAC-010 | After verifying matching invoking/console identities: `sysadminctl -screenLock status`; CoreFoundation resolution including ByHost/managed policy; finally typed exact own-user configuration with verified unforced management. | Explicit immediate/numeric native lock delay establishes a password requirement (PASS); native Off establishes no requirement (FAIL). A reliable own-user Boolean can assess the preference, with configured fallback labelled separately from native effective state. | No reliable requirement, unverified/changed console context, unresolved management, denied/unsupported/unrecognized sources or conflicting policy. Readable preferences of a different invoking user are not substituted. |
| MAC-011 | Under the same pre/post console-user guard: the native getter, a reliable resolved numeric delay, or verified unforced exact own-user configuration. | An explicit zero/immediate delay is PASS; a known positive delay is FAIL under the unchanged control. | No numeric delay, native Off without a delay, unsupported/denied evidence, unresolved management, unverified/changed console context or contradiction. No zero is invented. |
| MAC-012 | `systemsetup -getusingnetworktime`, then `sysadminctl -automaticTime status`, then an independently verified forced-positive machine `TMAutomaticTimeOnlyEnabled` policy. | Explicit native On is PASS and Off is FAIL. Verified enforced automatic time can establish PASS. | Denied/unsupported/unrecognized native status with no enforced policy, or contradiction. False/unforced enforcement, a server name, cached data or a running time daemon cannot establish the automatic-time state. |

Modern screen-lock state may have migrated away from `com.apple.screensaver`;
the native status route deliberately does not depend on those keys. It never
switches accounts, reads another user's home, or equates the current screen's
locked state or an account password policy with the configured lock requirement.
`loginwindow/DisableScreenLockImmediate` controls the immediate lock function,
not the wake/password requirement. A declared maximum grace period is not
necessarily the actual selected delay. Neither is substituted for these keys.
Likewise, `pmset` power/sleep configuration does not establish the password
requirement or its grace period. Profile presence alone does not prove a
resolved policy; no unrestricted profile or preference dump is collected.

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
[NIST issue 129](https://github.com/usnistgov/macos_security/issues/129) also
documents managed policy overriding the time daemon's stored plist. Reading
that file alone would not prove the effective automatic-time setting.

## Re-run the latest live assessment

Update a clean checkout of the feature branch on the authorized Mac. Then run
from the repository root as the currently logged-in console user in their
Terminal, without sudo:

```bash
git switch feature/multiplatform-cyberassess
git pull --ff-only origin feature/multiplatform-cyberassess
git rev-parse HEAD
.venv/bin/python main.py --profile macos --local --output reports/macos-tahoe-review
```

If an ERROR remains, share the complete sanitized `raw_evidence` (including
the native getter's failure/skip reason), the running commit SHA, and the
relevant getter output/exit status. The supplied preference-only summaries do
not identify whether the native getter was denied, skipped, unsupported or
unrecognized. These additional commands
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
  illustrates migration to MobileKeyBag state, but
  [its context limitation](https://github.com/osquery/osquery/issues/6451)
  means it is not a portable fix for arbitrary invocation contexts. This
  collector does not add that private framework dependency.
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
sudo. User-preference and screen-lock commands cannot be elevated. No user
switching, interactive password request, setting change or remediation is
introduced. No other user's preferences are read.
