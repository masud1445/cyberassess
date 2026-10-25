# MAC-005 and MAC-012: remaining live evidence limits

The latest real validation reports MAC-009 and MAC-010 as PASS and MAC-011 as
a correctly evaluated FAIL. Those collection paths are unchanged here. The
Ubuntu SSH validation was reported as 15 PASS, 0 FAIL and 0 ERROR; its collector
is unchanged.

## Diagnosis before changing code

No JSON from the latest real Mac run is present in this checkout. The supplied
diagnostics establish that the update-check key/schedule did not yield a known
scalar, and that the time getter required privileges while preference
resolution was unavailable. They do not establish whether either setting is
enabled or disabled. Exact native getter output has been requested; a parser
mismatch cannot be identified from these summaries alone.

Code inspection found a separate, reproducible MAC-005 scope bug. The helper
can return a missing current-user `CFPreferencesCopyAppValue` alongside valid
machine `CFPreferencesCopyValue` observations. The parent discarded that entire
payload. It also required machine configuration to agree with the invoking
user's composite application preference, although those represent different
scopes. Neither requirement is appropriate for reading a machine setting.

MAC-012 already tries both native status getters without sudo:

```text
/usr/sbin/systemsetup -getusingnetworktime
/usr/sbin/sysadminctl -automaticTime status
```

It then checks a verified enforced machine automatic-time policy. The existing
automatic-time decoder accepts only explicit whole status sentences; its exact
wording has not yet been captured from the receiving Mac. This revision does
not broaden that decoder using speculative messages or add an unsupported
source of automatic-time state.

## Changes and fallback order

MAC-005 retains typed machine observations even when the current-user composite
value is missing. The permitted fallback reads machine current-host, then
machine any-host, through public CoreFoundation APIs. It requires a readable
management-status check showing no forced value; a verified managed machine
policy remains the separate managed route. A malformed or unreadable
higher-priority machine value prevents falling through to a lower-priority
value. A user-only preference cannot establish machine configuration.

The native `softwareupdate --schedule` status remains preferred. A known
schedule status contradicting the reliable machine observation remains ERROR.
When only a reliable machine Boolean is available, evidence explicitly labels
it **explicit machine configuration**, rather than claiming the daemon's
effective runtime state. A known false value is FAIL. No missing value becomes
true or false, and no raw preference file is promoted to effective state.

MAC-005 and MAC-012 now distinguish three previously combined status failures:
nonzero exit, empty output, and unrecognized/ambiguous output. Permission denial
and timeout retain their existing reasons. These are fixed sanitized summaries;
command output, identities and unrestricted preference dumps are not retained.

MAC-012's evidence order and interpretation are unchanged: native systemsetup
status, native sysadminctl automatic-time status, then independently verified
positive enforced machine policy. Contradictory known states remain ERROR.
`TMAutomaticTimeOnlyEnabled=false` merely removes enforcement and cannot prove
automatic time is disabled. An unforced true value, a configured server, a
running `timed` service, a successful one-off time probe or cached time data
cannot prove the automatic-time setting is enabled.

There are no new native commands, dependencies or CLI options. The existing
explicit opt-in elevation mode is unchanged; normal collection never runs
sudo. No setting changes, remediation or password prompts are introduced.

## Platform limits and sources

- [Apple CoreFoundation preference implementation](https://github.com/apple-oss-distributions/CF/blob/main/CFPreferences.c)
  distinguishes exact `(application, user, host)` reads from
  [application preference search](https://github.com/apple-oss-distributions/CF/blob/main/CFApplicationPreferences.c).
- [NIST macOS Security Compliance Project issue 437](https://github.com/usnistgov/macos_security/issues/437)
  records removal of the separate check-for-updates GUI toggle on Sequoia and
  discussion of retiring the corresponding benchmark rule. Other update
  toggles are not equivalent evidence for the existing MAC-005 definition.
- [Apple's legacy SoftwareUpdate payload](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.SoftwareUpdate.yaml)
  deprecates that management payload in macOS 26. Its
  [declarative replacement](https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/softwareupdate.settings.yaml)
  exposes download/install settings, without an equivalent check-specific
  Boolean. This is not a reason to infer a default or change the control.
- The [systemsetup manual](https://raw.githubusercontent.com/keith/xcode-man-pages/main/docs/systemsetup.8.html)
  documents the getter and administrative privilege requirements.
- The [NIST automatic-time enforcement check](https://github.com/usnistgov/macos_security/blob/main/rules/system_settings/system_settings_time_server_enforce.yaml)
  uses a forced `com.apple.timed/TMAutomaticTimeOnlyEnabled` policy.
  Apple's [TimeServer payload](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.MCX%28TimeServer%29.yaml)
  configures a server/time zone, not a substitute automatic-time Boolean.

MAC-005 can still legitimately be ERROR when a recent OS exposes no reliable
check-specific status or preference. MAC-012 can still be ERROR when both
getters are denied/unsupported or use unrecognized output and no enforced
policy is readable. Neither live error is claimed fixed by fixture tests.

## Live validation

Update the existing feature branch, then run from the repository root as the
intended assessment user without sudo:

```bash
git switch feature/multiplatform-cyberassess
git pull --ff-only origin feature/multiplatform-cyberassess
.venv/bin/python main.py --profile macos --local --output reports/macos-update-time
```

If either control remains ERROR, share its sanitized `raw_evidence` from the
new JSON and the output/exit code of these status-only commands, without sudo:

```bash
/usr/sbin/softwareupdate --schedule
printf 'softwareupdate exit=%s\n' "$?"
/usr/sbin/sysadminctl -automaticTime status
printf 'sysadminctl exit=%s\n' "$?"
```

Only explicit recognized evidence establishes a value. These commands make no
security setting changes. This work does not verify clock accuracy or successful
time synchronization.
