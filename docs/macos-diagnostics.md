# Diagnose the remaining macOS screen-lock and network-time errors

The latest supplied live summary reports MAC-009 PASS and MAC-010/011/012
ERROR. The summaries establish unavailable evidence but omit the native getter
outcome and the code revision used. No additional supported effective-state
source or verified new output format was found during this review. The current
collector continues to preserve ERROR when reliable evidence is unavailable.

The standalone diagnostic utility records the existing collection stages with
sanitized values. It does not change the assessment CLI, control definitions,
scoring, report presentation or assessment JSON format. It executes only the
three affected collection paths, with elevated reads disabled.

The diagnostic utility has 35 regression tests covering known states, absence,
denial, malformed
output, management scope, privacy, platform rejection and no automatic elevation.
The combined suite passes **1,266 tests** and the portability checks pass.
These tests do not establish live resolution
of MAC-010/011/012 on a real Mac.

## Exact commands

Use the reviewed working tree on the authorized native Mac, as the currently
logged-in console user in Terminal, without sudo:

```bash
.venv/bin/python scripts/diagnose_macos.py > macos-diagnostics.json
.venv/bin/python main.py --profile macos --local --output reports/macos-three-review
```

Update a clean checkout of the feature branch before running these commands:

```bash
git switch feature/multiplatform-cyberassess
git pull --ff-only origin feature/multiplatform-cyberassess
git rev-parse HEAD
```

The source-file SHA-256 values in the diagnostic document identify the actual
collector implementation, including any local changes that leave
`git rev-parse HEAD` unchanged.

The utility writes its diagnostic document to stdout. The first command above
explicitly saves it in the current directory. Exit zero means the diagnostic
document was generated, not that the security controls passed. An unsupported
platform or invalid arguments returns exit two before collection. The utility
accepts no option to enable elevated reads.

## Native sources used

| Controls | Native status source | Existing fallback and scope |
| --- | --- | --- |
| MAC-010/011 | `/usr/sbin/sysadminctl -screenLock status` | Public CoreFoundation `CFPreferencesCopyAppValue`, `CFPreferencesCopyValue` and `CFPreferencesAppValueIsForced` for `com.apple.screensaver/askForPassword` and `askForPasswordDelay`; exact own-user ByHost/any-host configuration is separately labelled and requires verified unforced management. |
| MAC-012 | `/usr/sbin/systemsetup -getusingnetworktime` and `/usr/sbin/sysadminctl -automaticTime status` | A forced positive `com.apple.timed/TMAutomaticTimeOnlyEnabled` value must agree with the narrowly extracted managed machine key. False or unforced enforcement is not an automatic-time On/Off reading. |

Screen-lock sources run only when the non-root invoking user and console user
match safely. A known result is discarded if that context changes. The
collector never switches to another account or reads another user's home.
Native immediate/numeric delay and Off status remain distinct: Off establishes
no password requirement but supplies no numeric delay. No absent value becomes
zero, true or false.

The native getters have a ten-second execution timeout, closed stdin, fixed
arguments and no shell. Preference probes use the same bounded existing helper.
The diagnostic utility inspects the resulting command cache; it does not rerun
getters just to display additional details.

## Interpreting the diagnostic document

The document identifies whether each native getter was run, its exit status
when retained, whether stdout/stderr was present, its recognized state, and a
fixed unavailable reason. An unavailable or not-run probe has no invented
state. Some denied or failed executions have no retained process result; their
exit status and stream-presence fields remain unknown rather than guessed.

Preference observations distinguish a resolved application value, exact scoped
configuration and management availability. Missing or malformed observations
remain unavailable. A `timed` enforcement preference is labelled as enforcement
evidence; it is not reported as a general automatic-time enabled flag.

Selected evidence summaries use the collector's sanitized provenance. Native
stdout/stderr, exception messages, environment values, usernames, hostnames,
UIDs, home paths, process IDs and timestamps are not emitted. Source hashes
refer to program files, not device identifiers. There are no unrestricted
profile or preference dumps.

Share the generated `macos-diagnostics.json` and the complete sanitized
`raw_evidence` for MAC-010/011/012 from the matching assessment. These identify
whether the unresolved path is console context, denied access, unsupported
commands, empty/malformed output, preference scope, or unknown state. If a
getter reports unrecognized output, its exact sanitized status text may still
be needed before adding another supported format.

## Privilege and compatibility limits

A running `timed` daemon, configured server or cached time data does not prove
automatic time is enabled. `systemsetup` can require administrator privileges;
the diagnostic utility keeps that result unavailable and never invokes sudo.
The existing explicitly authorized read-only assessment mode is documented in
[macOS live collection](macos-live-collection.md). It requires pre-approved
passwordless access to fixed getters and does not use or update cached sudo
credentials. No new authorization, privilege configuration or security setting
change is performed.

The implementation uses feature/output detection, with no version, hostname,
device, user or home-directory exceptions. Unfamiliar native formats or
unavailable policy on another macOS release remain ERROR. Linux fixtures and
the diagnostic utility's tests do not establish live success on a Mac.

Source references and rejected substitutes remain in the
[collector investigation](macos-remaining-four.md). Private MobileKeyBag APIs,
`pmset` power settings and loginwindow lock-menu restrictions were not added as
substitutes for effective password policy.
