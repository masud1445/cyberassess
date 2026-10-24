# Remaining macOS collection errors: native status compatibility

This update targets MAC-005, MAC-010, MAC-011 and MAC-012 only. MAC-009 was
reported passing on the real Mac and its collection path is unchanged. The
remaining diagnostics establish unavailable evidence; they do not establish
whether the underlying settings are enabled or disabled.

No real Mac is attached to the development environment. The changes below are
collector improvements validated with native-output fixtures and fake
CoreFoundation bindings. They are **not confirmed live fixes** until a new
assessment is performed on an actual Mac.

## Exact changes

- CoreFoundation still resolves the invoking user's effective preferences,
  including applicable managed and ByHost precedence. A valid effective value
  is no longer discarded merely because an unrelated supplemental observation
  has an unsupported legacy type. Unreadable scopes are flagged internally;
  an unreadable higher-priority scope is never silently treated as absent.
- Bounded public CFString reads support the native documented legacy Boolean
  spellings `true`/`YES` and `false`/`NO`, case-insensitively. Password-delay
  integer strings are accepted only when the whole ASCII string is a supported
  nonnegative integer. NULL, malformed strings, unexpected types and denied
  native reads remain unavailable. No string or preference dictionary is dumped.
- The update-schedule and network-time getters accept exactly one explicit
  status from stdout or stderr, including a recognized native Cocoa process
  prefix. A known softwareupdate banner is permitted, but is not itself a
  status. Duplicate/conflicting states, warnings, unknown text and nonzero
  exits remain ERROR.
  Malformed native byte output is also contained as unavailable evidence in
  these four paths, rather than aborting unrelated controls.
- A current-user screen-lock fallback uses only
  `/usr/sbin/sysadminctl -screenLock status`. Verified native messages include
  `screenLock delay is immediate`, `screenLock delay is N seconds`, and
  `screenLock is off`. Off supplies no numeric delay: it must not invent zero
  or a disabled sentinel for MAC-011.
- Before that screen-lock getter executes, the real/effective process identity,
  safe home context and public `/dev/console` ownership must identify the same
  non-root user. This is checked again before accepting the result; a console
  identity change discards it. A different console user, root/loginwindow context, unavailable
  console or home redirect prevents the query. The collector never switches
  users or reads another user's preferences. The existing CFPreferences route
  can still assess the invoking user's own readable values.
- Current native screen-lock status takes precedence over stale **unforced**
  legacy preferences, which may no longer represent active lock policy after
  migration. A verified managed requirement/delay that contradicts native
  policy remains ERROR.
- Network time additionally queries only
  `/usr/sbin/sysadminctl -automaticTime status`, without elevation. Native help
  documents this getter on older and recent releases. The decoder accepts
  only a whole explicit named automatic-time property sentence with
  enabled/disabled or on/off state, optionally one final period and a known
  Cocoa prefix. Actual output wording is not a stable documented API and has
  not been captured from the receiving Mac; unfamiliar wording remains ERROR.
  This reports automatic-time configuration, not clock accuracy or proof of
  successful synchronization.

The existing CLI options, noninteractive opt-in elevation contract and exact
sudo allowlist are unchanged. Neither new sysadminctl getter can be elevated.
Normal mode never invokes sudo. Existing opt-in reads retain `sudo -n`, closed
stdin and the timeout; no interactive authentication is introduced. All native
commands are fixed argument lists, read-only and bounded to ten seconds.

Report UI/presentation, all control definitions, scoring, PASS/FAIL/ERROR
semantics, public JSON keys, Ubuntu collection and Windows collection are
unchanged. Only sanitized selected scalars and fixed provenance labels enter
reports; native timestamps, process IDs and raw diagnostics are not retained.

## Native sources and migration evidence

- [Apple preference implementation](https://raw.githubusercontent.com/apple-oss-distributions/CF/main/CFApplicationPreferences.c) documents legacy Boolean/integer representation handling. No unguarded getter default is used.
- [Native sysadminctl help, older macOS](https://github.com/microsoft/macos-cookbook/issues/32) and [recent captured help](https://github.com/xfreebird/kcpassword/issues/5) document status-only screen-lock and automatic-time forms. Help is evidence for the commands, not a guarantee of stable status wording.
- Captured native screen-lock statuses: [immediate/current output](https://github.com/sametsazak/mergen/issues/39), [numeric delay](https://github.com/iamivanhx/macos-setup/issues/30), [additional delay example](https://github.com/lil-shimon/dotfiles/issues/199), and [Off status](https://github.com/openai/codex/issues/55615).
- [osquery's current screen-lock implementation](https://raw.githubusercontent.com/osquery/osquery/master/osquery/tables/system/darwin/screenlock.mm) reads effective grace-period policy through MobileKeyBag. That explains why legacy screensaver preferences can be missing/stale, but this collector does not add that private framework dependency.
- `timed` cached data and a running daemon do not establish that automatic time
  is enabled. Missing/false/unforced `TMAutomaticTimeOnlyEnabled` remains
  insufficient; contradictory known native states remain ERROR.

## Expected live outcomes and exact validation command

Use the reviewed feature-branch revision and run from its repository root as
the intended logged-in assessment user, without adding sudo:

```bash
.venv/bin/python main.py --profile macos --local --output reports/macos-remaining-four
```

Inspect the matching JSON/HTML paths printed by the command. The existing
`--allow-elevated-read` option is unchanged and remains optional; it does not
elevate screen-lock/user-preference reads or either new status getter.

| Control | What can now make it assessable | Why ERROR can still be legitimate |
| --- | --- | --- |
| MAC-005 | Explicit native schedule status across supported streams, or valid resolved machine preferences including supported legacy representations. | Unsupported/denied schedule query, absent machine evidence, malformed higher-priority source or contradictory known states. |
| MAC-010 | Safely scoped native current-user screen-lock status, or valid native preference resolution. | Console/invoking identity mismatch, privacy restrictions, unsupported status wording, unavailable policy or conflicting managed state. |
| MAC-011 | An explicitly reported native numeric/immediate delay, or a reliable own-user resolved numeric preference. | No numeric delay while native lock is Off, missing/invalid policy, unsafe user context or contradiction. Off/absence never supplies zero. |
| MAC-012 | Readable native systemsetup or automatic-time status, or existing verified enforced machine policy. | Native permission denial, unsupported getter/status format, missing policy or conflicting known observations. Daemon presence is never enough. |

Known insecure observations produce FAIL. Unknown evidence remains ERROR; this
update does not predict the receiving Mac's values or guarantee all four resolve.
