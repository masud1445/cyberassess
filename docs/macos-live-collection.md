# macOS live collection and optional elevated reads

MAC-005, MAC-009, MAC-010, MAC-011 and MAC-012 use read-only native commands and
public CoreFoundation preference resolution. The supplied live diagnostics
match the published explicit-key implementation: three named preferences were
absent/unreadable, while Remote Login and network-time status queries required
additional local privileges. Those diagnostics do not establish a secure or
insecure value. The [investigation](macos-effective-state-investigation.md)
records that evidence gap, the native sources and the conservative resolution
rules.

## Exact live validation commands

Run from the reviewed repository root on the authorized native Mac as the
intended assessment user. Normal read-only mode never invokes sudo:

```bash
.venv/bin/python main.py --profile macos --local --output reports/macos-read-only
```

Optional elevated read-only mode explicitly permits a narrow noninteractive
retry; do not prefix the whole Python command with sudo:

```bash
.venv/bin/python main.py --profile macos --local --allow-elevated-read --output reports/macos-elevated-read
```

The option also works with matching macOS `--auto-detect`. It is rejected for
other platforms, demo, listing and SSH modes. Inspect the matching new JSON/HTML
paths printed by each command and compare MAC-005, MAC-009, MAC-010, MAC-011 and
MAC-012, including their sanitized evidence summaries.

## Elevation boundary

The collector first tries reliable unprivileged evidence. Only when a status
remains unresolved after a recognized permission denial may the optional mode
retry one of these exact read-only getters with `sudo -n --`:

| Native getter | Purpose |
| --- | --- |
| `/usr/sbin/systemsetup -getremotelogin` | Read Remote Login On/Off status. |
| `/usr/sbin/systemsetup -getusingnetworktime` | Read automatic network-time On/Off status. |
| `/usr/sbin/softwareupdate --schedule` | Read automatic update-check scheduling; no `on`/`off` setting argument is supplied. |

Known contradictions between SSH registration and its explicit override remain
ERROR. They are not replaced with an elevated result or a secure assumption.

Retries have closed stdin, no shell and a ten-second timeout. Existing approved
noninteractive sudo authorization or a valid credential cache is required.
CyberAssess does not request passwords, establish authorization, modify sudoers,
grant privileges, change settings or run remediation. If sudo is unavailable,
expired or denied, the affected result remains ERROR with a clear sanitized
reason. No permission failure or empty output receives an assumed secure value.

Screen-lock and user-preference reads are never elevated. They stay in the
invoking user's context, include applicable ByHost/managed precedence, and reject
unsafe identity or home redirects. The collector does not switch to another
account, dump preferences or run the entire application as root.

## Evidence limits

Evidence summaries distinguish resolved/native configuration, explicit stored
values and unavailable state. Missing, denied, unsupported or contradictory
evidence remains ERROR; a reliably insecure value produces FAIL. MAC-011's
known numeric delay is evaluated independently using its unchanged control;
a zero delay alone does not prove that MAC-010 password enforcement is enabled.

Remote Login can use consistent launchd registration, override and actual
service-definition evidence. A missing override, process or empty output alone
never proves disabled SSH. `TMAutomaticTimeOnlyEnabled` is an automatic-time
enforcement key, not a general On/Off flag; an absent, false or unforced value
does not prove that automatic time is disabled.

Report design, control definitions, NIST mappings, scoring and public JSON
structure are unchanged. Effective preference configuration is not an
interactive lock/unlock test or proof of successful time synchronization.
Native macOS acceptance remains pending: Linux command fixtures and fake
CoreFoundation tests do not establish live results on another Mac.
