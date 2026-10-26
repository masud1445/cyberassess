# macOS live collection and optional elevated reads

MAC-005, MAC-009, MAC-010, MAC-011 and MAC-012 use read-only native commands and
public CoreFoundation preference resolution. The latest supplied live results
resolve MAC-009 and MAC-010 as PASS and MAC-011 as a reliable FAIL. MAC-005 and
MAC-012 remain ERROR where no reliable scalar is readable; permission denial or
an absent preference does not establish a secure or insecure value. The
[evidence-source investigation](macos-remaining-four.md) records the native
sources, scope checks and conservative resolution rules. Optional privileged
reads can improve access to native status, but do not guarantee resolution.

## Exact live validation commands

Run from the reviewed repository root on the authorized native Mac as the
intended assessment user. Normal read-only mode never invokes sudo:

```bash
.venv/bin/python main.py --profile macos --local --output reports/macos-read-only
```

Passing the optional flag is explicit operator consent for this assessment's
fixed privileged getters. The CLI explains their scope and lists them before
collection begins. The flag does not grant OS privileges: existing
administrator-approved passwordless authorization for each exact getter is
required. Do not prefix the whole Python command with sudo:

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
retry one of these exact read-only getters with `sudo -n -k --`:

| Native getter | Purpose |
| --- | --- |
| `/usr/sbin/systemsetup -getremotelogin` | Read Remote Login On/Off status. |
| `/usr/sbin/systemsetup -getusingnetworktime` | Read automatic network-time On/Off status. |
| `/usr/sbin/softwareupdate --schedule` | Read automatic update-check scheduling; no `on`/`off` setting argument is supplied. |

Known contradictions between SSH registration and its explicit override remain
ERROR. They are not replaced with an elevated result or a secure assumption.

Retries have closed stdin, no shell and a ten-second timeout. `-n` prevents
interactive authentication. With a command, `-k` ignores existing cached sudo
credentials and does not update them, as documented by the
[native sudo manual](https://raw.githubusercontent.com/keith/xcode-man-pages/main/docs/sudo.8.html).
A valid credential cache alone is therefore insufficient; the exact getter
needs existing administrator-approved passwordless authorization. CyberAssess
does not establish authorization, request or collect passwords, create or refresh
cached credentials, modify sudoers, grant privileges, change settings or run
remediation. It does not run a privileged preflight or standalone timestamp
management command. If sudo is unavailable or the getter is denied, the result
remains ERROR with a sanitized reason. Empty or ambiguous output never receives
an assumed secure value.

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

For MAC-012, authorized `systemsetup -getusingnetworktime` can expose direct
On/Off automatic-time configuration when an ordinary read is denied. A running
`timed` service or configured server cannot substitute for that evidence. For
MAC-005, an authorized bare `softwareupdate --schedule` can help only when it
returns a reliable check-specific scalar. Recent macOS update policy may not
expose one; download/install settings and missing keys cannot replace it. Both
controls remain ERROR if their supported sources are unavailable, unsupported,
ambiguous or contradictory, even with the optional mode enabled.

Report design, control definitions, NIST mappings, scoring and public JSON
structure are unchanged. Effective preference configuration is not an
interactive lock/unlock test or proof of successful time synchronization.
Live acceptance of the remaining changes is still required: Linux command
fixtures and fake CoreFoundation tests do not establish results on another Mac.
