# macOS effective-state collection investigation

## Why the previous fixes can leave all five controls at ERROR

The initial diagnosis was recorded before the effective-state collector edits.
A real Mac still reported MAC-005, MAC-009, MAC-010, MAC-011 and MAC-012 as ERROR
after commit `7f8ffd99fa3a8b76251def7364e4265413ae7c53`. The supplied collection
diagnostics match that published explicit-key implementation: AutomaticCheckEnabled,
askForPassword and askForPasswordDelay were absent/unreadable, and the Remote
Login/network-time native queries required additional local privileges. They
do not establish the underlying secure/insecure values. This evidence also
explains why the previous fallback chain could leave all five unavailable:

| Control | Previous evidence chain | Why it can remain unavailable |
| --- | --- | --- |
| MAC-005 | `defaults` reads `AutomaticCheckEnabled`; `plutil` extracts the same explicit key. | A second read of the same absent key cannot discover the automatic-update subsystem's effective setting. The implementation deliberately never queries the native effective schedule status. |
| MAC-009 | Administrator-gated `systemsetup -getremotelogin`; then one explicit `launchctl print-disabled system` SSH override. | A denied `systemsetup` read followed by an absent override is unknown. The collector does not inspect the effective service definition or current launchd registration. An absent override is not a disabled service. |
| MAC-010 | `defaults` and exact-key `plutil` read the invoking user's any-host `askForPassword` key. | Both reads can fail on an absent key. Neither resolves current-host/managed preference precedence or asks a supported native screen-lock status command. |
| MAC-011 | The same any-host-only reads for `askForPasswordDelay`. | A missing stored delay says nothing about an effective delay. The previous implementation cannot distinguish inherited/native policy from unavailable evidence. |
| MAC-012 | Administrator-gated `systemsetup -getusingnetworktime`; then explicit `TMAutomaticTimeOnlyEnabled` reads. | A denied status query and absent or unreadable key remain unknown. Daemon presence and a configured server name do not prove that automatic network time is enabled. |

The previous patch improved how explicit evidence was read; it did not implement
effective-state assessment. Preserving ERROR for those cases was correct for
that implementation, but its evidence model was narrower than the requested
effective-state controls.

## Investigation constraints

Prefer documented native status queries and supported preference resolution for
the invoking user. Distinguish explicit configuration, effective configuration
and unavailable evidence in sanitized provenance. A readable effective value
can establish evidence even when a stored key is absent; absence itself never
establishes a value. Conflicting authoritative observations remain ERROR.

No command may change settings, silently elevate, switch users or retain
unrestricted output. The new explicit optional elevation mode is limited to
three allowlisted status getters and never requests a password. User paths must
derive from the actual process identity. Report presentation, complete control
definitions, scoring, NIST mappings, public JSON structure and assessment
semantics remain unchanged. Native acceptance requires a new actual-Mac run;
Linux fixture tests cannot establish live success.

## Native-source findings and implementation

| Control | Effective evidence | When ERROR is still legitimate |
| --- | --- | --- |
| MAC-005 | `softwareupdate --schedule` without a setting argument. A second path uses typed CoreFoundation resolution with matching machine scope or verified managed machine policy. Independent effective observations must agree. | Authentication/permission restrictions, unsupported output with no reliable machine preference, or contradictory observations. |
| MAC-009 | Recognized `systemsetup` status, or a valid launchd override map combined with registered-service evidence. Without an override, recognized service absence must also match an actual stock definition whose SSH label and `Disabled=true` are explicitly read. | Missing override/service alone; denied/unrecognized output; enabled override with absent registration; disabled override with registered service. |
| MAC-010 | Public `CFPreferencesCopyAppValue` resolves the invoking user's password requirement, including applicable managed/current-host/any-host precedence. Exact configured values are observed separately with `CFPreferencesCopyValue`. | NULL, invalid types, unreadable native lookup, unsafe process identity/home context, or contradictory unmanaged observations. |
| MAC-011 | The same native resolution for numeric password delay, evaluated independently by the unchanged published control. | Missing/invalid delay or contradictory unmanaged observations. An absent value is not zero; a known zero does not prove MAC-010 enforcement. |
| MAC-012 | Recognized `systemsetup -getusingnetworktime` status. If inaccessible, a native forced-true automatic-time policy must match the explicit managed machine key before effective enforced automatic time is accepted. | Ordinary unmanaged machines may remain ERROR if the status is inaccessible. False/unforced/missing enforcement preferences do not prove automatic time is off. A positive enforced policy conflicting with native Off is ERROR. |

The old false-to-disabled inference for `TMAutomaticTimeOnlyEnabled` is removed:
this is an enforcement preference, not a general On/Off indicator. A running
daemon, configured time server, SSH process, open port or empty output never
substitutes for the requested configuration evidence.

The preference helper uses standard-library ctypes and public CoreFoundation
inside a bounded subprocess. It reads four fixed domain/key pairs; it never
calls setters, registers defaults, synchronizes preferences or serializes a
preference dictionary. NULL remains unavailable; unguarded Boolean/integer
convenience getters are not used. It rejects real/effective UID mismatch,
unresolved accounts, and HOME/CFFIXED_USER_HOME redirects. It never substitutes
SUDO_USER or the console user. The parent performs no earlier user-domain
`defaults` read that could bypass those safeguards.

Arguments are fixed lists without a shell; commands have ten-second timeouts,
closed stdin and no password-bearing flags or setting changes. Unknown output
and diagnostics remain sanitized unavailable evidence. The launchctl print
format is documented as unstable; only known complete shapes are accepted. No
hostname, username, home location, architecture, OS build or observed result is
hard-coded.

## Explicit privilege-aware status reads

Normal mode never invokes sudo. `--allow-elevated-read` is accepted only for a
native local macOS assessment, including matching auto-detection. Reliable
unprivileged sources are tried first. Only a recognized permission denial with
status still unresolved permits a retry using `sudo -n -k --` and one exact getter.
Passing the flag is explicit operator authorization for that run; before
collection, the CLI lists the fixed commands and explains the boundary:

- `/usr/sbin/systemsetup -getremotelogin`
- `/usr/sbin/systemsetup -getusingnetworktime`
- `/usr/sbin/softwareupdate --schedule` with no setting argument

No other command, preference helper or screen-lock read is elevated. Closed
stdin and `-n` prevent password prompts; the ten-second timeout remains in
force. Each exact getter must already have administrator-approved passwordless
authorization. `-k` with a command ignores existing cached sudo credentials and
does not update them; a cached sudo login is insufficient. CyberAssess never
creates authorization, requests or collects passwords, establishes or refreshes
cached credentials, changes sudoers or runs a privileged preflight. Unavailable
or denied elevation produces a clear sanitized ERROR; the collector does not
replace it with a guessed PASS.
No setter, enable/disable operation, write or remediation command is allowlisted.
Known conflicting SSH override/registration evidence remains ERROR without an
elevated retry; additional privilege must not conceal a state contradiction.

## Evidence provenance and protected behavior

Existing public evidence keys are retained: the assessed scalar,
`_collection_ok`, `_raw` and `_scope`. Fixed labels distinguish effective native
status, effective resolved/managed configuration, explicit configured values,
and unavailable effective state. Valid ByHost/managed precedence can make an
effective value differ from the any-host value. Conflicting effective sources,
or inconsistent highest-priority configured values without a verified managed
override, remain ERROR. Raw system output is not retained.

Report presentation, scoring, SSH collection, complete control definitions,
severity, NIST mappings and public JSON structure are unchanged. Existing CLI
behavior is preserved without the added optional flag. MAC-011's known numeric
delay continues to be evaluated independently under its published definition;
it is not gated on MAC-010. Configuration resolution is not an interactive
lock/unlock test or proof of successful time synchronization.

## Live validation handoff

Use the maintainer's reviewed revision on
`feature/multiplatform-cyberassess`. Record the tested commit and working-tree
state before native acceptance. Do not merge into main for these checks. From
the repository root, as the intended assessment user, run normal read-only mode:

```bash
.venv/bin/python main.py --profile macos --local --output reports/macos-read-only
```

If the owner has authorized the optional privileged getters and existing
administrator-approved passwordless authorization covers the exact getters,
run elevated read-only mode:

```bash
.venv/bin/python main.py --profile macos --local --allow-elevated-read --output reports/macos-elevated-read
```

Do not run the entire Python process with sudo: that changes the user-preference
scope. Each command prints its matching JSON/HTML report paths. Inspect
MAC-005, MAC-009, MAC-010, MAC-011 and MAC-012, including sanitized raw_evidence
and the evidence bundle's _scope/_raw where available. Compare normal and
optional elevated results. A reliably insecure value produces FAIL; an
assessment completing successfully does not guarantee every control passed.

MAC-005 and MAC-009 can become assessable when native status or complete scoped
configuration is readable. MAC-010/011 can become assessable when the native
resolver exposes current-user/ByHost/managed values even without legacy
any-host keys. NULL still means ERROR. MAC-011 does not depend on MAC-010's
status; it assesses only its own known numeric delay. MAC-012 may remain ERROR
when normal reads are denied and policy cannot establish state. The optional
mode can resolve a recognized permission block only if sudo authorizes the
exact status getter without cached credentials. Authorized native network-time
On/Off status can establish MAC-012 configuration; a running daemon cannot.
MAC-005 remains ERROR if the OS exposes no reliable check-specific schedule
scalar, including when other download/install settings are known. Denied or
unsupported elevated evidence remains ERROR, without guessed defaults.

## Source references and validation limits

- [softwareupdate manual](https://raw.githubusercontent.com/keith/xcode-man-pages/master/docs/softwareupdate.8.html): --schedule queries the machine automatic-check preference; authentication may be required.
- [sudo manual](https://raw.githubusercontent.com/keith/xcode-man-pages/main/docs/sudo.8.html): `-n` prohibits prompts; `-k` with a command ignores and does not update cached credentials.
- [Apple public CFPreferences API](https://raw.githubusercontent.com/apple-oss-distributions/CF/main/CFPreferences.h) and [resolution implementation](https://raw.githubusercontent.com/apple-oss-distributions/CF/main/CFApplicationPreferences.c): resolved values, exact user/host domains and NULL handling.
- [Current NIST screen-lock requirement](https://raw.githubusercontent.com/usnistgov/macos_security/main/src/mscp/data/rules/system_settings/system_settings_screensaver_password_enforce.yaml) and [delay rule](https://raw.githubusercontent.com/usnistgov/macos_security/main/src/mscp/data/rules/system_settings/system_settings_screensaver_ask_for_password_delay_enforce.yaml): native resolved preference reads.
- [launchctl manual](https://raw.githubusercontent.com/keith/xcode-man-pages/master/docs/launchctl.1.html) and [Apple SSH definition](https://raw.githubusercontent.com/apple-oss-distributions/OpenSSH/main/com.openssh.sshd.plist): system-domain queries, explicit defaults and unstable diagnostic output.
- [Current NIST automatic-time enforcement](https://raw.githubusercontent.com/usnistgov/macos_security/main/src/mscp/data/rules/system_settings/system_settings_time_server_enforce.yaml): forced automatic-time policy, not an unprivileged general runtime status API.

Automated checks use injected commands and fake CoreFoundation bindings on
Linux. They verify parsing, state resolution, scopes, privacy, permissions,
resource release and portable code behavior. They do not establish acceptance
on a real macOS release; the live command above is still required.
