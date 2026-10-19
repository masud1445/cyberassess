# SSH and target preparation

Use this checklist before the first live assessment from each laptop. Demo mode
needs no SSH access. These instructions describe the existing collector; they do
not configure or remediate the target automatically.

## Scope and target compatibility

- Obtain the system owner's authorization for the specific host, account,
  assessment window, and access level. Record that approval in the handover.
- Use an Ubuntu target with OpenSSH server, a normal login shell, and reachable
  SSH TCP port. The baseline assumes Ubuntu paths, GNU `stat`, systemd, and
  Debian package/APT tools. A macOS or Windows **client** is supported; a macOS,
  Windows, non-systemd container, or arbitrary Linux **target** is not an
  equivalent assessment platform.
- The collector reads configuration, service state, and package state using
  `hostname`, `awk`, `head`, `stat`, `grep`, `tail`, `sed`, `systemctl`,
  `dpkg-query`, `apt-config`, and `timedatectl`. It also probes `ufw`,
  `/usr/sbin/sshd`, and optionally `chronyc`. The account needs ordinary read
  access to the password-policy and PAM files under `/etc`.
- UFW, auditd, unattended-upgrades, password policy, and time synchronization
  are assessment subjects. Do not install or enable them merely to make a
  preflight pass: their absence or configuration is evidence to assess.

## SSH identity on the new laptop

Ask the administrator to authorize the **public** key for a dedicated assessment
account through the organization's normal process. Keep the private key outside
the repository, reports, and shared handover files. Do not copy another person's
private key as part of the handover.

The application requires an explicit `--key` path. It disables SSH-agent use and
automatic identity discovery, and has no password or key-passphrase prompt or
option. An encrypted private key that works with interactive OpenSSH or an agent
will therefore not work here. Use an approved, dedicated file-based identity
usable without a passphrase, with restrictive file permissions and limited target
access. If organizational policy requires an encrypted or hardware-backed key,
live use is blocked by the current authentication support; demo mode remains
available. Do not remove a passphrase from an existing personal key.

On macOS/Linux, restrict the dedicated private key to its owner:

```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/cyberassess_audit
```

On Windows, store the key in the user's profile `.ssh` directory and inspect its
ACL using `icacls "$env:USERPROFILE\.ssh\cyberassess_audit"` in PowerShell.
Use the organization's Windows/OpenSSH ACL procedure to restrict access to the
owner and required administrators. Never grant broad read access to fix a key
error. The application itself does not enforce OpenSSH's private-key ACL checks.

## Verify and persist the server host key

Obtain the server's host-key fingerprint through a trusted administrator or
console channel. For example, the administrator can inspect an Ed25519 host key
on the target using `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`; confirm
the fingerprint for the algorithm actually offered by that server.

From the new laptop, use OpenSSH once, comparing the displayed fingerprint
before accepting it. Replace the example address and account with the authorized
values. `192.0.2.10` is a documentation address.

macOS/Linux:

```bash
ssh -o IdentitiesOnly=yes -o IdentityAgent=none -o PreferredAuthentications=publickey \
  -i ~/.ssh/cyberassess_audit -p 22 auditor@192.0.2.10 true
```

Windows PowerShell with the OpenSSH Client installed:

```powershell
ssh -o IdentitiesOnly=yes -o IdentityAgent=none -o PreferredAuthentications=publickey `
  -i "$env:USERPROFILE\.ssh\cyberassess_audit" -p 22 auditor@192.0.2.10 true
```

Use the same hostname/IP and port in CyberAssess. Nondefault ports are stored as
`[hostname]:port` in `known_hosts`; an entry for port 22 does not cover port 2222.
Do not treat an unverified `ssh-keyscan` result as trusted. Investigate changed
host keys with the administrator instead of deleting entries blindly.

Paramiko loads only the current Python user's `~/.ssh/known_hosts` through
`load_system_host_keys()`. Despite that method's name, this invocation does not
load `/etc/ssh/ssh_known_hosts`, Windows system-wide trust files, or custom
OpenSSH `UserKnownHostsFile` settings. It also does not apply `~/.ssh/config`
aliases, `ProxyJump`, identities, or port settings. The address must be directly
reachable from the laptop and supplied explicitly to the CLI.

Check the actual trust-file location with the virtual environment's Python on
**each OS**, especially Windows, WSL, or when switching user accounts:

```bash
python -c "import os; print(os.path.expanduser('~/.ssh/known_hosts'))"
```

Ensure that file contains the verified server key. Windows OpenSSH normally uses
`%USERPROFILE%\.ssh\known_hosts`; WSL uses its own Linux home. Successful
OpenSSH login alone does not prove Paramiko is reading the same trust file.

`--accept-new-host` accepts an unknown host without verifying its identity. In
the current collector it does **not** persist that key for later runs. Prefer
the verified, saved trust procedure above for routine use.

## Passwordless sudo for the three privileged reads

The collector has no interactive terminal or sudo-password input. It uses
`sudo -n`, so the assessment account needs approved passwordless access to these
specific invocations on the target:

| Invocation | Read performed |
| --- | --- |
| `sudo -n /usr/sbin/sshd -T` | Effective SSH daemon configuration. |
| `sudo -n ufw status` | Firewall state, if UFW is installed. |
| `sudo -n awk -F: '…' /etc/shadow` | Counts entries with an empty password field using the exact program below; does not return password hashes. |

The AWK program in `cyberassess/collector.py` is:

```awk
($2=="") {
    count++
}
END {
    print count+0
}
```

Have the target administrator review `SSHCollector.collect()` and the local
`sudoers` policy. Resolve `ufw` and `awk` to their installed absolute paths and
limit permissions to the actual executable **and arguments**. Sudoers matching
of the AWK program includes its literal whitespace/newlines; the formatted
excerpt above is an explanation, not a drop-in sudoers argument string. Use
`visudo` to edit and validate any administrator-approved policy.

Do not grant `NOPASSWD: ALL`, unrestricted root `awk`, a privileged shell, or
wildcard program arguments as a shortcut. AWK is an interpreter that can execute
commands and write files; a permissive AWK rule grants far more than a read-only
count. The application runs read-only commands, but its credentials and sudo
permissions can still carry broader authority. A root-owned helper could offer
a smaller privilege boundary, but the current collector does not call one and
adopting one requires a separate reviewed code change. If an acceptable policy
cannot support the existing exact invocations, record the blocker and use demo
mode rather than widening access.

## Administrator-assisted preflight

In a normal SSH session as the assessment account, the administrator should:

1. Confirm the expected hostname, Ubuntu release, executable paths, and approved
   sudo rules. `sudo -n -l` can help inspect policy, but may itself require a
   password under local policy and is not proof that a particular read works.
2. Clear any cached sudo authorization with `sudo -k`, then test
   `sudo -n /usr/sbin/sshd -T` and, if installed, `sudo -n ufw status` **without**
   output redirection or pipelines, so permission and configuration errors stay
   visible. Keep configuration output within the authorized team.
3. Test the exact empty-password counting invocation from the collector under
   `sudo -n`, with its approved literal arguments. Check its exit status and
   count only; never print or copy `/etc/shadow` contents. Confirm that the
   invocation still works without a cached password and without a TTY.
4. Run the unprivileged probes under the same account and confirm the necessary
   files/tools are readable. Missing assessment services are findings; missing
   platform tooling or permissions are collection limitations to record.

Some current collector commands suppress stderr or use pipelines whose final
stage can succeed even when a privileged read failed. A completed run or zero
process exit code therefore does not establish successful collection. Review
the preflight, reported evidence, and all PASS/FAIL/ERROR results together.

Once those prerequisites are satisfied, run from the repository root with the
virtual environment active:

```bash
python main.py --host 192.0.2.10 --user auditor --key ~/.ssh/cyberassess_audit --port 22
```

On Windows PowerShell, use the explicit key path:

```powershell
python main.py --host 192.0.2.10 --user auditor --key "$env:USERPROFILE\.ssh\cyberassess_audit" --port 22
```

Reports contain target identity, account names, and configuration evidence.
Store and transfer them using the owner's approved access and retention rules.
