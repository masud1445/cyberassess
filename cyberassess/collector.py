from __future__ import annotations

from pathlib import Path
from typing import Any
import re
import time

import paramiko

from cyberassess.timestamps import collection_clock


_PACKAGE_STATE = r"""
package_state() {
    package="$1"
    status="$(LC_ALL=C dpkg-query -W -f='${Status}' "$package" 2>&1)"
    code=$?
    if [ "$code" -eq 0 ]; then
        case "$status" in
            'unknown ok installed'|'install ok installed'|'hold ok installed'|\
            'deinstall ok installed'|'purge ok installed') echo true ;;
            'unknown ok not-installed'|'install ok not-installed'|'hold ok not-installed'|\
            'deinstall ok not-installed'|'purge ok not-installed'|\
            'unknown ok config-files'|'install ok config-files'|'hold ok config-files'|\
            'deinstall ok config-files'|'purge ok config-files') echo false ;;
            *) return 1 ;;
        esac
    elif [ "$code" -eq 1 ] && [ "$status" = "dpkg-query: no packages found matching $package" ]; then
        echo false
    else
        return 1
    fi
}
"""


class CollectionError(RuntimeError):
    pass


class SSHCollector:
    """
    Collect read-only security evidence from an authorized
    Ubuntu/Linux target over SSH.
    """

    def __init__(
        self,
        host: str,
        username: str,
        key_file: str,
        port: int = 22,
        accept_new_host: bool = False,
    ) -> None:
        self.host = host
        self.username = username
        self.key_file = str(
            Path(key_file).expanduser()
        )
        self.port = port
        self.accept_new_host = accept_new_host


    def _connect(
        self,
    ) -> paramiko.SSHClient:
        """
        Create the SSH connection.
        """

        client = paramiko.SSHClient()

        client.load_system_host_keys()

        if self.accept_new_host:
            client.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
            )
        else:
            client.set_missing_host_key_policy(
                paramiko.RejectPolicy()
            )

        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            key_filename=self.key_file,
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
        )

        return client


    @staticmethod
    def _run(
        client: paramiko.SSHClient,
        command: str,
    ) -> dict[str, Any]:
        """
        Run one read-only command and return
        stdout, stderr and exit code.
        """

        channel = None
        try:
            _stdin, stdout, stderr = client.exec_command(command, timeout=20)
            channel = stdout.channel
            # Drain the bounded query summaries before awaiting status; waiting
            # first can deadlock a full SSH receive window. Paramiko bounds
            # channel I/O separately; this deadline bounds the later status wait.
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            deadline = time.monotonic() + 20
            while not channel.exit_status_ready():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Read-only SSH exit status unavailable.")
                time.sleep(min(0.05, remaining))
            exit_code = channel.recv_exit_status()
        except (OSError, paramiko.SSHException) as exc:
            if channel is not None:
                try:
                    channel.close()
                except (OSError, paramiko.SSHException):
                    pass
            return {
                "exit_code": 124 if isinstance(exc, TimeoutError) else 255,
                "stdout": "",
                "stderr": "Unavailable: read-only SSH command could not complete reliably.",
            }
        return {"exit_code": exit_code, "stdout": out, "stderr": err}



    @staticmethod
    def _integer(
        text: str,
    ) -> int | None:
        """Accept a complete bounded ASCII integer, never digits in diagnostics."""
        if isinstance(text, str) and re.fullmatch(r"[0-9]{1,10}", text):
            value = int(text)
            return value if value <= 2147483647 else None
        return None


    @staticmethod
    def _yes_no_to_bool(
        value: str,
    ) -> bool | None:
        """Read the exact normalized Boolean emitted by the fixed queries."""
        return {"true": True, "false": False}.get(value) if isinstance(value, str) else None

    @staticmethod
    def _successful(result: dict) -> bool:
        return (
            type(result.get("exit_code")) is int and result["exit_code"] == 0
            and isinstance(result.get("stdout"), str)
            and isinstance(result.get("stderr"), str) and not result["stderr"].strip()
        )

    @classmethod
    def _scalar_result(cls, result: dict, parser) -> dict:
        """Keep typed scalar summaries, not failed or malformed native output."""
        value = parser(result["stdout"]) if cls._successful(result) else None
        if value is None:
            return {"exit_code": 1, "stdout": "", "stderr": "Unavailable: read-only Ubuntu query failed or returned ambiguous evidence."}
        text = str(value).lower() if isinstance(value, bool) else str(value)
        return {"exit_code": 0, "stdout": text, "stderr": ""}


    def collect(
        self,
    ) -> dict[str, Any]:
        """
        Collect all live evidence required by
        the CyberAssess baseline.
        """

        try:
            client = self._connect()

        except Exception as exc:
            raise CollectionError(
                f"SSH connection failed: {exc}"
            ) from exc


        try:
            # ==================================================
            # Target identity
            # ==================================================

            hostname_result = self._run(
                client,
                "hostname",
            )

            hostname = (
                hostname_result["stdout"]
                or self.host
            )


            # ==================================================
            # SSH hardening evidence
            # ==================================================

            sshd = self._run(
                client,
                r"""
                configuration="$(sudo -n /usr/sbin/sshd -T 2>/dev/null)" || exit 1
                printf '%s\n' "$configuration" | awk '
                $1=="permitrootlogin" || $1=="passwordauthentication" ||
                $1=="maxauthtries" || $1=="x11forwarding" ||
                $1=="clientaliveinterval" {
                    if (NF != 2 || seen[$1]++) invalid=1
                    values[$1]=$2
                }
                END {
                    if (invalid) exit 1
                    print "PermitRootLogin=" values["permitrootlogin"];
                    print "PasswordAuthentication=" values["passwordauthentication"];
                    print "MaxAuthTries=" values["maxauthtries"];
                    print "X11Forwarding=" values["x11forwarding"];
                    print "ClientAliveInterval=" values["clientaliveinterval"]
                }'
                """,
            )

            sshd_map = {}
            sshd_ok = self._successful(sshd)
            known_fields = {"PermitRootLogin", "PasswordAuthentication", "MaxAuthTries", "X11Forwarding", "ClientAliveInterval"}
            if sshd_ok:
                for line in sshd["stdout"].splitlines():
                    key, separator, value = line.partition("=")
                    if not separator or key not in known_fields or key in sshd_map:
                        sshd_ok = False
                        break
                    sshd_map[key] = value
                sshd_ok = sshd_ok and set(sshd_map) == known_fields
            if sshd_ok:
                for key, allowed in (
                    ("PermitRootLogin", {"yes", "no", "prohibit-password", "without-password", "forced-commands-only"}),
                    ("PasswordAuthentication", {"yes", "no"}),
                    ("X11Forwarding", {"yes", "no"}),
                ):
                    if sshd_map[key] not in allowed:
                        sshd_map[key] = None
                for key in ("MaxAuthTries", "ClientAliveInterval"):
                    value = self._integer(sshd_map[key])
                    sshd_map[key] = str(value) if value is not None else None
                sshd = {"exit_code": 0, "stdout": "\n".join(
                    key + "=" + (str(sshd_map[key]) if sshd_map[key] is not None else "Unknown")
                    for key in ("PermitRootLogin", "PasswordAuthentication", "MaxAuthTries", "X11Forwarding", "ClientAliveInterval")
                ), "stderr": ""}
            else:
                sshd_map = {}
                sshd = {"exit_code": 1, "stdout": "", "stderr": "Unavailable: effective SSH configuration could not be read reliably."}


            # ==================================================
            # Firewall
            # ==================================================

            firewall = self._run(
                client,
                _PACKAGE_STATE + r"""
                if command -v ufw >/dev/null 2>&1; then
                    status="$(LC_ALL=C sudo -n ufw status 2>/dev/null)" || exit 1
                    first="$(printf '%s\n' "$status" | head -n 1)"
                    case "$first" in
                        'Status: active') echo active ;;
                        'Status: inactive') echo inactive ;;
                        *) exit 1 ;;
                    esac
                else
                    state="$(package_state ufw)" || exit 1
                    [ "$state" = false ] || exit 1
                    echo not_installed
                fi
                """,
            )


            # ==================================================
            # File permissions
            # ==================================================

            shadow_mode = self._run(
                client,
                r"""
                stat -c '%a' /etc/shadow 2>/dev/null
                """,
            )

            passwd_mode = self._run(
                client,
                r"""
                stat -c '%a' /etc/passwd 2>/dev/null
                """,
            )


            # ==================================================
            # Account security
            # ==================================================

            empty_passwords = self._run(
                client,
                r"""
                sudo -n awk -F: '
                ($2=="") {
                    count++
                }
                END {
                    print count+0
                }' /etc/shadow 2>/dev/null
                """,
            )

            uid_zero = self._run(
                client,
                r"""
                awk -F: '
                ($3==0 && $1!="root") {
                    count++
                }
                END {
                    print count+0
                }' /etc/passwd
                """,
            )


            # ==================================================
            # Password policy
            # ==================================================

            password_policy = self._run(
                client,
                r"""
                # Absence is meaningful only after all relevant directories and
                # existing files were readable. Conflicting explicit values are
                # not resolved by guessing file/PAM precedence.
                [ -r /etc/security ] && [ -x /etc/security ] || exit 1
                if [ -L /etc/security/pwquality.conf.d ] && [ ! -e /etc/security/pwquality.conf.d ]; then
                    exit 1
                fi
                observations=''
                for file in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
                do
                    if [ "$file" != /etc/security/pwquality.conf ]; then
                        if [ -e /etc/security/pwquality.conf.d ]; then
                            [ -d /etc/security/pwquality.conf.d ] &&
                            [ -r /etc/security/pwquality.conf.d ] &&
                            [ -x /etc/security/pwquality.conf.d ] || exit 1
                        fi
                    fi
                    if [ ! -e "$file" ]; then
                        [ ! -L "$file" ] || exit 1
                        continue
                    fi
                    [ -f "$file" ] && [ -r "$file" ] || exit 1
                    lines="$(grep -hE '^[[:space:]]*minlen[[:space:]]*=' "$file" 2>/dev/null)"
                    status=$?
                    [ "$status" -eq 0 ] || [ "$status" -eq 1 ] || exit 1
                    observations="$observations
$lines"
                done
                printf '%s\n' "$observations" | awk '
                /^[[:space:]]*minlen[[:space:]]*=/ {
                    value=$0
                    sub(/^[[:space:]]*minlen[[:space:]]*=[[:space:]]*/, "", value)
                    sub(/[[:space:]]*#.*/, "", value)
                    sub(/[[:space:]]*$/, "", value)
                    if (value !~ /^[0-9]+$/) invalid=1
                    if (found && value+0 != previous+0) invalid=1
                    previous=value
                    found=1
                }
                END {
                    if (invalid) exit 1
                    if (found) print previous
                }'
                """,
            )

            pam_policy = self._run(
                client,
                r"""
                [ -f /etc/pam.d/common-password ] &&
                [ -r /etc/pam.d/common-password ] || exit 1
                configuration="$(cat /etc/pam.d/common-password 2>/dev/null)" || exit 1
                printf '%s\n' "$configuration" | awk '
                /^[[:space:]]*#/ { next }
                {
                    sub(/[[:space:]]*#.*/, "")
                    if ($1!="password" && $1!="-password") next
                    module=0
                    for (field=1; field<=NF; field++) {
                        if ($field ~ /(^|\/)pam_pwquality[.]so$/) module=field
                    }
                    if (!module) next
                    for (field=module+1; field<=NF; field++) {
                        if ($field ~ /^#/) break
                        if ($field ~ /^minlen=/) {
                            value=$field
                            sub(/^minlen=/, "", value)
                            if (value !~ /^[0-9]+$/ || found++) invalid=1
                            previous=value
                        }
                    }
                }
                END {
                    if (invalid) exit 1
                    if (found) print previous
                }'
                """,
            )

            file_ok = self._successful(password_policy)
            pam_ok = self._successful(pam_policy)
            file_minimum = self._integer(password_policy["stdout"]) if file_ok and password_policy["stdout"] else None
            pam_minimum = self._integer(pam_policy["stdout"]) if pam_ok and pam_policy["stdout"] else None
            password_policy_ok = (
                file_ok and pam_ok
                and (not password_policy["stdout"] or file_minimum is not None)
                and (not pam_policy["stdout"] or pam_minimum is not None)
                and (file_minimum is None or pam_minimum is None or file_minimum == pam_minimum)
            )
            minimum_length = (pam_minimum if pam_minimum is not None else file_minimum) if password_policy_ok else None


            # ==================================================
            # Audit daemon
            # ==================================================

            auditd = self._run(
                client,
                r"""
                LC_ALL=C systemctl is-active --quiet auditd 2>/dev/null
                state=$?
                if [ "$state" -eq 0 ]; then
                    echo active
                    exit 0
                fi
                [ "$state" -eq 3 ] || [ "$state" -eq 4 ] || exit 1
                units="$(LC_ALL=C systemctl list-unit-files auditd.service --no-legend --no-pager 2>/dev/null)" || exit 1
                if [ -z "$units" ]; then
                    echo not_installed
                elif [ "$state" -eq 3 ] && printf '%s\n' "$units" | grep -Eq '^auditd[.]service[[:space:]]'; then
                    echo inactive
                else
                    exit 1
                fi
                """,
            )


            # ==================================================
            # Automatic security updates
            # ==================================================

            updates = self._run(
                client,
                _PACKAGE_STATE + r"""
                installed="$(package_state unattended-upgrades)" || exit 1
                if [ "$installed" = false ]; then
                    echo false
                    exit 0
                fi
                configuration="$(LC_ALL=C apt-config dump 2>/dev/null)" || exit 1
                [ -n "$configuration" ] || exit 1
                printf '%s\n' "$configuration" | awk '
                NF {
                    rows++
                    if ($0 !~ /^[[:space:]]*[^[:space:]"]+[[:space:]]+"([^"\\]|\\.)*";[[:space:]]*$/) invalid=1
                }
                $1=="APT::Periodic::Unattended-Upgrade" {
                    count++
                    if (NF != 2 || $2 !~ /^"[0-9]+";$/) invalid=1
                    if ($2=="\"1\";") enabled=1
                }
                END {
                    if (invalid || !rows || count>1) exit 1
                    print enabled ? "true" : "false"
                }'
                """,
            )

            # ==================================================
            # Time synchronization
            # ==================================================

            time_sync = self._run(
                client,
                r"""
                LC_ALL=C
                export LC_ALL
                synced="$(LC_ALL=C timedatectl show -p NTPSynchronized --value 2>/dev/null)"
                status=$?
                known_inactive=false
                if [ "$status" -eq 0 ]; then
                    case "$synced" in
                        yes|true) echo active; exit 0 ;;
                        no|false) known_inactive=true ;;
                        *) exit 1 ;;
                    esac
                fi
                if command -v chronyc >/dev/null 2>&1; then
                    LC_ALL=C systemctl is-active --quiet chrony 2>/dev/null
                    service=$?
                    if [ "$service" -eq 0 ]; then
                        tracking="$(LC_ALL=C chronyc tracking 2>/dev/null)" || exit 1
                        printf '%s\n' "$tracking" | awk -F: '
                        /^[ \t]*Reference ID[ \t]*:/ { refs++; reference=$2; sub(/^[ \t]+/, "", reference); split(reference, parts, /[ \t]+/); reference=parts[1] }
                        /^[ \t]*Leap status[ \t]*:/ { leaps++; leap=$2; gsub(/^[ \t]+|[ \t]+$/, "", leap) }
                        /^[ \t]*System time[ \t]*:/ {
                            times++; time=$2; gsub(/^[ \t]+|[ \t]+$/, "", time)
                            fields=split(time, parts, /[ \t]+/); offset=parts[1]
                            if (fields!=6 || parts[2]!="seconds" || (parts[3]!="fast" && parts[3]!="slow") || parts[4]!="of" || parts[5]!="NTP" || parts[6]!="time") invalid=1
                        }
                        END {
                            if (invalid || refs!=1 || leaps!=1 || times!=1) exit 1
                            if (reference!="0" && (reference !~ /^[0-9A-Fa-f]+$/ || length(reference)!=8)) exit 1
                            if (offset !~ /^[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+)([eE][+-]?[0-9]+)?$/ || length(offset)>40) exit 1
                            value=offset+0
                            if (value>1e12 || value< -1e12) exit 1
                            if (leap!="Normal" && leap!="Not synchronised") exit 1
                            if (leap=="Normal" && (reference=="00000000" || reference=="0")) exit 1
                            if (value<0) value=-value
                            print (leap=="Normal" && value<=5.0) ? "active" : "inactive"
                        }'
                        exit $?
                    fi
                fi
                [ "$known_inactive" = true ] || exit 1
                echo inactive
                """,
            )


            # ==================================================
            # Insecure service check - Telnet server
            # ==================================================

            telnet = self._run(
                client,
                _PACKAGE_STATE + r"""
                installed=false
                unavailable=false
                for package in telnetd inetutils-telnetd
                do
                    state="$(package_state "$package")"
                    if [ "$?" -ne 0 ]; then
                        unavailable=true
                    elif [ "$state" = true ]; then
                        installed=true
                    fi
                done
                # One confirmed installed server is conclusive. Secure absence
                # requires both package queries to have succeeded reliably.
                if [ "$installed" = true ]; then
                    echo true
                elif [ "$unavailable" = true ]; then
                    exit 1
                else
                    echo false
                fi
                """,
            )

            # ==================================================
            # Build structured evidence
            # ==================================================

            # The fixed scripts emit bounded summaries; never extract digits
            # from diagnostics or treat an unknown scalar as a security state.
            firewall = self._scalar_result(firewall, lambda value: value if value in {"active", "inactive", "not_installed"} else None)
            auditd = self._scalar_result(auditd, lambda value: value if value in {"active", "inactive", "not_installed"} else None)
            time_sync = self._scalar_result(time_sync, lambda value: value if value in {"active", "inactive"} else None)
            updates = self._scalar_result(updates, self._yes_no_to_bool)
            telnet = self._scalar_result(telnet, self._yes_no_to_bool)
            updates_enabled = self._yes_no_to_bool(updates["stdout"])
            telnet_installed = self._yes_no_to_bool(telnet["stdout"])
            for query_name in ("shadow_mode", "passwd_mode"):
                result = shadow_mode if query_name == "shadow_mode" else passwd_mode
                result = self._scalar_result(result, lambda value: value if re.fullmatch(r"[0-7]{1,4}", value) else None)
                if query_name == "shadow_mode":
                    shadow_mode = result
                else:
                    passwd_mode = result
            empty_passwords = self._scalar_result(empty_passwords, self._integer)
            uid_zero = self._scalar_result(uid_zero, self._integer)

            # Metadata only: this unprivileged getter does not affect any
            # security value or replace unavailable target timezone evidence.
            try:
                clock = self._run(client, "LC_ALL=C /bin/date --iso-8601=seconds")
                target_time = clock["stdout"] if clock["exit_code"] == 0 and not clock["stderr"] else None
            except (OSError, paramiko.SSHException):
                target_time = None

            return {
                "target_name":
                    hostname,

                "platform":
                    "Ubuntu Linux",

                "collector": {
                    **collection_clock(remote=True, target_time=target_time),
                    "method":
                        "SSH / Paramiko",

                    "host":
                        self.host,

                    "username":
                        self.username,

                    "read_only":
                        True,

                    "scope":
                        "Authorized Ubuntu target; selected configuration, package inventory and supported service-status checks.",

                    "limitations":
                        "Password checks compare explicit pwquality/PAM minlen observations, not complete PAM execution or enforcement. "
                        "Unreadable, malformed, unsupported or conflicting evidence remains ERROR.",
                },

                "evidence": {

                    # ------------------------------------------
                    # SSH
                    # ------------------------------------------

                    "sshd": {
                        "PermitRootLogin":
                            sshd_map.get(
                                "PermitRootLogin"
                            ),

                        "PasswordAuthentication":
                            sshd_map.get(
                                "PasswordAuthentication"
                            ),

                        "MaxAuthTries":
                            self._integer(
                                sshd_map.get(
                                    "MaxAuthTries",
                                    "",
                                )
                            ),

                        "X11Forwarding":
                            sshd_map.get(
                                "X11Forwarding"
                            ),

                        "ClientAliveInterval":
                            self._integer(
                                sshd_map.get(
                                    "ClientAliveInterval",
                                    "",
                                )
                            ),

                        "_collection_ok":
                            sshd[
                                "exit_code"
                            ] == 0,

                        "_raw":
                            (
                                sshd["stdout"]
                                or
                                sshd["stderr"]
                            ),
                    },


                    # ------------------------------------------
                    # Firewall
                    # ------------------------------------------

                    "firewall": {
                        "status":
                            firewall[
                                "stdout"
                            ] or None,

                        "_collection_ok":
                            firewall[
                                "exit_code"
                            ] == 0,

                        "_raw":
                            (
                                firewall["stdout"]
                                or
                                firewall["stderr"]
                            ),
                    },


                    # ------------------------------------------
                    # File permissions
                    # ------------------------------------------

                    "files": {
                        "shadow_mode":
                            shadow_mode[
                                "stdout"
                            ] or None,

                        "passwd_mode":
                            passwd_mode[
                                "stdout"
                            ] or None,

                        "_collection_ok":
                            (
                                shadow_mode[
                                    "exit_code"
                                ] == 0
                                and
                                passwd_mode[
                                    "exit_code"
                                ] == 0
                            ),

                        "_raw":
                            (
                                "shadow_mode="
                                f"{shadow_mode['stdout']}; "
                                "passwd_mode="
                                f"{passwd_mode['stdout']}"
                            ),
                    },


                    # ------------------------------------------
                    # Accounts
                    # ------------------------------------------

                    "accounts": {
                        "empty_password_count":
                            self._integer(
                                empty_passwords[
                                    "stdout"
                                ]
                            ),

                        "uid0_nonroot_count":
                            self._integer(
                                uid_zero[
                                    "stdout"
                                ]
                            ),

                        "_collection_ok":
                            (
                                empty_passwords[
                                    "exit_code"
                                ] == 0
                                and
                                uid_zero[
                                    "exit_code"
                                ] == 0
                            ),

                        "_raw":
                            (
                                "empty_password_count="
                                f"{empty_passwords['stdout']}; "
                                "uid0_nonroot_count="
                                f"{uid_zero['stdout']}"
                            ),
                    },


                    # ------------------------------------------
                    # Password policy
                    # ------------------------------------------

                    "password_policy": {
                        "minimum_length":
                            minimum_length,

                        "configured":
                            minimum_length is not None if password_policy_ok else None,

                        "_collection_ok":
                            password_policy_ok,

                        "_raw":
                            (
                                "minimum_length="
                                f"{minimum_length}"
                                if minimum_length
                                is not None
                                else
                                "No explicit minimum password length detected"
                                if password_policy_ok else
                                "Unavailable: password configuration is unreadable, malformed or contradictory."
                            ),
                    },


                    # ------------------------------------------
                    # Audit daemon
                    # ------------------------------------------

                    "auditd": {
                        "status":
                            auditd[
                                "stdout"
                            ] or None,

                        "_collection_ok":
                            auditd[
                                "exit_code"
                            ] == 0,

                        "_raw":
                            (
                                auditd["stdout"]
                                or
                                auditd["stderr"]
                            ),
                    },


                    # ------------------------------------------
                    # Automatic updates
                    # ------------------------------------------

                    "updates": {
                        "enabled":
                            updates_enabled,

                        "_collection_ok":
                            (
                                updates[
                                    "exit_code"
                                ] == 0
                                and
                                updates_enabled
                                is not None
                            ),

                        "_raw":
                            (
                                updates["stdout"]
                                or
                                updates["stderr"]
                            ),
                    },


                    # ------------------------------------------
                    # Time synchronization
                    # ------------------------------------------

                    "time_sync": {
                        "status":
                            time_sync[
                                "stdout"
                            ] or None,

                        "_collection_ok":
                            (
                                time_sync[
                                    "exit_code"
                                ] == 0
                            ),

                        "_raw":
                            (
                                time_sync["stdout"]
                                or
                                time_sync["stderr"]
                            ),
                    },


                    # ------------------------------------------
                    # Services
                    # ------------------------------------------

                    "services": {
                        "telnet_installed":
                            telnet_installed,

                        "_collection_ok":
                            (
                                telnet[
                                    "exit_code"
                                ] == 0
                                and
                                telnet_installed
                                is not None
                            ),

                        "_raw":
                            (
                                "telnet_installed="
                                f"{telnet['stdout']}"
                            ),
                    },
                },
            }


        finally:
            client.close()
