from __future__ import annotations

from pathlib import Path
from typing import Any
import re

import paramiko


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

        _stdin, stdout, stderr = (
            client.exec_command(
                command,
                timeout=20,
            )
        )

        exit_code = (
            stdout.channel.recv_exit_status()
        )

        out = (
            stdout.read()
            .decode(
                "utf-8",
                errors="replace",
            )
            .strip()
        )

        err = (
            stderr.read()
            .decode(
                "utf-8",
                errors="replace",
            )
            .strip()
        )

        return {
            "exit_code": exit_code,
            "stdout": out,
            "stderr": err,
        }


    @staticmethod
    def _first_number(
        text: str,
    ) -> int | None:
        """
        Extract the first integer from text.
        """

        match = re.search(
            r"(\d+)",
            text or "",
        )

        if match:
            return int(
                match.group(1)
            )

        return None


    @staticmethod
    def _yes_no_to_bool(
        value: str,
    ) -> bool | None:
        """
        Convert common yes/no values to bool.
        """

        normalized = (
            str(value)
            .strip()
            .lower()
        )

        if normalized in {
            "yes",
            "true",
            "1",
            "enabled",
            "active",
        }:
            return True

        if normalized in {
            "no",
            "false",
            "0",
            "disabled",
            "inactive",
        }:
            return False

        return None


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
                sudo -n /usr/sbin/sshd -T 2>/dev/null |
                awk '
                $1=="permitrootlogin" {
                    a=$2
                }
                $1=="passwordauthentication" {
                    b=$2
                }
                $1=="maxauthtries" {
                    c=$2
                }
                $1=="x11forwarding" {
                    d=$2
                }
                $1=="clientaliveinterval" {
                    e=$2
                }
                END {
                    print "PermitRootLogin=" a;
                    print "PasswordAuthentication=" b;
                    print "MaxAuthTries=" c;
                    print "X11Forwarding=" d;
                    print "ClientAliveInterval=" e
                }'
                """,
            )

            sshd_map: dict[str, str] = {}

            if sshd["exit_code"] == 0:

                for line in (
                    sshd["stdout"]
                    .splitlines()
                ):

                    if "=" in line:
                        key, value = (
                            line.split(
                                "=",
                                1,
                            )
                        )

                        sshd_map[
                            key.strip()
                        ] = value.strip()


            # ==================================================
            # Firewall
            # ==================================================

            firewall = self._run(
                client,
                r"""
                if command -v ufw >/dev/null 2>&1; then

                    status="$(
                        sudo -n ufw status 2>/dev/null |
                        head -n 1
                    )"

                    case "$status" in
                        *inactive*)
                            echo inactive
                            ;;
                        *active*)
                            echo active
                            ;;
                        *)
                            echo unknown
                            ;;
                    esac

                else
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
                (
                    grep -RhE \
                    '^[[:space:]]*minlen[[:space:]]*=' \
                    /etc/security/pwquality.conf \
                    /etc/security/pwquality.conf.d \
                    2>/dev/null |
                    tail -n 1 |
                    sed -E \
                    's/.*=[[:space:]]*([0-9]+).*/\1/'
                )
                """,
            )

            minimum_length = (
                self._first_number(
                    password_policy["stdout"]
                )
            )


            # Check PAM if pwquality config
            # did not contain an explicit minlen.

            if minimum_length is None:

                pam_policy = self._run(
                    client,
                    r"""
                    grep -E \
                    'pam_pwquality\.so.*minlen=' \
                    /etc/pam.d/common-password \
                    2>/dev/null |
                    tail -n 1 |
                    sed -nE \
                    's/.*minlen=([0-9]+).*/\1/p'
                    """,
                )

                minimum_length = (
                    self._first_number(
                        pam_policy["stdout"]
                    )
                )


            # ==================================================
            # Audit daemon
            # ==================================================

            auditd = self._run(
                client,
                r"""
                if systemctl is-active \
                    --quiet auditd \
                    2>/dev/null
                then
                    echo active

                elif systemctl list-unit-files \
                    auditd.service \
                    2>/dev/null |
                    grep -q '^auditd\.service'
                then
                    echo inactive

                else
                    echo not_installed
                fi
                """,
            )


            # ==================================================
            # Automatic security updates
            # ==================================================

            updates = self._run(
                client,
                r"""
                if ! dpkg-query \
                    -W \
                    -f='${Status}' \
                    unattended-upgrades \
                    2>/dev/null |
                    grep -q \
                    'install ok installed'
                then
                    echo false
                    exit 0
                fi

                if apt-config dump \
                    2>/dev/null |
                    grep -Eq \
                    'APT::Periodic::Unattended-Upgrade[[:space:]]+"1"'
                then
                    echo true
                else
                    echo false
                fi
                """,
            )

            updates_enabled = (
                self._yes_no_to_bool(
                    updates["stdout"]
                )
            )


            # ==================================================
            # Time synchronization
            # ==================================================

            time_sync = self._run(
                client,
                r"""
                # Method 1: systemd/timedatectl
                synced="$(
                    timedatectl show \
                    -p NTPSynchronized \
                    --value \
                    2>/dev/null
                )"

                if [ "$synced" = "yes" ] || [ "$synced" = "true" ]; then
                    echo active
                    exit 0
                fi

                # Method 2: Chrony
                if command -v chronyc >/dev/null 2>&1 \
                   && systemctl is-active --quiet chrony 2>/dev/null
                then
                    tracking="$(chronyc tracking 2>/dev/null)"

                    leap="$(
                        printf '%s\n' "$tracking" |
                        awk -F: '/Leap status/ {
                            gsub(/^[ \t]+|[ \t]+$/, "", $2)
                            print $2
                        }'
                    )"

                    reference="$(
                        printf '%s\n' "$tracking" |
                        awk -F: '/Reference ID/ {
                            gsub(/^[ \t]+|[ \t]+$/, "", $2)
                            print $2
                        }'
                    )"

                    offset="$(
                        printf '%s\n' "$tracking" |
                        awk '/System time/ {
                            print $4
                        }'
                    )"

                    if [ "$leap" = "Normal" ] \
                       && [ -n "$reference" ] \
                       && [ "$reference" != "0" ] \
                       && [ -n "$offset" ]
                    then
                        if awk -v value="$offset" 'BEGIN {
                            if (value < 0) value = -value
                            exit !(value <= 5.0)
                        }'
                        then
                            echo active
                            exit 0
                        fi
                    fi

                    echo inactive
                    exit 0
                fi

                echo inactive
                """,
            )


            # ==================================================
            # Insecure service check - Telnet server
            # ==================================================

            telnet = self._run(
                client,
                r"""
                installed=false

                for package in \
                    telnetd \
                    inetutils-telnetd
                do

                    if dpkg-query \
                        -W \
                        -f='${Status}' \
                        "$package" \
                        2>/dev/null |
                        grep -q \
                        'install ok installed'
                    then
                        installed=true
                    fi

                done

                echo "$installed"
                """,
            )

            telnet_installed = (
                self._yes_no_to_bool(
                    telnet["stdout"]
                )
            )


            # ==================================================
            # Build structured evidence
            # ==================================================

            return {
                "target_name":
                    hostname,

                "platform":
                    "Ubuntu Linux",

                "collector": {
                    "method":
                        "SSH / Paramiko",

                    "host":
                        self.host,

                    "username":
                        self.username,

                    "read_only":
                        True,
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
                            self._first_number(
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
                            self._first_number(
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
                            self._first_number(
                                empty_passwords[
                                    "stdout"
                                ]
                            ),

                        "uid0_nonroot_count":
                            self._first_number(
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
                            minimum_length
                            is not None,

                        "_collection_ok":
                            True,

                        "_raw":
                            (
                                "minimum_length="
                                f"{minimum_length}"
                                if minimum_length
                                is not None
                                else
                                "No explicit minimum "
                                "password length detected"
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