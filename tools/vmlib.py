# SPDX-License-Identifier: MIT
"""Transports to the test VMs of goal A.

OpenWrt VM 192.168.189.130: root with a password that the caller passes on one
stdin line. The password stays in memory and reaches ssh through sshpass -d (a
pipe), never a command line, a file or the environment. The host key is checked
against a saved known_hosts file.

Ubuntu VM 192.168.189.142: user codex with a key (see linuxreflect's AGENTS.md).
"""

import os
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OPENWRT = "192.168.189.130"
UBUNTU = "192.168.189.142"
STAGE = "/tmp/haproxy-advanced-test"
UBUNTU_DIR = "/home/codex/haproxy-advanced-test"
KNOWN_HOSTS = ROOT / "logs" / "vm-known_hosts"
SOURCE_KNOWN_HOSTS = Path("/home/w0w/cake-autorate-rs/logs/vm-20260923-known_hosts")


class OpenWrt:
    def __init__(self, password=None):
        if password is None:
            password = sys.stdin.buffer.readline().rstrip(b"\r\n")

        if not password or len(password) > 4096:
            raise ValueError("no password on stdin")

        self.password = password

        if not KNOWN_HOSTS.exists():
            KNOWN_HOSTS.parent.mkdir(parents=True, exist_ok=True)
            KNOWN_HOSTS.write_bytes(SOURCE_KNOWN_HOSTS.read_bytes())

    def _argv(self, rd, command, extra=()):
        return ["/usr/bin/sshpass", "-d", str(rd), "/usr/bin/ssh",
                "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlias=" + OPENWRT,
                "-o", "UserKnownHostsFile=" + str(KNOWN_HOSTS),
                "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1",
                "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3",
                "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
                *extra, "root@" + OPENWRT, command]

    def run(self, command, data=None, timeout=60, check=True):
        rd, wr = os.pipe()

        try:
            os.write(wr, self.password + b"\n")
        finally:
            os.close(wr)

        try:
            r = subprocess.run(self._argv(rd, command), pass_fds=(rd,), input=data,
                               capture_output=True, timeout=timeout)
        finally:
            os.close(rd)

        if check and r.returncode:
            raise RuntimeError("OpenWrt command failed (%d): %s\n%s" % (
                r.returncode, command[:200], r.stderr.decode(errors="replace")[-2000:]))

        return r

    def out(self, command, **kw):
        return self.run(command, **kw).stdout.decode(errors="replace")

    def upload(self, data, dest, mode="600"):
        assert dest.startswith(STAGE + "/") or dest.startswith("/etc/config/haproxy-advanced"), dest
        assert all(c.isalnum() or c in "/._-" for c in dest), dest

        if isinstance(data, str):
            data = data.encode()

        self.run("umask 077; mkdir -p %s && cat > %s && chmod %s %s" % (
            shlex.quote(os.path.dirname(dest)), shlex.quote(dest), mode, shlex.quote(dest)), data=data)

    def tunnel(self, local_port, remote_port, control):
        """SSH master forwarding a local port to the VM's loopback port."""
        rd, wr = os.pipe()

        try:
            os.write(wr, self.password + b"\n")
        finally:
            os.close(wr)

        argv = self._argv(rd, "", extra=["-N", "-M", "-S", control, "-o", "ControlPersist=no",
                                         "-o", "ExitOnForwardFailure=yes",
                                         "-L", "127.0.0.1:%d:127.0.0.1:%d" % (local_port, remote_port)])
        argv.remove("")

        try:
            return subprocess.Popen(argv, pass_fds=(rd,), stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        finally:
            os.close(rd)


class Ubuntu:
    ARGV = ["/usr/bin/ssh", "-o", "BatchMode=yes", "-o", "HostKeyAlias=192.168.189.144",
            "-o", "ConnectTimeout=10", "-i", "/home/w0w/.ssh/rustadmin_vm_ed25519",
            "codex@" + UBUNTU]

    def run(self, command, data=None, timeout=60, check=True):
        r = subprocess.run(self.ARGV + [command], input=data, capture_output=True, timeout=timeout)

        if check and r.returncode:
            raise RuntimeError("Ubuntu command failed (%d): %s\n%s" % (
                r.returncode, command[:200], r.stderr.decode(errors="replace")[-2000:]))

        return r

    def out(self, command, **kw):
        return self.run(command, **kw).stdout.decode(errors="replace")

    def upload(self, data, dest, mode="644"):
        assert dest.startswith(UBUNTU_DIR + "/"), dest

        if isinstance(data, str):
            data = data.encode()

        self.run("mkdir -p %s && cat > %s && chmod %s %s" % (
            shlex.quote(os.path.dirname(dest)), shlex.quote(dest), mode, shlex.quote(dest)), data=data)
