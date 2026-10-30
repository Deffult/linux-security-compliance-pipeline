#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Mr. Deffult | Linux Security & Compliance Pipeline - host auditor.

Read-only audit of a Linux host (or an unpacked root filesystem via --root):

  suid     SUID/SGID inventory, GTFOBins-class binaries, binaries in writable paths
  perms    permissions of critical files, world-writable files/dirs, sticky /tmp
  ssh      sshd hardening (effective `sshd -T` config, else parsed sshd_config)
  network  listening sockets exposed beyond loopback, risky ports, owning process
  users    UID 0 accounts, empty passwords, sudoers NOPASSWD, root-equivalent groups

Outputs structured JSON and/or a self-contained HTML report and exits non-zero
when the compliance gate (--fail-on / --min-score) is not met, so it can be used
as a CI/CD security gate.  Standard library only; the auditor never modifies the
system it inspects.
"""
from __future__ import annotations

import argparse
import fnmatch
import glob
import html
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

__version__ = "1.0.0"
TOOL_NAME = "Mr. Deffult | Linux Security & Compliance Pipeline"

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEV_WEIGHT = {"critical": 30, "high": 15, "medium": 5, "low": 2, "info": 0}
MAX_EVIDENCE = 100
ALL_CHECKS = ["suid", "perms", "ssh", "network", "users"]

DEFAULT_EXCLUDES = ["/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/var/lib/containerd"]
NETWORK_FS = {"nfs", "nfs4", "cifs", "smbfs", "smb3", "9p", "afs", "ceph", "glusterfs", "fuse.sshfs"}
CRITICAL_DIRS = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec",
                 "/lib", "/lib64", "/boot", "/usr/local/bin", "/usr/local/sbin"]
SUSPECT_PREFIXES = ["/tmp", "/var/tmp", "/dev/shm", "/home", "/root", "/mnt", "/media", "/srv",
                    "/var/www", "/run/user"]


# --------------------------------------------------------------------------- model
@dataclass
class Finding:
    id: str
    category: str
    title: str
    severity: str
    status: str  # pass | fail | skip
    detail: str = ""
    evidence: list = field(default_factory=list)
    remediation: str = ""


def _trim(items):
    items = list(items)
    if len(items) > MAX_EVIDENCE:
        extra = len(items) - MAX_EVIDENCE
        items = items[:MAX_EVIDENCE] + [f"... and {extra} more"]
    return items


def mk(fid, cat, title, sev, evidence, detail_fail, remediation, detail_pass="No issues found."):
    bad = bool(evidence)
    return Finding(fid, cat, title, sev, "fail" if bad else "pass",
                   detail_fail if bad else detail_pass, _trim(evidence) if bad else [], remediation)


def skip(fid, cat, title, why):
    return Finding(fid, cat, title, "info", "skip", why)


def under(path, prefixes):
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in prefixes)


def fmode(m):
    return format(stat.S_IMODE(m), "04o")


# --------------------------------------------------------------------------- context
class Ctx:
    """Filesystem view: live host (root == '/') or an unpacked rootfs."""

    def __init__(self, root="/", network="auto", excludes=None, allowlist=None):
        self.root = os.path.realpath(root)
        self.live = self.root == "/"
        self.network = self.live if network == "auto" else network == "on"
        self.excludes = list(DEFAULT_EXCLUDES) + list(excludes or [])
        self.allow = set(allowlist or [])
        self.warnings = []
        self._scan = None

    def p(self, path):
        return path if self.live else os.path.join(self.root, path.lstrip("/"))

    def rel(self, abspath):
        if self.live:
            return abspath
        r = abspath[len(self.root):]
        return r if r.startswith("/") else "/" + r

    def read(self, path):
        try:
            with open(self.p(path), encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    def lstat(self, path):
        try:
            return os.lstat(self.p(path))
        except OSError:
            return None

    def excluded(self, rel):
        for pat in self.excludes:
            if rel == pat or rel.startswith(pat.rstrip("/") + "/") or fnmatch.fnmatch(rel, pat):
                return True
        return False

    def _network_mounts(self):
        out = []
        if not self.live:
            return out
        try:
            with open("/proc/self/mounts", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] in NETWORK_FS:
                        out.append(parts[1].replace("\\040", " "))
        except OSError:
            pass
        return out

    def scan(self):
        """Single filesystem walk shared by the suid and perms checks."""
        if self._scan is not None:
            return self._scan
        res = {"suid": [], "ww_crit": [], "ww_dirs": [], "errors": 0}
        self.excludes += self._network_mounts()

        def onerr(_e):
            res["errors"] += 1

        for dirpath, dirnames, filenames in os.walk(self.root, topdown=True, onerror=onerr):
            rel = self.rel(dirpath)
            dirnames[:] = [d for d in dirnames if not self.excluded(os.path.join(rel, d))]
            crit = under(rel, CRITICAL_DIRS)
            for name in dirnames + filenames:
                try:
                    st = os.lstat(os.path.join(dirpath, name))
                except OSError:
                    res["errors"] += 1
                    continue
                m = st.st_mode
                relp = os.path.join(rel, name)
                if stat.S_ISLNK(m):
                    continue
                rec = (relp, m, st.st_uid, st.st_gid)
                if stat.S_ISDIR(m):
                    if m & stat.S_IWOTH and not m & stat.S_ISVTX:
                        res["ww_dirs"].append(rec)
                elif stat.S_ISREG(m):
                    if m & (stat.S_ISUID | stat.S_ISGID):
                        res["suid"].append(rec)
                    if crit and m & stat.S_IWOTH:
                        res["ww_crit"].append(rec)
        self._scan = res
        if res["errors"]:
            self.warnings.append(f"{res['errors']} filesystem entries could not be read (run as root for full coverage).")
        return res


def fmt_rec(rec):
    path, m, uid, gid = rec
    flags = []
    if m & stat.S_ISUID:
        flags.append("SUID")
    if m & stat.S_ISGID:
        flags.append("SGID")
    return f"{path}  mode={fmode(m)} uid={uid} gid={gid} {'+'.join(flags)}".rstrip()


# --------------------------------------------------------------------------- SUID / SGID
DANGEROUS_BASENAMES = {
    "bash", "sh", "dash", "zsh", "csh", "tcsh", "ksh", "fish", "busybox", "env", "find", "xargs", "awk", "gawk",
    "mawk", "sed", "vim", "vi", "nano", "emacs", "less", "more", "man", "cp", "mv", "dd", "tar", "zip", "unzip",
    "rsync", "tee", "cat", "head", "tail", "nmap", "tcpdump", "strace", "ltrace", "gdb", "docker", "podman",
    "systemctl", "taskset", "nice", "ionice", "wget", "curl", "nc", "ncat", "netcat", "socat", "openssl",
    "base64", "xxd", "node", "nodejs", "lua", "ed", "ftp", "scp", "ssh", "git", "make", "mount.cifs",
}
DANGEROUS_RE = re.compile(r"^(python[\d.]*|perl[\d.]*|ruby[\d.]*|php[\d.]*|bash[\d.]*)$")
STANDARD_SUID = {
    "su", "sudo", "sudoedit", "passwd", "chsh", "chfn", "gpasswd", "newgrp", "newuidmap", "newgidmap", "mount",
    "umount", "ping", "ping6", "fusermount", "fusermount3", "unix_chkpwd", "pam_extrausers_chkpwd", "ssh-keysign",
    "dbus-daemon-launch-helper", "expiry", "chage", "wall", "write", "crontab", "at", "ssh-agent", "locate",
    "mlocate", "plocate", "bsd-write", "mail-dotlock", "mail-lock", "mail-unlock", "dotlockfile", "Xorg.wrap",
    "polkit-agent-helper-1", "mount.nfs", "mount.ecryptfs_private", "umount.nfs", "ntfs-3g", "traceroute6.iputils",
    "chrome-sandbox", "snap-confine", "vmware-user-suid-wrapper", "unix2_chkpwd", "utempter", "screen",
    "shadow", "sg", "ksu", "pkexec", "staprun", "sudoreplay", "userhelper", "usernetctl", "lockdev", "postdrop",
    "postqueue", "Xwrapper", "VBoxHeadless", "gnome-pty-helper",
}
SUID_FIX = ("Remove the bit if not required (`chmod u-s,g-s <file>`), prefer capabilities (`setcap`) or sudo rules, "
            "and keep an approved baseline via --suid-allowlist.")


def classify_suid(rel, allow):
    base = os.path.basename(rel)
    if rel in allow or base in allow:
        return "allowed"
    if under(rel, SUSPECT_PREFIXES):
        return "suspect"
    if base in DANGEROUS_BASENAMES or DANGEROUS_RE.match(base):
        return "dangerous"
    if base in STANDARD_SUID:
        return "standard"
    return "unknown"


def check_suid(ctx):
    scan = ctx.scan()
    buckets = {"suspect": [], "dangerous": [], "unknown": [], "standard": [], "allowed": []}
    for rec in scan["suid"]:
        buckets[classify_suid(rec[0], ctx.allow)].append(rec)
    out = [
        mk("SUID-001", "suid", "No SUID/SGID binaries in user-writable or staging locations", "critical",
           [fmt_rec(r) for r in buckets["suspect"]],
           "SUID/SGID files found under /tmp, /home, /srv, /mnt and similar paths - a classic persistence and "
           "privilege-escalation technique.", SUID_FIX),
        mk("SUID-002", "suid", "No SUID/SGID on shells, interpreters or GTFOBins-class utilities", "high",
           [fmt_rec(r) for r in buckets["dangerous"]],
           "General-purpose binaries with SUID/SGID allow trivial privilege escalation to root.", SUID_FIX),
        mk("SUID-003", "suid", "All SUID/SGID binaries are recognised or allow-listed", "medium",
           [fmt_rec(r) for r in buckets["unknown"]],
           "Unrecognised SUID/SGID binaries; review each, then remove the bit or add it to the allow-list.",
           SUID_FIX),
    ]
    inv = Finding("SUID-000", "suid", "SUID/SGID inventory", "info", "pass",
                  f"{len(scan['suid'])} SUID/SGID regular files ({len(buckets['standard'])} standard, "
                  f"{len(buckets['allowed'])} allow-listed).",
                  _trim(fmt_rec(r) for r in buckets["standard"] + buckets["allowed"]))
    return out + [inv]


# --------------------------------------------------------------------------- permissions
CRITICAL_FILES = [
    ("/etc/passwd", 0o644), ("/etc/group", 0o644), ("/etc/shadow", 0o640), ("/etc/gshadow", 0o640),
    ("/etc/sudoers", 0o440), ("/etc/ssh/sshd_config", 0o644), ("/etc/crontab", 0o644), ("/etc/fstab", 0o644),
    ("/etc/hosts", 0o644), ("/boot/grub/grub.cfg", 0o644), ("/boot/grub2/grub.cfg", 0o644),
]


def check_perms(ctx):
    bad = []
    targets = list(CRITICAL_FILES)
    for key in glob.glob(ctx.p("/etc/ssh/ssh_host_*_key")):
        targets.append((ctx.rel(key), 0o640))
    for path, max_mode in targets:
        st = ctx.lstat(path)
        if st is None or not stat.S_ISREG(st.st_mode):
            continue
        problems = []
        if st.st_uid != 0:
            problems.append(f"owner uid {st.st_uid} (expected 0)")
        if stat.S_IMODE(st.st_mode) & ~max_mode:
            problems.append(f"mode {fmode(st.st_mode)} is looser than {max_mode:04o}")
        if problems:
            bad.append(f"{path}: " + "; ".join(problems))

    scan = ctx.scan()
    tmp_bad = []
    for d in ("/tmp", "/var/tmp"):
        st = ctx.lstat(d)
        if st is not None and stat.S_ISDIR(st.st_mode) and not st.st_mode & stat.S_ISVTX:
            tmp_bad.append(f"{d}: mode {fmode(st.st_mode)} lacks the sticky bit")

    return [
        mk("PERM-001", "perms", "Critical files have strict ownership and permissions", "high", bad,
           "Sensitive files are group/world accessible or not owned by root.",
           "chmod/chown to the recommended modes, e.g. `chmod 640 /etc/shadow`, `chmod 440 /etc/sudoers`."),
        mk("PERM-002", "perms", "No world-writable files in system and boot paths", "high",
           [fmt_rec(r) for r in scan["ww_crit"]],
           "World-writable files under /etc, /bin, /usr, /lib, /boot let any local user alter trusted code/config.",
           "Remove write for others: `chmod o-w <file>`; investigate how it happened."),
        mk("PERM-003", "perms", "No world-writable directories without the sticky bit", "medium",
           [fmt_rec(r) for r in scan["ww_dirs"]],
           "Anyone can create, rename or delete other users' files in these directories.",
           "`chmod o-w <dir>` or `chmod +t <dir>` if shared write access is intended."),
        mk("PERM-004", "perms", "/tmp and /var/tmp have the sticky bit", "high", tmp_bad,
           "Temp directories without the sticky bit allow cross-user file deletion/replacement.",
           "`chmod 1777 /tmp /var/tmp`"),
    ]


# --------------------------------------------------------------------------- SSH
SSH_DEFAULTS = {
    "permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
    "kbdinteractiveauthentication": "yes", "maxauthtries": "6", "permitemptypasswords": "no",
    "x11forwarding": "no", "logingracetime": "120", "hostbasedauthentication": "no", "ignorerhosts": "yes",
    "clientaliveinterval": "0", "clientalivecountmax": "3", "permituserenvironment": "no",
    "pubkeyauthentication": "yes", "ciphers": "", "macs": "",
}
SSH_ALIASES = {"challengeresponseauthentication": "kbdinteractiveauthentication"}
WEAK_CIPHERS = re.compile(r"3des|arcfour|blowfish|cast128|rijndael", re.IGNORECASE)
WEAK_MACS = re.compile(r"md5|umac-64|hmac-sha1-96", re.IGNORECASE)


def _secs(v):
    if not re.fullmatch(r"(?:\d+[smhdw]?)+", v.strip().lower()):
        return None
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    return sum(int(n) * mult[u or "s"] for n, u in re.findall(r"(\d+)([smhdw]?)", v.strip().lower()))


def _int(v, default=10 ** 6):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _parse_sshd_file(ctx, rel_path, cfg, depth=0):
    """first-value-wins parser; stops at the first Match block. Returns True if a Match block was hit."""
    if depth > 8:
        return False
    text = ctx.read(rel_path)
    if text is None:
        return False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s*=\s*|\s+", line, maxsplit=1)
        key = parts[0].lower()
        val = parts[1].strip().strip('"') if len(parts) > 1 else ""
        if key == "match":
            return True
        if key == "include":
            for pattern in val.split():
                pattern = pattern if pattern.startswith("/") else os.path.join("/etc/ssh", pattern)
                for inc in sorted(glob.glob(ctx.p(pattern))):
                    if _parse_sshd_file(ctx, ctx.rel(inc), cfg, depth + 1):
                        return True
            continue
        key = SSH_ALIASES.get(key, key)
        cfg.setdefault(key, val.lower())
    return False


def load_sshd_config(ctx):
    """Return (config, source_description, has_match_blocks) or (None, reason, False)."""
    if not os.path.exists(ctx.p("/etc/ssh/sshd_config")):
        return None, "sshd_config not found (OpenSSH server not installed?)", False
    if ctx.live and os.geteuid() == 0 and shutil.which("sshd"):
        try:
            proc = subprocess.run([shutil.which("sshd"), "-T"], capture_output=True, text=True, timeout=15, check=False)
            if proc.returncode == 0 and proc.stdout:
                cfg = {}
                for line in proc.stdout.splitlines():
                    k, _, v = line.partition(" ")
                    cfg.setdefault(SSH_ALIASES.get(k.lower(), k.lower()), v.strip().lower())
                return cfg, "effective configuration via `sshd -T`", False
        except (OSError, subprocess.SubprocessError):
            pass
    cfg = {}
    matched = _parse_sshd_file(ctx, "/etc/ssh/sshd_config", cfg)
    return cfg, "parsed /etc/ssh/sshd_config (OpenSSH defaults assumed for unset keys)", matched


SSH_RULES = [
    ("SSH-001", "Root login over SSH is disabled", ["permitrootlogin"],
     lambda c: c["permitrootlogin"] == "no", lambda c: "high" if c["permitrootlogin"] == "yes" else "low",
     "PermitRootLogin no"),
    ("SSH-002", "Password authentication is disabled (key-based only)", ["passwordauthentication"],
     lambda c: c["passwordauthentication"] == "no", lambda c: "high", "PasswordAuthentication no"),
    ("SSH-003", "Keyboard-interactive/challenge-response auth is disabled", ["kbdinteractiveauthentication"],
     lambda c: c["kbdinteractiveauthentication"] == "no", lambda c: "medium", "KbdInteractiveAuthentication no"),
    ("SSH-004", "MaxAuthTries is 4 or lower", ["maxauthtries"],
     lambda c: _int(c["maxauthtries"]) <= 4, lambda c: "medium", "MaxAuthTries 3"),
    ("SSH-005", "Empty passwords are rejected", ["permitemptypasswords"],
     lambda c: c["permitemptypasswords"] == "no", lambda c: "critical", "PermitEmptyPasswords no"),
    ("SSH-006", "X11 forwarding is disabled", ["x11forwarding"],
     lambda c: c["x11forwarding"] == "no", lambda c: "low", "X11Forwarding no"),
    ("SSH-007", "LoginGraceTime is 60 seconds or lower", ["logingracetime"],
     lambda c: (_secs(c["logingracetime"]) or 0) > 0 and (_secs(c["logingracetime"]) or 0) <= 60,
     lambda c: "low", "LoginGraceTime 30"),
    ("SSH-008", "Host-based authentication is disabled", ["hostbasedauthentication"],
     lambda c: c["hostbasedauthentication"] == "no", lambda c: "medium", "HostbasedAuthentication no"),
    ("SSH-009", ".rhosts/.shosts files are ignored", ["ignorerhosts"],
     lambda c: c["ignorerhosts"] == "yes", lambda c: "medium", "IgnoreRhosts yes"),
    ("SSH-010", "Idle sessions are terminated (ClientAliveInterval/CountMax)", ["clientaliveinterval", "clientalivecountmax"],
     lambda c: 0 < _int(c["clientaliveinterval"], 0) <= 900 and _int(c["clientalivecountmax"], 99) <= 3,
     lambda c: "low", "ClientAliveInterval 300\nClientAliveCountMax 2"),
    ("SSH-011", "User environment processing is disabled", ["permituserenvironment"],
     lambda c: c["permituserenvironment"] == "no", lambda c: "medium", "PermitUserEnvironment no"),
    ("SSH-012", "Public-key authentication is enabled", ["pubkeyauthentication"],
     lambda c: c["pubkeyauthentication"] == "yes", lambda c: "low", "PubkeyAuthentication yes"),
    ("SSH-013", "No weak ciphers or MACs are enabled", ["ciphers", "macs"],
     lambda c: not WEAK_CIPHERS.search(c["ciphers"]) and not WEAK_MACS.search(c["macs"]),
     lambda c: "medium", "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com\n"
                          "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"),
]


def check_ssh(ctx):
    cfg, source, matched = load_sshd_config(ctx)
    if cfg is None:
        return [skip("SSH-000", "ssh", "SSH server hardening", source)]
    eff = dict(SSH_DEFAULTS)
    eff.update(cfg)
    out = []
    for fid, title, keys, ok, sev, fix in SSH_RULES:
        shown = ", ".join(f"{k}={eff[k] or '(default)'}" for k in keys)
        passed = ok(eff)
        out.append(Finding(fid, "ssh", title, sev(eff) if not passed else "info",
                           "pass" if passed else "fail",
                           f"{shown}  [{source}]", [], "" if passed else f"Set in sshd_config:\n{fix}"))
    if matched:
        ctx.warnings.append("sshd_config contains Match blocks; per-user/host overrides were not evaluated "
                            "(run as root on the host for `sshd -T` coverage).")
    return out


# --------------------------------------------------------------------------- network
RISKY_PORTS = {
    2375: ("docker-api (unauthenticated)", "critical"), 23: ("telnet", "high"), 21: ("ftp", "high"),
    69: ("tftp", "high"), 512: ("rexec", "high"), 513: ("rlogin", "high"), 514: ("rsh/syslog", "high"),
    5900: ("vnc", "high"), 6379: ("redis", "high"), 27017: ("mongodb", "high"), 9200: ("elasticsearch", "high"),
    11211: ("memcached", "high"), 111: ("rpcbind", "medium"), 2049: ("nfs", "medium"), 139: ("netbios", "medium"),
    445: ("smb", "medium"), 3306: ("mysql", "medium"), 5432: ("postgresql", "medium"), 1433: ("mssql", "medium"),
    5984: ("couchdb", "medium"), 873: ("rsync", "medium"), 161: ("snmp", "medium"), 25: ("smtp", "low"),
}


def _decode_addr(hexaddr, v6):
    raw = bytes.fromhex(hexaddr)
    if sys.byteorder == "little":
        if v6:
            raw = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
        else:
            raw = raw[::-1]
    return socket.inet_ntop(socket.AF_INET6 if v6 else socket.AF_INET, raw)


def _is_loopback(ip):
    a = ipaddress.ip_address(ip)
    if a.is_loopback:
        return True
    return a.version == 6 and a.ipv4_mapped is not None and a.ipv4_mapped.is_loopback


def read_listeners(proc="/proc"):
    """Return [(proto, ip, port, inode)] for TCP LISTEN and bound UDP sockets."""
    out = []
    for proto, want in (("tcp", "0A"), ("udp", "07")):
        for v6 in (False, True):
            path = f"{proc}/net/{proto}{'6' if v6 else ''}"
            try:
                with open(path, encoding="utf-8") as fh:
                    lines = fh.read().splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                parts = line.split()
                if len(parts) < 10 or parts[3] != want:
                    continue
                try:
                    addr_hex, port_hex = parts[1].rsplit(":", 1)
                    out.append((proto + ("6" if v6 else ""), _decode_addr(addr_hex, v6), int(port_hex, 16), parts[9]))
                except (ValueError, OSError):
                    continue
    return out


def socket_owners(proc="/proc"):
    owners = {}
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()]
    except OSError:
        return owners
    for pid in pids:
        fd_dir = f"{proc}/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                link = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            if link.startswith("socket:[") and link[8:-1] not in owners:
                try:
                    with open(f"{proc}/{pid}/comm", encoding="utf-8") as fh:
                        comm = fh.read().strip()
                except OSError:
                    comm = "?"
                owners[link[8:-1]] = f"{comm}[{pid}]"
    return owners


def check_network(ctx):
    if not ctx.network:
        return [skip("NET-000", "network", "Service exposure",
                     "Network checks are disabled for non-live roots (use --network on with --net=host to force).")]
    listeners = read_listeners()
    if not listeners and not os.path.exists("/proc/net/tcp"):
        return [skip("NET-000", "network", "Service exposure", "/proc/net is not available.")]
    owners = socket_owners()
    if os.geteuid() != 0:
        ctx.warnings.append("Not running as root: process names for listening sockets may be missing.")
    exposed, seen = [], set()
    by_sev = {"critical": [], "high": [], "medium": [], "low": []}
    for proto, ip, port, inode in sorted(listeners, key=lambda x: (x[2], x[0])):
        if _is_loopback(ip):
            continue
        key = (proto, ip, port)
        if key in seen:
            continue
        seen.add(key)
        owner = owners.get(inode, "unknown-process")
        label = f"{proto}/{port} on {ip} <- {owner}"
        exposed.append(label)
        if port in RISKY_PORTS:
            name, sev = RISKY_PORTS[port]
            by_sev[sev].append(f"{label}  ({name})")
    fix = ("Stop/disable the service (`systemctl disable --now <unit>`), bind it to 127.0.0.1 or a management "
           "interface, and restrict with a host firewall (nftables/ufw/firewalld).")
    return [
        mk("NET-001", "network", "No unauthenticated remote-control APIs exposed (Docker API)", "critical",
           by_sev["critical"], "Docker daemon API listens on a non-loopback address - unauthenticated root RCE.", fix),
        mk("NET-002", "network", "No cleartext/legacy remote services or open data stores exposed", "high",
           by_sev["high"], "Legacy, cleartext or unauthenticated-by-default services listen on external interfaces.", fix),
        mk("NET-003", "network", "Infrastructure/database services are not exposed to all interfaces", "medium",
           by_sev["medium"], "Services commonly targeted by attackers are reachable from the network.", fix),
        mk("NET-004", "network", "Mail/other watched services are intentionally exposed", "low",
           by_sev["low"], "Review whether these listeners are required.", fix),
        Finding("NET-005", "network", "Listening socket inventory (non-loopback)", "info", "pass",
                f"{len(exposed)} externally reachable listeners.", _trim(exposed)),
    ]


# --------------------------------------------------------------------------- users & privileges
NOLOGIN = {"nologin", "false", "sync", "shutdown", "halt"}
ROOT_EQUIV_GROUPS = {"docker", "lxd", "disk", "shadow", "root"}
SUDO_GROUPS = {"sudo", "wheel", "admin"}


def _passwd(ctx):
    rows = []
    for line in (ctx.read("/etc/passwd") or "").splitlines():
        f = line.split(":")
        if len(f) >= 7 and f[2].lstrip("-").isdigit():
            rows.append({"name": f[0], "uid": int(f[2]), "gid": f[3], "home": f[5], "shell": f[6]})
    return rows


def check_users(ctx):
    users = _passwd(ctx)
    if not users:
        return [skip("USR-000", "users", "User and privilege checks", "/etc/passwd not readable or empty.")]
    out = []
    out.append(mk("USR-001", "users", "Only root has UID 0", "critical",
                  [f"{u['name']} (uid 0, shell {u['shell']})" for u in users if u["uid"] == 0 and u["name"] != "root"],
                  "Additional accounts with UID 0 are full root equivalents.", "Remove or renumber the account."))

    shadow = ctx.read("/etc/shadow")
    if shadow is None:
        out.append(skip("USR-002", "users", "No accounts with empty passwords", "/etc/shadow not readable (run as root)."))
    else:
        empty = [ln.split(":")[0] for ln in shadow.splitlines() if ln.count(":") >= 1 and ln.split(":")[1] == ""]
        out.append(mk("USR-002", "users", "No accounts with empty passwords", "critical", empty,
                      "Accounts have an empty password hash and can log in without credentials.",
                      "Lock the account (`passwd -l <user>`) or set a strong password."))

    sudo_issues = []
    files = ["/etc/sudoers"] + sorted(ctx.rel(p) for p in glob.glob(ctx.p("/etc/sudoers.d/*")))
    for f in files:
        text = ctx.read(f)
        if text is None:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "NOPASSWD" in s or re.search(r"!\s*authenticate", s):
                sudo_issues.append(f"{f}:{n}: {s}")
    if all(ctx.read(f) is None for f in files):
        out.append(skip("USR-003", "users", "sudoers requires authentication", "sudoers not readable (run as root)."))
    else:
        out.append(mk("USR-003", "users", "sudo requires authentication (no NOPASSWD / !authenticate)", "medium",
                      sudo_issues, "Passwordless sudo turns any account compromise into root compromise.",
                      "Remove NOPASSWD/!authenticate, or scope it to specific, non-shell commands."))

    by_uid = {}
    for u in users:
        by_uid.setdefault(u["uid"], []).append(u["name"])
    out.append(mk("USR-004", "users", "No duplicate UIDs", "medium",
                  [f"uid {uid}: {', '.join(n)}" for uid, n in by_uid.items() if len(n) > 1 and uid != 0],
                  "Accounts sharing a UID share all file permissions.", "Assign unique UIDs."))

    out.append(mk("USR-005", "users", "System accounts have no interactive shell", "medium",
                  [f"{u['name']} (uid {u['uid']}) shell={u['shell']}" for u in users
                   if 0 < u["uid"] < 1000 and os.path.basename(u["shell"]) not in NOLOGIN and u["shell"]],
                  "Service accounts with login shells can be used for interactive access after a service compromise.",
                  "`usermod -s /usr/sbin/nologin <user>`"))

    groups = {}
    for line in (ctx.read("/etc/group") or "").splitlines():
        f = line.split(":")
        if len(f) >= 4:
            groups[f[0]] = [m for m in f[3].split(",") if m]
    out.append(mk("USR-006", "users", "Few accounts in root-equivalent groups (docker, lxd, disk, shadow)", "medium",
                  [f"{g}: {', '.join(m)}" for g, m in groups.items() if g in ROOT_EQUIV_GROUPS and m],
                  "Membership in these groups grants root-equivalent access.",
                  "Remove members that do not strictly need it (`gpasswd -d <user> <group>`)."))
    admins = [f"{g}: {', '.join(m)}" for g, m in groups.items() if g in SUDO_GROUPS and m]
    out.append(Finding("USR-007", "users", "Administrative group membership", "info", "pass",
                       f"{len(admins)} administrative groups with members.", admins))

    ssh_bad = []
    for u in users:
        if not (u["uid"] == 0 or u["uid"] >= 1000):
            continue
        for sub in (".ssh", ".ssh/authorized_keys"):
            st = ctx.lstat(os.path.join(u["home"], sub))
            if st is not None and not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022:
                ssh_bad.append(f"{os.path.join(u['home'], sub)}: mode {fmode(st.st_mode)} is group/world writable "
                               f"(owner {u['name']})")
    out.append(mk("USR-008", "users", "SSH key directories are not group/world writable", "high", ssh_bad,
                  "Anyone able to write these paths can plant keys and log in as the user.",
                  "`chmod go-w ~/.ssh ~/.ssh/authorized_keys` (ideally 700 / 600)."))
    return out


# --------------------------------------------------------------------------- orchestration
CHECKS = {"suid": check_suid, "perms": check_perms, "ssh": check_ssh, "network": check_network, "users": check_users}


def summarize(findings):
    failed = [f for f in findings if f.status == "fail"]
    counts = {s: sum(1 for f in failed if f.severity == s) for s in SEVERITIES}
    penalty = sum(SEV_WEIGHT[f.severity] for f in failed)
    score = max(0, 100 - penalty)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    return {"score": score, "grade": grade, "failed": len(failed),
            "passed": sum(1 for f in findings if f.status == "pass"),
            "skipped": sum(1 for f in findings if f.status == "skip"), "failed_by_severity": counts}


def run_audit(ctx, checks):
    start = time.time()
    findings = []
    for name in checks:
        try:
            findings.extend(CHECKS[name](ctx))
        except Exception as exc:  # noqa: BLE001 - a broken check must never hide the others
            findings.append(skip(f"{name.upper()}-ERR", name, f"{name} check crashed", f"{type(exc).__name__}: {exc}"))
            ctx.warnings.append(f"check '{name}' failed: {type(exc).__name__}: {exc}")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        ctx.warnings.append("Not running as root: shadow/sudoers/`sshd -T` and some paths are unreadable; "
                            "results are partial.")
    findings.sort(key=lambda f: (f.status != "fail", SEV_RANK[f.severity], f.id))
    uname = platform.uname()
    os_name = ""
    text = Ctx(ctx.root).read("/etc/os-release") or ""
    m = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', text, re.MULTILINE)
    if m:
        os_name = m.group(1)
    return {
        "meta": {
            "tool": TOOL_NAME, "version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "hostname": uname.node, "kernel": uname.release, "os": os_name,
            "root": ctx.root, "euid": os.geteuid() if hasattr(os, "geteuid") else None,
            "checks": checks, "duration_s": round(time.time() - start, 2), "warnings": sorted(set(ctx.warnings)),
        },
        "summary": summarize(findings),
        "findings": [asdict(f) for f in findings],
    }


def gate(report, fail_on, min_score):
    reasons = []
    if fail_on != "none":
        limit = SEV_RANK[fail_on]
        hit = [f for f in report["findings"] if f["status"] == "fail" and SEV_RANK[f["severity"]] <= limit]
        if hit:
            reasons.append(f"{len(hit)} failed finding(s) at severity >= {fail_on}: " + ", ".join(f["id"] for f in hit))
    if report["summary"]["score"] < min_score:
        reasons.append(f"score {report['summary']['score']} < required {min_score}")
    return reasons


# --------------------------------------------------------------------------- reporting
HTML_CSS = """
:root{--bg:#0b0f14;--panel:#111821;--line:#1f2a37;--fg:#c9d1d9;--dim:#7d8590;--accent:#39ff14;
--critical:#ff3b5c;--high:#ff8a3d;--medium:#f5d142;--low:#4da3ff;--info:#7d8590}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
main{max-width:1000px;margin:0 auto;padding:24px 16px 64px}
h1{color:var(--accent);font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:32px 0 8px;color:var(--accent);text-transform:uppercase;letter-spacing:.08em}
.dim{color:var(--dim)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;margin:16px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:10px 12px}
.card b{display:block;font-size:24px}.score{color:var(--accent)}
.f{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:6px;margin:6px 0;padding:0}
.f.fail.critical{border-left-color:var(--critical)}.f.fail.high{border-left-color:var(--high)}
.f.fail.medium{border-left-color:var(--medium)}.f.fail.low{border-left-color:var(--low)}
.f.pass{border-left-color:var(--accent);opacity:.8}
summary{cursor:pointer;padding:8px 12px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.badge{font-size:11px;font-weight:700;text-transform:uppercase;padding:1px 7px;border-radius:3px;background:var(--line)}
.badge.critical{background:var(--critical);color:#000}.badge.high{background:var(--high);color:#000}
.badge.medium{background:var(--medium);color:#000}.badge.low{background:var(--low);color:#000}
.badge.pass{background:var(--accent);color:#000}.badge.skip{background:var(--line)}
.body{padding:0 12px 12px}pre{background:#070a0e;border:1px solid var(--line);padding:8px;border-radius:4px;overflow:auto;white-space:pre-wrap;word-break:break-all;margin:6px 0}
.warn{border:1px solid var(--medium);color:var(--medium);padding:8px 12px;border-radius:6px;margin:8px 0}
"""


def render_html(report):
    e = html.escape
    m, s = report["meta"], report["summary"]
    cards = [("Score", f"{s['score']}/100 ({s['grade']})", "score")] + [
        (sev.title(), str(s["failed_by_severity"][sev]), "") for sev in SEVERITIES[:4]
    ] + [("Passed", str(s["passed"]), ""), ("Skipped", str(s["skipped"]), "")]
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>Security Report - {e(m['hostname'])}</title><style>{HTML_CSS}</style></head><body><main>",
        f"<h1>&gt; {e(TOOL_NAME)}</h1>",
        f"<div class='dim'>host <b>{e(m['hostname'])}</b> | {e(m['os'] or 'unknown OS')} | kernel {e(m['kernel'])} | "
        f"{e(m['generated_at'])} | v{e(m['version'])} | root={e(m['root'])}</div>",
        "<div class='grid'>",
    ]
    for label, val, cls in cards:
        parts.append(f"<div class='card'><span class='dim'>{e(label)}</span><b class='{cls}'>{e(val)}</b></div>")
    parts.append("</div>")
    for w in m["warnings"]:
        parts.append(f"<div class='warn'>! {e(w)}</div>")
    for title, pred in (("Findings", lambda f: f["status"] == "fail"),
                        ("Passed / informational", lambda f: f["status"] == "pass"),
                        ("Skipped", lambda f: f["status"] == "skip")):
        items = [f for f in report["findings"] if pred(f)]
        if not items:
            continue
        parts.append(f"<h2>{title} ({len(items)})</h2>")
        for f in items:
            cls = f"{f['status']} {f['severity']}"
            badge = f['severity'] if f["status"] == "fail" else f["status"]
            parts.append(f"<details class='f {e(cls)}'{' open' if f['status'] == 'fail' and SEV_RANK[f['severity']] <= 1 else ''}>"
                         f"<summary><span class='badge {e(badge)}'>{e(badge)}</span><b>{e(f['id'])}</b> {e(f['title'])}</summary>"
                         f"<div class='body'><div>{e(f['detail'])}</div>")
            if f["evidence"]:
                parts.append("<pre>" + e("\n".join(f["evidence"])) + "</pre>")
            if f["remediation"]:
                parts.append(f"<div class='dim'>Fix:</div><pre>{e(f['remediation'])}</pre>")
            parts.append("</div></details>")
    parts.append("</main></body></html>")
    return "".join(parts)


def print_summary(report, reasons, stream):
    use_color = hasattr(stream, "isatty") and stream.isatty()
    col = {"critical": "31;1", "high": "33;1", "medium": "33", "low": "34", "info": "90"}

    def c(text, code):
        return f"\033[{code}m{text}\033[0m" if use_color else text

    s, m = report["summary"], report["meta"]
    print(c(f"== {TOOL_NAME} v{m['version']} ==", "32;1"), file=stream)
    print(f"host={m['hostname']} root={m['root']} euid={m['euid']} duration={m['duration_s']}s", file=stream)
    for w in m["warnings"]:
        print(c(f"[!] {w}", "33"), file=stream)
    for f in report["findings"]:
        if f["status"] == "fail":
            print(f"{c('[FAIL:' + f['severity'].upper() + ']', col[f['severity']])} {f['id']} {f['title']}", file=stream)
            for ev in f["evidence"][:5]:
                print(f"    - {ev}", file=stream)
            if len(f["evidence"]) > 5:
                print(f"    ... (+{len(f['evidence']) - 5} more, see report)", file=stream)
    sev = ", ".join(f"{k}={v}" for k, v in s["failed_by_severity"].items() if k != "info")
    print(f"score={s['score']}/100 grade={s['grade']} passed={s['passed']} failed={s['failed']} "
          f"skipped={s['skipped']} ({sev})", file=stream)
    if reasons:
        print(c("GATE: FAIL - " + " | ".join(reasons), "31;1"), file=stream)
    else:
        print(c("GATE: PASS", "32;1"), file=stream)


def _write(path, data):
    if path == "-":
        sys.stdout.write(data)
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(data)


def build_parser():
    p = argparse.ArgumentParser(prog="linux_audit.py", description=__doc__.split("\n\n")[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--root", default="/", help="audit an unpacked root filesystem instead of the live host (default: /)")
    p.add_argument("--checks", default="all", help=f"comma list of: {','.join(ALL_CHECKS)} (default: all)")
    p.add_argument("--json", metavar="PATH", help="write JSON report ('-' for stdout)")
    p.add_argument("--html", metavar="PATH", help="write self-contained HTML report")
    p.add_argument("--fail-on", choices=SEVERITIES[:4] + ["none"], default="high",
                   help="exit 1 if any failed finding has at least this severity (default: high)")
    p.add_argument("--min-score", type=int, default=0, help="exit 1 if the score is below this value (default: 0)")
    p.add_argument("--network", choices=["auto", "on", "off"], default="auto",
                   help="listening-socket checks (auto = only when --root is /)")
    p.add_argument("--exclude", action="append", default=[], metavar="PATH", help="extra path/glob to skip (repeatable)")
    p.add_argument("--suid-allowlist", metavar="FILE", help="file with approved SUID/SGID paths or basenames, one per line")
    p.add_argument("--render", metavar="JSON", help="re-render an existing JSON report to --html (no scan)")
    p.add_argument("--quiet", action="store_true", help="no console summary")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.render:
        if not args.html:
            print("error: --render requires --html", file=sys.stderr)
            return 2
        try:
            with open(args.render, encoding="utf-8") as fh:
                _write(args.html, render_html(json.load(fh)))
        except (OSError, ValueError, KeyError) as exc:
            print(f"error: cannot render {args.render}: {exc}", file=sys.stderr)
            return 2
        return 0
    checks = ALL_CHECKS if args.checks == "all" else [c.strip() for c in args.checks.split(",") if c.strip()]
    unknown = [c for c in checks if c not in CHECKS]
    if unknown:
        print(f"error: unknown check(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    if not os.path.isdir(args.root):
        print(f"error: --root {args.root!r} is not a directory", file=sys.stderr)
        return 2
    allow = []
    if args.suid_allowlist:
        try:
            with open(args.suid_allowlist, encoding="utf-8") as fh:
                allow = [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
        except OSError as exc:
            print(f"error: cannot read allow-list: {exc}", file=sys.stderr)
            return 2
    ctx = Ctx(args.root, args.network, args.exclude, allow)
    try:
        report = run_audit(ctx, checks)
    except Exception as exc:  # noqa: BLE001  # pragma: no cover
        print(f"error: audit failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    reasons = gate(report, args.fail_on, args.min_score)
    report["gate"] = {"passed": not reasons, "fail_on": args.fail_on, "min_score": args.min_score, "reasons": reasons}
    if args.json:
        _write(args.json, json.dumps(report, indent=2) + "\n")
    if args.html:
        _write(args.html, render_html(report))
    if not args.quiet:
        print_summary(report, reasons, sys.stderr if args.json == "-" else sys.stdout)
    return 1 if reasons else 0


if __name__ == "__main__":
    sys.exit(main())
