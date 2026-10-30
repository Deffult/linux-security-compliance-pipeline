#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Mr. Deffult | Linux Security & Compliance Pipeline - hardening helper
#
#   hardening.sh audit  [auditor args]   run the Python auditor (read-only)
#   hardening.sh plan                    show what `apply` would change (default, changes nothing)
#   hardening.sh apply  [--force]        apply SSH, sysctl and permission hardening (root required)
#
# Safety: every file touched is backed up to /var/backups/mrdeffult/<timestamp>/, sshd changes are
# validated with `sshd -t` and rolled back on failure, and password/root SSH login is NOT disabled
# unless a non-root user with an authorized_keys file exists (override with --force).
set -Eeuo pipefail
IFS=$'\n\t'
shopt -s nullglob

readonly VERSION="1.0.0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly BACKUP_DIR="/var/backups/mrdeffult/$(date -u +%Y%m%dT%H%M%SZ)"
readonly SSH_DROPIN="/etc/ssh/sshd_config.d/99-mrdeffult-hardening.conf"
readonly SYSCTL_DROPIN="/etc/sysctl.d/99-mrdeffult-hardening.conf"

APPLY=0
FORCE=0

if [[ -t 1 ]]; then
  G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'
else
  G=''; Y=''; R=''; N=''
fi
info() { printf '%s[+]%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s[!]%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

on_err() { die "failed at line $1 (exit $2) - backups, if any, are in $BACKUP_DIR"; }
trap 'on_err $LINENO $?' ERR

usage() { sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# run <cmd...>: execute in apply mode, print in plan mode
run() {
  if (( APPLY )); then "$@"; else printf '[plan] %s\n' "$*"; fi
}

backup() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  if (( APPLY )); then
    mkdir -p -m 0700 "$BACKUP_DIR$(dirname "$f")"
    cp -a "$f" "$BACKUP_DIR$f"
  fi
}

write_file() { # write_file <path> <mode> <content>
  local path="$1" mode="$2" content="$3"
  if (( APPLY )); then
    backup "$path"
    install -m "$mode" -o root -g root /dev/null "$path"
    printf '%s\n' "$content" >"$path"
  else
    printf '[plan] write %s (mode %s):\n%s\n' "$path" "$mode" "$content" | sed 's/^/        /'
  fi
}

require_root() { (( EUID == 0 )) || die "apply must run as root (try: sudo $0 apply)"; }

# --- lockout protection -------------------------------------------------------------------
has_key_login_user() {
  local name uid home shell
  while IFS=: read -r name _ uid _ _ home shell; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    (( uid >= 1000 && uid < 65534 )) || continue
    [[ "$shell" != */nologin && "$shell" != */false ]] || continue
    [[ -s "$home/.ssh/authorized_keys" ]] && return 0
  done </etc/passwd
  return 1
}

# --- SSH ----------------------------------------------------------------------------------
harden_ssh() {
  [[ -f /etc/ssh/sshd_config ]] || { warn "OpenSSH server not installed - skipping SSH hardening"; return 0; }
  if ! grep -Eqi '^[[:space:]]*Include[[:space:]].*sshd_config\.d' /etc/ssh/sshd_config; then
    warn "sshd_config has no 'Include /etc/ssh/sshd_config.d/*.conf' - refusing to edit the main file automatically"
    return 0
  fi

  local lines=(
    "# Managed by Mr. Deffult Linux Security & Compliance Pipeline v${VERSION}"
    "MaxAuthTries 3" "PermitEmptyPasswords no" "LoginGraceTime 30" "X11Forwarding no"
    "HostbasedAuthentication no" "IgnoreRhosts yes" "PermitUserEnvironment no"
    "ClientAliveInterval 300" "ClientAliveCountMax 2" "PubkeyAuthentication yes"
  )
  if has_key_login_user || (( FORCE )); then
    lines+=("PermitRootLogin no" "PasswordAuthentication no" "KbdInteractiveAuthentication no")
  else
    warn "no non-root user with ~/.ssh/authorized_keys found: NOT disabling root/password login (lockout guard). Use --force to override."
  fi
  local content
  content="$(printf '%s\n' "${lines[@]}")"
  write_file "$SSH_DROPIN" 0644 "$content"

  if (( APPLY )); then
    if ! sshd -t; then
      warn "sshd -t rejected the new configuration - rolling back"
      if [[ -e "$BACKUP_DIR$SSH_DROPIN" ]]; then cp -a "$BACKUP_DIR$SSH_DROPIN" "$SSH_DROPIN"; else rm -f "$SSH_DROPIN"; fi
      return 1
    fi
    systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service 2>/dev/null \
      || warn "could not reload sshd automatically - reload it manually"
    info "SSH hardening applied ($SSH_DROPIN)"
  fi
}

# --- kernel / network sysctl --------------------------------------------------------------
harden_sysctl() {
  local content
  content="$(cat <<'EOF'
# Managed by Mr. Deffult Linux Security & Compliance Pipeline
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF
)"
  write_file "$SYSCTL_DROPIN" 0644 "$content"
  if (( APPLY )); then
    # -e: ignore keys that do not exist on this kernel
    sysctl -e -p "$SYSCTL_DROPIN" >/dev/null && info "sysctl hardening applied ($SYSCTL_DROPIN)"
  fi
}

# --- permissions --------------------------------------------------------------------------
tighten() { # tighten <path> <max-octal-mode>  (only ever removes bits)
  local path="$1" max="$2" cur new
  [[ -f "$path" && ! -L "$path" ]] || return 0
  cur=$((8#$(stat -c '%a' "$path")))
  new=$(( cur & 8#$max ))
  if (( new != cur )); then
    backup "$path"
    run chmod "$(printf '%o' "$new")" "$path"
    info "$path: $(printf '%o' "$cur") -> $(printf '%o' "$new")"
  fi
}

fix_permissions() {
  tighten /etc/shadow 640
  tighten /etc/gshadow 640
  tighten /etc/sudoers 440
  tighten /etc/passwd 644
  tighten /etc/group 644
  tighten /etc/crontab 644
  local key
  for key in /etc/ssh/ssh_host_*_key; do tighten "$key" 640; done
  local d mode
  for d in /tmp /var/tmp; do
    [[ -d "$d" ]] || continue
    mode="$(stat -c '%a' "$d")"
    if (( (8#$mode & 8#1000) == 0 )); then
      run chmod +t "$d"
      info "$d: sticky bit set"
    fi
  done
}

# --- main ---------------------------------------------------------------------------------
cmd="${1:-plan}"
shift || true
case "$cmd" in
  audit)
    command -v python3 >/dev/null || die "python3 is required"
    exec python3 "$SCRIPT_DIR/linux_audit.py" "$@"
    ;;
  plan|apply)
    [[ "$cmd" == apply ]] && APPLY=1
    for a in "$@"; do
      case "$a" in
        --force) FORCE=1 ;;
        -h|--help) usage 0 ;;
        *) die "unknown option: $a" ;;
      esac
    done
    (( APPLY )) && require_root
    (( APPLY )) || info "PLAN MODE - nothing will be changed. Run '$0 apply' to enforce."
    (( APPLY )) && mkdir -p -m 0700 "$BACKUP_DIR"
    harden_ssh
    harden_sysctl
    fix_permissions
    (( APPLY )) && info "done. backups: $BACKUP_DIR | re-run '$0 audit' to verify"
    ;;
  -h|--help|help) usage 0 ;;
  *) usage 1 ;;
esac
