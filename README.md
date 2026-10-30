<div align="center">

```
 __  __      ____  _____ _____ _____ _   _ _     _____
|  \/  |_ __|  _ \| ____|  ___|  ___| | | | |   |_   _|
| |\/| | '__| | | |  _| | |_  | |_  | | | | |     | |
| |  | | |_ | |_| | |___|  _| |  _| | |_| | |___  | |
|_|  |_|_(_)|____/|_____|_|   |_|    \___/|_____| |_|
        L I N U X   S E C U R I T Y   &   C O M P L I A N C E   P I P E L I N E
```

**Audit the host. Gate the pipeline. Ship nothing you can't prove is hardened.**

[![Security Pipeline](https://github.com/Deffult/linux-security-compliance-pipeline/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/Deffult/linux-security-compliance-pipeline/actions/workflows/security-pipeline.yml)
![License](https://img.shields.io/badge/license-MIT-39ff14)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen)

*by **Mr. Deffult***

</div>

---

## What is this?

Two halves of one idea: **a Linux host (or container image) is only "compliant" if a machine can prove it, on every commit.**

| Layer | What it does |
|---|---|
| **Auditor** (`audit/linux_audit.py`) | Read-only, zero-dependency Python auditor. Checks SUID/SGID, permissions, SSH, exposed services and privilege hygiene. Emits **JSON + a self-contained HTML report** and an **exit code** usable as a gate. |
| **Hardener** (`audit/hardening.sh`) | Safe-by-default Bash helper: `plan` (dry run) → `apply` (backups, `sshd -t` validation, lockout guard, rollback). |
| **Pipeline** (`.github/workflows/security-pipeline.yml`) | SAST (Semgrep, Bandit, CodeQL), secret detection (Gitleaks, full history), container scanning (Hadolint, Trivy), and a **fail-closed security gate** driven by `policy/gate-policy.json`. |

## Architecture

```mermaid
flowchart LR
    dev([git push / PR / weekly cron]) --> A

    subgraph A[GitHub Actions - security-pipeline.yml]
      direction TB
      T[lint-test<br/>ruff · shellcheck · pytest]
      S[sast<br/>Semgrep · Bandit]
      Q[codeql<br/>security-extended]
      G[secrets<br/>Gitleaks · full history]
      C[container<br/>Hadolint · build · Trivy ·<br/>host audit of image rootfs]
    end

    T & S & Q & G & C --> E[(evidence JSON<br/>trivy · gitleaks · semgrep<br/>bandit · audit)]
    E --> GATE{{security-gate<br/>scripts/security_gate.py<br/>policy/gate-policy.json}}
    GATE -- all controls pass --> OK([✔ merge / release])
    GATE -- any control fails or<br/>report missing --> NO([✘ blocked])

    H[Linux host / VM] -. sudo linux_audit.py .-> R[JSON + HTML report<br/>score · grade · exit code]
    I[Container / rootfs] -. --root . .-> R
```

**How it fits together**

1. The **auditor** inspects a live host (`--root /`) or any unpacked filesystem (`--root /path`, e.g. a container image) and scores it. It never writes to the target.
2. In CI the same auditor runs against the **image you are about to ship**, so the compliance check travels with the artifact.
3. Scanners (Semgrep, Bandit, Gitleaks, Trivy) only **produce evidence**; they never decide. The `security-gate` job loads every report, compares it to **policy-as-code**, and **fails closed** - a missing or unparsable report is a failure, not a pass.
4. Hardening is a separate, explicit step (`hardening.sh apply`), and the auditor verifies it afterwards.

## Repository layout

```
.
├── audit/
│   ├── linux_audit.py        # auditor: suid · perms · ssh · network · users  → JSON / HTML / exit code
│   └── hardening.sh          # audit | plan | apply  (backups, sshd -t, lockout guard)
├── scripts/security_gate.py  # aggregates scanner reports, enforces policy, fail-closed
├── policy/gate-policy.json   # thresholds (CVE counts, leaks, SAST severity, host score)
├── .github/workflows/security-pipeline.yml
├── .gitleaks.toml
├── Dockerfile                # unprivileged auditor image
├── tests/                    # pytest suite using synthetic rootfs fixtures
├── Makefile · pyproject.toml · requirements-dev.txt
└── SECURITY.md · LICENSE
```

## Install

```bash
git clone https://github.com/Deffult/linux-security-compliance-pipeline.git
cd linux-security-compliance-pipeline
python3 audit/linux_audit.py --help        # Python 3.9+, no pip install needed
```

Docker alternative:

```bash
docker build -t mrdeffult/linux-security-audit .
```

## Usage

```bash
# Full audit of this host (root recommended: shadow, sudoers, `sshd -T`, all processes)
sudo python3 audit/linux_audit.py --json reports/audit.json --html reports/audit.html

# Fail (exit 1) on any HIGH+ finding or a score below 85
sudo python3 audit/linux_audit.py --fail-on high --min-score 85

# Only some checks
python3 audit/linux_audit.py --checks ssh,users

# Audit an unpacked rootfs / mounted image without touching the live system
python3 audit/linux_audit.py --root /mnt/image --json -

# Approved SUID baseline (paths or basenames, one per line)
sudo python3 audit/linux_audit.py --suid-allowlist policy/suid-allowlist.txt

# Re-render a stored JSON report as HTML
python3 audit/linux_audit.py --render reports/audit.json --html reports/audit.html

# Through Docker: read-only host mount
docker run --rm --user 0:0 --net=host --pid=host -v /:/host:ro \
  mrdeffult/linux-security-audit --root /host --network on
```

**Exit codes:** `0` gate passed · `1` gate failed · `2` usage/internal error.

### Hardening

```bash
sudo bash audit/hardening.sh plan        # dry run: prints every change, touches nothing
sudo bash audit/hardening.sh apply       # backs up to /var/backups/mrdeffult/<ts>/, validates, reloads sshd
sudo bash audit/hardening.sh audit       # verify afterwards
```

Safety rails: SSH settings go into a **drop-in** (`/etc/ssh/sshd_config.d/99-mrdeffult-hardening.conf`), validated with
`sshd -t` and rolled back on failure. Root/password login is **only disabled when a non-root user with an
`authorized_keys` file exists** (`--force` overrides). Permission fixes only ever *remove* bits.

## What it checks

| ID | Area | Examples | Severity |
|---|---|---|---|
| `SUID-001` | SUID/SGID | any SUID/SGID file under `/tmp`, `/home`, `/srv`, `/mnt`… | critical |
| `SUID-002` | SUID/SGID | shells, interpreters, `find`, `vim`, `cp`, `nmap`… (GTFOBins-class) | high |
| `SUID-003` | SUID/SGID | unrecognised binaries not in the baseline/allow-list | medium |
| `PERM-001` | Permissions | `/etc/shadow`, `sudoers`, `sshd_config`, host keys: owner + max mode | high |
| `PERM-002` | Permissions | world-writable files in `/etc`, `/bin`, `/usr`, `/lib`, `/boot` | high |
| `PERM-003/004` | Permissions | world-writable dirs without sticky bit; `/tmp` sticky bit | medium/high |
| `SSH-001…013` | SSH | `PermitRootLogin`, `PasswordAuthentication`, `MaxAuthTries`, empty passwords, X11, grace time, host-based auth, idle timeout, weak ciphers/MACs | critical → low |
| `NET-001…005` | Services | non-loopback listeners mapped to processes; Docker API, Telnet/FTP, Redis, Mongo, DBs… | critical → low |
| `USR-001…008` | Privileges | extra UID 0, empty password hashes, `NOPASSWD`, duplicate UIDs, system accounts with shells, `docker`/`lxd`/`disk` members, writable `~/.ssh` | critical → medium |

`sshd` is evaluated with the **effective** configuration (`sshd -T`) when run as root on a live host, otherwise by parsing
`sshd_config` (first-value-wins, `Include` aware, OpenSSH defaults applied).

**Scoring:** start at 100, subtract per failed finding (critical 30, high 15, medium 5, low 2). Grade A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · F.

### JSON shape

```json
{
  "meta":    { "tool": "...", "hostname": "...", "euid": 0, "warnings": [] },
  "summary": { "score": 62, "grade": "D", "failed_by_severity": { "critical": 1, "high": 2, "medium": 1, "low": 0 } },
  "findings": [
    { "id": "SSH-002", "category": "ssh", "severity": "high", "status": "fail",
      "title": "Password authentication is disabled (key-based only)",
      "detail": "passwordauthentication=yes  [effective configuration via `sshd -T`]",
      "evidence": [], "remediation": "Set in sshd_config:\nPasswordAuthentication no" }
  ],
  "gate": { "passed": false, "fail_on": "high", "min_score": 85, "reasons": ["..."] }
}
```

## The CI/CD pipeline

| Job | Control | Tooling |
|---|---|---|
| `lint-test` | code quality, unit tests | Ruff, ShellCheck, pytest |
| `sast` | static analysis | Semgrep (`p/python`, `p/security-audit`, `p/secrets`, `p/dockerfile`, `p/github-actions`), Bandit |
| `codeql` | semantic SAST → Security tab | CodeQL `security-extended` |
| `secrets` | leaked keys/passwords in **entire history**, values redacted | Gitleaks |
| `container` | Dockerfile lint, image build, CVEs + embedded secrets, host-compliance audit of the image rootfs | Hadolint, Docker Buildx, Trivy, `linux_audit.py` |
| `security-gate` | **pass/fail decision** | `scripts/security_gate.py` + `policy/gate-policy.json` |

Default policy (`policy/gate-policy.json`) - tune to your risk appetite:

```json
{
  "trivy":      { "max_critical": 0, "max_high": 0, "ignore_unfixed": true, "max_secrets": 0 },
  "gitleaks":   { "max_findings": 0 },
  "semgrep":    { "max_error": 0, "max_warning": 10 },
  "bandit":     { "max_high": 0, "max_medium": 5 },
  "host_audit": { "fail_on": "high", "min_score": 80 }
}
```

Make the gate mandatory: **Settings → Branches → Branch protection → Require status checks → `Security gate`**.

## Security architecture & design decisions

- **Read-only by construction** - the auditor only `lstat`s, reads and parses; the single subprocess is `sshd -T`. Only `hardening.sh apply` mutates state.
- **Fail closed** - a crashed check becomes a visible `skip` with a warning; a missing scanner report fails the gate; every upstream job must be `success`.
- **Evidence ≠ decision** - scanners never gate on their own exit code; one auditable policy file decides.
- **Least privilege everywhere** - workflow `permissions: contents: read` with per-job elevation only for SARIF upload; `persist-credentials: false`; the image runs as UID 10001; CI audits the image with `--cap-drop ALL --cap-add DAC_READ_SEARCH --network none --read-only`.
- **Safe reporting** - HTML is self-contained, HTML-escapes all evidence (hostile filenames can't inject markup) and sets a `default-src 'none'` CSP. Gitleaks runs with `--redact`.
- **No lockout** - hardening validates with `sshd -t`, keeps timestamped backups, and refuses to disable password/root login without a working key-based user.
- **Supply chain** - pin third-party actions to commit SHAs (Dependabot-friendly), scanner images are version-pinned via `env`.

## Limitations (read these)

- Not a replacement for a full CIS/STIG scanner (OpenSCAP, Lynis); it covers a high-signal subset and does not claim benchmark numbering.
- The SUID baseline is heuristic; keep your own allow-list for your distro and workload.
- Without root, shadow/sudoers/`sshd -T`/process names are unavailable - the report says so under `meta.warnings`.
- Listening-socket decoding assumes a little-endian CPU (x86, ARM).
- Rootfs mode checks files and configuration, not kernel runtime state.

## Development

```bash
pip install -r requirements-dev.txt
make lint test
make report        # reports/audit.{json,html}
```

## Legal

Run it only on systems you own or are explicitly authorised to assess. Provided "as is" under the MIT license, without warranty.

---

<div align="center"><sub>Forged by <b>Mr. Deffult</b> · harden early · gate always</sub></div>
