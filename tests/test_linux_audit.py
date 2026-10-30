import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


la = _load("linux_audit", "audit/linux_audit.py")
gate = _load("security_gate", "scripts/security_gate.py")


def build_rootfs(tmp, hardened=False):
    r = tmp / "rootfs"
    for d in ("etc/ssh", "etc/sudoers.d", "usr/bin", "tmp", "var/www/upload", "home/alice/.ssh"):
        (r / d).mkdir(parents=True, exist_ok=True)
    ssh = ("PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nMaxAuthTries 3\n"
           "LoginGraceTime 30\nClientAliveInterval 300\nClientAliveCountMax 2\n") if hardened else (
        "PermitRootLogin yes\nPasswordAuthentication yes\nMaxAuthTries 10\nPermitEmptyPasswords yes\n")
    (r / "etc/ssh/sshd_config").write_text(ssh)
    if hardened:
        (r / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
        (r / "etc/group").write_text("sudo:x:27:alice\n")
    else:
        (r / "etc/passwd").write_text(
            "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\n"
            "alice:x:1000:1000::/home/alice:/bin/bash\ndaemon:x:1:1::/usr/sbin:/bin/bash\n")
        (r / "etc/shadow").write_text("root:*:19000:0:99999:7:::\nbob::19000:0:99999:7:::\n")
        (r / "etc/group").write_text("sudo:x:27:alice\ndocker:x:998:alice\n")
        (r / "etc/sudoers.d/90-test").write_text("alice ALL=(ALL) NOPASSWD:ALL\n")
        (r / "usr/bin/find").write_text("x")
        os.chmod(r / "usr/bin/find", 0o4755)
        (r / "tmp/evil").write_text("x")
        os.chmod(r / "tmp/evil", 0o4755)
        (r / "usr/bin/mystery").write_text("x")
        os.chmod(r / "usr/bin/mystery", 0o4755)
        (r / "etc/badfile").write_text("x")
        os.chmod(r / "etc/badfile", 0o666)
        os.chmod(r / "var/www/upload", 0o777)
        os.chmod(r / "home/alice/.ssh", 0o777)
    os.chmod(r / "tmp", 0o1777)
    return r


def run(root, *extra):
    out = root.parent / "report.json"
    code = la.main(["--root", str(root), "--json", str(out), "--quiet", *extra])
    return code, json.loads(out.read_text())


def failed_ids(report):
    return {f["id"] for f in report["findings"] if f["status"] == "fail"}


def test_vulnerable_rootfs_is_detected(tmp_path):
    code, rep = run(build_rootfs(tmp_path))
    ids = failed_ids(rep)
    assert code == 1
    assert {"SUID-001", "SUID-002", "SUID-003", "PERM-002", "PERM-003", "SSH-001", "SSH-002", "SSH-004",
            "SSH-005", "USR-001", "USR-002", "USR-003", "USR-005", "USR-006", "USR-008"} <= ids
    suspect = next(f for f in rep["findings"] if f["id"] == "SUID-001")
    assert any("/tmp/evil" in e for e in suspect["evidence"])
    assert rep["summary"]["score"] < 50
    assert rep["gate"]["passed"] is False


def test_hardened_rootfs_passes_gate(tmp_path):
    code, rep = run(build_rootfs(tmp_path, hardened=True), "--fail-on", "high", "--min-score", "90")
    assert failed_ids(rep) <= {"USR-005"} or not failed_ids(rep)
    assert code == 0, rep["gate"]["reasons"]


def test_suid_allowlist_suppresses_findings(tmp_path):
    root = build_rootfs(tmp_path)
    allow = tmp_path / "allow.txt"
    allow.write_text("# approved\nmystery\n")
    _, rep = run(root, "--suid-allowlist", str(allow))
    unknown = next(f for f in rep["findings"] if f["id"] == "SUID-003")
    assert unknown["status"] == "pass"


def test_include_and_first_match_wins(tmp_path):
    root = build_rootfs(tmp_path, hardened=True)
    (root / "etc/ssh/sshd_config.d").mkdir()
    (root / "etc/ssh/sshd_config.d/10.conf").write_text("MaxAuthTries 2\n")
    (root / "etc/ssh/sshd_config").write_text("Include /etc/ssh/sshd_config.d/*.conf\nMaxAuthTries 9\n")
    cfg, _, _ = la.load_sshd_config(la.Ctx(str(root)))
    assert cfg["maxauthtries"] == "2"


def test_html_report_escapes_evidence(tmp_path):
    root = build_rootfs(tmp_path)
    nasty = root / "tmp" / "<img src=x onerror=alert(1)>"
    nasty.write_text("x")
    os.chmod(nasty, 0o4755)
    out = tmp_path / "r.html"
    la.main(["--root", str(root), "--html", str(out), "--quiet"])
    text = out.read_text()
    assert "<img src=x" not in text
    assert "&lt;img src=x" in text
    assert "Content-Security-Policy" in text


def test_listener_decoding():
    assert la._decode_addr("0100007F", False) == "127.0.0.1"
    assert la._decode_addr("00000000000000000000000001000000", True) == "::1"
    assert la._is_loopback("::ffff:127.0.0.1")
    assert not la._is_loopback("0.0.0.0")


def test_time_parsing():
    assert la._secs("1m30s") == 90
    assert la._secs("120") == 120
    assert la._secs("abc") is None


def test_bad_arguments_exit_2(tmp_path):
    assert la.main(["--checks", "bogus", "--quiet"]) == 2
    assert la.main(["--root", str(tmp_path / "missing"), "--quiet"]) == 2


def test_gate_script_fail_closed(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps({"required": ["gitleaks", "bandit"], "gitleaks": {"max_findings": 0},
                               "bandit": {"max_high": 0}}))
    (reports / "gitleaks.json").write_text("[]")
    # bandit.json missing -> fail closed
    assert gate.main(["--policy", str(pol), "--reports", str(reports), "--summary", ""]) == 1
    (reports / "bandit.json").write_text(json.dumps({"results": [{"issue_severity": "LOW"}]}))
    assert gate.main(["--policy", str(pol), "--reports", str(reports), "--summary", ""]) == 0
    (reports / "gitleaks.json").write_text(json.dumps([{"RuleID": "x"}]))
    assert gate.main(["--policy", str(pol), "--reports", str(reports), "--summary", ""]) == 1


def test_gate_trivy_ignore_unfixed():
    data = {"Results": [{"Vulnerabilities": [
        {"Severity": "CRITICAL", "FixedVersion": ""}, {"Severity": "HIGH", "FixedVersion": "1.2"}]}]}
    bad, _ = gate.gate_trivy(data, {"max_critical": 0, "max_high": 0, "ignore_unfixed": True})
    assert bad == ["high=1>0"]


def test_live_audit_smoke(tmp_path):
    out = tmp_path / "live.json"
    code = la.main(["--checks", "ssh,users,network", "--json", str(out), "--quiet", "--fail-on", "none"])
    assert code == 0
    rep = json.loads(out.read_text())
    assert rep["meta"]["tool"].startswith("Mr. Deffult")
    assert stat.S_ISREG(out.stat().st_mode)
