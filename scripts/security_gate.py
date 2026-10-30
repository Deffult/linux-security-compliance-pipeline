#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Mr. Deffult | Security gate: aggregates scanner reports and enforces policy-as-code.

Reads JSON reports from a directory (trivy.json, gitleaks.json, semgrep.json, bandit.json, audit.json),
compares them with policy/gate-policy.json and exits 1 if any control fails. Fails CLOSED: a required report
that is missing or unparsable is a failure.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

SEV = ["critical", "high", "medium", "low"]


def load(path):
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read().strip()
        return json.loads(text) if text else []
    except (OSError, ValueError):
        return None


def count_by(items, getter):
    out = {s: 0 for s in SEV}
    for it in items:
        s = (getter(it) or "").lower()
        if s in out:
            out[s] += 1
    return out


def over(counts, limits):
    return [f"{s}={counts[s]}>{limits[f'max_{s}']}" for s in SEV if f"max_{s}" in limits and counts[s] > limits[f"max_{s}"]]


def gate_trivy(data, pol):
    vulns, secrets = [], 0
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            if pol.get("ignore_unfixed") and not v.get("FixedVersion"):
                continue
            vulns.append(v)
        secrets += len(res.get("Secrets") or [])
    counts = count_by(vulns, lambda v: v.get("Severity"))
    bad = over(counts, pol)
    if secrets > pol.get("max_secrets", 0):
        bad.append(f"secrets={secrets}")
    return bad, f"vulns {counts} secrets={secrets}"


def gate_gitleaks(data, pol):
    n = len(data) if isinstance(data, list) else 0
    return ([f"leaks={n}>{pol.get('max_findings', 0)}"] if n > pol.get("max_findings", 0) else []), f"{n} leak(s)"


def gate_semgrep(data, pol):
    res = data.get("results") or []
    counts = {"error": 0, "warning": 0, "info": 0}
    for r in res:
        sev = ((r.get("extra") or {}).get("severity") or "").lower()
        if sev in counts:
            counts[sev] += 1
    bad = [f"{k}={counts[k]}>{pol[f'max_{k}']}" for k in counts if f"max_{k}" in pol and counts[k] > pol[f"max_{k}"]]
    return bad, str(counts)


def gate_bandit(data, pol):
    counts = count_by(data.get("results") or [], lambda r: r.get("issue_severity"))
    return over(counts, pol), str({k: v for k, v in counts.items() if k != "critical"})


def gate_audit(data, pol):
    order = {s: i for i, s in enumerate(SEV)}
    fail_on = pol.get("fail_on", "high")
    hits = [f["id"] for f in data.get("findings", [])
            if f.get("status") == "fail" and order.get(f.get("severity"), 9) <= order.get(fail_on, 1)]
    score = data.get("summary", {}).get("score", 0)
    bad = []
    if hits:
        bad.append(f">= {fail_on}: {', '.join(hits)}")
    if score < pol.get("min_score", 0):
        bad.append(f"score {score}<{pol.get('min_score', 0)}")
    return bad, f"score={score}"


CONTROLS = [
    ("Container vulnerabilities & secrets (Trivy)", "trivy", "trivy.json", gate_trivy),
    ("Secret detection (Gitleaks)", "gitleaks", "gitleaks.json", gate_gitleaks),
    ("SAST (Semgrep)", "semgrep", "semgrep.json", gate_semgrep),
    ("SAST (Bandit)", "bandit", "bandit.json", gate_bandit),
    ("Host compliance audit", "host_audit", "audit.json", gate_audit),
]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--policy", default="policy/gate-policy.json")
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY"), help="markdown summary file")
    args = ap.parse_args(argv)
    policy = load(args.policy)
    if not isinstance(policy, dict):
        print(f"error: cannot load policy {args.policy}", file=sys.stderr)
        return 2
    required = set(policy.get("required", [c[1] for c in CONTROLS]))
    rows, failed = [], False
    for title, key, fname, fn in CONTROLS:
        if key not in policy:
            continue
        data = load(os.path.join(args.reports, fname))
        if data is None or (not isinstance(data, (dict, list))):
            status, detail = ("FAIL", "report missing or unparsable (fail-closed)") if key in required else ("SKIP", "no report")
        else:
            try:
                bad, info = fn(data, policy[key])
            except (AttributeError, TypeError):
                bad, info = ["report has unexpected format"], ""
            status, detail = ("FAIL", f"{'; '.join(bad)}  [{info}]") if bad else ("PASS", info)
        failed |= status == "FAIL"
        rows.append((title, status, detail))
    width = max(len(r[0]) for r in rows) if rows else 10
    for t, s, d in rows:
        print(f"[{s}] {t.ljust(width)}  {d}")
    print("SECURITY GATE:", "FAILED" if failed else "PASSED")
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write("## Security gate\n\n| Control | Result | Detail |\n|---|---|---|\n")
            for t, s, d in rows:
                fh.write(f"| {t} | {'PASS' if s == 'PASS' else s} | {d.replace('|', '/')} |\n")
            fh.write(f"\n**{'FAILED' if failed else 'PASSED'}**\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
