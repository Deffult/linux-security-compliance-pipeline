# Security Policy

## Reporting a vulnerability
Please **do not** open a public issue. Use GitHub's *Report a vulnerability* (Security tab → Advisories) so the
report stays private. Expect an acknowledgement within 72 hours.

## Scope & design guarantees
- The auditor is **read-only**: it never modifies the inspected system. Only `hardening.sh apply` changes state,
  and only after explicit invocation, with backups and `sshd -t` validation.
- HTML reports are self-contained, escape all evidence, and ship a restrictive Content-Security-Policy.
- Audit reports contain hostnames, usernames and paths - treat them as sensitive and do not publish them.
