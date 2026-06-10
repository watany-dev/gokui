# Security Policy

gokui is a security gate for Agent Skill bundles, so vulnerability reports
receive priority handling. Thank you for taking the time to report
responsibly.

## Supported Versions

gokui is pre-release software. Only the latest release (including beta
pre-releases) and the current `main` branch receive security fixes.

## Reporting a Vulnerability

Please do NOT open a public issue for security vulnerabilities.

Report privately via GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Describe the issue, affected versions, and reproduction steps.

GitHub advisories are the preferred channel because they keep the report,
discussion, and fix coordination in one private place.

### What to include

- The gokui version or commit (`gokui --version`).
- The command and inputs that trigger the issue (a minimal skill bundle
  fixture is ideal).
- The impact as you understand it — for example: a malicious bundle that
  bypasses detection, escapes quarantine during materialization, writes
  outside the install target, or causes a decision of `PASS` where
  `REJECTED` is expected.

### Scope notes

Detection gaps are security-relevant for this project. If you find a
malicious-skill pattern that gokui passes silently, treat it as a
vulnerability report (privately) rather than a feature request, especially
when the pattern defeats an existing rule rather than requiring a new one.

False positives (benign content flagged as malicious) are not
vulnerabilities — please file those through the public
false-positive issue template instead.

## Response

You can expect an acknowledgement within 7 days. Coordinated disclosure
timing is agreed in the advisory thread; fixes for confirmed reports land in
the next release.
