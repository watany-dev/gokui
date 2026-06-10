# Adoption Strategy

This document describes how gokui goes from a well-engineered pre-release tool
to a tool people actually use. It complements `ROADMAP.md`: the roadmap defines
what gets built and in which order; this document defines how the result
reaches users and what stands between them and a first successful run.

The core diagnosis: gokui's adoption bottleneck is not product quality. Test
coverage is enforced at 95%, CI runs a three-OS matrix with race detection and
vulnerability scanning, output contracts are machine-readable, and the README
documents the threat model in detail. The bottleneck is the path from "heard
about gokui" to "saw it catch a malicious skill on my machine". Today that path
requires installing Go 1.26 and building from source, and nothing in the first
screen of the README demonstrates value before that investment. Every growth
channel ultimately funnels into "try it", and "try it" is where the funnel
currently breaks.

## Current State

### Strengths to build on

- Quarantine-first positioning is differentiated and honest. No comparable
  tool occupies the "security gate for Agent Skill bundles" niche yet.
- The threat model, rule reference, policy profiles, and non-goals are already
  documented to a depth most projects never reach.
- SARIF output, compact CI summaries, and structured error codes make gokui
  automation-ready out of the box.
- `fixtures/malicious-skill`, `fixtures/fake-prereq-skill`, and the other
  fixtures are ready-made demo material: a complete "attack and detection"
  story already lives in the repository.
- Apache-2.0 license, pinned CI actions, and reproducible build flags signal
  trustworthiness to exactly the security-conscious audience gokui targets.

### Adoption barriers

- No published binaries yet. Building from source with Go 1.26 is the only
  install path, which filters out most prospective users at step one.
- The README is a specification, not a pitch. At roughly 66 KB it answers
  every question except the first one a visitor has: "what does this do for
  me in the next 30 seconds?"
- No inbound channels: no published release, no articles, no listing on
  ecosystem indexes, no GitHub Action for zero-install evaluation.
- No community surface: `CONTRIBUTING.md`, `SECURITY.md`, and issue templates
  are absent. For a security tool, a missing vulnerability-disclosure channel
  is itself a credibility gap.

### Market timing

Agent Skills are spreading faster than the security practices around them.
Teams are starting to ask whether a third-party `SKILL.md` is safe to let an
agent read, and no default answer exists. The window to become the reference
quarantine gate is open now; it will narrow once platform vendors or larger
projects ship their own gating.

## The Adoption Funnel

Awareness → Trial → Adoption → Advocacy.

- Awareness: near zero today, addressable with content and listings
  (initiative 4).
- Trial: broken today; this is the binding constraint. Initiatives 1–3 exist
  to fix it.
- Adoption: already well-served by the product itself (policy profiles,
  lockfiles, SARIF, error codes) once a user gets through trial.
- Advocacy: premature to invest in until trial works.

Sequencing rule: do not spend on awareness before the trial path works.
Traffic sent at a broken funnel is wasted, and a first impression of "I could
not even try it" is hard to reverse.

## Priority Initiatives

### 1. Remove distribution friction (first priority)

Goal: a user with no Go toolchain installs gokui in under a minute.

The release machinery is already planned and largely built: the Beta Release
Track in `ROADMAP.md` specifies that beta tags (`vX.Y.Z-beta.N`) publish
GitHub pre-releases with binaries for all supported targets plus `SHA256SUMS`,
and `.github/workflows/release-beta.yml` exists. What remains is finishing the
beta gate and actually cutting the first public tag.

- Drive `make beta-check` to green on a release commit and publish the first
  `v0.x.y-beta.N` pre-release with binaries for darwin/amd64, darwin/arm64,
  linux/amd64, linux/arm64, and windows/amd64.
- Verify `go install github.com/watany-dev/gokui/cmd/gokui@<tag>` works and
  document it as the path for users who do have Go.
- After the first tagged release, add lightweight package-manager paths in
  rough order of audience overlap: a Homebrew tap, then aqua/mise registry
  entries. Defer official homebrew-core, winget, and similar until GA.

Done when: a fresh machine with no Go toolchain goes from the README to a
working `gokui --version` in under a minute.

### 2. Build the 30-second demo (do together with 1)

Goal: a visitor sees gokui catch a real attack before deciding whether to
read further.

- Add a Quick Start to the top of the README: install command, then
  `gokui inspect ./fixtures/malicious-skill`, then the actual findings output
  (prompt injection, invisible Unicode, exec chains). Three commands, one
  payoff.
- Record the same flow as an asciinema cast or GIF and embed it above the
  fold.
- Restructure the README into a pitch: first screen says what gokui is, who
  it is for, and shows the demo; the deep material (rule reference, exit-code
  contracts, lockfile format, policy schema) moves to `docs/` with links.
  None of that content is wasted — it is the right material for the
  evaluation phase — it is just in the wrong position for first contact.
- Per the Beta Exit Criteria in `ROADMAP.md`, keep `README.md`, `ROADMAP.md`,
  and `RELEASE.md` consistent through the restructure.

Done when: the value proposition and a real detection are visible without
scrolling, and the demo is reproducible by copy-paste.

### 3. Ship a GitHub Action for zero-install trial

Goal: a team can evaluate gokui without installing anything locally.

gokui already emits SARIF from `inspect` (the CI SARIF smoke job proves the
path), so the distance to a usable Action is short.

- Publish an action (in-repo `action.yml` first; a dedicated repo and
  Marketplace listing can follow) that downloads a pinned gokui release, runs
  `gokui inspect --format sarif` against skill paths in the repository, and
  uploads results to GitHub code scanning.
- Document the three-line workflow snippet in the README. PR annotations on
  skill changes are the wedge into organizational adoption: one security
  engineer adds the workflow, the whole team sees findings.

Done when: a repository can surface gokui findings in code scanning by
copying one workflow file, with no local install.

Depends on initiative 1 (needs a published release to download).

### 4. Earn awareness with threat-driven content

Goal: reach the people who already feel the problem.

Security tools spread through demonstrated threats, not feature lists. The
fixtures directory is the raw material.

- Write "How a malicious SKILL.md attacks your agent — and how to catch it":
  walk through the attack techniques the fixtures embody (prompt injection,
  invisible Unicode, fake prerequisites, decode-to-exec chains), then show
  gokui detecting each. Publish in English (blog/HN/X) and Japanese (Zenn) —
  the Japanese AI-agent community is active and underserved on this topic.
- Submit gokui to the awesome-list ecosystem around Claude Code and Agent
  Skills. Low effort, durable inbound links.
- Treat each significant rule-coverage addition as a small content
  opportunity ("gokui now detects X") rather than a silent changelog entry.

Done when: the first article is published in both languages and gokui is
listed on at least the major ecosystem indexes. Ongoing thereafter.

Should land after initiatives 1–2, so arriving readers can actually try it.

### 5. Stand up the community surface

Goal: turn arriving users into reporters and contributors instead of
bounce-offs.

- Add `SECURITY.md` with a private vulnerability-disclosure channel. For a
  security tool this is table stakes and should not wait for the rest.
- Add `CONTRIBUTING.md` covering the dev loop (`make check`, `make test`,
  coverage threshold, fixture conventions) — the Makefile already encodes
  the process; it just needs prose.
- Add issue templates: bug report, rule false-positive/false-negative report
  (the highest-value feedback a scanner can receive), and feature request.

Done when: a stranger can report a vulnerability privately, file a useful
false-positive report, and land a first PR without asking how.

## Non-Goals (for now)

Consistent with gokui's quarantine-gate positioning, the following are
explicitly out of scope for this phase:

- A project website or documentation portal. The README plus `docs/` is
  sufficient until traffic justifies more.
- A skill marketplace or registry. gokui gates skills; hosting them is a
  different product and a different trust model.
- A GUI or TUI. The audience is engineers and CI pipelines.
- Paid promotion. The audience is reachable through technical content and
  ecosystem lists.

## Sequencing and Effort

| Order | Initiative | Effort | Dependency |
| --- | --- | --- | --- |
| 1 | First beta release with binaries | Days (gate is mostly built) | Beta exit criteria in `ROADMAP.md` |
| 2 | README quick start + demo + restructure | Days | None (best shipped with 1) |
| 3 | GitHub Action | Days | 1 |
| 4 | Threat-driven content + listings | Ongoing, article-sized units | 1, 2 |
| 5 | SECURITY.md / CONTRIBUTING.md / templates | Hours | None (SECURITY.md can ship immediately) |

The single most important milestone: a stranger can follow a link, and within
three minutes watch gokui reject a malicious skill on their own machine.
Everything else in this document either feeds that moment or builds on it.
