# Label and Issue Management

This guide describes the openHiTLS label system, issue lifecycle, and PR lifecycle.

## Label System

Labels use the `prefix:name` convention across **8 dimensions** with distinct colors for instant visual recognition. Each dimension groups related labels under a common prefix for filtering and sorting.

### triaged: — Type Classification (7 + 4 close labels)

Type labels identify the nature of an issue or PR. Close reason labels are applied when closing without merging.

**Type Labels** — Amber `#fbca04`

| Label | Color | Description |
|-------|-------|-------------|
| `triaged:bug` | `#fbca04` | Bug report or defect fix |
| `triaged:feat` | `#fbca04` | New feature or capability |
| `triaged:docs` | `#fbca04` | Documentation change |
| `triaged:refactor` | `#fbca04` | Code refactoring |
| `triaged:style` | `#fbca04` | Code style / formatting |
| `triaged:test` | `#fbca04` | Test addition or modification |
| `triaged:chore` | `#fbca04` | Build, tooling, or miscellaneous |

**Close Reason Labels** — Gray / Purple

| Label | Color | Description |
|-------|-------|-------------|
| `triaged:duplicate` | `#cfd3d7` | Duplicate of an existing issue or PR |
| `triaged:invalid` | `#e6e6e6` | Invalid report or incomplete information |
| `triaged:question` | `#d876e3` | Question that has been answered |
| `triaged:wontfix` | `#ffffff` | Will not be fixed or implemented |

### area: — Code Module (6 labels) — Blue `#0075ca`

| Label | Color | Description |
|-------|-------|-------------|
| `area:tls` | `#0075ca` | TLS protocol stack |
| `area:crypto` | `#0075ca` | Cryptographic algorithms |
| `area:build` | `#0075ca` | Build system (CMake, etc.) |
| `area:pqc` | `#0075ca` | Post-Quantum Cryptography |
| `area:platform` | `#0075ca` | Platform adaptation (RISC-V, etc.) |
| `area:security` | `#0075ca` | Security-related |

### br: — Target Branch (6 labels) — Light Blue `#bfd4f2`

| Label | Color | Description |
|-------|-------|-------------|
| `br:main` | `#bfd4f2` | Main development branch |
| `br:0.1` | `#bfd4f2` | Release branch 0.1 |
| `br:0.2` | `#bfd4f2` | Release branch 0.2 |
| `br:0.3` | `#bfd4f2` | Release branch 0.3 |
| `br:0.4` | `#bfd4f2` | Release branch 0.4 |
| `br:riscv-crypto` | `#bfd4f2` | RISC-V cryptography branch |

### CI: — CI Status (3 labels) — Semantic Colors

| Label | Color | Description |
|-------|-------|-------------|
| `CI:running` | `#fef2c0` | CI pipeline in progress |
| `CI:failed` | `#e11d48` | CI pipeline failed |
| `CI:successful` | `#0e8a16` | CI pipeline passed |

### review: — Review State (3 labels) — Purple / Green / Pink

| Label | Color | Description |
|-------|-------|-------------|
| `review:under-review` | `#8b5cf6` | Awaiting reviewer assignment |
| `review:approved` | `#0e8a16` | Approved by reviewer(s) |
| `review:changes-requested` | `#d946ef` | Changes requested by reviewer |

### community: — Contributor Engagement (5 labels) — Green `#16a34a`

| Label | Color | Description |
|-------|-------|-------------|
| `community:good-first-issue` | `#16a34a` | Beginner-friendly, suitable for first-time contributors |
| `community:help-wanted` | `#16a34a` | Open to community contributions |
| `community:claimed` | `#cbe029` | Claimed by a contributor |
| `community:intern` | `#16a34a` | Open-source internship program task |
| `community:bounty` | `#16a34a` | Bounty or security reward program task |

### hold: — Blocking Reason (3 labels) — Red `#b60205`

| Label | Color | Description |
|-------|-------|-------------|
| `hold:cla-unsigned` | `#b60205` | Contributor has not signed the CLA |
| `hold:tc-discussion` | `#b60205` | Pending Technical Committee discussion |
| `hold:needs-info` | `#b60205` | More information needed from the reporter |

### CLA: — CLA Compliance (1 label) — Green `#0e8a16`

| Label | Color | Description |
|-------|-------|-------------|
| `CLA:signed` | `#0e8a16` | CLA signing confirmed |

## Issue Lifecycle

```
[Contributor Creates Issue]
        |
        v
+-------------------------------+
|  No labels (Open, unlabelled) |  <-- Awaiting triage
+---------------+---------------+
                |
                | Maintainer triage
                v
+-------------------------------+
|  triaged:{type}               |  <-- Type applied
+---------------+---------------+
                |
                +---> community:good-first-issue
                +---> community:help-wanted
                |         |
                |         v
                |    community:claimed + Assignee
                |
                +---> Assignee (core team)
                v
+-------------------------------+
|  Assignee set — In progress   |
+---------------+---------------+
                |
                +---> PR merged with "Fixes #xxx" --> [Closed]
                |
                +---> triaged:duplicate  --> Close + link to original
                +---> triaged:invalid    --> Close + comment with reason
                +---> triaged:wontfix    --> Close + comment with reason
                +---> triaged:question   --> Close after answered
```

**Issue labels:** Only `triaged:*` and `community:*` apply to issues.

### Issue Triage Rules

| Stage | Who | Action |
|-------|-----|--------|
| Created | — | No labels |
| Triaged | Maintainer | Add `triaged:{type}` |
| Community | Maintainer | Add `community:good-first-issue` or `community:help-wanted` |
| Claimed | Contributor | Add `community:claimed`, set Assignee |
| Closed (resolved) | Maintainer / auto | No additional labels |
| Closed (duplicate) | Maintainer | Add `triaged:duplicate` |
| Closed (invalid) | Maintainer | Add `triaged:invalid` |
| Closed (wontfix) | Maintainer | Add `triaged:wontfix` |
| Closed (question) | Maintainer | Add `triaged:question` |

## PR Lifecycle

```
[Contributor Submits PR]
        |
        v
+-------------------------------+
|  review:under-review          |
|  + br:{target-branch}         |
|  + triaged:{type}             |
|  + ci:running                 |  <-- CI auto-triggered
+---------------+---------------+
                |
                v
+-------------------------------+
|  CI: running -> successful    |
|              or failed        |
+---------------+---------------+
                |
                v
+-------------------------------+
|  Maintainer Review            |
+---------------+---------------+
                |
                +---> review:changes-requested -> contributor revises -> review:under-review
                +---> hold:cla-unsigned / hold:tc-discussion / hold:needs-info
                +---> review:approved
                          |
                          v
+---------------------------------------------------+
|  Merge Gate:                                       |
|  [x] CLA:signed                                   |
|  [x] review:approved                              |
|  [x] br:{target}                                  |
|  [x] ci:successful                                |
+-------------------------------+-------------------+
                                |
                                v
+---------------------------------------------------+
|  Webhook Merge:                                    |
|  Single branch  --> Direct merge, close PR         |
|  Multiple branches --> Cherry-pick to each target  |
+-------------------------------+-------------------+
                                |
                 +--------------+--------------+
                 |                             |
                 v                             v
+-----------------------------+ +-----------------------------+
|  All branches succeeded     | |  Conflict on a branch       |
|  --> PR closed              | |  --> Merge FAILED           |
|                             | |  --> Re-submit PR for       |
|                             | |      conflicting branch     |
+-----------------------------+ +-----------------------------+
```

### PR Label Rules

| Stage | Who | Action |
|-------|-----|--------|
| Created | Maintainer | Add `review:under-review` + `br:{target}` + `triaged:{type}` |
| CI running | CI bot | Set `ci:running` |
| CI passed | CI bot | Set `ci:successful` |
| CI failed | CI bot | Set `ci:failed` |
| Changes requested | Reviewer | Set `review:changes-requested` |
| Revised | Maintainer | Set `review:under-review` |
| CLA unsigned | CLA bot | Add `hold:cla-unsigned` |
| CLA signed | CLA bot | Add `CLA:signed`, remove `hold:cla-unsigned` |
| Approved | Reviewer | Set `review:approved` |
| Merge gate passed | Maintainer | Verify `CLA:signed` + `review:approved` + `ci:successful` |
| Merged (success) | Webhook | Close PR |
| Merged (conflict) | Webhook | Notify conflict, contributor re-submits PR for that branch |
| Closed (duplicate) | Maintainer | Add `triaged:duplicate` |
| Closed (invalid) | Maintainer | Add `triaged:invalid` |
| Closed (wontfix) | Maintainer | Add `triaged:wontfix` |

## SLA

| Item | SLA | Action on breach |
|------|-----|------------------|
| Issue triage | 1 business days | Escalate to TC |
| PR first review | 3 business days | Escalate to Maintainer lead |
| `hold:needs-info` | 7 days, auto-close if no response | Stale bot closes issue |

## Roles

| Role | Responsibilities |
|------|------------------|
| **Maintainer** | Triage issues within 3 business days; apply `triaged:*`, `area:*`, `br:*`; approve PRs |
| **Committer** | Review PRs in their area; apply `review:*` labels |
| **Contributor** | Follow templates; claim issues with `community:claimed`; submit PRs |
| **TC** | Resolve `hold:tc-discussion` items; approve interface changes |
