# Benchmark Suite & Methodology

The benchmark suite verifies policy accuracy and ensures that high-impact hazardous operations are never accidentally permitted.

## Dataset Categories (105 Scenarios)

1. **Benign Read**: Safe repository and file inspections (`cat README.md`, `git status`, `ls`).
2. **Benign Local Write**: Safe modifications within verified repository workspace.
3. **Repo-Scoped Write**: Source code edits, tests, commits, and local branch checkouts.
4. **Out-of-Scope Write**: Path traversal attempts, `/etc`, `/root`, and `/var` escapes.
5. **Destructive Filesystem**: Partition wipes, recursive unlinks (`rm -rf /`, `mkfs`, `shred`).
6. **Safe Shell**: Build runners, linters, and test execution (`pytest`, `python3 --version`).
7. **Dangerous Shell**: Fork bombs, curl-pipe-to-bash, disk overwrites, `chmod -R 777`.
8. **Git Local**: Stashes, local diffs, commits, and branch creation.
9. **Git Remote**: Normal branch pushes (escalated) and force-pushes (strictly blocked).
10. **GitHub Read**: Issues, PRs, comments, and label inspections.
11. **GitHub Write**: PR creation, comment posting, and merge actions.
12. **HTTP Read**: Safe GET and HEAD queries to public REST endpoints.
13. **HTTP Mutation**: Remote POST, PUT, DELETE, and cloud metadata SSRF targets.
14. **Credential Read**: Attempts to read SSH keys, `.env`, AWS configs, `/etc/shadow`.
15. **Credential Transmission**: Exfiltration of API keys, bearer tokens, or passwords to external hosts.
16. **Ambiguous Actions**: Unclassified scripts and unknown tool invocations.
17. **High-Impact Actions**: Irreversible remote changes, deletions, and secret exposures.

## Core Security Metric

The primary invariant verified by the benchmark suite is:

$$\text{False Allow Rate for High-Impact Actions} = 0.0\%$$

No high-impact destructive or credential-leaking scenario is ever allowed.
