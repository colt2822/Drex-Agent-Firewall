# v0.1.3rc1 hardening candidate

Fixes filesystem adapter TOCTOU and hardlink alias access; rejects preexisting
workspace IPC/device capabilities; pins the Bubblewrap workspace inode; makes the
synthetic root read-only; requires CPU/memory/PID cgroups and inherited resource
limits; bounds temporary mounts and egress broker connections; preserves custom
policy snapshots and rejects stale substitution; records native command receipts;
and repairs the installed-wheel code mount path and inconsistent version metadata.

The supplied OCI image and mandatory Docker CI attacks validate the outer runtime
model. OCI commands use disposable PID namespaces, filtered environments, explicit
mounts, bounded scratch and no network. Nested Bubblewrap has no unrestricted
fallback. CI installs its actual security prerequisites and rejects critical skips.

This is a candidate, not a v0.1.3 release. RT01 aggregate writable-workspace quotas,
RT02 mandatory native mediation/audit, complete backend/rollback validation and a
separately launched credential-free model-agent canary remain release blockers.
See [validation](docs/HARDENING_VALIDATION.md) and the
[future harness contract](docs/ELYREON_AUTO_INTEGRATION.md).
