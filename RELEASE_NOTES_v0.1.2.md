# Drex Agent Firewall v0.1.2

## RT-03 Audit Isolation Hardening

This patch adds a scoped managed-session audit-store boundary. **THIS PATCH DOES NOT CLAIM GLOBAL RT-03 CLOSURE.** Managed Bubblewrap audit-store tamper prevention is demonstrated in the tested scope. OCI runtime validation and global RT-03 closure remain future work.

### Added

- Host-private authoritative audit history managed by the trusted launcher.
- A trusted host-side SQLite writer and per-session Unix-socket audit channel.
- Narrow append-oriented IPC with bounded framing, absolute deadlines, and a per-session payload budget.
- Fail-closed behavior when decision persistence fails before a protected effect.
- OCI generated-configuration regression coverage for database mounts, per-session socket wiring, and fail-closed runtime selection. These tests use mocked runtime commands and do not establish container runtime containment.

### Security hardening

- Managed Bubblewrap agents in the tested boundary could not directly read, write, delete, or replace the authoritative audit database or its WAL/SHM files.
- The workspace path, guest environment, and MCP configuration cannot redirect the authoritative writer destination.
- History-edit IPC requests are rejected. The protection is enforced by the guest mount boundary and host writer design; it does not depend on MCP mediation.
- Raw NoIsolation and unrestricted same-UID host execution remain unsafe. Standalone stores remain caller-controlled and tamperable.

### Validation

- 26 synthetic filesystem tamper cases: 0 successful tamper events in managed Bubblewrap.
- Final validation passed 120 pytest tests with zero failures, including five OCI configuration regressions. This test run does not validate Docker or Podman runtime behavior.
- Deterministic replay measurements (not general security proof): standard 105 / 100.0%, red-team 220 / 99.55%, hostile bypass 186 / 98.39%, and isolation 100 / 98.0%; each recorded 0 observed high-impact false allows.
- Docker and Podman were unavailable on the validation host. OCI tests cover generated configuration only.

### Still unresolved

- RT-01 resource isolation, RT-02 mandatory mediation, and global RT-03.
- OCI runtime validation, including container-root behavior, socket substitution, cross-session isolation, and committed-history survival.
- Raw NoIsolation/same-UID host trust boundary and independent trusted-host rollback detection. Host rollback detection is **not implemented**.
- Global disk quota and complete resource-budget enforcement.
- A real-agent RT-03 canary.
