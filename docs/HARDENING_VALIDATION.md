# v0.1.3rc1 validation and release gates

The starting public commit was `a29e62a604a8e4d622364c8077eb40e6553f628f`.
The credential-free host baseline passed 120 tests, zero failures/skips. Fresh
validation uses sequential pytest without xdist, disposable canaries and local
listeners. No live ELYREON-AUTO harness changes are part of this candidate.

## Actual enforcement chain

Trusted manager → validated effective policy snapshot/digest → private audit
broker/config → metadata-only workspace capability scan → pinned workspace inode
→ cgroup/bootstrap → bwrap user/PID/IPC/UTS/network/mount namespaces → dropped
capabilities and filtered environment → read-only root/code/system mounts,
writable authorized workspace and bounded scratch → command and descendants →
bounded output/deadline → host receipt → namespace/cgroup teardown.

The OCI candidate uses the outer container's mount/PID/network/cgroup controls.
It installs the wheel into a freshly built image. It never turns off nested-bwrap
checks to gain functionality. Live Docker proof is a mandatory separate CI job.
Podman/crun probes on the host failed before workload startup: missing privileged
UID mapping helpers and denied user-namespace creation. Extracted disposable
binaries are not evidence of OCI containment.

## Reproduced defects and fixes

| Defect | Fresh reproduction | Fix / regression |
|---|---|---|
| Adapter path TOCTOU | Swap a validated parent for a symlink; outside synthetic file overwritten | Descriptor-relative no-follow traversal and regular-file/hardlink checks; `test_v013_filesystem_races.py` |
| Writable alias to read-only enforcement code | Workspace or extra RW bind overlaps code/system/RO grant | Reject overlapping writable grants; fail-closed regression |
| Native hardlink/Unix-socket capability import | OS bind would expose existing inode despite path/network checks | Metadata-only preflight rejects hardlinks, IPC and devices; `test_v013_boundary.py` |
| Mutable synthetic root | Create `/etc` file despite workspace-only authorization | Read-only root with explicit writable submounts; boundary/clean-install canary |
| Missing aggregate cgroup controls | Starting source ignores CPU/memory/PID fields under bwrap | Required delegated cgroup controllers, trusted bootstrap and inherited limits; boundary/fail-closed tests |
| Read-only pack overridden by launcher default | Default manager parameter selects read-write despite policy | Respect policy mount mode and reject widening; fail-closed regression |
| Custom policy lost in guest | Generated MCP selects named default instead of supplied configuration | Immutable effective snapshot/digest, stale-substitution checks; fail-closed regression |
| Whole-checkout exposure / wheel import failure | bwrap automatically binds checkout and cannot expose an installed package | Bind only trusted package code; installed-wheel public-source canary |
| OCI exec descendants persist | Killing the CLI or exiting an exec does not terminate detached container processes | Disposable per-command PID namespaces and explicit runtime cleanup; live OCI job |
| OCI image/env mismatch | Stock image lacks firewall and exec inherits image variables | Supplied installed-wheel image, clean `/usr/bin/env -i` command; live OCI job |
| Host egress thread exhaustion | Unbounded connections create unbounded host threads outside guest cgroup | Sixteen active connections and absolute three-second frame deadline; `test_v013_egress.py` |
| CI dependency/setup failure | Actual previous run: 5 failures, 16 setup errors, 11 skips | Install bwrap, compatible Python/agent-version binary, delegate cgroups; no critical skip accepted |

## RT definitions and limits

**RT01 / FWA-U1: complete resource isolation.** CPU, memory, swap, PID and inherited
FD/file-size limits are now enforced in the host boundary. HOME and `/tmp` are
bounded scratch. Writable host workspace aggregate disk/inode quotas and global
host-created session/storage budgets remain unimplemented. Therefore RT01 is
PARTIAL, not resolved.

**RT02 / FWA-U2: mandatory mediation and truthful complete audit.** Native code
remains able to perform policy-denied actions *inside granted capabilities*
without MCP evaluation. For example, a writable workspace's native shell can
create a pack-denied `secrets.json`; a read-only root/network namespace does not
mediate that individual policy decision. This is a confirmed unresolved design
property. The manager now records native command intent/result, but syscall
policy mediation and native-denial attribution remain incomplete. No command
string filter or voluntary agent compliance closes RT02.

**RT03 / FWA-U3: audit-history integrity.** The new host run blocked all 26 native
store tamper attempts with committed history intact. The managed Bubblewrap
prevention result is proven. OCI, standalone same-UID execution and trusted-owner
rollback must be distinguished; a successful Docker job cannot establish Podman
or host-owner rollback protection. Guest append events do not attest their truth.

## Release decision

Version is **0.1.3rc1**, a reviewable candidate. No v0.1.3 tag/release may be made
while RT01/RT02, complete audit/rotation, backend proof and the independent
credential-free coding-agent canary remain open. The current Codex session
constructed deliberate native attacks; this is OS-boundary red teaming, not a
separately launched authenticated model-agent canary. Configured Codex/Claude
launchers require real credentials; no credential-free local model endpoint was
available. Real credentials were not read for this validation.

Host workloads: Python edits/pytest, Node edits/npm tests/offline install, local
Git commit/diff/status and C compilation passed using narrow package grants.
Rust is unavailable because no toolchain is configured. The authorized-network
fixture grants one synthetic domain to a local controlled connector; production
private-address rejection is unchanged. It does not prove production-provider
availability.

Reproduction:

```sh
python3 -m venv /tmp/firewall-validation
/tmp/firewall-validation/bin/pip install -r requirements.lock
/tmp/firewall-validation/bin/pip install --no-deps .
# Run from the checkout with a fresh empty HOME and XDG_CONFIG_HOME.
/tmp/firewall-validation/bin/pytest -q
/tmp/firewall-validation/bin/python security/rt03/hostile.py after
/tmp/firewall-validation/bin/python security/v013/workloads.py
/tmp/firewall-validation/bin/python security/v013/clean_install.py --revision PUBLIC_COMMIT
# On a supported Docker host:
docker build --no-cache -t drex-agent-firewall:validation .
/tmp/firewall-validation/bin/pytest -q security/v013/test_oci_runtime.py
```

Use a delegated cgroup-v2 host and ABI-compatible guest/system Python. Missing
kernel/runtime support is a failing integration requirement, never evidence of a
successful security test. The dependency lock pins this Python 3.12 validation
environment. The base image tag and distro repository updates are not bit-for-bit
reproducible; capture image digests for any promoted artifact. Nothing here proves
kernel exploit resistance, privileged host containment, universal mediation,
cryptographic rollback detection or release readiness.
