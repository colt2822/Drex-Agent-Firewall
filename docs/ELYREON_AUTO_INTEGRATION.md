# ELYREON-AUTO integration contract (candidate; deployment not approved)

This task does not modify or wrap the live harness. Firewall v0.1.3rc1 remains
non-authoritative while the release gates in `docs/HARDENING_VALIDATION.md` are
open. Integration must be reviewed against an immutable validated commit.

## Trusted launcher

The harness supervisor selects the policy and backend before starting any worker.
It creates a private, mode-0700 audit directory outside every workspace, toolchain,
and code mount, then instantiates `SandboxManager("bubblewrap", db_path=...)`.
Use a dedicated disposable workspace, not host HOME, the firewall checkout,
a credential directory, or a live repository containing credentials.

```python
from drex_agent_firewall.sandbox.manager import SandboxManager

manager = SandboxManager("bubblewrap", db_path=private_audit_path)
info = manager.create_session(
    workspace_path=worker_workspace,
    agent_type="generic",
    policy_pack="safe-local-coding",
    network_mode="none",
)
try:
    result = manager.exec_command(info.session_id, worker_argv)
    if result.returncode:
        raise RuntimeError("worker failed inside firewall")
finally:
    manager.destroy_session(info.session_id)
```

`worker_argv` is an argument vector, never concatenated untrusted shell text. A
model agent launched via `run_agent` currently requires explicit controlled-online
mode and credential staging. That path is unsuitable for a credential-free
release canary and must not be used to claim all actions are MCP-mediated.

## Workspace, toolchains, environment and network

The canonical workspace inode is pinned before Bubblewrap launch and mounted at
`/workspace`. Read-only policy packs default to a read-only bind and reject a
read-write override. Writable workspaces permit native local coding; aggregate
disk/inode limits and complete per-action policy mediation are not implemented.
The launcher owns workspace staging until mounts complete. Do not let a second
unconfined worker mutate it concurrently. Preexisting hardlinks, Unix sockets,
FIFOs and device nodes are refused by a metadata-only scan. In-workspace symlinks
cannot expose an unmounted host path. Trusted host rearrangement of an already
opened directory is outside the guest-only boundary.

System binaries/libraries are read-only. Additional dependencies use explicit
`SandboxMount` grants for individual package/toolchain paths; never grant whole
HOME, site-packages containing unrelated data, Docker/Podman/containerd sockets,
or host `/run`. These sources must be trusted and immutable during launch.

HOME is `/home/agent`; HOME and `/tmp` are bounded per-command scratch mounts.
State there does not survive a command. `/proc` describes the guest PID namespace;
`/dev` contains synthetic basic devices. Root directories are read-only.

No parent environment is inherited. Defaults are PATH, HOME, USER, SHELL, LANG,
LC_ALL, TERM and PYTHONPATH with guest-safe values. Explicit allowlisted names and
operator overrides are filtered for credential, auth, cookie, proxy and key names.
Never forward a parent environment dictionary. Repair workers must construct a
new session with the same or narrower policy; they receive the same filtering.

`none` and `firewall-only` have an independent network namespace; `allowlisted`
currently also denies all egress. `controlled-online` supports only the named
Codex/Claude provider destinations on port 443 through the host CONNECT broker;
private/reserved DNS answers are rejected. This is domain permission, not an
application-level or model-only communication guarantee. `host` is an explicit
loss of network isolation and must not be selected by the integration. The
integration must reject requests for unsupported narrower policies rather than
pretend they are implemented.

## Resource and lifecycle requirements

Bubblewrap requires delegated cgroup-v2 CPU, memory and PID controllers. Missing
controllers cause `RESOURCE_LIMIT_UNAVAILABLE`; there is no unbounded fallback.
The trusted bootstrap joins before bwrap executes. Descendants inherit the same
cgroup, descriptor/file-size/core limits and namespaces. Command deadlines kill
the process namespace and cgroup and mark the session failed. Reuse after failure
or stop is prohibited; retries use a fresh session.

OCI uses the outer runtime boundary, not an unrestricted nested-bwrap fallback.
Build the supplied image and use its exact digest after validation. Commands run
as PID 1 in disposable per-command containers with a read-only root, bounded
scratch, dropped capabilities, no-new-privileges, explicit mounts and no network.
Each command's descendants die when its namespace ends. Docker and Podman proof
must be tracked separately. Runtime cleanup failure is an error, never permission
to relaunch on the host.

## Policy, receipts and failures

Policy schema version 1 and the SHA256 digest bind the effective serialized
configuration. The guest receives a read-only private snapshot; MCP validates its
digest. The manager rejects valid-but-stale substitution before native execution.
Session metadata includes policy version/digest, firewall and Python versions.
Record the actual OS/runtime version alongside that metadata in harness receipts.

The authoritative SQLite store stays outside the sandbox. The guest gets only a
per-session append capability at `/run/drex-audit.sock`. Generated MCP configuration
is read-only at `/tmp/.drex_mcp_config.json`. Teardown removes IPC and config while
retaining history. `native_runs` records run ID, session ID, digest, start/end time,
process class, exit status and timeout/error class; commands and environment values
are excluded. MCP receipts include policy reasons. Native OS denials are not yet
fully attributed or logged per syscall; a failed command is not automatically a
policy-denial event. Do not treat guest-submitted append events as truthful or
complete coverage. Host-owner rollback detection and rotation are unimplemented.

Failures surface as exceptions or nonzero `SandboxResult.returncode`; timeouts
return 124. Known failure classes include `SANDBOX_UNAVAILABLE`,
`RESOURCE_LIMIT_UNAVAILABLE`, `RESOURCE_BOOTSTRAP_FAILURE`, `MOUNT_SETUP_FAILURE`,
`POLICY_INVALID`, `AUDIT_UNAVAILABLE` and `SESSION_NOT_RUNNING`. Errors around
persisting completed results cannot undo an already completed side effect.
The supervisor must treat every exception/nonzero result as failure and may only
retry inside a fresh validated boundary. It must never catch an error and invoke
the original worker directly.

Generated verifiers run inside a separate session under the same or narrower
grants. Verification that must inspect host receipts belongs to the trusted
supervisor; never mount the audit store into a verifier or repair worker.
