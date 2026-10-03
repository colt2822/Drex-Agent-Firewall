# RT-03 pre-implementation boundary and design

REPOSITORY=/home/colton-mcclain/drex-agent-firewall
BASE_HEAD=7d06afa873e4c372294879672881a9d4124cc33d
RELEASE=v0.1.1
WORKTREE=/home/colton-mcclain/drex-worktrees/firewall-rt03-audit-store-20261002
BRANCH=security/rt03-audit-store-isolation-20261002
INITIAL_GIT_STATUS=CLEAN

## Current boundary

The manager opens its configurable `drex_firewall.db` on the host. Generated MCP
configuration starts `python3 -m drex_agent_firewall.mcp.server` in the guest with
`DREX_DATABASE_PATH=/workspace/.drex_firewall.db`. That guest MCP process opens
SQLite via `ActionRepository -> init_db -> sqlite3.connect`. SDK, API, standalone
MCP, calibration, simulator and demo paths separately open operator/config-selected
databases; they have no independent storage boundary. This candidate scopes
protection to sessions created through SandboxManager; standalone same-UID use
is not protected.

Agent tool -> guest MCP -> normalizer/policy -> BaseAdapter.record_decision ->
SQLite DB/WAL -> adapter execution -> record_execution. Native execution bypasses
that chain. Manager session metadata is recorded separately on the host. Guest
filesystem/git calls previously used default session IDs and lacked sandbox
correlation.

Disposable measurement: writer UID=1000, native UID=1000, share UID=YES; DB/WAL/SHM
mode=0644 under umask 0002, fixture parent=0775, owner=1000. Guest DB, WAL, SHM and parent
are visible and writable through the workspace mount. Host and guest normally
map to the same host identity in Bubblewrap; namespace visibility, not chmod
against the same UID, must enforce this boundary. NoIsolation exposes host paths.
The default OCI image does not install this package; microVM is an execution stub.
Private 0700 config with a read-only guest mount does not protect the DB.

`before.json` records native subprocess attacks with a live connection and a
subsequent close/reopen. These are disposable fixtures, not production evidence.
Errors reveal corruption in some cases; valid replacement/row mutation need not
trigger an integrity error. There is no rollback anchor. SQLite NORMAL/WAL is
not independent tamper resistance.

## Required property and options (before coding)

Committed authoritative history, including prior decision and result snapshots,
must remain outside all guest filesystem mounts and inaccessible to native guest
processes. Agent input must never select its destination. Persistence must be
acknowledged before a protected action executes. Teardown must retain the DB;
host inspection and session correlation must work. Mount ancestors/aliases of
the store must be rejected, including code and policy extra mounts.

| Option | Assessment |
|---|---|
| A: host-private DB, host-only writer | Necessary, but guest MCP currently needs a persistence channel. A writable guest DB mount defeats this option. |
| B: host-side writer over narrow local IPC | Selected with A. Only the socket inode is mounted; no database, sidecars or private directory. Possession grants append capability for one fixed host-bound session, never SQL/update/delete/history management. |
| C: per-session private DB/export | Adds discovery/export and merging complexity; existing API/repository inspection benefits from a shared host store. |
| D: authenticated append log/hash chain | Cannot detect stale snapshots without an independent tail anchor. Unnecessary for filesystem prevention with a trusted host. Preserve immutable event snapshots instead; do not claim cryptographic detection. |

SELECTED_DESIGN=A+B, shared host-private DB and per-session socket capability.
TAMPER_PREVENTION=filesystem namespace exclusion plus append-only IPC surface.
TAMPER_DETECTION=NOT IMPLEMENTED against trusted-host database tamper/rollback.
Trust assumptions: host manager, host UID, kernel, runtime and its mount configuration
remain trusted; agent runs only inside the validated namespace. The agent may fake
new audit events or omit MCP use (RT-02), but cannot change committed event snapshots.
Host/root compromise, kernel escape, same-UID unrestricted host execution and
administrator replacement of host files remain outside this guarantee.
NoIsolation must be tested as unsafe. OCI remains runtime-unverified if unavailable.
RT-03 stays globally UNRESOLVED unless the supported execution boundary is proven;
a pathname or mock mount test is insufficient.
