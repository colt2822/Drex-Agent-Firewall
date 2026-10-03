# RT-03 local fix candidate — 2026-10-02

The candidate prevents the tested native Bubblewrap process from reaching or
altering committed managed audit history. Global RT-03 remains unresolved:
Docker/Podman were unavailable, microVM is a stub, and no real-agent canary could
be run without real credentials. Standalone same-UID host execution still has no
independent tamper boundary. This is a local review candidate, not a release or
deployment approval.

```text
PROJECT=Drex Agent Firewall RT-03 Audit-Store Isolation
BASE_HEAD=7d06afa873e4c372294879672881a9d4124cc33d
FINAL_HEAD=the local commit containing this report; retrieve with git rev-parse HEAD
WORKTREE=/home/colton-mcclain/drex-worktrees/firewall-rt03-audit-store-20261002
BRANCH=security/rt03-audit-store-isolation-20261002
GIT_STATUS=verified after local commit in final response

RT03_BEFORE=CONFIRMED_UNRESOLVED; native workspace tamper and silent rollback reproduced
RT03_AFTER=BUBBLEWRAP_PREVENTION_DEMONSTRATED; GLOBAL_CLOSURE_UNPROVEN
AUDIT_DB_TAMPERABLE=YES (standalone/unrestricted host execution); NO within tested managed Bubblewrap boundary
AUDIT_TAMPER_DETECTABLE=NO independent tamper/rollback detection
RT03_STATUS=UNRESOLVED
FWA_U3_AUDIT_DB_ISOLATION=UNRESOLVED

SELECTED_ARCHITECTURE=host-private SQLite + per-session host-side Unix-socket writer + immutable event snapshots
AUTHORITATIVE_AUDIT_LOCATION=trusted host HOME/.local/state/drex-agent-firewall/audit/history.db by default; trusted host constructor may select a private operator path
AGENT_CAN_READ_DB=NO within tested managed Bubblewrap
AGENT_CAN_WRITE_DB=NO within tested managed Bubblewrap
AGENT_CAN_DELETE_DB=NO within tested managed Bubblewrap
AGENT_CAN_REPLACE_DB=NO within tested managed Bubblewrap
AGENT_CAN_ACCESS_WAL=NO within tested managed Bubblewrap
AGENT_CAN_ACCESS_SHM=NO within tested managed Bubblewrap

PERSISTENCE_FAILURE_FAILS_CLOSED=YES before protected execution; result-write failure cannot undo a completed effect
WORKSPACE_CAN_REDIRECT_AUDIT_PATH=NO for the host writer
ENV_CAN_REDIRECT_AUDIT_PATH=NO for guest-controlled environment
MCP_CONFIG_CAN_REDIRECT_AUDIT_PATH=NO for authoritative history; an alternate guest MCP can write a non-authoritative decoy or omit mediation

RT03_FIX_DEPENDS_ON_MCP_MEDIATION=NO
RT02_STATUS=UNRESOLVED
RT01_STATUS=UNRESOLVED

FOCUSED_TESTS_PASSED=23
FULL_PYTEST_PASSED=115
FULL_PYTEST_FAILED=0
STANDARD_BENCHMARK=105 scenarios / 100.0% / 0 observed high-impact false allows
REDTEAM_BENCHMARK=220 scenarios / 99.55% / 0 observed high-impact false allows
HOSTILE_BYPASS_BENCHMARK=186 scenarios / 98.39% / 0 observed high-impact false allows
ISOLATION_BENCHMARK=100 scenarios / 98.0% / 0 observed high-impact false allows

REAL_AGENT_CANARY_RUN=NOT_RUN
REAL_AGENT_TASK_COMPLETED=NOT_RUN
AUDIT_TAMPER_ATTEMPTS=26 native filesystem cases; additional focused IPC, redirection, persistence and lifecycle cases
AUDIT_TAMPER_SUCCESSES=0 in final managed Bubblewrap filesystem matrix
AUDIT_HISTORY_INTACT=YES in those cases

NEW_REGRESSIONS=NONE_OBSERVED in tested runtime; intentional default path change, NoIsolation rejection and per-session payload cap
NEW_SECURITY_RISKS=bounded forged-event/budget denial remains possible; trust/ABI of read-only dependency packages required; no global disk quota across trusted host-created sessions
DOCUMENTATION_UPDATED=YES
CLAIMS_REVIEWED=YES; removed append-only-WAL, universal mediation, closed-host-access and stale test-count claims

PUSH_PERFORMED=NO
TAG_CREATED=NO
DEPLOY_PERFORMED=NO
RT03_FIX_READY_FOR_REVIEW=YES, scoped local candidate
DEPLOY_READY=NO
DEPLOY_BLOCKERS=OCI runtime/image/IPC proof; credential-free real-agent canary unavailable; RT01/RT02 unresolved for authoritative deployment
NEXT_RED_TEAM_PRIORITY=finish OCI RT03 native validation and a safely supported real-agent canary, then RT02 mandatory mediation
```

## Boundary measurements and lineage

Production checkout was clean at the exact expected head and `v0.1.1`; all edits
occurred in the named new worktree. [Design](DESIGN.md) records the initial trust
boundary and A/B/C/D evaluation before implementation. [Boundary data](boundary.json)
records disposable ownership, permissions, sidecars and native guest visibility.

Before: guest MCP `python3 -m drex_agent_firewall.mcp.server` opens
`/workspace/.drex_firewall.db` through `ActionRepository -> init_db ->
sqlite3.connect`. Host manager separately opens its configured DB. Fixture
DB/WAL/SHM were UID 1000, mode 0644, workspace parent 0775. Native execution can
operate independently of MCP and modify that same mounted inode/path.

After: host SandboxManager Python process opens SQLite; a per-session serial
writer thread handles append requests. DB/WAL/SHM are UID 1000, mode 0600,
parent 0700. Native guest UID is also 1000, proving that cosmetic same-UID chmod
is insufficient. The real mount/PID namespaces exclude the store and sidecars;
the attacker was given the exact host pathname and still could not access it.
Only a mode-0600 socket inode from a separate mode-0700 IPC directory is mounted
read-only. Store ancestors/descendants, aliases and code/dependency mount overlap
are rejected. Session identity is bound by the host writer, overriding guest
session/agent claims. Duplicate session IDs are refused.

Managed chain: agent MCP tool -> guest normalizer/policy -> adapter -> synchronous
append capability -> host SQLite immutable event snapshot and compatible reporting
projection -> success acknowledgement -> protected effect -> one result append.
Native shell/Python attacks against DB/WAL/SHM require no policy evaluation and
still fail at the namespace boundary. An alternative MCP config cannot select the
host writer destination, but may omit mediation or create a guest decoy (RT-02).

The authoritative `audit_events` table retains decision/result snapshots. Its IPC
surface has no query, arbitrary SQL, deletion, overwrite, rollback, session-state,
or outcome-edit method. Duplicate decision/result appends are rejected. Trusted
host reporting/projection rows remain mutable through their existing API. Event
and projection commits are separate: if a projection write fails, the immutable
snapshot remains, the client receives failure, and a protected decision does not
receive permission to execute. No success is converted into a warning.

## Prevention, detection, and limits

This implements prevention within the tested mount boundary, not independent
cryptographic tamper detection. A trusted host owner/root can replace or roll
back the entire DB, including event snapshots. No hash chain, secret seal or
independent tail anchor exists. Ordinary SQLite corruption errors are reported
as errors in the matrix; they are not reliable tamper attribution. Closed valid
snapshot rollback was silent before; the guest cannot reach its replacement
destination after. Do not infer host-owner rollback detection from that result.

NoIsolation is rejected by SandboxManager before a session launches. A focused
raw-backend test still demonstrates that an unrestricted same-UID native process
can unlink a 0600 DB under a 0700 host-owned parent. Standalone MCP/SDK/API/demo
stores remain operator/config-selected, with no automatic migration of historical
workspace data and no global tamper-proof claim.

Docker/Podman command construction mounts only the session socket and maps the
host UID (Podman keep-id). Neither CLI exists on this host, so no real OCI native
matrix ran. In particular, the stock OCI image does not install the Firewall;
its package/runtime ABI and usable IPC require further validation. MicroVM is an
unimplemented driver. Explicit backend limits keep global RT-03 unresolved.

The guest can submit false *new* events, consume its bounded event budget, or
skip MCP. Possession of the append socket does not attest event truth or complete
coverage. Kernel/runtime compromise, trusted-host attacks and arbitrary host
services are outside the demonstrated filesystem guarantee. No secret-bearing
host directory was added to mounts: Bubblewrap mounts only explicit dependency
package directories/files, not site-packages or host home parents.

The available real-agent launch path stages actual Codex/Claude credentials and
needs provider egress. That conflicts with the task's no-real-secrets constraint;
the canary was NOT_RUN. Synthetic real-MCP coding writes completed and legitimate
files survived native tamper attempts, but these are not a model-agent canary.

## RT-01 resource interaction

One serial handler, listen backlog two, 128 KiB frames, a three-second absolute
frame deadline, and a durable 16 MiB payload cap per host-created session bound
IPC storage/buffering. A focused slow-sender test proves repeated partial bytes
cannot extend the deadline. No background event queue or TCP service was added.
SQLite has bounded busy waits and FULL synchronous persistence. Tests cover
read-only SQLite, missing IPC, oversized requests, exhausted payload budget,
and SQLITE_FULL via a disposable max-page-count limit, without filling host disk.

General sandbox CPU/memory/fd quotas and global disk growth across trusted sessions
are still unresolved. Bounded denial of mediated progress by a hostile socket
holder remains possible; protected effects fail closed rather than silently omit
decision persistence. A result-write error after an effect is surfaced but cannot
undo that effect. Cleanup retains authoritative history and removes session IPC
and config resources. Host API/CLI inspection and MCP session correlation passed.

## Validation and reproducibility

One pytest process at a time; no xdist or `-n`. Focused changes were debugged first.
Existing suites ran sequentially: storage/audit 12 passed, sandbox 18 passed, MCP
5 passed, API/CLI 14 passed. Full project verification initially passed 114 tests;
final review then added the absolute-deadline regression and the final full run
passed 115. No broad suite was rerun without a relevant code change. Each replay
benchmark ran once. All runs used an empty HOME, explicit source PYTHONPATH,
disabled live Drex key and disposable resources. A pre-existing Starlette/httpx
deprecation warning remained; no failure was weakened into a warning.

Evidence: [focused tests](focused-tests.txt), [full pytest](full-pytest.txt),
[storage](storage-tests.txt), [sandbox](sandbox-tests.txt), [MCP](mcp-tests.txt),
[API/CLI](api-cli-tests.txt), [benchmark summary](benchmark-summary.txt).
All benchmark results are deterministic replay measurements, not universal
containment proof. [Before sandbox](before-sandbox.json) used the exact release
source via PYTHONPATH; [after sandbox](after-sandbox.json) used this candidate.
[Persistence suppression/session reuse](suppression-before.json) separately confirms release error behavior and silent empty-history acceptance. [Initial native-owner attacks](before.json) separately measured the shared-UID
filesystem behavior before edits. Attack scripts only allocate local temporary
workspaces and databases and never open production stores.

Run `hostile.py before` with the release source on PYTHONPATH and `hostile.py
after` with this worktree source. `boundary.py` measures fixture permissions and
visibility. `benchmarks.py` sequentially runs the four replay datasets without an
audit DB. `tests/test_rt03_audit_isolation.py` exercises real MCP, native Bubblewrap,
IPC, failure, lifecycle and authorized inspection paths. Real namespace capability
is required; mock argument generation is insufficient.

## RT03_ATTACK_MATRIX

The generated matrix below distinguishes a successful native mutation from actual
history loss: live WAL recovery preserved some fixtures despite a successful
mutation. `detected` means SQLite surfaced an error before or after reopening,
not an independent tamper alarm. Native filesystem actions are not MCP-mediated,
so their fail-closed column is N/A; the protected persistence-failure tests are
reported separately.

| Attack | Before | After | Blocked after | Detected before / after | Fail-closed |
|---|---|---|---|---|---|
| unlink_live | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| zero_truncate_live | mutation accepted; fixture survived | history intact | YES | NO / NO | N/A (filesystem prevention) |
| partial_truncate_live | mutation accepted; fixture survived | history intact | YES | NO / NO | N/A (filesystem prevention) |
| unlink_recreate_live | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| rename_empty_live | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| valid_empty_live | mutation accepted; fixture survived | history intact | YES | NO / NO | N/A (filesystem prevention) |
| rollback_live | mutation accepted; fixture survived | history intact | YES | NO / NO | N/A (filesystem prevention) |
| delete_rows_live | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| update_rows_live | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| update_decision_result_live | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| delete_block_live | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| wal_delete_live | mutation accepted; fixture survived | history intact | YES | NO / NO | N/A (filesystem prevention) |
| wal_truncate_live | history changed | history intact | YES | YES / NO | N/A (filesystem prevention) |
| wal_replace_live | mutation accepted; fixture survived | history intact | YES | NO / NO | N/A (filesystem prevention) |
| shm_remove_live | mutation accepted; fixture survived | history intact | YES | NO / NO | N/A (filesystem prevention) |
| db_symlink_live | history changed | history intact | YES | YES / NO | N/A (filesystem prevention) |
| parent_symlink_live | native denied | history intact | YES | NO / NO | N/A (filesystem prevention) |
| directory_replace_live | history changed | history intact | YES | YES / NO | N/A (filesystem prevention) |
| unwritable_live | history changed | history intact | YES | YES / NO | N/A (filesystem prevention) |
| rename_race_live | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| inode_replace_live | mutation accepted; fixture survived | history intact | YES | NO / NO | N/A (filesystem prevention) |
| zero_truncate_closed | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| partial_truncate_closed | history changed | history intact | YES | YES / NO | N/A (filesystem prevention) |
| valid_empty_closed | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| rollback_closed | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| inode_replace_closed | history changed | history intact | YES | NO / NO | N/A (filesystem prevention) |
| protected decision persistence failure | release read-only fixture blocked effect with NameError | read-only, SQLITE_FULL, missing IPC and payload-budget failures prevent effect | YES (effect) | YES (failure surfaced) | YES |
| session reuse after valid empty replacement | history lost silently; protected effect allowed | native replacement denied; historical record preserved on reopen; duplicate managed session ID rejected | YES | no independent rollback detector | N/A (replacement prevented) |
| IPC SQL / committed-result overwrite | no independent append boundary | requests rejected; snapshots and reporting rows intact | YES | YES (request rejected) | YES (no edit) |
| slow partial IPC frame | no broker in release | absolute deadline rejects frame; no event persisted | YES | YES (timeout) | YES |

## FILES_CHANGED

| Path | Purpose |
|---|---|
| `CHANGELOG.md` | Correct limitations, measured validation count and audit scope |
| `README.md` | Correct limitations, measured validation count and audit scope |
| `docs/isolation-threat-model.md` | Correct limitations, measured validation count and audit scope |
| `docs/sandbox.md` | Correct limitations, measured validation count and audit scope |
| `docs/threat-model.md` | Correct limitations, measured validation count and audit scope |
| `security/rt03/DESIGN.md` | Pre-implementation trust boundary, security property and design options |
| `security/rt03/REPORT.md` | Final scoped evidence, limitations and review status |
| `security/rt03/after-sandbox.json` | Retained bounded disposable measurement or validation output |
| `security/rt03/api-cli-tests.txt` | Retained bounded disposable measurement or validation output |
| `security/rt03/attack-matrix.md` | Complete native before/after matrix |
| `security/rt03/attacks.py` | Disposable native filesystem attack definitions |
| `security/rt03/before-sandbox.json` | Retained bounded disposable measurement or validation output |
| `security/rt03/before.json` | Retained bounded disposable measurement or validation output |
| `security/rt03/benchmark-summary.txt` | Retained bounded disposable measurement or validation output |
| `security/rt03/benchmarks.py` | Four sequential credential-free replay benchmark runs |
| `security/rt03/boundary.json` | Retained bounded disposable measurement or validation output |
| `security/rt03/boundary.py` | Measure ownership, permissions, guest visibility and retained history |
| `security/rt03/final-focused-checks.txt` | Retained bounded disposable measurement or validation output |
| `security/rt03/focused-tests.txt` | Retained bounded disposable measurement or validation output |
| `security/rt03/full-pytest.txt` | Retained bounded disposable measurement or validation output |
| `security/rt03/hostile-bypass-benchmark.json` | Retained bounded disposable measurement or validation output |
| `security/rt03/hostile.py` | Real Bubblewrap before/after matrix including live/closed writers |
| `security/rt03/isolation-benchmark.json` | Retained bounded disposable measurement or validation output |
| `security/rt03/mcp-tests.txt` | Retained bounded disposable measurement or validation output |
| `security/rt03/no-isolation-test.txt` | Retained bounded disposable measurement or validation output |
| `security/rt03/redteam-benchmark.json` | Retained bounded disposable measurement or validation output |
| `security/rt03/sandbox-tests.txt` | Retained bounded disposable measurement or validation output |
| `security/rt03/sqlite-full-test.txt` | Retained bounded disposable measurement or validation output |
| `security/rt03/standard-benchmark.json` | Retained bounded disposable measurement or validation output |
| `security/rt03/storage-tests.txt` | Retained bounded disposable measurement or validation output |
| `security/rt03/suppression-before.json` | Retained bounded disposable measurement or validation output |
| `security/rt03/suppression.py` | Disposable release persistence-error and new-session reproduction |
| `src/drex_agent_firewall/adapters/base.py` | Repair missing fail-closed decision enum import |
| `src/drex_agent_firewall/cli/sandbox_cli.py` | Trusted host database selection for existing list/inspect commands |
| `src/drex_agent_firewall/mcp/server.py` | Host-audit mode with fixed socket and no local DB fallback |
| `src/drex_agent_firewall/persistence/audit_broker.py` | Private path/mount guards; bounded serial append writer and guest client |
| `src/drex_agent_firewall/persistence/database.py` | Immutable event schema and FULL SQLite persistence |
| `src/drex_agent_firewall/sandbox/bubblewrap.py` | Guest dependency PYTHONPATH |
| `src/drex_agent_firewall/sandbox/container.py` | Host UID mapping for private IPC; runtime verification remains pending |
| `src/drex_agent_firewall/sandbox/manager.py` | Host store ownership, per-session socket, mount validation, fail-closed NoIsolation and cleanup |
| `src/drex_agent_firewall/sandbox/python_runtime.py` | Read-only explicit dependency mounts without host parent exposure |
| `tests/test_audit_manager.py` | Use real private host repository in capture test and close IPC |
| `tests/test_rt03_audit_isolation.py` | 23 real namespace/MCP/native/IPC/failure/lifecycle regressions |

## COMMITS

One local commit: `security: isolate managed audit history behind host writer`.
The containing commit hash is reported in the final response; no push, tag or
deployment was performed.
