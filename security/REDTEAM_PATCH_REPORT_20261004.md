# Drex-Agent-Firewall v0.1.3 (hardening/v0.1.3) — Red-Team Audit & Patch Report

- **Date:** 2026-10-04
- **Target:** `<hardening-worktree>` @ `7a153c2`
- **Auditor:** red-team subagent (authorized local audit, safe/reversible PoCs only, all artifacts under `/tmp/drex-rt-poc/`)
- **Test suite status:** `191 passed, 0 failed` (55s) **only when the worktree src is pinned** (`PYTHONPATH=<worktree>/src python3 -m pytest tests -q`). A bare `pytest` run imports an older editable install and reports `30 failed, 161 passed` (see F-08).

## Summary table (by severity)

| # | Severity | Finding | Affected file:line |
|---|----------|---------|--------------------|
| F-01 | CRITICAL | Command allowlist/prefix smuggling via shell metacharacters | `src/drex_agent_firewall/constraints/enforcer.py:34-48` |
| F-02 | CRITICAL | Env-var injection (LD_PRELOAD / PYTHONPATH / BASH_ENV …) bypasses command constraints → native code exec | `src/drex_agent_firewall/security/environment.py:8-74`, `src/drex_agent_firewall/adapters/shell_adapter.py:133-149` |
| F-03 | HIGH | Host-path timeout kills only the direct child; daemonized descendants outlive the sandbox and session destroy | `src/drex_agent_firewall/utils/process_io.py:82-99`, `src/drex_agent_firewall/sandbox/no_isolation.py:99-123` |
| F-04 | HIGH | `bounded_communicate` blocks until every inherited pipe writer exits → firewall DoS / unbounded runtime | `src/drex_agent_firewall/utils/process_io.py:38-99` |
| F-05 | MEDIUM | Fail-open default: provider failure → READ actions silently ALLOWed | `src/drex_agent_firewall/schemas/config.py:39`, `src/drex_agent_firewall/policy/engine.py:69-85` |
| F-06 | MEDIUM | SSRF via DNS on shell egress: validator is string-only, no resolution/pinning | `src/drex_agent_firewall/security/network_validator.py:92-177`, `src/drex_agent_firewall/policy/deterministic_rules.py:263-282` |
| F-07 | MEDIUM | Unauthenticated HTTP API exposes full audit trail (+ enforce) | `src/drex_agent_firewall/server/app.py:48-360`, `src/drex_agent_firewall/cli/main.py:406-422` |
| F-08 | MEDIUM | Editable install of older checkout shadows worktree code (tests/CI run stale package) | environment (`~/.local/lib/python3.12/site-packages/__editable__.drex_agent_firewall-0.1.0.pth`) |
| F-09 | LOW | Audit log forging: control characters stored verbatim in `arguments_json`/`reason` | `src/drex_agent_firewall/persistence/repository.py:58-100` |
| F-10 | LOW | `PathValidator` treats `file://` URIs as path components instead of rejecting | `src/drex_agent_firewall/security/path_validator.py:29-54` |
| F-11 | LOW | Default `allowed_roots` includes `"."` (firewall process cwd) — over-broad by default | `src/drex_agent_firewall/schemas/config.py:54` |

**Verified-strong controls (no action needed):** Bubblewrap backend withstood full end-to-end attack (F-verify §7): synthetic `/etc/passwd`, host home unreachable, PID-ns init-death reaps daemons, fork bomb capped by `pids.max`, 400 MB alloc SIGKILLed by cgroup `memory.max`, `RLIMIT_NOFILE/FSIZE` enforced, netns isolation confirmed, timeout kills whole cgroup. Filesystem adapter blocked `..`, `%2e%2e`, NFKC full-width dots, symlink escape, hardlink aliases, `/proc` paths, rename-dest traversal, blocked subdirs (§6). HTTP adapter pins DNS answers and rejects non-global IPs, redirects disabled (§5.1). SQLite layer is fully parameterized (no SQL injection found). Egress broker validates host before DNS, pins to global IPs, CONNECT :443 only.

PoC scripts (runnable, self-contained): `/tmp/drex-rt-poc/poc1_command_constraints.py`, `poc2_process_escape.py`, `poc3_policy_audit.py`, `poc4_bwrap.py`, `poc5_fs_network.py`. All insert the worktree `src` at `sys.path[0]`.

---

## F-01 — CRITICAL — Command allowlist/prefix smuggling

**Affected:** `src/drex_agent_firewall/constraints/enforcer.py:34-48` (`ConstraintEnforcer.verify_command`); consumed by `adapters/shell_adapter.py:108`.

**Verified PoC:**
```
$ python3 /tmp/drex-rt-poc/poc1_command_constraints.py
=== 1a ===  BYPASS CONFIRMED: 'ls .; cat /etc/hostname' accepted with allowed_commands=['ls']
=== 1b ===  BYPASS CONFIRMED: 'git config ...; id' accepted with command_prefix='git'
=== 1c (end-to-end ShellAdapter, allowed_commands=['ls']) ===
  allowed=True exit=0 stdout='SMUGGLED\n'
  smuggled.txt exists: True        # file created OUTSIDE the allowlist intent
```
The check is `cmd_clean == ac or cmd_clean.startswith(ac + " ")` (and `startswith(command_prefix)`). Any command that *begins* with an allowed token passes; everything after the first space is attacker-controlled shell. `ls .; rm …`, `git status && …`, `python3 -c … ; …` all pass.

**Root cause:** string-prefix comparison on a shell command line; no tokenization, no metacharacter rejection, `shell=True` in `ShellAdapter` (`adapters/shell_adapter.py:141-149`).

**Fix recommendation:**
1. When `allowed_commands`/`command_prefix` are active, **refuse shell syntax entirely**: reject any of `; | & > < $ ` \n ( ) { }` *unless* the constraint explicitly allows shell interpretation; or
2. Parse with `shlex.split` and require exact `argv[0]` match (resolved via `shutil.which`, compared by realpath) against the allowlist — never a prefix of the raw string; or
3. Best: when constraints are active, execute `argv` directly (`shell=False`); keep `shell=True` only when no command constraints are set and document that a constrained shell command is not enforceable.
Add regression tests: `["ls"]` must reject `ls .; id`, `ls$(id)`, `` ls`id` ``, `ls\nid`, `ls || id`, `git; id` with prefix `git`.

---

## F-02 — CRITICAL — Environment-variable injection defeats command constraints (native code exec)

**Affected:** `src/drex_agent_firewall/security/environment.py:8-74` (`filter_environment` blocks only credential/proxy names), `src/drex_agent_firewall/adapters/shell_adapter.py:134-136` (`exec_env = filter_environment(os.environ); exec_env.update(filter_environment(env))`), `policy/deterministic_rules.py:89-101` (env inspection covers only `HTTP(S)_PROXY`/`ALL_PROXY`).

**Verified PoC** (`/tmp/drex-rt-poc/poc1_command_constraints.py`, plus LD_PRELOAD run):
```
=== 1d (allowed_commands=['python3'], command 'python3 -c "print(1)"', env={'PYTHONPATH': '/tmp/drex-rt-poc/evil'}) ===
  ENV_INJECTION_RAN.txt exists: True          # evil/sitecustomize.py executed
=== 1e ===  survived filter: {'LD_PRELOAD': '/tmp/evil.so', 'PYTHONPATH': '/tmp/evil',
            'BASH_ENV': '/tmp/evil.sh', 'DYLD_INSERT_LIBRARIES': ..., 'GIT_SSH_COMMAND': 'evil'}
=== gcc-built .so, allowed_commands=['ls'], command 'ls', env={'LD_PRELOAD': evil.so} ===
  LD_PRELOAD_RAN.txt exists: True  ("native code executed via LD_PRELOAD")
```
Loader/interpreter control variables (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `DYLD_INSERT_LIBRARIES`, `PYTHONPATH`, `PYTHONHOME`, `BASH_ENV`, `ENV`, `PS4`, `PROMPT_COMMAND`, `SHELLOPTS`, `BASHOPTS`, `CDPATH`, `IFS`, `GIT_SSH_COMMAND`, `GIT_TEMPLATE_DIR`, `GIT_CONFIG_*`, `PERL5LIB`, `RUBYLIB`, `NODE_OPTIONS`, …) pass straight through both caller-supplied `env` **and the host `os.environ`** into every firewalled subprocess. Under any command constraint this is arbitrary code execution with the firewall's own host privileges; without constraints it also silently leaks the host environment into "guarded" runs.

**Root cause:** a denylist designed for credential hygiene is being used as an execution-safety boundary; env var *names* are passed to the policy as context (`shell_adapter.py:64-76`) but never enforced.

**Fix recommendation:**
1. Switch `ShellAdapter` to an **env allowlist** (mirror `BubblewrapBackend._sanitize_environment`, `sandbox/bubblewrap.py:338-376`): start from a minimal known-safe set, add operator-configured keys only.
2. Additionally strip (defense in depth) `LD_*`, `DYLD_*`, `PYTHONPATH`, `PYTHONHOME`, `BASH_ENV`, `ENV`, `PS4`, `PROMPT_COMMAND`, `SHELLOPTS`, `BASHOPTS`, `CDPATH`, `IFS`, `GIT_SSH_COMMAND`, `GIT_TEMPLATE_DIR`, `PERL5LIB`, `RUBYLIB`, `NODE_OPTIONS` in `filter_environment`.
3. Treat `env` as policy input: evaluate env *names* through the deterministic engine (block the above by hard rule, like the existing proxy-var check at `deterministic_rules.py:89-101`).
4. Regression tests: constrained `python3` with hostile `PYTHONPATH` must not execute `sitecustomize`; `ls` with `LD_PRELOAD` must fail.

---

## F-03 — HIGH — Host-path process escape: timeout/session kill only reaches the direct child

**Affected:** `src/drex_agent_firewall/utils/process_io.py:82-99` (`process.kill()` only; no process group), `src/drex_agent_firewall/adapters/shell_adapter.py:141-149` (`shell=True`, no `start_new_session`, no cgroup), `src/drex_agent_firewall/sandbox/no_isolation.py:99-123` (raw `Popen`).

**Verified PoC** (`/tmp/drex-rt-poc/poc2_process_escape.py`):
```
=== 2c: NoIsolationBackend daemon outlives session destroy ===
exec returned after 0s: True
daemon alive: ['2624800']
daemon alive AFTER destroy: ['2624800']  <-- no tracking/kill of descendants
daemon alive after MANUAL pkill: []
```
A guest command `bash -c '(setsid sleep 600 </dev/null >/dev/null 2>&1 &)'` detaches a daemon that (a) is never killed on timeout (`bounded_communicate` SIGKILLs only the direct child), (b) survives `stop()`/`destroy()` (only `session_data["pids"]` — direct Popen children — are signaled, and only with `SIGKILL` to already-dead pids), (c) keeps running on the host unbounded by any rlimit/cgroup. Same applies to `ShellAdapter` on hosts (the firewall's default execution path when no sandbox backend is selected).

**Root cause:** no process-group/session creation (`start_new_session=True`) and no `os.killpg` on timeout; no descendant tracking outside the bubblewrap cgroup/pid-ns.

**Fix recommendation:**
1. `subprocess.Popen(..., start_new_session=True)` in `ShellAdapter` and `NoIsolationBackend`; on timeout/termination `os.killpg(proc.pid, SIGKILL)`.
2. For `NoIsolationBackend`, reuse `ResourceGuard` (cgroup v2) exactly like the bubblewrap path, or set `prctl(PR_SET_CHILD_SUBREAPER)` + reap/kill tree; if neither is available, **fail closed** the same way `factory.py:75-78` does for missing backends.
3. In `bounded_communicate`, after killing, briefly reap and verify no child of the dead process still holds resources (best-effort `killpg`).

---

## F-04 — HIGH — `bounded_communicate` blocks until every pipe writer exits (firewall DoS / unbounded runtime)

**Affected:** `src/drex_agent_firewall/utils/process_io.py:38-99`. The drain threads call `stream.read()` on `BufferedReader`s; on timeout the main thread does `reader.join(timeout=1.0)` (gives up) and then `stream.close()`, but **`BufferedReader.close()` blocks acquiring the lock held by the stuck reader thread** — which only returns when the pipe hits EOF, i.e. when *all* writers (including orphaned grandchildren that inherited stdout/stderr) exit.

**Verified PoC** (`/tmp/drex-rt-poc/poc2_process_escape.py`, and minimal repro `/tmp/drex-rt-poc/mini.py`):
```
$ python3 -u mini.py        # subprocess "sh -c '(sleep 25 &)'; sleep 8", timeout=3
returned after 25.0 timed_out: True        <-- returned after 25s, not 3s
=== 2a+2b (full adapter, 3s timeout, daemon sleep 600) ===
t=6s (timeout was 3s): execute() returned? False     <-- still blocked
t=8s: after killing orphan, execute() returned: True
```
A guest that backgrounds a long-lived (or never-ending) process makes `execute()`/`exec()` hang for the daemon's whole lifetime, tying up the agent loop; combined with F-03 the daemon is also unkillable. (The bubblewrap path self-heals via pid-ns init-death + `--die-with-parent`, so the impact is on host execution paths.)

**Root cause:** closing user-space buffered streams from another thread while a reader is blocked on a pipe shared with untracked processes.

**Fix recommendation:**
1. Kill the whole process group first (F-03) so pipe writers die, then join.
2. Don't close buffered streams while readers may be blocked: use raw `os.read` on the pipe fds (no `BufferedReader` lock), and after `wait()`, `os.close(fd)` directly / `shutdown(SHUT_RDWR)` on a `socketpair` transport.
3. Add a hard post-timeout bound (e.g. return after `wait()` + short grace, abandoning pipes with `os.close`).

---

## F-05 — MEDIUM — Fail-open default: provider failure → READ actions silently ALLOWed

**Affected:** `src/drex_agent_firewall/schemas/config.py:39` (`FailDisposition.READ = FinalDecision.ALLOW`), applied in `src/drex_agent_firewall/policy/engine.py:69-85` / `policy/fail_disposition.py:16-34`.

**Verified PoC:**
```
provider raised; envelope read_only=True -> decision=ALLOW allowed=True
  reason: [PROVIDER_FAILURE_FALLBACK]: ConnectionError: drex api unreachable -> Fail disposition applied: ALLOW
READ(shell) provider-failure -> ALLOW allowed=True
```
Any READ-classified action not caught by the deterministic hard rules proceeds unlogged-by-Drex and allowed when the provider errors/times out. Hard rules still run, but everything they don't pattern-match (new tools, novel encodings, allowed-root reads of sensitive-but-unlisted files) fails open. This is a shipped *default*, not an operator opt-in.

**Fix recommendation:** default `READ` to `ESCALATE` (fail-closed) and require operators to explicitly set fail-open in config; call it out in `SECURITY.md`. If availability demands READ fail-open, at least restrict it to envelopes whose tool+operation+path pattern is on an explicit read allowlist.

---

## F-06 — MEDIUM — SSRF via DNS on shell egress (validator never resolves)

**Affected:** `src/drex_agent_firewall/security/network_validator.py:92-177` (string-only checks; no `getaddrinfo` anywhere in the module), `src/drex_agent_firewall/policy/deterministic_rules.py:263-282` (embedded-URL check delegates to the same string validator; the literal-IP check at line 275 only matches IP *literals* in the command text).

**Verified PoC** (`/tmp/drex-rt-poc/poc5_fs_network.py` + engine check):
```
ALLOWED  http://127.0.0.1.nip.io
ALLOWED  http://169.254.169.254.nip.io          (validator output)
=== 5h: 169.254.169.254.nip.io -> ('169.254.169.254', 80)   (local resolver proof)
engine: 'curl -s https://evil-ssrf-example.com/'  ->  True ALLOW rule=None
```
Literal non-global IPs are well defended (decimal/hex/octal/IPv4-mapped all blocked — verified), and the HTTP adapter re-resolves and pins DNS (`GuardedHTTPTransport`), but the **shell path does not**: a hostname whose A/AAAA record points at 169.254.169.254, 127.0.0.1, or RFC1918 space passes all hard rules, and the egress firewall has no resolution step. On cloud hosts this yields metadata-service SSRF; everywhere it yields internal-service SSRF via `curl`/`wget`/`python`.

**Fix recommendation:**
1. Enforce egress through the existing controlled-egress broker for sandboxed agents; for the host shell path, either forbid network tools by default in policy packs, or
2. add a connect-time guard: for shell executions that passed an embedded-URL check, resolve the host and verify `ip.is_global` before the process starts (pre-exec resolution + pinned allowlist passed to the child via a per-run env/flag), or LD-free wrapper; and
3. log resolved IPs for any allowed egress.

---

## F-07 — MEDIUM — Unauthenticated HTTP API exposes full audit trail

**Affected:** `src/drex_agent_firewall/server/app.py:48-360` (no auth dependency on any route), `src/drex_agent_firewall/cli/main.py:406-422` (`--host` option, default `127.0.0.1`).

**Static-only.** All endpoints — `/actions`, `/traces`, `/calibration`, `/sandbox-sessions`, `/enforce` — are unauthenticated. Default bind is loopback, but a single `--host 0.0.0.0` (or a reverse-proxy misconfig) exposes the complete audit database contents (full command arguments, paths, URLs, decisions, sessions) to the network and lets remote callers probe/enforce policy.

**Fix recommendation:** require a bearer token (env `DREX_API_TOKEN`, constant-time compare) on all routes except `/healthz`; refuse or loudly warn when binding non-loopback without a token; consider making `/actions`+`/traces` read admin-scoped.

---

## F-08 — MEDIUM — Stale editable install shadows the worktree (tests/CI run old code)

**Affected:** environment — `~/.local/lib/python3.12/site-packages/__editable__.drex_agent_firewall-0.1.0.pth` → `<older-editable-install>/src` (v0.1.0, **lacks `security/safe_filesystem.py` and `sandbox/resource_guard.py`**).

**Verified:** bare `pytest` in the worktree → `30 failed, 161 passed` (every failure is a v013 hardening test importing the old package); with `PYTHONPATH=<worktree>/src` → `191 passed, 0 failed`. Anyone running the suite without pinning gets misleading failures — and worse, any *app* launched from an environment with that `.pth` silently runs the unhardened package while the hardening branch is believed deployed.

**Fix recommendation:** `pip uninstall drex-agent-firewall` (or install the worktree editable) on dev/CI hosts; add `python -c "import drex_agent_firewall, pathlib; assert 'firewall-v013' in pathlib.Path(drex_agent_firewall.__file__).parents[2].as_posix()"` (or a version check) to CI/test bootstrap; consider renaming the dist or using `pip install -e .` inside the worktree.

---

## F-09 — LOW — Audit log forging via control characters

**Affected:** `src/drex_agent_firewall/persistence/repository.py:58-100` (`arguments_json`, `reason` stored verbatim); returned raw by `get_action`/`get_trace` (`repository.py:141-168`).

**Verified PoC** (poc3 §3f): a command `echo hi\n[FAKE_AUDIT] decision=ALLOW rule=admin_override action_id=admin-1` is stored and returned verbatim, including a forged admin-override line. SQLite is parameterized everywhere (no SQLi found), and `SecretRedactor` scrubs secret *values*, but nothing prevents newline/ANSI injection that forges lines when the audit trail is rendered as text.

**Fix recommendation:** reject (at envelope validation) or JSON-escape control chars (`\n`, `\r`, ESC) in agent-controlled strings before persistence; if log-chain integrity matters, add a hash chain (each row stores HMAC of prev hash + payload) keyed by a host secret.

---

## F-10 — LOW — `PathValidator` treats `file://` URIs as path components

**Affected:** `src/drex_agent_firewall/security/path_validator.py:29-54`.

**Verified PoC** (poc3 §3c): `validate_path("file:///etc/passwd", base_dir=ws)` → ALLOWED, canonicalized to `<ws>/file:/etc/passwd` (the URI becomes a literal relative path). The deterministic rules strip `file://` before path checks (`deterministic_rules.py:396-397`), so the filesystem tool is covered, but any consumer that calls `validate_path` directly (custom adapters, future tools, `ConstraintEnforcer.verify_path` with `cwd`) gets inconsistent URI handling.

**Fix recommendation:** in `normalize_input`, reject strings matching `^[a-zA-Z][a-zA-Z0-9+.-]*://` (return unsafe / raise), so URI scheme handling lives in one place.

---

## F-11 — LOW — Default `allowed_roots` includes `"."` (firewall cwd)

**Affected:** `src/drex_agent_firewall/schemas/config.py:54` (`allowed_roots=["/workspace", "."]`).

**Static-only.** `"."` expands to the firewall *process* cwd. If the firewall is launched from `$HOME` or a checkout containing `.env`/credentials, the entire tree becomes an allowed root (only the short `blocked_paths` list stands in the way — e.g. it blocks `.git/config` but not `.git/hooks`, `~/.bashrc`, cloud creds in other locations, etc.).

**Fix recommendation:** require explicit `allowed_roots` before WRITE/DELETE decisions (fail-closed when unset); remove `"."` from defaults; expand `blocked_paths` defaults (`.git/hooks`, `~/.config`, `~/.aws`, `~/.kube`, shell rc files).

---

## 4. Attack coverage notes (attempted → result)

| Attempt | Result |
|---|---|
| `..`, `%2e%2e`, `%2f`, NFKC full-width dots, absolute traversal | **Blocked** (hard rule + `PathValidator`) |
| Symlink swap of parent between validate and open | **Blocked** — `parent_fd` walks with `O_NOFOLLOW`; repo's own race tests pass on worktree code |
| Hardlink alias write/read | **Blocked** — `st_nlink != 1` rejected |
| `/proc/self/*`, `/proc/<pid>` paths | **Blocked** (string check + canonicalization shows resolved path escaping roots) |
| `file://` scheme confusion | Blocked at policy layer (F-10 = validator-layer gap) |
| Literal metadata IPs (dotted/decimal/hex/octal/IPv4-mapped) | **Blocked** |
| DNS-name SSRF (attacker domain → link-local) | **ALLOWED** (F-06) |
| Shell allowlist/prefix bypass (`;`, `&&`, newlines) | **ALLOWED** (F-01) |
| `python3 -c` under constraints | works by design; **arbitrary code via env** (F-02) |
| Fork bomb / 400 MB alloc / output flood in bwrap | **Contained** (pids.max, memory.max+oom.group, bounded output) |
| setsid/double-fork daemon in bwrap | **Reaped** (pid-ns init death) |
| setsid/double-fork daemon on host path | **Escapes** (F-03) |
| Firewall DoS via inherited pipes | **Works** (F-04) |
| SQLite injection / audit-store tamper via IPC | **None found** — parameterized; broker fail-closed; guest appends only with redaction and session binding |
| Policy pack tampering | Packs are code (`policy/packs.py`), not loaded from unsigned files — no unsigned-policy surface found (static) |

## 5. Test-suite status & coverage gaps

- **Command:** `PYTHONPATH=<worktree>/src python3 -m pytest tests -q` → **191 passed, 0 failed, 1 warning** (55s).
- Bare run (stale editable install) → 30 failed / 161 passed — see F-08; do not trust an unpinned run.
- **Gaps confirmed:** no test exercises metacharacter smuggling against `verify_command` (`tests/test_constraints.py` only tests benign prefixes); no test covers loader-env injection (`LD_PRELOAD`/`PYTHONPATH`/`BASH_ENV`); no test covers descendant survival after timeout/`destroy`; no test covers the `bounded_communicate` pipe hang; no test covers DNS-rebinding SSRF through the shell path; fail-open READ disposition is tested as-designed but not flagged as risky.

## 6. Remediation priority order

1. F-01 + F-02 (constraint layer) — one patch series in `constraints/enforcer.py` + `security/environment.py` + `adapters/shell_adapter.py`, with the regression tests listed above.
2. F-03 + F-04 (process lifecycle) — `start_new_session` + `killpg` + raw-fd pipe handling in `utils/process_io.py`.
3. F-05 — flip default to `ESCALATE`.
4. F-06 — connect-time IP verification for shell egress.
5. F-07/F-08 — auth on server; environment/CI pinning.
6. F-09–F-11 hardening.
