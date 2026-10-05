# K3 hardening ledger (evidence bounded)

Source evidence: `security/REDTEAM_PATCH_REPORT_20261004.md`, hardening branch commits `d7e051c`, `e435e20`, `7a153c2`, and dirty regression changes carried into this release worktree. The report confirms 11 findings; category counts overlap.

```
K3_STRESS_FINDINGS_TOTAL=11
POLICY_BYPASSES=2
SANDBOX_ESCAPES=1
SECRET_EXPOSURE_FAILURES=1
EGRESS_FAILURES=1
MCP_FAILURES=0 (no MCP defect counted in the K3 report; alpha MCP gaps separately found)
AUDIT_FAILURES=1
MODEL_ROUTING_FAILURES=0
DB_OR_RACE_FAILURES=0
RESOURCE_EXHAUSTION_FAILURES=1
```

| ID | Severity | Original failure | Root cause | Fix status | Regression test | Reproducible now | Still relevant |
|---|---|---|---|---|---|---|---|
| F-01 | Critical | Shell metacharacters smuggled commands through allowlists/prefixes | Raw string prefix checks and `shell=True` | YES | `test_command_allowlist_rejects_shell_syntax`, prefix test | NO, report's original PoC not rerun on release tree | YES |
| F-02 | Critical | Loader/interpreter env vars enabled code execution and secret exposure | Credential denylist used as execution env policy | YES | environment and shell audit tests | NO, original code-execution PoC not rerun | YES |
| F-03 | High | Descendants outlived timeout/session destruction | Direct-child termination only | PARTIAL | process-group regression | UNKNOWN; detached `setsid` attack is explicitly outside proof | YES |
| F-04 | High | Inherited pipe writer could hold adapter indefinitely | Closing buffered streams while reader thread remained blocked | YES | bounded process output regression | NO, original PoC not rerun | YES |
| F-05 | Medium | Provider outage allowed reads by default | Fail-open READ default | YES | provider failure and default disposition tests | NO, original PoC not rerun | YES |
| F-06 | Medium | Shell hostname DNS could target internal addresses | String-only validation without DNS pinning | PARTIAL | shell DNS hard-rule test | UNKNOWN for varied DNS rebinding; host shell is documented as not contained | YES |
| F-07 | Medium | Unauthenticated API exposed audit and enforcement routes | No bearer authentication | YES | API authentication tests | NO, original unauthenticated exposure not rerun | YES |
| F-08 | Medium | Tests imported stale editable installation | No deterministic source selection/assertion | YES | `tests/conftest.py` asserts exact module path and records expected HEAD | NO in current pytest invocation; observed module path matches release `src` | YES |
| F-09 | Low | Audit strings could forge terminal lines | Control chars stored/rendered verbatim | YES | audit control-character regression | NO, exact original PoC not rerun | YES |
| F-10 | Low | `file://` URI accepted as filesystem path text | URI scheme not rejected | YES | file URI regression | NO, exact original PoC not rerun | YES |
| F-11 | Low | Default root included process cwd | Broad default allowed root | YES | policy default test | NO, exact original PoC not rerun | YES |

Classification of carried dirty work:

- `SECURITY_FIX`: adapter, policy, constraint, sandbox, process, environment, path, persistence, API, and configuration changes corresponding to F-01..F-11.
- `REGRESSION_TEST`: changed and added security tests, including `tests/conftest.py` source pinning.
- `RED_TEAM_EVIDENCE`: `security/REDTEAM_PATCH_REPORT_20261004.md` and the committed `security/rt03` / `security/v013` evidence.
- `PRODUCT_CHANGE`: API bearer-token requirement and default policy changes required by findings.
- `DEBUG_ARTIFACT=NONE`; `LOCAL_MACHINE_ARTIFACT=NONE`; `UNRELATED=NONE` identified in the observed dirty path list.

F-03 and F-06 remain bounded/open: no claim is made that host execution is fully contained or all DNS-based host egress is mediated. Previously reported RT01 (workspace aggregate quota), RT02 (native path-policy mediation), and RT03 global/OCI/standalone containment limitations remain open; their original evidence is in `docs/HARDENING_VALIDATION.md` and `security/rt03/REPORT.md`.

Alpha-only finding (not included in the K3 count): operation-name substring classification treated `delete_test_workspace` as read-only because `test` matched a read keyword. The MCP normalizer now tokenizes operation names and prioritizes destructive verbs. `test_mcp_destructive_verb_with_test_suffix_is_not_misclassified_as_read` verifies BLOCK and zero upstream invocations.
