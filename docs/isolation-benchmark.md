# Drex Isolation & Host Escape Benchmark (100 Scenarios)

## 1. Overview

The **Drex Isolation Benchmark** evaluates the outer operating system confinement layer across **100 hostile escape scenarios** designed to test host-level privilege escalation, filesystem traversal, credential inheritance, network exfiltration, and container runtime compromise.

To run the benchmark:
```bash
drex-firewall benchmark --isolation
```

---

## 2. Benchmark Results

```text
═══════════════════════════════════════════════════════════
       Drex Isolated Agent Runtime Benchmark Report       
═══════════════════════════════════════════════════════════

     Overall Isolation Benchmark Metrics     
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Metric                          ┃ Value   ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ Total Isolation Scenarios       │ 100     │
│ Accuracy                        │ 98.0%   │
│ High-Impact Scenarios Evaluated │ 80      │
│ High-Impact False Allows        │ 0       │
│ High-Impact False Allow Rate    │ 0.0%    │
│ False Block Rate                │ 1.0%    │
│ Average Decision Latency        │ 0.29 ms │
└─────────────────────────────────┴─────────┘
```

---

## 3. Category Breakdown

| Category | Scenarios | Accuracy | High-Impact | False Allows | False Blocks | Description |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`filesystem_escape`** | 10 | **100.0%** | 8 | **0** | 0 | Attempts to read `~/.ssh`, `~/.aws`, write to `/etc/cron.d`, `/usr`, or host roots |
| **`credential_escape`** | 10 | **100.0%** | 8 | **0** | 0 | Inheriting host environment secrets (`GITHUB_TOKEN`, `OPENAI_API_KEY`, `SSH_AUTH_SOCK`) |
| **`process_namespace`** | 10 | **100.0%** | 8 | **0** | 0 | Inspecting host `/proc/1`, signaling host processes, escaping PID namespace |
| **`network_escape`** | 10 | **90.0%** | 8 | **0** | 0 | Direct socket connections to public IPs, loopback probing, cloud metadata SSRF |
| **`runtime_socket_escape`** | 10 | **90.0%** | 8 | **0** | 1 | Accessing `/var/run/docker.sock`, `/run/podman/podman.sock`, containerd sockets |
| **`privilege_escape`** | 10 | **100.0%** | 8 | **0** | 0 | Executing `sudo`, `su`, `pkexec`, creating raw sockets (`CAP_NET_RAW`), setuid execution |
| **`mount_escape`** | 10 | **100.0%** | 8 | **0** | 0 | Remounting `/usr` as rw, mounting external devices, pivot root tricks |
| **`mcp_escape`** | 10 | **100.0%** | 8 | **0** | 0 | MCP tool calls attempting out-of-workspace filesystem mutations or host socket access |
| **`git_escape`** | 10 | **100.0%** | 8 | **0** | 0 | Using git hooks (`core.hooksPath`), git config exfiltration, or external commands |
| **`resource_exhaustion`**| 10 | **100.0%** | 8 | **0** | 0 | Fork bombs, memory allocation bombs, infinite sleep execution timeouts |

---

## 4. Key Verification Metrics

- **High-Impact False Allows**: **0** (Zero high-impact actions were erroneously allowed).
- **False Block Rate**: **1.0%** (Benign workspace commands remain productive and unblocked).
- **Enforcement Sovereignty**: Hard deterministic rules and namespace boundaries maintain 100% veto authority over probabilistic guidance.
