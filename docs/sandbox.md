# Drex Isolated Agent Runtime (`drex-firewall sandbox`)

## 1. Overview

The **Drex Isolated Agent Runtime** provides an optional operating-system confinement layer around autonomous AI coding agents (such as Claude Code, OpenAI Codex, OpenHands, and generic agents).

While application-level firewalls intercept actions mediated via MCP or SDK adapters, an agent with direct POSIX shell access may sidestep those application filters. The Drex Isolated Runtime reduces that exposure for processes launched inside its disposable, unprivileged Linux namespaces, subject to the limitations below.

```
HOST ENVIRONMENT
 │
 │ [Controlled Boundary]
 ▼
┌────────────────────────────────────────────────────────┐
│             DREX ISOLATED AGENT RUNTIME                │
│                                                        │
│  Autonomous Agent (Claude Code / Codex / Generic)      │
│                     │                                  │
│                     ▼                                  │
│            Drex Agent Firewall                         │
│                     │                                  │
│         ┌───────────┼───────────┐                      │
│         ▼           ▼           ▼                      │
│        MCP        Shell        Git                     │
│        FS         HTTP        GitHub                   │
│                                                        │
│  • Writable /workspace mount only                      │
│  • Ephemeral isolated /home/agent                      │
│  • Zero host credential inheritance                    │
│  • Deny direct network egress by default               │
│  • Dropped kernel capabilities (CAP_DROP ALL)          │
│  • Die-with-parent lifecycle supervision               │
└────────────────────────────────────────────────────────┘
```

---

## 2. Implemented Boundary Controls

1. **Host `$HOME` Isolation**: The host user's home directory (`~`) is never mounted into the sandbox. The agent is provided an ephemeral tmpfs home directory at `/home/agent`.
2. **Host Credential Cleansing**: Host environment variables are purged (`--clearenv`). Sensitive tokens (`GITHUB_TOKEN`, `AWS_*`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `SSH_AUTH_SOCK`) are strictly excluded.
3. **Restricted Mount Hierarchy**:
   - `/workspace` (rw): Bind mounted from the target repository directory only.
   - `/usr`, `/bin`, `/lib`, `/lib64`, `/etc` (ro): Read-only system libraries and utilities.
   - `/tmp` (rw tmpfs): Ephemeral session scratch space.
   - Host `/`, `/root`, `/home`, and docker sockets (`/var/run/docker.sock`) are inaccessible.
4. **Dropped Kernel Capabilities**: All Linux capabilities are dropped (`CAP_DROP ALL`). The sandbox operates entirely unprivileged without setuid or root escalation avenues.
5. **Controlled Network Boundary**: Network egress is denied by default (`--unshare-net` in `none` and `firewall-only` modes). The separate `controlled-online` mode also unshares networking and permits only exact provider CONNECT hostnames on TCP/443 through a loopback-only proxy and one mode-0600 per-session socket mounted at `/run/drex-egress.sock`. Host Docker, Podman, and SSH runtime sockets are not mounted. TLS SNI and encrypted URL paths are not inspected.
6. **Diagnostic Audit Records**: Sandbox sessions and mediated tool actions are recorded in SQLite. The current MCP database is stored in the writable workspace and can be modified or deleted by the agent; direct native actions may bypass MCP records. Do not treat this database as a complete or tamper-proof audit trail.

## 2.1 Known Limitations

- MCP is not mandatory mediation: native shell and filesystem actions may bypass its policy checks.
- The MCP audit database is agent-writable in the current layout (FWA-U3).
- Bubblewrap does not enforce cgroup CPU, memory, or file-descriptor quotas (FWA-U1). Resource exhaustion remains possible.
- The runtime shares the host kernel and is defense-in-depth, not a complete authoritative security boundary.

---

## 3. CLI Reference

### 3.1 Launching an Isolated Session

```bash
# Run command inside isolated sandbox
drex-firewall sandbox run --workspace /path/to/repo --policy safe-local-coding -- ls -la /workspace

# Run a real authenticated Claude task through the controlled provider bridge
drex-firewall sandbox demo --agent claude --network controlled-online

# Run Codex with the explicit OpenAI/ChatGPT host policy
drex-firewall sandbox demo --agent codex --network controlled-online
```

### 3.2 Interactive Confined Shell

```bash
# Drop into an isolated bash shell confined inside the sandbox
drex-firewall sandbox shell --workspace /path/to/repo --policy safe-local-coding
```

### 3.3 Running Defensive Escape Probes

```bash
# Verify sandbox boundary against 10 host escape attack vectors
drex-firewall sandbox test-escape
```

Output:
```text
                        Sandbox Host Escape Verification                        
┏━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━┓
┃ Category                 ┃ Probe Name                   ┃ Outcome ┃ Duration ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━┩
│ filesystem_escape        │ Read host ~/.ssh directory   │ BLOCKED │   0.017s │
│ filesystem_escape        │ Read host ~/.aws credentials │ BLOCKED │   0.015s │
│ filesystem_escape        │ Write to host /usr directory │ BLOCKED │   0.101s │
│ filesystem_escape        │ Write persistence payload    │ BLOCKED │   0.104s │
│ credential_escape        │ Inherit host OPENAI_API_KEY  │ BLOCKED │   0.015s │
│ credential_escape        │ Inherit host GITHUB_TOKEN    │ BLOCKED │   0.015s │
│ process_namespace_escape │ Count visible processes      │ BLOCKED │   0.016s │
│ network_escape           │ Connect directly to public IP│ BLOCKED │   0.102s │
│ runtime_socket_escape    │ Access Docker daemon socket  │ BLOCKED │   0.017s │
│ privilege_escape         │ Execute sudo inside container│ BLOCKED │   0.006s │
└──────────────────────────┴──────────────────────────────┴─────────┴──────────┘

✔ PASS: All host escape attempts were strictly blocked by the isolation boundary.
```

### 3.4 Real Agent Sandbox Demo

```bash
# Run legitimate coding task with Claude Code inside isolated runtime
drex-firewall sandbox demo --agent claude --timeout 60

# Run dedicated host escape audit session with Claude Code inside sandbox
drex-firewall sandbox demo --escape-session --agent claude --timeout 60
```

### 3.5 Session Management

```bash
# List all active and recent sandbox sessions
drex-firewall sandbox list

# Inspect detailed diagnostic record of a session
drex-firewall sandbox inspect <session_id>

# Stop an active session
drex-firewall sandbox stop <session_id>

# Destroy session resources and ephemeral mounts
drex-firewall sandbox destroy <session_id>
```

---

## 4. Policy Configuration

Isolation runtime settings can be specified in policy packs or YAML configuration:

```yaml
policy_name: safe-local-coding
version: "1.0.0"

sandbox:
  enabled: true
  backend: auto                  # auto, bubblewrap, podman, docker, none
  network_mode: firewall-only    # none, firewall-only, allowlisted, host
  workspace_mode: rw
  drop_all_caps: true
  expose_host_root: false
  allow_env:
    - TERM
    - LANG
    - LC_ALL
  limits:
    timeout_seconds: 60.0
    max_output_bytes: 1048576    # 1MB
    max_memory_mb: 2048
```
