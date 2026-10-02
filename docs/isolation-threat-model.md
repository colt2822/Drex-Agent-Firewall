# Drex Isolated Agent Runtime Threat Model

## 1. Scope & Objective

The **Drex Isolated Agent Runtime** addresses the final core trust-boundary challenge of autonomous AI agents: **direct native host execution**.

### The Trust-Boundary Problem
In application-level firewalls, requests routed through mediation layers (MCP, HTTP proxies, or Python SDK wrappers) are inspected and policy-enforced. However, if an agent possesses unrestricted native POSIX shell execution on the developer's workstation:
1. The agent could read unmounted files (`~/.ssh`, `~/.aws`, browser profiles).
2. The agent could exfiltrate secrets via raw socket connections (`/dev/tcp`, `curl`, `nc`).
3. The agent could access container management sockets (`/var/run/docker.sock`) to launch privileged host escapes.
4. The agent could stage persistence hooks in system directories (`/etc/cron.d`, `~/.bashrc`).

The isolated agent runtime establishes an **outer operating system confinement boundary** ensuring the agent cannot reach host resources even if it executes arbitrary native binary commands.

---

## 2. Threat Matrix & Defense-in-Depth Confinement

| Threat Vector | Attack Mechanism | Inner Layer (Firewall) | Outer Layer (Sandbox Runtime) | Defense Status |
| :--- | :--- | :--- | :--- | :--- |
| **Host Filesystem Snooping** | `cat ~/.ssh/id_rsa`, `cat ~/.aws/credentials` | `PathValidator` blocks non-workspace paths | Host `$HOME` is not mounted. Ephemeral `/home/agent` has no host keys | **MUTUALLY REINFORCED** |
| **Host System Mutation** | `rm -rf /`, `touch /etc/cron.d/pwn` | `DeterministicHardRules` veto destructive paths | `/usr`, `/bin`, `/lib`, `/etc` mounted read-only (`--ro-bind`) | **MUTUALLY REINFORCED** |
| **Environment Credential Stealing** | `env`, `echo $GITHUB_TOKEN` | `SecretRedactor` masks output | Environment sanitized via `--clearenv`; tokens never inherited | **MUTUALLY REINFORCED** |
| **Direct Socket SSRF / Exfil** | `curl http://169.254.169.254` | `NetworkValidator` blocks metadata IPs | Network namespace isolated (`--unshare-net`) by default | **MUTUALLY REINFORCED** |
| **Container Daemon Escape** | `docker run -v /:/host ...` | Shell parser blocks `docker.sock` patterns | `/var/run/docker.sock` is not mounted into sandbox | **MUTUALLY REINFORCED** |
| **Privilege Escalation** | `sudo su`, `pkexec`, `unshare` | Hard rules block `sudo` invocations | Unprivileged user namespace, setuid disabled, `CAP_DROP ALL` | **MUTUALLY REINFORCED** |
| **Process Snooping** | `kill -9 <host_pid>`, inspecting `/proc` | Shell argument inspection | PID namespace isolated (`--unshare-pid`); host PIDs invisible | **MUTUALLY REINFORCED** |
| **Resource Exhaustion** | Fork bombs, memory bombs | Max command runtime limits | Process tree killed on timeout; `--die-with-parent` enforced | **MUTUALLY REINFORCED** |

---

## 3. Kernel Isolation Specifications (Bubblewrap Backend)

The default Linux backend utilizes unprivileged user namespaces via `bwrap`:

1. **Namespaces Created**:
   - `CLONE_NEWUSER`: Creates a sandboxed user namespace where the agent runs as `uid=1000(agent)`.
   - `CLONE_NEWPID`: Prevents visibility or signaling of host processes.
   - `CLONE_NEWIPC`: Isolates shared memory, semaphores, and message queues.
   - `CLONE_NEWUTS`: Isolates hostname and domain identifiers.
   - `CLONE_NEWNET`: Default deny-all network namespace with no external routing.

2. **Capability Dropping**:
   - Drops `CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_DAC_OVERRIDE`, `CAP_SETUID`, and all 38 Linux capabilities (`--cap-drop ALL`).
   - `PR_SET_NO_NEW_PRIVS` prevents regaining privileges via setuid executables.

3. **Mount Model**:
   - Pivot root to private virtual root.
   - Read-only bind of `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/etc`.
   - Ephemeral `tmpfs` mounts for `/tmp` and `/home/agent`.
   - Target workspace bind mounted at `/workspace` (rw).
