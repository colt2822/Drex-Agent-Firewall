# Execution Adapters Guide

Adapters sit between the policy engine and execution environments to enforce constraints and capture audit telemetry.

## 1. Shell Adapter (`ShellAdapter`)
- **Guarded Execution**: Subprocess execution with strict timeouts (`max_runtime_seconds`).
- **Memory Bounding**: Truncates `stdout` and `stderr` to `max_output_bytes` to prevent memory exhaustion.
- **Environment Filtering**: Only environment variable names are analyzed by the firewall; secret values are never transmitted to Drex or persisted in logs.
- **Hard Rule Interception**: Pre-filters dangerous shell patterns (e.g. `rm -rf /`, `mkfs`, fork bombs).

## 2. Filesystem Adapter (`FilesystemAdapter`)
- **Supported Operations**: `read`, `create`, `modify`, `rename`, `delete`, `mkdir`.
- **Symlink Resolution**: Resolves all symlinks with `os.path.realpath` before boundary checks.
- **Confinement & Traversal**: Verifies paths strictly reside within configured allowed roots.
- **Audit Hashes**: Calculates SHA-256 pre-operation and post-operation file hashes.

## 3. Git Adapter (`GitAdapter`)
- **Local vs Remote**: Treats local read/commit actions as reversible, while treating `git push` as an external write requiring human escalation.
- **Force Push Prohibition**: Strictly blocks `git push --force`, `-f`, or `+ref` specifiers.

## 4. GitHub Adapter (`GitHubAdapter`)
- **Operations**: Issues, pull requests, comments, labels, merges.
- **Idempotency**: Generates SHA-256 idempotency keys for mutations.
- **Credential Stripping**: Strips GitHub authentication tokens prior to Drex queries or persistence.

## 5. HTTP Adapter (`HttpAdapter`)
- **Methods**: `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`.
- **SSRF Prevention**: Blocks cloud metadata services (`169.254.169.254`, `metadata.google.internal`) and local loopback.
- **Payload Redaction**: Inspects payloads to prevent exfiltration of API keys, bearer tokens, or credentials.
