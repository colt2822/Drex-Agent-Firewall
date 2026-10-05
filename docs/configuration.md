# Configuration Guide

Drex Agent Firewall is configured via YAML configuration files or environment variables.

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `DREX_PROVIDER_TYPE` | `drex` (live) or `replay` | `replay` (auto-detects if `DREX_API_KEY` set) |
| `DREX_API_KEY` | Bearer token for https://drex.nace.ai | `None` |
| `DREX_API_URL` | Drex Decision Gateway endpoint | `https://drex.nace.ai` |
| `DREX_REQUESTED_MODEL` | Model alias to request | `drex-latest` |
| `DREX_DATABASE_PATH` | SQLite audit database location | `drex_firewall.db` |
| `DREX_TIMEOUT_SECONDS` | Provider HTTP query timeout | `5.0` |

## Confidence Thresholds

Policies require minimum model confidence per action class before permitting an action:

```yaml
thresholds:
  READ: 0.70
  WRITE: 0.90
  DELETE: 0.98
  EXECUTE: 0.90
  NETWORK: 0.85
  AUTH: 0.95
  EXTERNAL_PUBLISH: 0.97
  MONEY_MOVEMENT: 0.99
```

If Drex's confidence falls below the threshold for an action class, the action is automatically **ESCALATED** rather than silently allowed.

## Fail-Open vs Fail-Closed

Configurable per action class when the provider encounters errors or timeouts:

```yaml
fail_disposition:
  READ: ESCALATE           # Default: fail closed when the decision provider is unavailable
  WRITE: ESCALATE          # Escalate write operations
  DELETE: BLOCK            # Fail-closed for destructive operations
  EXECUTE: ESCALATE        # Escalate shell execution
  NETWORK: BLOCK           # Fail-closed for network access
  AUTH: BLOCK              # Fail-closed for auth operations
  EXTERNAL_PUBLISH: BLOCK  # Fail-closed for external publications
```
