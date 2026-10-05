# Privacy and local data: external alpha

## What stays on this machine

Drex stores its policy at `~/.config/drex-firewall/policy.yaml` and its audit database at `~/.local/share/drex-firewall/audit.db` by default. `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, and `DREX_DATABASE_PATH` can change those locations. Audit rows include timestamps, client/session labels when available, tool and operation names, normalized targets, redacted arguments, policy decisions and reasons, execution status, error class, and result metadata. The packaged canary writes only its invocation counter under a temporary directory, then removes that directory.

Drex's built-in Prometheus counters and histograms are process-local. The alpha package does not send usage or diagnostic telemetry. The CLI does not upload traces.

## Provider and upstream traffic

The default provider is local deterministic replay. Setting `DREX_API_KEY`, or configuring the `drex` provider with credentials, makes Drex use the remote provider and send HTTPS evaluation requests to the configured provider URL. The request includes the action envelope and scrubbed arguments/context so the provider can classify the action. MCP requests also go to the upstream MCP server you configure; that server may itself use network services. Those are explicit configured integrations, not Drex usage analytics.

## Redaction limits

Drex redacts recognized credential patterns and values under recognized sensitive field names before persistence and provider evaluation. Redaction is heuristic: arbitrary secrets, private prompts, source text, file contents, or novel credential formats may not be recognized. Treat local audit data as sensitive and inspect it before sharing. Redaction does not erase information already received by an MCP upstream.

## Delete local alpha data

After undoing Claude integration, remove the default alpha data manually if desired:

```bash
rm -rf ~/.config/drex-firewall ~/.local/share/drex-firewall
```

If you used XDG overrides or `DREX_DATABASE_PATH`, remove those configured paths separately. This command permanently deletes local policy and audit history; do not run it if you want to retain them.

Sharing feedback, a bug report, or sanitized logs is voluntary. Do not send secrets, private prompts, source code, credentials, or sensitive file contents.
