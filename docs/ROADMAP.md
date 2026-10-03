# Roadmap

This roadmap lists investigation and engineering priorities. It contains no delivery dates, and planned work should not be read as an existing security property.

## Near term

1. **OCI RT-03 runtime validation** — validate Docker and rootless Podman, including container-root attempts, socket substitution, cross-session isolation, and committed-history survival.
2. **RT-02 mandatory mediation** — inventory native shell and filesystem bypasses, identify sensitive effects that need mediation, and preserve the sandbox as an independent defense layer. Sandbox containment and policy mediation are separate properties.
3. **RT-01 bounded resource isolation** — evaluate memory, CPU, PID/process counts, file descriptors, disk/inodes, descendants, and wall-clock/session budgets.
4. **Independent audit integrity** — investigate host rollback detection, append integrity, authenticated provenance, crash consistency, and optional integrity sealing or hash-chain designs.

## Medium term

- Run real-agent red-team canaries with a controlled credential and evidence boundary.
- Build a cross-backend security validation matrix.
- Improve controlled-online credential crash cleanup.
- Expand parser/DNS/TLS confusion, TOCTOU/path-race, and delayed/cross-session execution testing.

## Product and integration plans

- Provide a cleaner coding-agent integration SDK/API and reference adapters for common agent harnesses.
- Develop turnkey policy packs, clearer audit observability, deployment examples, and pilot integration documentation.
