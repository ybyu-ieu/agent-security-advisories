# goose (aaif-goose/goose) security advisories

Advisories for the goose AI developer agent ([aaif-goose/goose](https://github.com/aaif-goose/goose), Rust CLI + Electron). All findings were verified against version 1.52.0 and reported to the vendor through public GitHub issues ([#12566](https://github.com/aaif-goose/goose/issues/12566), [#12567](https://github.com/aaif-goose/goose/issues/12567)) on 2026-09-29. CVE IDs have been requested through [VulnCheck](https://www.vulncheck.com) and are pending assignment. No patched release is available at the time of writing.

Each advisory is accompanied by an English proof-of-concept script in the same directory.

| Advisory | CWE | CVSS v3.1 | Affected versions |
|----------|:---:|:---------:|-------------------|
| [Developer `shell` tool passes LLM-supplied commands verbatim to the host shell, enabling prompt-injection-driven arbitrary command execution](goose-1.52.0-shell-tool-arbitrary-command-execution.md) | CWE-78 | 9.8 Critical | `<= 1.52.0` |
| [Default `Auto` permission mode approves every tool call without authorization, removing the out-of-the-box policy gate](goose-1.52.0-default-auto-mode-no-policy-gate.md) | CWE-862 | 8.8 High | `<= 1.52.0` |

## Severity summary

1 Critical (9.8), 1 High (8.8). Both vectors use CVSS v3.1; individual advisories document the primary vector and any alternate-scoring rationale.

## Credit

Discovered and documented by Yongbo Yu ([ybyu-ieu](https://github.com/ybyu-ieu)).
