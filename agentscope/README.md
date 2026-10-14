# AgentScope (agentscope-ai/agentscope) security advisories

Advisories for the AgentScope multi-agent framework ([agentscope-ai/agentscope](https://github.com/agentscope-ai/agentscope)). All findings were verified against version 2.0.4 and reported through CNVD coordinated disclosure before publication; vendor notification via public GitHub issues is proceeding as part of this publication batch (earlier private GitHub Security Advisory reports remain in Triage). No patched release is available at the time of writing.

| Advisory | CWE | CVSS v3.1 | Affected versions |
|----------|:---:|:---------:|-------------------|
| [Unauthenticated arbitrary process execution via MCP stdio workspace configuration](agentscope-mcp-stdio-workspace-unauthenticated-process-execution.md) | CWE-78 | 9.8 Critical | 2.0.4 |
| [Bash tool misclassifies `tee` as a read-only command, allowing arbitrary file write without user confirmation](agentscope-bash-tool-tee-misclassification-arbitrary-file-write.md) | CWE-863 | 8.1 High | 2.0.4 |
| [Agent Service missing authentication — X-User-ID header accepted as identity without verification](agentscope-agent-service-x-user-id-missing-authentication.md) | CWE-306 | 9.8 Critical | 2.0.4 |

## Severity summary

2 Critical (9.8 / 9.8), 1 High (8.1). All vectors use CVSS v3.1; individual advisories document the primary vector and any alternate-scoring rationale.

## Credit

Discovered and documented by Yongbo Yu ([ybyu-ieu](https://github.com/ybyu-ieu)).
