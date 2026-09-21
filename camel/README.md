# CAMEL (camel-ai/camel) security advisories

Advisories for the CAMEL agent framework ([camel-ai/camel](https://github.com/camel-ai/camel), PyPI package `camel-ai`). All findings were verified against version 0.2.91a5 and reported to the vendor through GitHub Private Vulnerability Reporting on 2026-09-01. No patched release is available at the time of writing.

| Advisory | CWE | CVSS v3.1 | Affected versions |
|----------|:---:|:---------:|-------------------|
| [TerminalToolkit safe-mode command disallowlist bypass allows unauthenticated arbitrary command execution](camel-terminaltoolkit-safe-mode-disallowlist-bypass-command-execution.md) | CWE-78 | 10.0 Critical | `<= 0.2.91a5` |
| [ChatAgentOpenAPIServer serves all agent-management endpoints without authentication, enabling unauthenticated remote code execution when shell tools are registered](camel-chatagentopenapiserver-missing-authentication-rce.md) | CWE-306 | 9.8 Critical | `>= 0.2.71a3, <= 0.2.91a5` |
| [Runtime API server exposes all registered tool endpoints without authentication, enabling unauthenticated tool invocation and host command execution](camel-runtime-api-server-missing-authentication-tool-invocation.md) | CWE-306 | 8.6 High | `>= 0.2.10, <= 0.2.91a5` |
| [CAMEL creates MCP servers with no authentication, exposing agent history and tool-driven command execution to unauthenticated clients](camel-mcp-server-creation-missing-authentication.md) | CWE-306 | 9.8 Critical | `>= 0.2.61, <= 0.2.91a5` |
| [ChatAgentOpenAPIServer performs no object-level authorization: any client can enumerate all agent IDs and read, reset, or delete any agent](camel-chatagentopenapiserver-no-object-level-authorization.md) | CWE-639 | 7.5 High | `>= 0.2.71a3, <= 0.2.91a5` |
| [FaissStorage unrestricted pickle deserialization of vector-store metadata allows arbitrary code execution](camel-faissstorage-pickle-deserialization-code-execution.md) | CWE-502 | 9.3 Critical | `>= 0.2.61, <= 0.2.91a5` |
| [FileToolkit working-directory path traversal allows arbitrary host file read and modification](camel-filetoolkit-path-traversal-file-read.md) | CWE-22 | 8.2 High | `>= 0.2.76a1, <= 0.2.91a5` |
| [FileToolkit working_directory path traversal allows arbitrary file write and persistent code execution](camel-filetoolkit-path-traversal-file-write-persistent-code-execution.md) | CWE-22 | 9.8 Critical | `>= 0.2.76a1, <= 0.2.91a5` |

## Severity summary

4 Critical (10.0 / 9.8 / 9.8 / 9.3), 3 High (8.6 / 7.5 / 8.2), 1 Critical via path traversal write (9.8). All vectors use CVSS v3.1; individual advisories document the primary vector and any alternate-scoring rationale.

## Credit

Discovered and documented by Yongbo Yu ([ybyu-ieu](https://github.com/ybyu-ieu)).
