# DeepSeek-Reasonix (esengine/DeepSeek-Reasonix) security advisories

Advisories for the DeepSeek-Reasonix project ([esengine/DeepSeek-Reasonix](https://github.com/esengine/DeepSeek-Reasonix)). All findings were verified against version 1.17.8 and reported through CNVD coordinated disclosure before publication; reported to the vendor through a public GitHub issue on 2026-10-14 ([#13061](https://github.com/esengine/DeepSeek-Reasonix/issues/13061)); an earlier private GitHub Security Advisory report remains in Triage with maintainer engagement. No patched release is available at the time of writing.

| Advisory | CWE | CVSS v3.1 | Affected versions |
|----------|:---:|:---------:|-------------------|
| [Repository-controlled AGENTS.md/CLAUDE.md/REASONIX.md silently injected as trusted guidance into the system prompt, enabling shell-tool steering](deepseek-reasonix-agents-md-prompt-injection-command-execution.md) | CWE-1427, CWE-349 | 9.6 Critical | 1.17.8 |

## Severity summary

1 Critical (9.6). All vectors use CVSS v3.1; individual advisories document the primary vector and any alternate-scoring rationale.

## Credit

Discovered and documented by Yongbo Yu ([ybyu-ieu](https://github.com/ybyu-ieu)).
