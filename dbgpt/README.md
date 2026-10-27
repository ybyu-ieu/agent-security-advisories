# DB-GPT (eosphoros-ai/DB-GPT) security advisories

Advisories for the DB-GPT framework ([eosphoros-ai/DB-GPT](https://github.com/eosphoros-ai/DB-GPT)). All findings were verified against version 0.8.1 and reported through CNVD coordinated disclosure before publication; five findings were reported to the vendor through public GitHub issues on 2026-10-14 ([#3287](https://github.com/eosphoros-ai/DB-GPT/issues/3287), [#3288](https://github.com/eosphoros-ai/DB-GPT/issues/3288), [#3289](https://github.com/eosphoros-ai/DB-GPT/issues/3289), [#3290](https://github.com/eosphoros-ai/DB-GPT/issues/3290), [#3291](https://github.com/eosphoros-ai/DB-GPT/issues/3291)), and two earlier findings (default-deployment zero-authentication; skill-script native execution) were reported to the vendor on 2026-10-26. No patched release is available at the time of writing.

| Advisory | CWE | CVSS v3.1 | Affected versions |
|----------|:---:|:---------:|-------------------|
| [Default deployment serves the entire Web/API surface without authentication (mock identity, fail-open API-key check, unauthenticated route mounting)](dbgpt-default-deployment-zero-authentication-web-api.md) | CWE-306 | 9.8 Critical | 0.8.1 (authentication core unchanged in 0.8.2) |
| [Skill-script execution path runs uploaded Python natively on the host, enabling unauthenticated remote code execution](dbgpt-skill-script-native-subprocess-execution-rce.md) | CWE-94 | 9.8 Critical | 0.8.0–0.8.1 (execution module unchanged in 0.8.2) |
| [CodeAction native subprocess execution of LLM-generated code allows unauthenticated remote code execution](dbgpt-codeaction-native-subprocess-llm-code-execution.md) | CWE-94 | 9.8 Critical | 0.8.1 |
| [code_interpreter tool native subprocess execution of arbitrary Python code allows unauthenticated remote code execution](dbgpt-codeinterpreter-native-subprocess-code-execution.md) | CWE-94 | 9.8 Critical | 0.8.1 |
| [ReAct agent missing tool-execution permission gate allows unauthenticated remote action execution without human confirmation](dbgpt-react-agent-tool-execution-missing-permission-gate.md) | CWE-862 | 9.8 Critical | 0.8.1 |
| [HuggingFace model loading enables `trust_remote_code` by default, allowing unauthenticated remote code execution via a malicious model](dbgpt-hf-model-trust-remote-code-default-remote-code-execution.md) | CWE-829 | 9.8 Critical | 0.8.1 |
| [Skill template injection (Jinja2 SSTI) allows unauthenticated arbitrary code execution](dbgpt-skill-template-jinja2-ssti-rce.md) | CWE-1336 | 9.8 Critical | 0.8.1 |

## Severity summary

7 Critical (9.8 / 9.8 / 9.8 / 9.8 / 9.8 / 9.8 / 9.8). All vectors use CVSS v3.1; individual advisories document the primary vector and any alternate-scoring rationale.

## Credit

Discovered and documented by Yongbo Yu ([ybyu-ieu](https://github.com/ybyu-ieu)).
