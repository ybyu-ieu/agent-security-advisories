# DB-GPT (eosphoros-ai/DB-GPT) security advisories

Advisories for the DB-GPT framework ([eosphoros-ai/DB-GPT](https://github.com/eosphoros-ai/DB-GPT)). All findings were verified against version 0.8.1 and reported through CNVD coordinated disclosure before publication; vendor notification via public GitHub issues is proceeding as part of this publication batch. No patched release is available at the time of writing.

| Advisory | CWE | CVSS v3.1 | Affected versions |
|----------|:---:|:---------:|-------------------|
| [CodeAction native subprocess execution of LLM-generated code allows unauthenticated remote code execution](dbgpt-codeaction-native-subprocess-llm-code-execution.md) | CWE-94 | 9.8 Critical | 0.8.1 |
| [code_interpreter tool native subprocess execution of arbitrary Python code allows unauthenticated remote code execution](dbgpt-codeinterpreter-native-subprocess-code-execution.md) | CWE-94 | 9.8 Critical | 0.8.1 |
| [ReAct agent missing tool-execution permission gate allows unauthenticated remote action execution without human confirmation](dbgpt-react-agent-tool-execution-missing-permission-gate.md) | CWE-862 | 9.8 Critical | 0.8.1 |
| [HuggingFace model loading enables `trust_remote_code` by default, allowing unauthenticated remote code execution via a malicious model](dbgpt-hf-model-trust-remote-code-default-remote-code-execution.md) | CWE-829 | 9.8 Critical | 0.8.1 |
| [Skill template injection (Jinja2 SSTI) allows unauthenticated arbitrary code execution](dbgpt-skill-template-jinja2-ssti-rce.md) | CWE-1336 | 9.8 Critical | 0.8.1 |

## Severity summary

5 Critical (9.8 / 9.8 / 9.8 / 9.8 / 9.8). All vectors use CVSS v3.1; individual advisories document the primary vector and any alternate-scoring rationale.

## Credit

Discovered and documented by Yongbo Yu ([ybyu-ieu](https://github.com/ybyu-ieu)).
