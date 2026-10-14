# Dify (langgenius/dify) security advisories

Advisories for the Dify LLM application platform ([langgenius/dify](https://github.com/langgenius/dify)). All findings were verified against version 1.15.0 and reported through CNVD coordinated disclosure before publication; reported to the vendor through a public GitHub issue on 2026-10-14 ([#44054](https://github.com/langgenius/dify/issues/44054)); an earlier private GitHub Security Advisory report remains in Triage. No patched release is available at the time of writing.

| Advisory | CWE | CVSS v3.1 | Affected versions |
|----------|:---:|:---------:|-------------------|
| [Code-execution sandbox uses shipped default API key "dify-sandbox"](dify-sandbox-hardcoded-default-api-key.md) | CWE-798 | 7.5 High | 1.15.0 |

## Severity summary

1 High (7.5). All vectors use CVSS v3.1; individual advisories document the primary vector and any alternate-scoring rationale.

## Credit

Discovered and documented by Yongbo Yu ([ybyu-ieu](https://github.com/ybyu-ieu)).
