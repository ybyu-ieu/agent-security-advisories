# DB-GPT 0.8.1 — Skill-script execution path runs uploaded Python natively on the host, enabling unauthenticated remote code execution (CWE-94, CVSS 9.8)

| Field | Value |
|-------|-------|
| **Product** | DB-GPT ([eosphoros-ai/DB-GPT](https://github.com/eosphoros-ai/DB-GPT)) |
| **Affected version** | 0.8.0–0.8.1 (the Agent Skill system shipped in 0.8.0; verified in source and dynamically on 0.8.1). No fixed release as of 2026-10-26: the vulnerable execution module (`packages/dbgpt-core/src/dbgpt/agent/skill/manage.py`, git blob `b4197d88c2b2e11e57ba4d716a8af85e4817baff`) is byte-identical in the latest stable release 0.8.2, and the 0.8.2 API layer still registers the `execute_skill_script_file` tool, the `/api/v1/skills/upload` endpoint, and the `/api/v1/chat/react-agent` endpoint |
| **Severity** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8 Critical** |
| **CWE** | CWE-94 Improper Control of Generation of Code (Code Injection) (primary); CWE-306 Missing Authentication for Critical Function |
| **Discovered** | 2026-08-08 (dynamically verified the same day, 7/7 assertions) |

## Summary

The Agent Skill system that DB-GPT introduced in 0.8.0 lets an agent execute Python scripts from installed skills through `SkillManager.execute_skill_script_file()` (`packages/dbgpt-core/src/dbgpt/agent/skill/manage.py:941-1049`). That path performs no security validation of the script: it wraps the file minimally, writes it to a temporary `.py` file, and executes it with the host Python interpreter via `asyncio.create_subprocess_exec(sys.executable, tmp_path, ...)` — no sandbox, no command allowlist, no human confirmation. This is a separate raw-subprocess route: the module's own `execute_script()` (`manage.py:321`) and `_execute_script_from_path()` (`manage.py:842`) go through the `code_server` sandbox, while `execute_skill_script_file()` bypasses it. Combined with the unauthenticated `/api/v1/skills/upload` endpoint and the default zero-authentication deployment, an attacker with network access uploads a skill package containing a malicious script and induces the ReAct agent to run it, executing arbitrary commands on the server host with no credentials. The path is independent of Docker: it exists in a standard source deployment.

## Root cause

1. `execute_skill_script_file()` (`manage.py:941-988`) resolves the skill path (searching `"", "user", "claude", "project"` under the skills directory, so uploaded personal skills in `skills/user/` are reachable) and locates the script with only an `os.path.exists` check (`manage.py:976-977`).
2. The script content is read and embedded into a wrapper (`manage.py:990-1002`) with no dangerous-API screening and no allowlist.
3. The wrapped code is written to a temporary file (`tempfile.mkstemp(suffix=".py", prefix="_skill_run_")`, `manage.py:1022-1024`) and executed natively through `asyncio.create_subprocess_exec(sys.executable, tmp_path, ...)` (`manage.py:1031-1038`, 120 s timeout) — host-interpreter execution with no sandbox, no container isolation, and no privilege drop.
4. The personal-skill gate defaults to allow: `_should_reject_personal_skill_execution()` (`manage.py:588-592`) only rejects when the environment variable `DBGPT_DISABLE_PERSONAL_SKILL_SCRIPT_EXECUTION` is set to a truthy value (`manage.py:547-553`); the shipped default is an empty string, so uploaded personal skills execute.
5. The `execute_skill_script_file` tool is registered on the ReAct agent's tool pack (`packages/dbgpt-app/src/dbgpt_app/openapi/api_v1/agentic_data_api.py:284-306`, registration at `:3351-3355`/`:3495-3502`), and both the upload endpoint `/api/v1/skills/upload` (`agentic_data_api.py:548-552`, installing into `skills/user/`) and the conversation endpoint `/api/v1/chat/react-agent` (`:4373-4377`) are reachable unauthenticated under the default deployment (`auth.py:25-38` mock identity; service on `0.0.0.0:5670`).

Relation to previously published reports: the vendor tracker contains a related issue (#3047, closed by PR #3071), but the module executing skill scripts is byte-identical (git blob `b4197d88…`) in v0.8.1 and the latest stable release v0.8.2, and the v0.8.2 API layer still registers the tool and both endpoints. This record documents the skill-file raw-subprocess execution route itself; it is distinct from reports covering the built-in agent interpreters or the sandbox-fallback path, and from composition-level descriptions of upload-then-execute — the defect here is the unsandboxed native execution of attacker-uploaded scripts through `execute_skill_script_file()`.

## Impact

Verified end to end without credentials: arbitrary command execution on the server host with the privileges of the server process — reading files and secrets (including LLM API keys), modifying or destroying data, installing persistence, and moving laterally into the host network. Because the upload and conversation endpoints are unauthenticated in the default deployment, no credential or victim interaction is required anywhere in the chain. 7 of 7 assertions passed on 2026-08-08 against a standard source deployment of v0.8.1.

## Proof of concept

A standard-library Python script drives the full chain unauthenticated: it uploads a skill package (zip with `SKILL.md` + `scripts/run.py`, where the script writes a marker file) through `POST /api/v1/skills/upload`, then calls `POST /api/v1/chat/react-agent` with a natural-language prompt inducing the agent to run the uploaded script. The SSE stream shows the agent invoking the tool (`"action": "execute_skill_script_file"`), and the marker file appears on the server host with content `POC_EXECUTED` — the script executed natively through the raw host-interpreter subprocess. The script retries with three prompt variants against wording fluctuations and cleans up the marker and the installed skill afterwards.

## Reproduction environment

| Component | Value |
|-----------|-------|
| Product version | DB-GPT v0.8.1, standard source deployment (Docker-independent) |
| OS | Windows 11 / Linux (verified on Windows 11) |
| Python | 3.11 |
| Dependencies | PoC uses the Python standard library only |
| Key switches | `DBGPT_DISABLE_PERSONAL_SKILL_SCRIPT_EXECUTION` unset (shipped default = allow); LLM backend configured for the agent (`deepseek-v4-pro` in the verification); service on `0.0.0.0:5670` |

Full PoC (English): [dbgpt-skill-script-native-subprocess-execution-rce-poc.py](dbgpt-skill-script-native-subprocess-execution-rce-poc.py)

## Mitigation

- Do not expose port 5670 to untrusted networks; restrict it to localhost or a trusted segment (firewall/security group).
- Set `DBGPT_DISABLE_PERSONAL_SKILL_SCRIPT_EXECUTION=true` to reject personal-skill script execution, and do not register the `execute_skill_script_file` tool on user-facing agents.
- Place an authenticating reverse proxy in front of the service so `/api/v1/skills/upload` and `/api/v1/chat/react-agent` are not reachable without credentials.
- Monitor for `_skill_run_*` temp-script execution, subprocess spawns from the server process, and unexpected file writes under the skills directory.

## Remediation (vendor)

1. Route `execute_skill_script_file()` through the same `code_server` sandbox used by `execute_script()` / `_execute_script_from_path()`, or remove the raw-subprocess route entirely.
2. Make the personal-skill script gate deny by default and require an explicit operator opt-in.
3. Enforce authentication on the upload and conversation endpoints (see the deployment-wide authentication advisory) and add an explicit operator allowlist for which skills/tools an agent may execute.
4. Screen uploaded skill scripts (static checks plus sandboxed execution) before they become executable by an agent.

## References

- Release: https://github.com/eosphoros-ai/DB-GPT/releases/tag/v0.8.1
- Native execution of skill scripts: https://github.com/eosphoros-ai/DB-GPT/blob/v0.8.1/packages/dbgpt-core/src/dbgpt/agent/skill/manage.py#L941-L1049
- Personal-skill gate default: https://github.com/eosphoros-ai/DB-GPT/blob/v0.8.1/packages/dbgpt-core/src/dbgpt/agent/skill/manage.py#L547-L553
- Tool definition: https://github.com/eosphoros-ai/DB-GPT/blob/v0.8.1/packages/dbgpt-app/src/dbgpt_app/openapi/api_v1/agentic_data_api.py#L284-L306
- Unauthenticated skill upload: https://github.com/eosphoros-ai/DB-GPT/blob/v0.8.1/packages/dbgpt-app/src/dbgpt_app/openapi/api_v1/agentic_data_api.py#L548-L552
- Vendor issue: https://github.com/eosphoros-ai/DB-GPT/issues/3322

## Disclosure timeline

- 2026-08-08 — Discovered and dynamically verified (7/7 assertions)
- 2026-08-15 — Reported to CNVD (coordinated disclosure; under review)
- 2026-10-26 — Submitted to MITRE (pending CVE assignment)
- 2026-10-27 — Reported to vendor (GitHub issue [#3322](https://github.com/eosphoros-ai/DB-GPT/issues/3322))

## Credit

Discovered and documented by Yongbo Yu.
