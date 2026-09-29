# goose 1.52.0 — Developer `shell` Tool Arbitrary Command Execution

| | |
|---|---|
| **Product** | goose (aaif-goose) |
| **Affected version** | <= 1.52.0 |
| **Severity** | Critical — CVSS v3.1: 9.8 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) |
| **CWE** | CWE-78 (OS Command Injection), CWE-94 (Code Injection) |
| **Discovered** | 2026-09 |

## Summary

The developer extension's `shell` tool in goose passes the LLM-supplied command string verbatim to the host shell (`cmd /C` on Windows, `<shell> -c` on POSIX) with no allowlist, sandbox, or content validation. Because the default permission mode is `GooseMode::Auto` — which approves every tool call without confirmation — attacker-controlled content that reaches the agent's conversation (a web page, README, git repository, MCP tool output, or file) can induce the model to issue a `shell` tool call and thereby execute arbitrary commands on the host (prompt-injection-driven remote code execution).

## Root cause

1. **Unsandboxed sink** — `crates/goose/src/agents/platform_extensions/developer/shell.rs:682-749`: `build_shell_command()` assembles `cmd /C <raw>` / `pwsh -NoProfile -NonInteractive -Command <cmd>` / `<shell> -c <cmd>` from the LLM-supplied `ShellParams.command`, with no allowlist or content validation.
2. **No meaningful pre-checks** — `shell.rs:388-400`: `shell_with_cwd_and_emitter()` only guards against an empty string and a Windows `cmd` newline before executing.
3. **Default auto-approval** — `crates/goose/src/permission/permission_inspector.rs:159-161`: `inspect()` returns `InspectionAction::Allow` unconditionally for the `GooseMode::Auto` branch, before any user-permission, read-only, or extension-management checks.
4. **Auto is the default** — `crates/goose-provider-types/src/goose_mode.rs`: `#[default]` is on `Auto` ("Automatically approve tool calls").
5. **Fail-open fallback** — `crates/goose/src/agents/agent.rs:396`: `config.get_goose_mode().unwrap_or_default()` falls back to `Auto` when `GOOSE_MODE` is unset.
6. **Always exposed** — `crates/goose/src/agents/platform_extensions/mod.rs:170-178`: the developer extension is registered with `default_enabled: true` and `unprefixed_tools: true`, so the `shell` tool is always registered under the bare name.

## Impact

On a default installation, an attacker who controls any content the agent processes can achieve:

- Arbitrary command execution on the host with the current user's privileges (RCE)
- Theft of credentials, provider API keys, and environment variables (e.g. `~/.config`)
- Arbitrary file read/write, persistence via autostart/scheduled tasks, and reverse shell

## Proof of concept

A deterministic proof-of-concept (Python standard library only, embedded mock LLM) drives the `shell` tool to run a command containing a `>` redirection, creating a marker file on the host with no approval gate. Result: **20 of 20 assertions passed**.

## Reproduction environment

| Component | Detail |
|---|---|
| goose | v1.52.0 official CLI binary (on PATH) |
| OS | Windows 11 (host shell `cmd /C`; POSIX uses `<shell> -c`) |
| Python | 3.x, standard library only (`http.server` / `subprocess` / `os` / `tempfile` / `threading`) |
| LLM | embedded mock LLM (no real API key required) |
| GOOSE_MODE | unset (out-of-the-box default → `Auto`) |

Full PoC (English): [goose-1.52.0-shell-tool-arbitrary-command-execution-poc.py](goose-1.52.0-shell-tool-arbitrary-command-execution-poc.py)

## Mitigation

- Set `GOOSE_MODE=approve` (or `SmartApprove`) explicitly.
- Run goose only in an isolated VM/container, and only connect reviewed MCP extensions.
- Do not process untrusted content (web pages, repositories, issues, MCP output) with the default mode.

## Remediation (vendor)

- Change the default `GooseMode` from `Auto` to `Approve`/`SmartApprove` (fail closed).
- Remove the `unwrap_or_default()` fallback to `Auto`; fail closed when `GOOSE_MODE` is unset.
- Sandbox or allowlist the `shell` tool (command allowlist, re-confirmation for dangerous operations, or VM/container isolation).
- Treat external content as untrusted and add prompt-injection defenses.

## References

- Release: https://github.com/aaif-goose/goose/releases/tag/v1.52.0
- `shell.rs` (build_shell_command): https://github.com/aaif-goose/goose/blob/v1.52.0/crates/goose/src/agents/platform_extensions/developer/shell.rs
- `permission_inspector.rs` (inspect): https://github.com/aaif-goose/goose/blob/v1.52.0/crates/goose/src/permission/permission_inspector.rs
- `goose_mode.rs` (GooseMode): https://github.com/aaif-goose/goose/blob/v1.52.0/crates/goose-provider-types/src/goose_mode.rs
- `agent.rs` (Agent::new): https://github.com/aaif-goose/goose/blob/v1.52.0/crates/goose/src/agents/agent.rs
- Vendor issue: https://github.com/aaif-goose/goose/issues/12566

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-09 | Discovered and verified |
| 2026-09 | Submitted to VulnCheck (pending CVE assignment) |
| 2026-09 | Reported to vendor (GitHub issue #12566) |

## Credit

Yongbo Yu
