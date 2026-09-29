# goose 1.52.0 — Default `Auto` Permission Mode Approves All Tool Calls (No Policy Gate)

| | |
|---|---|
| **Product** | goose (aaif-goose) |
| **Affected version** | <= 1.52.0 |
| **Severity** | High — CVSS v3.1: 8.8 (`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`) |
| **CWE** | CWE-862 (Missing Authorization), CWE-276 (Incorrect Default Permissions) |
| **Discovered** | 2026-09 |

## Summary

goose ships with `GooseMode::Auto` as its default permission mode, which automatically approves every tool call with no authorization check. A fresh install therefore has no policy gate. When `GOOSE_MODE` and the config key are unset, `unwrap_or_default()` falls back to `Auto`, and `PermissionInspector::inspect` returns `Allow` unconditionally before any user-permission, read-only, or extension-management checks. Combined with the default-enabled, unsandboxed `shell` tool, attacker-controlled content processed by the agent can drive a shell tool call that executes on the host with no confirmation (prompt-injection-driven RCE).

## Root cause

1. **Auto is the default** — `crates/goose-provider-types/src/goose_mode.rs:22-25`: `#[default]` on `Auto` ("Automatically approve tool calls"), the most permissive of the four modes.
2. **No safe default from config** — `crates/goose/src/config/base.rs:765-786`: `Config::get_param` returns `ConfigError::NotFound` when `GOOSE_MODE` is neither an env var nor a config key.
3. **Fail-open fallback** — `crates/goose/src/agents/agent.rs:396`: `config.get_goose_mode().unwrap_or_default()` falls back to `Auto` (the same pattern appears in `cli.rs` and `term.rs`).
4. **Unconditional allow** — `crates/goose/src/permission/permission_inspector.rs:159-161`: `GooseMode::Auto => InspectionAction::Allow`, before any authorization check.
5. **Unsandboxed execution surface** — `crates/goose/src/agents/platform_extensions/developer/shell.rs:557-668,682-749`: `run_command`/`build_shell_command` spawn `cmd /C` / `pwsh -NoProfile -NonInteractive -Command` / `<shell> -c` directly on the host.
6. **First-run setup never warns** — `crates/goose-cli/src/commands/configure.rs:225-283`: `handle_first_time_setup` only asks about telemetry and provider, never the permission mode.

## Impact

With the default configuration, an attacker who injects instructions into content the agent processes can achieve arbitrary command execution on the host (RCE), credential/API-key theft, and persistence.

## Proof of concept

A deterministic proof-of-concept compares two runs over the same injected instruction file:

- Control group (`GOOSE_MODE=approve`): the run is refused non-interactively; no marker written.
- Attack group (`GOOSE_MODE` unset → default `Auto`): the shell command executes with zero confirmation; marker written.

Result: **16 of 16 assertions passed**.

## Reproduction environment

| Component | Detail |
|---|---|
| goose | v1.52.0 official CLI binary (on PATH) |
| OS | Windows 11 (cross-platform; POSIX uses `<shell> -c`) |
| Python | 3.x, standard library only (`os` / `sys` / `subprocess` / `shutil` / `tempfile` / `time` / `warnings`) |
| LLM | DeepSeek (provider configured via `config.yaml` + `secrets.yaml`) |
| GOOSE_MODE | control group `approve` vs attack group unset (default `Auto`) |

Full PoC (English): [goose-1.52.0-default-auto-mode-no-policy-gate-poc.py](goose-1.52.0-default-auto-mode-no-policy-gate-poc.py)

## Mitigation

- Set `GOOSE_MODE=approve` (or `SmartApprove`) explicitly.
- Do not process untrusted content with the default mode.
- Isolate the host running goose (dedicated VM or container).

## Remediation (vendor)

- Change the default `GooseMode` from `Auto` to `Approve`/`SmartApprove` so the unconfigured state fails closed.
- Prompt for a permission mode during first-run setup and warn that `Auto` approves every tool call.
- Make an unset `GOOSE_MODE` fail closed instead of falling back to `Auto`.
- Even in `Auto`, require confirmation for dangerous tools such as `shell`, or disable the developer extension by default.

## References

- Release: https://github.com/aaif-goose/goose/releases/tag/v1.52.0
- `goose_mode.rs` (GooseMode): https://github.com/aaif-goose/goose/blob/v1.52.0/crates/goose-provider-types/src/goose_mode.rs
- `agent.rs` (Agent::new): https://github.com/aaif-goose/goose/blob/v1.52.0/crates/goose/src/agents/agent.rs
- `permission_inspector.rs` (inspect): https://github.com/aaif-goose/goose/blob/v1.52.0/crates/goose/src/permission/permission_inspector.rs
- `shell.rs` (run_command/build_shell_command): https://github.com/aaif-goose/goose/blob/v1.52.0/crates/goose/src/agents/platform_extensions/developer/shell.rs
- `configure.rs` (first-run setup): https://github.com/aaif-goose/goose/blob/v1.52.0/crates/goose-cli/src/commands/configure.rs
- Vendor issue: https://github.com/aaif-goose/goose/issues/12567

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-09 | Discovered and verified |
| 2026-09 | Submitted to VulnCheck (pending CVE assignment) |
| 2026-09 | Reported to vendor (GitHub issue #12567) |

## Credit

Yongbo Yu
