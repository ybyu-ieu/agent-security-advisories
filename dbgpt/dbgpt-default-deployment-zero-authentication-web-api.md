# DB-GPT 0.8.1 — Default deployment serves the entire Web/API surface without authentication (CWE-306, CVSS 9.8)

| Field | Value |
|-------|-------|
| **Product** | DB-GPT ([eosphoros-ai/DB-GPT](https://github.com/eosphoros-ai/DB-GPT)) |
| **Affected version** | 0.8.1 (verified in source and dynamically). No fixed release as of 2026-10-26: the mock-authentication function (`packages/dbgpt-serve/src/dbgpt_serve/utils/auth.py`, git blob `72d240e6c153625a8c657762bb342735bf1380bd`) and the V2 API-key check (`packages/dbgpt-app/src/dbgpt_app/openapi/api_v2.py`, git blob `500cd57e59807e304b02db8341fac070ef2e1920`) are byte-identical in the latest stable release 0.8.2 |
| **Severity** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8 Critical** |
| **CWE** | CWE-306 Missing Authentication for Critical Function (primary); CWE-284 Improper Access Control |
| **Discovered** | 2026-08-06 (dynamically verified the same day, 9/9 assertions) |

## Summary

The default deployment of DB-GPT 0.8.1 (`dbgpt start webserver`, binding `0.0.0.0:5670`) exposes its entire Web/API surface with no functioning authentication. The only identity resolution on the API paths is a mock function that returns the `admin` role for every caller regardless of what headers are sent; the V2 API-key check fails open when no keys are configured, which is the shipped default; and the server mounts 120+ routes (chat, knowledge spaces, model controller/worker, AWEL, GPTS, plugins) with no authentication middleware or dependency. Any client that can reach the port can, with no credentials, read the model registry, drive full LLM conversations, and create, list, or delete knowledge spaces.

## Root cause

1. `get_user_from_headers()` (`packages/dbgpt-serve/src/dbgpt_serve/utils/auth.py:25-38`) is a mock: any `user-id` header value is trusted and assigned `role="admin"`, and with no header it defaults to `user_id="001"`, `role="admin"`.
2. `check_api_key()` (`packages/dbgpt-app/src/dbgpt_app/openapi/api_v2.py:43-68`) returns `None` (allow) whenever `service.config.api_keys` is empty; the shipped default is `None`/`[]` (`BaseServeConfig.api_keys`, `configs/dbgpt-app-config.example.toml:5`), so the check is a no-op out of the box.
3. `mount_routers()` (`packages/dbgpt-app/src/dbgpt_app/dbgpt_server.py:55-88`) mounts 120+ routes across chat, knowledge spaces, the model controller/worker, AWEL, GPTS, and plugins with no authentication middleware and no per-route authentication dependency.
4. The knowledge-space endpoints are internally inconsistent (`packages/dbgpt-app/src/dbgpt_app/knowledge/api.py:84-130`): `space_add` declares an identity dependency that is never enforced, while `space_list` and `space_delete` declare none, and the data layer applies no ownership filtering.
5. CORS allows any origin with credentials (`dbgpt_server.py:264-270`: `allow_origins=["*"]`, `allow_credentials=True`), and the default bind is `0.0.0.0:5670` (`packages/dbgpt-app/src/dbgpt_app/config.py:267-269`).

## Impact

Verified without credentials in the dynamic proof of concept: full model-registry read via `GET /api/controller/models`; the V2 chat endpoint accepts unauthenticated requests into business validation (no 401, `E0001` request validation instead) even with no `Authorization` header; unauthenticated `POST /knowledge/space/list` returns all spaces; a space created with a forged `user-id: forged-attacker` header is accepted; CORS preflight from an arbitrary origin passes with `allow-credentials: true`; and an unauthenticated end-to-end LLM conversation returns model output. Because the unauthenticated surface includes the agent, code-execution, and plugin entry points, this defect is the access-control enabler for every unauthenticated exploitation chain against a default deployment; it also exposes conversation and knowledge-base content to any network peer and lets any peer consume the operator's model quota.

## Proof of concept

A standard-library Python script drives the default deployment end to end without any credential: it reads the model registry, posts to `/api/v2/chat/completions` with no `Authorization` header and observes the request enter business validation instead of an authentication challenge, lists all knowledge spaces, creates a space carrying a forged `user-id` header, verifies the CORS preflight allows an arbitrary origin with credentials, completes a full LLM conversation unauthenticated, and finally deletes the test space (demonstrating unauthenticated deletion). Dynamically verified against v0.8.1 on 2026-08-06; 9 of 9 assertions passed.

## Reproduction environment

| Component | Value |
|-----------|-------|
| Product version | DB-GPT v0.8.1, default configuration (`api_keys` empty), standard source deployment |
| OS | Windows 11 / Linux (verified on Windows 11) |
| Python | 3.11 |
| Dependencies | PoC uses the Python standard library only |
| Key switches | `api_keys` empty (shipped default); service on `0.0.0.0:5670` |

Full PoC (English): [dbgpt-default-deployment-zero-authentication-web-api-poc.py](dbgpt-default-deployment-zero-authentication-web-api-poc.py)

## Mitigation

- Do not expose port 5670 to untrusted networks; restrict it to localhost or a trusted segment (firewall/security group).
- Place an authenticating reverse proxy in front of the service and require it for all routes.
- Configure `api_keys` with real values so the V2 key check has material to enforce (note this only covers the V2 surface, not the mounted routers).
- Monitor for unauthenticated knowledge-space mutations and model-registry enumeration, and treat any external client reaching 5670 as a compromise indicator.

## Remediation (vendor)

1. Enforce authentication on every mounted route (middleware or a router-level dependency), denying by default in the shipped configuration.
2. Replace the mock identity resolution with real authentication, and never derive authorization state from client-controlled headers.
3. Make the V2 API-key check fail closed when `api_keys` is unconfigured, or refuse to start with a loud warning instead of silently allowing all.
4. Add ownership filtering to knowledge-space operations and scope the CORS policy to explicit origins.

## References

- Release: https://github.com/eosphoros-ai/DB-GPT/releases/tag/v0.8.1
- Mock authentication: https://github.com/eosphoros-ai/DB-GPT/blob/v0.8.1/packages/dbgpt-serve/src/dbgpt_serve/utils/auth.py#L25-L38
- V2 API-key fail-open: https://github.com/eosphoros-ai/DB-GPT/blob/v0.8.1/packages/dbgpt-app/src/dbgpt_app/openapi/api_v2.py#L43-L68
- Unauthenticated route mounting: https://github.com/eosphoros-ai/DB-GPT/blob/v0.8.1/packages/dbgpt-app/src/dbgpt_app/dbgpt_server.py#L55-L88
- Permissive CORS: https://github.com/eosphoros-ai/DB-GPT/blob/v0.8.1/packages/dbgpt-app/src/dbgpt_app/dbgpt_server.py#L264-L270
- Vendor issue: (add after filing — https://github.com/eosphoros-ai/DB-GPT/issues/NNN)

## Disclosure timeline

- 2026-08-06 — Discovered and dynamically verified (9/9 assertions)
- 2026-08-15 — Reported to CNVD (coordinated disclosure; under review)
- 2026-10-26 — Submitted to MITRE (pending CVE assignment)
- 2026-10-26 — Reported to vendor (GitHub issue #NNN — add after filing)

## Credit

Discovered and documented by Yongbo Yu.
