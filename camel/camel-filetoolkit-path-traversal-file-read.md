# CAMEL FileToolkit working-directory path traversal allows arbitrary host file read and modification (CWE-22, CVSS 8.2)

## Summary

FileToolkit in camel-ai resolves agent-supplied relative paths against its configured `working_directory` and calls `Path.resolve()` without ever checking that the resolved path stays inside that directory, so any caller able to influence the path arguments of its file operations -- an agent whose inputs an attacker can influence, or any direct caller -- can read arbitrary files on the host outside that directory (for example `../credentials.txt`) and modify files outside it through the same missing check. Absolute paths are accepted as-is. In camel-ai 0.2.91a5 this affects `read_file`, `edit_file`, and `notebook_edit_cell`.

## Details

The resolution helper joins relative paths onto the configured directory and returns the resolved path, performing no containment check; its own docstring confirms that even input sanitization is deliberately absent ("Resolve a file path without sanitizing the filename"):

```python
# camel/toolkits/file_toolkit.py:113-118 (v0.2.91a5)
    def _resolve_existing_filepath(self, file_path: str) -> Path:
        r"""Resolve a file path without sanitizing the filename."""
        path_obj = Path(file_path)
        if not path_obj.is_absolute():
            path_obj = self.working_directory / path_obj
        return path_obj.resolve()
```

The read trigger hands the resolved path straight to the file loader:

```python
# camel/toolkits/file_toolkit.py:1204-1209 (v0.2.91a5)
                resolved_path = self._resolve_existing_filepath(file_paths)

                # Use MarkItDownLoader to convert the file
                result = MarkItDownLoader().convert_files(
                    file_paths=[str(resolved_path)], parallel=False
                )
```

`edit_file` resolves the same way (file_toolkit.py:1264) and then reads and rewrites the target (`read_text`/`write_text`, :1274/:1292), so the same missing check yields modification of files outside the configured directory; `notebook_edit_cell` resolves the same way (:1507). Because the only branch is `if not path_obj.is_absolute()`, absolute paths are also used unchanged -- no code path in the toolkit verifies containment.

The `working_directory` parameter is the toolkit's file-access root: the constructor resolves it (or falls back to the `CAMEL_WORKDIR` environment variable, then to `./camel_working_dir`) and creates it (file_toolkit.py:66-74), and the agent-facing tool list exposes the affected operations via `get_tools()` (`read_file`, `edit_file`, `notebook_edit_cell` among the seven tools, file_toolkit.py:1763-1771).

```python
# camel/toolkits/file_toolkit.py:1763-1771 (v0.2.91a5)
        return [
            FunctionTool(self.write_to_file),
            FunctionTool(self.read_file),
            FunctionTool(self.edit_file),
            FunctionTool(self.search_files),
            FunctionTool(self.notebook_edit_cell),
            FunctionTool(self.glob_files),
            FunctionTool(self.grep_files),
        ]
```

The missing containment has existed since the toolkit was introduced: `camel/toolkits/file_toolkit.py` first ships in the 0.2.76a1 release on PyPI (the 0.2.76a0 wheel does not contain the module). In 0.2.76a1 through 0.2.89, `read_file` and `edit_file` (and `write_to_file`) resolve through `_resolve_filepath`, which likewise joins relative paths to `working_directory` and calls `Path.resolve()` without a containment check -- its sanitization rewrites only the final filename component (spaces and special characters), leaving any `..` traversal in the parent path intact. From 0.2.90 onward the resolution moved to `_resolve_existing_filepath` (introduced during the 0.2.90 prerelease series); the whole file is byte-identical -- git blob `810d2f752c50daf592f27e81cde9b6c4c427baa6` -- in the latest stable release 0.2.90, in the audited 0.2.91a5, and on the current master branch, so neither any released version nor the current master state contains a fix.

**Why this is a vulnerability:**

- *"working_directory is a convenience default, not a security boundary."* It is the only confinement mechanism the toolkit offers: the constructor resolves and creates it (file_toolkit.py:66-74), every path-taking operation resolves against it, and `read_file`'s own docstring documents that relative paths "will be resolved relative to the working directory" (file_toolkit.py:1186-1188). The sibling resolver `_resolve_filepath` takes care to sanitize the final filename component "ensuring safe usage in downstream processing" (file_toolkit.py:85-88) -- hygiene is clearly intended -- yet no resolver ever verifies that the resolved path remains inside the directory, so the confinement an operator configures is silently never enforced. The constructor docstring itself calls the parameter "The default directory for output files" (file_toolkit.py:53-54) and the init log calls it the "output directory" (:77-79) -- yet the read, edit, search, glob, grep, and notebook operations all anchor their paths to it identically, so whatever it is labelled, it is the only path root the toolkit has and no operation ever enforces staying inside it.
- *"An LLM must be persuaded, so this is prompt injection, not a vulnerability."* No LLM is involved in the PoC below: calling `FileToolkit(working_directory=...).read_file('../credentials.txt')` directly returns the file outside the directory. The LLM is the intended caller of these tools -- that is what `get_tools()` exists for (file_toolkit.py:1755-1771) -- and the defect is the missing containment check, independent of who composed the path. Frameworks hand these tools to models whose context can contain untrusted content, and comparable path-limitation bypasses in agent coding tools are tracked as vulnerabilities (CVE-2025-54794: a path validation flaw in an agentic coding tool that allows access to files outside the working directory, CVSS 9.1; CVE-2025-59532: workspace-boundary confusion in a coding agent).
- *"Absolute paths are documented behavior."* Even granting that, it cannot coexist with a confinement parameter: if absolute paths are used as-is (file_toolkit.py:116-118), then `working_directory` cannot confine anything, and the parameter misleads every operator who relies on it. Conversely, a fix that only rejects `..` components would remain insufficient while absolute paths are accepted. The remediation below covers both.

**Exposure surface.** Beyond direct in-process calls, CAMEL's own components put these tools on network-reachable paths: the toolkit class is decorated with the package's `@MCPServer()` marker (file_toolkit.py:29-30), which registers a BaseToolkit's `get_tools()` operations with a FastMCP server (camel/utils/mcp.py:133-145), and the project ships OpenAPI/Runtime server surfaces (e.g. the FastAPI-based `camel/services/agent_openapi_server.py` and the `camel/runtimes/` package) through which tool arguments can likewise arrive from network clients. When an operator uses any of these surfaces, the path arguments are attacker-controllable remotely.

**Suggested remediation:**

1. After resolution, verify containment with `Path.is_relative_to(self.working_directory)` (or an equivalent canonical-prefix check) in `_resolve_existing_filepath` and `_resolve_filepath`, and reject the operation when it fails.
2. Apply the same check to the remaining path-resolving helpers and their callers, including `write_to_file` (resolves through `_resolve_filepath`, file_toolkit.py:1103) and the search functions (`search_files`/`glob_files`/`grep_files`, which resolve through `_resolve_search_path`, file_toolkit.py:104-111, with the same missing containment).
3. Consider rejecting absolute paths by default unless explicitly enabled.

## Proof of Concept

Dynamically verified against camel-ai 0.2.91a5 (2026-08-11, Windows host, 9/9 automated assertions passing in the full verification harness, of which a minimal reproduction is shown below; no LLM, no server, and no network are needed). The script is self-contained and cross-platform (paths are built with `tempfile`).

**Setup:** `pip install "camel-ai==0.2.91a5" "mcp<2" markitdown tqdm`

Three dependency notes: a current `mcp` 2.x release removes `mcp.server.FastMCP`, which camel-ai 0.2.91a5's unbounded `mcp>=1.3.0` pin does not yet account for -- without the `<2` pin, `camel.toolkits` imports fail at startup; `markitdown` is not a base dependency of camel-ai (it is declared only in the `document_tools`, `owl`, `eigent`, and aggregate `all` extras), while `read_file` imports the MarkItDown loader that package provides; and `tqdm` is imported by that loader on every call (camel/loaders/markitdown.py:166, `from tqdm.auto import tqdm`) yet is declared by neither camel-ai nor markitdown, so it must be installed explicitly or every `read_file` call returns an error string.

```python
import os, shutil, tempfile
from camel.toolkits import FileToolkit

base = tempfile.mkdtemp()                                  # neutral working area
sandbox = os.path.join(base, "sandbox")
secret = os.path.join(base, "credentials.txt")             # outside the sandbox
os.makedirs(sandbox, exist_ok=True)
with open(os.path.join(sandbox, "notes.txt"), "w") as f:   # in-bounds file
    f.write("project notes inside the working directory")
with open(secret, "w") as f:                               # simulated host secret
    f.write("DB_HOST=10.20.30.40\nDB_PASSWORD=S3cret-DB-P@ss-77\n")

tk = FileToolkit(working_directory=sandbox)                # the configured root

# 1) Baseline: a path inside the working directory reads normally
inside = tk.read_file("notes.txt")
assert "project notes" in inside, "baseline read failed"
assert "S3cret-DB-P@ss-77" not in inside, "baseline unexpectedly leaked"

# 2) Path traversal: one `../` component escapes the configured directory
leaked = tk.read_file("../credentials.txt")
print(leaked)          # -> the contents of <base>/credentials.txt, which
                       #    include: DB_PASSWORD=S3cret-DB-P@ss-77
assert "S3cret-DB-P@ss-77" in leaked, "traversal read failed"

# 3) The same missing check governs the write path (source-verified at
#    file_toolkit.py:1264 via edit_file; not exercised here):
#    tk.edit_file("../some_host_file", old, new)

shutil.rmtree(base)    # cleanup
```

The traversal read returns the file's contents -- including the simulated credential -- even though the file lies outside `working_directory`, demonstrating that no containment check exists anywhere in the resolution path. Absolute paths are equally used as-is (for example `tk.read_file(secret)` returns the outside file's contents).

## Impact

- **Type:** path traversal (CWE-22) -- a missing containment check after path resolution lets every path-accepting file operation escape the toolkit's configured directory; the direct consequence is exposure of sensitive host files (CWE-200).
- **Who is impacted:** (a) any application that hands FileToolkit's operations to an agent, or otherwise lets untrusted input reach their path arguments -- the toolkit's intended use, and the escape works whatever `working_directory` is set to (default fallback or operator-configured); (b) deployments that expose the toolkit's tools through CAMEL's MCP/OpenAPI/Runtime server surfaces, against any client that can reach those surfaces.
- **Attacker capabilities:**
  - read any file the CAMEL process can read: API keys, `.env` files, database credentials, SSH private keys, configuration files;
  - modify arbitrary files outside the configured directory via `edit_file` (same root cause, file_toolkit.py:1264) -- combined with shell startup files or `~/.ssh/authorized_keys` this becomes a persistence primitive;
  - read and modify Jupyter notebooks outside the directory via `notebook_edit_cell` (file_toolkit.py:1507).
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` = 8.2 (High).
  - AV:N -- the tool's path arguments can arrive from network-facing surfaces (agent frameworks processing untrusted content into tool calls; the MCP/OpenAPI/Runtime server surfaces when used), consistent with how the directly comparable agent-tool path-limitation bypass is scored on NVD (CVE-2025-54794, AV:N/PR:N). The library-level route demonstrated in the PoC needs no network.
  - AC:L -- a single fixed relative path defeats the boundary; no preconditions, no race; verified repeatedly.
  - PR:N -- no privileges are required on the attacker side; the toolkit performs no authorization check on path arguments.
  - UI:N -- no user interaction; a tool call is enough.
  - S:U -- the impact is filesystem access from within the CAMEL process (arbitrary read/edit on the host); no new component or authority context is created by the flaw itself.
  - C:H -- arbitrary host file disclosure, demonstrated end to end by the PoC.
  - I:L -- the exercised read path discloses files; the write path (`edit_file`) is the same-root-cause code verified in source, but the dynamic PoC exercised only reads, so integrity is rated Low rather than High.
  - A:N -- no availability impact.

**Scope note (alternate scoring).** If the resolution escape is instead viewed as crossing the toolkit's managed scope (the configured `working_directory`) into host resources beyond it, the same vector with S:C (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N`) scores **9.3** (Critical). Both values were computed with the official FIRST CVSS v3.1 formula: ISS = 1-(1-0.56)x(1-0.22)x(1-0) = 0.656800; Impact(S:U) = 6.42x0.656800 = 4.216656, Impact(S:C) = 7.52x(0.656800-0.029) - 3.25x(0.656800-0.02)^15 = 4.717324; Exploitability = 8.22x0.85x0.77x0.85x0.85 = 3.887043; Base(S:U) = round-up(4.216656+3.887043) = 8.2; Base(S:C) = round-up(1.08x(4.717324+3.887043)) = 9.3.

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
| **Severity** | `High` |
| **Vector string** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` |
| **Score** | `8.2` |

## Weaknesses

| # | CWE | Name | Rationale |
|:--:|------|------|------|
| 1 (primary) | CWE-22 | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | `_resolve_existing_filepath()` joins relative paths onto `working_directory` and only calls `Path.resolve()`, with no sanitization and no containment check (verified verbatim at file_toolkit.py:113-118); both `../` traversal and absolute paths escape |
| 2 | CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | After the escape, host credential, configuration, and key files are readable (the PoC demonstrated disclosure of a credential file located outside the configured directory) |
