# Edge0 Security Audit (read-only)

| Field | Value |
| --- | --- |
| Scope | Local clone of `https://github.com/Edge0-AI/edge0` |
| Commit | `0700e6532f45e0d0d99e9c588d7d8cd240538ea0` (`0700e65`) |
| Date | 2026-09-10 (America/New_York) |
| Auditor | Automated security audit (source review only) |
| Remediation | **Local hardening 2026-09-10** — see Remediation status section and `docs/HARDENING.md` |

## Summary

Edge0’s HTTP surface (`edge0 serve`) is an **unauthenticated**, OpenAI-compatible local inference API. The CLI default bind is `127.0.0.1:8000` (good), but operators can bind `0.0.0.0`, after which any network peer can generate against the loaded model, exhaust GPU/RAM, and read model metadata. Weight loading prefers safetensors/mmap (good), but **tokenizer load enables `trust_remote_code=True`**, and the Ling (`edge0-8b`) path renders a **non-sandboxed Jinja2** `chat_template.jinja` from the checkpoint directory — a compromised or swapped model tree can become code execution. Dependencies pin **yanked** `mlx-lm==0.31.0`. Operator scripts (`upload_hf.py`, `fetch_models.py`) add token-forwarding / supply-chain risk outside the serve path.

### Counts by severity

| Severity | Count |
| --- | ---: |
| Critical | 2 |
| High | 4 |
| Medium | 6 |
| Low | 5 |
| Info | 4 |
| **Total** | **21** |

### Top findings (priority)

1. **C-01** — Unauthenticated `/v1/*` chat API (full generation capability).
2. **C-02** — Non-sandboxed Jinja2 chat template loaded from checkpoint (`edge0-8b`).
3. **H-01** — `trust_remote_code=True` on local tokenizer load + checkpoint `auto_map` Python.
4. **H-02** — Unbounded `max_tokens` / prompt size → resource exhaustion DoS.
5. **H-03** — `--host 0.0.0.0` exposes the unauthenticated API LAN/WAN-wide.
6. **H-04** — Pinned dependency `mlx-lm==0.31.0` is **yanked** (KV-cache correctness).

---

## Trust model (as implemented)

- **Intended posture:** single-user / localhost Apple Silicon inference; checkpoint paths chosen by the operator via CLI or `EDGE0_*_MODEL`.
- **HTTP trust boundary:** once `serve` is running, **any client that can TCP-connect** may call `/healthz`, `/v1/models`, and `/v1/chat/completions` with no auth, no API key, no CORS policy, and no rate limit.
- **Model trust boundary:** anything under `model_dir` (safetensors, `config.json`, tokenizer files, `chat_template.jinja`, optional HF remote-code `.py`) is trusted at process privilege.
- **Not in scope of runtime HTTP:** changing which checkpoint is loaded, writing files, or shelling out — those are CLI/script paths.

---

## Findings

### C-01 — No authentication on `/v1/*` (or `/healthz`)

| | |
| --- | --- |
| **Severity** | Critical |
| **Location** | `src/edge0/server/app.py` (`build_app_handlers`, `create_app`, `_StdlibHandler`); `src/edge0/cli.py` `cmd_serve` |
| **Evidence** | Handlers expose `GET /healthz`, `GET /v1/models`, `POST /v1/chat/completions` with no Authorization / API-key check. Docs (`docs/models/edge0-8b.md`) document the same open surface. Tests (`tests/test_server.py`) exercise unauthenticated HTTP end-to-end. |
| **Exploit scenario** | Attacker who can reach the listen address sends chat completions (including streaming), burning GPU/SSD I/O, exfiltrating model behavior, or abusing the host as a free inference endpoint. On a shared machine, any local user can hit `127.0.0.1`. |
| **Recommended fix (describe only)** | Require a bearer token / mutual TLS / unix-socket-only serve mode; reject unauthenticated requests by default; document that network bind implies full trust of all clients. |

### C-02 — Non-sandboxed Jinja2 renders checkpoint `chat_template.jinja` (RCE if template malicious)

| | |
| --- | --- |
| **Severity** | Critical |
| **Location** | `src/edge0/engine/ling.py` `_chat_template` / `encode_chat` (lines ~242–285) |
| **Evidence** | Loads `os.path.join(self.dir, "chat_template.jinja")` into `jinja2.Environment(...).from_string(src)` with `autoescape=False`. Uses plain `Environment`, **not** `SandboxedEnvironment`. Invoked for every Ling chat request via `ChatSession.prompt_ids` → `engine.encode_chat`. Sample tree includes `models/edge0-8b/chat_template.jinja`. |
| **Exploit scenario** | Operator downloads a tampered HF snapshot (or an attacker with write access to the model dir plants a template). First `/v1/chat/completions` (or `edge0 chat/demo`) executes Jinja expressions with full interpreter capability (classic Jinja2 RCE gadgets), at the privilege of the `edge0` process. |
| **Recommended fix (describe only)** | Prefer the tokenizer’s built-in chat template; if a file must be used, render with `SandboxedEnvironment`, disable dangerous attrs/globals, integrity-pin templates (hash allowlist), and refuse unexpected `{%`/`__` constructs. Treat model dirs as executable trust roots in docs. |

### H-01 — `trust_remote_code=True` while loading tokenizers from local checkpoints

| | |
| --- | --- |
| **Severity** | High |
| **Location** | `src/edge0/backends/mlx/io.py` `load_tokenizer`; checkpoint `models/edge0-8b/config.json` `auto_map` → `configuration_bailing_moe_v3.py` / `modeling_bailing_moe_v3.py` |
| **Evidence** | `AutoTokenizer.from_pretrained(model_path, local_files_only=True, trust_remote_code=True)`. Comment acknowledges avoiding mlx-lm hub prompts but still enables remote code. Shipped 8B config registers HF `auto_map` to local Python modules (~100KB+ modeling file). |
| **Exploit scenario** | Malicious or substituted checkpoint ships custom tokenizer/config code executed during `from_pretrained`. Combined with `scripts/fetch_models.py` (any `EDGE0_*_REPO`), this is a supply-chain RCE path at load time — before serve even starts. |
| **Recommended fix (describe only)** | Default `trust_remote_code=False`; require explicit operator opt-in; pin expected file hashes; prefer vendored tokenizer JSON only; never execute checkpoint `.py` for production serve. |

### H-02 — Unbounded client-controlled generation / prompt size (resource exhaustion)

| | |
| --- | --- |
| **Severity** | High |
| **Location** | `src/edge0/server/chat.py` `parse_chat_request` / `gen_config` / `ChatSession.run`; `src/edge0/engine/base.py` `generate`; `src/edge0/server/app.py` POST body read |
| **Evidence** | `max_tokens` taken raw from JSON and merged into `GenerationConfig` with **no clamp**. Tier defaults allow up to 2048, but a client can set `max_tokens` to an arbitrarily large integer; `generate` loops that many steps. Message content length is unlimited. Stdlib transport does `self.rfile.read(length)` for full `Content-Length` with no max. |
| **Exploit scenario** | Unauthenticated (or local) client sends huge `max_tokens` and/or multi-megabyte prompts → prolonged GPU occupancy, memory growth (KV / expert cache), and denial of service for the single-flight queue. Large `Content-Length` can OOM the HTTP worker before inference starts. |
| **Recommended fix (describe only)** | Enforce absolute caps on body bytes, message count/size, prompt tokens, and `max_tokens` (hard ceiling ≤ tier default); reject non-int / negative values; idle and queue timeouts; optional concurrent connection limits. |

### H-03 — Binding `0.0.0.0` (or non-loopback) exposes unauthenticated inference

| | |
| --- | --- |
| **Severity** | High |
| **Location** | `src/edge0/cli.py` (`--host` default `127.0.0.1`); `src/edge0/server/app.py` `run_server` / `run_stdlib` / Flask `app.run` |
| **Evidence** | Default is loopback (good). `--host` is unconstrained; `ThreadingHTTPServer((host, port), …)` and Flask honor any bind address. No warning when host is not loopback. |
| **Exploit scenario** | Operator follows generic “bind all interfaces” advice or uses `--host 0.0.0.0` for LAN demos. Any host on the network gains C-01/H-02 capabilities; on a public IP this is internet-exposed GPU inference. |
| **Recommended fix (describe only)** | Warn / require `--i-understand-network-exposure` for non-loopback binds; default remain `127.0.0.1`; pair with auth (C-01). |

### H-04 — Pinned `mlx-lm==0.31.0` is yanked on PyPI

| | |
| --- | --- |
| **Severity** | High |
| **Location** | `pyproject.toml` dependencies; local `.venv` has `mlx-lm 0.31.0` |
| **Evidence** | Comment pins `0.31.0` for a `tolist()` crash workaround. PyPI marks **0.31.0 yanked** for “Batched KV cache cross contamination”; later 0.31.1–0.31.3 exist. Fresh `pip install` without `--force` may fail or surprise operators. |
| **Exploit scenario** | Correctness bug in yanked release can cross-contaminate batched KV state (integrity of generations). Supply/ops risk: reproducible installs break; operators may `--no-cache-dir` force a known-bad wheel. Not classic RCE, but high integrity impact for an inference stack. |
| **Recommended fix (describe only)** | Retest and move pin to a non-yanked release (≥0.31.3 or currently validated); document compatibility; add CI that fails on yanked pins. |

### M-01 — `scripts/upload_hf.py` re-attaches `Authorization` across cross-host redirects

| | |
| --- | --- |
| **Severity** | Medium |
| **Location** | `scripts/upload_hf.py` (`_handle` patch on `httpx.HTTPTransport.handle_request`) |
| **Evidence** | Custom redirect follower copies request headers (including Authorization) to the next URL, only stripping `host` / `content-length`. Explicitly works around hf-mirror → huggingface.co redirects. Also disables `HfApi._validate_yaml`. Uses `HF_TOKEN` from the environment (huggingface_hub default). |
| **Exploit scenario** | Malicious or compromised mirror/`Location` header causes the client to send the HF write token to an attacker-controlled host (credential theft). YAML validation bypass weakens repo card / config checks. |
| **Recommended fix (describe only)** | Do not forward `Authorization` on cross-origin redirects; allowlist redirect hosts; avoid monkey-patching TLS clients; keep validation enabled; never log tokens. |

### M-02 — `fetch_models.py` allows arbitrary Hub repo via env (supply-chain)

| | |
| --- | --- |
| **Severity** | Medium |
| **Location** | `scripts/fetch_models.py` `_repo_for` / `snapshot_download` |
| **Evidence** | `EDGE0_35B_REPO` / `EDGE0_8B_REPO` override defaults with no format allowlist; downloads straight into `--target-dir`. No checksum verification beyond Hub’s own. |
| **Exploit scenario** | Env injection or foot-gun points fetch at a lookalike repo hosting poisoned weights + remote code / Jinja template → H-01/C-02 on next load. Not classic SSRF to RFC1918 via raw sockets (Hub client), but fetch-abuse / supply-chain. |
| **Recommended fix (describe only)** | Allowlist org/repo; pin revision SHAs; verify published artifact digests; refuse overrides unless `--allow-unofficial-repo`. |

### M-03 — Unbounded safetensors header allocation (mmap / adapter load DoS)

| | |
| --- | --- |
| **Severity** | Medium |
| **Location** | `src/edge0/streaming/mmap.py` `SafetensorsMmap.__init__`; `src/edge0/backends/mlx/io.py` `SafeTensorsStore.__init__` |
| **Evidence** | `header_len = struct.unpack("<Q", …)[0]` then `json.loads` / `read(header_len)` with no maximum. |
| **Exploit scenario** | Crafted `model*.safetensors` or adapter file with huge header length causes large allocation / crash at load (operator or malicious file in model dir). |
| **Recommended fix (describe only)** | Cap header size (e.g. few MiB); validate offsets against file length before mmap views. |

### M-04 — Exception strings returned to HTTP clients (SSE)

| | |
| --- | --- |
| **Severity** | Medium |
| **Location** | `src/edge0/server/app.py` `_chat_stream` `except Exception as exc` → `{"error":{"message": str(exc)}}` |
| **Evidence** | Internal exception text is serialized into the event stream. |
| **Exploit scenario** | Attacker triggers edge-case failures to learn filesystem paths, library versions, or config details useful for further attacks. |
| **Recommended fix (describe only)** | Return generic client errors; log details server-side only. |

### M-05 — Single-flight lock does not bound queue / connection fan-out

| | |
| --- | --- |
| **Severity** | Medium |
| **Location** | `src/edge0/server/chat.py` `QueueServer`; `ThreadingHTTPServer` / Flask `threaded=True` |
| **Evidence** | Generations serialize on a lock, but the HTTP server is threaded: many clients can connect, buffer bodies, and wait. Streaming starts a daemon producer thread per request. |
| **Exploit scenario** | Connection / thread exhaustion and large backlog of pending generations → prolonged DoS even with one active generate. |
| **Recommended fix (describe only)** | Max queue depth with fast 429; limit concurrent HTTP connections; request deadlines; reject new work when saturated. |

### M-06 — Operator `np.load` of legacy adapters (pickle surface on old NumPy / untrusted npz)

| | |
| --- | --- |
| **Severity** | Medium |
| **Location** | `scripts/convert_adapters_legacy.py` `convert` → `np.load(source)` |
| **Evidence** | Loads operator-supplied `.npz` without explicit `allow_pickle=False` (modern NumPy in this venv defaults to `False`, which is safer). Still trusts arbitrary array payloads from `EDGE0_NPZ_DIR` / `--npz-dir`. |
| **Exploit scenario** | On older NumPy or if pickle-containing npz is forced, code execution during conversion. Even without pickle, huge arrays can DoS the converter. |
| **Recommended fix (describe only)** | Always pass `allow_pickle=False`; validate expected keys/shapes; run conversion in a low-privilege context. |

### L-01 — No CORS configuration (browser cross-origin)

| | |
| --- | --- |
| **Severity** | Low |
| **Location** | `src/edge0/server/app.py` (no `Access-Control-*` headers) |
| **Evidence** | Neither Flask nor stdlib handlers set CORS headers. |
| **Exploit scenario** | Browsers will not freely read responses cross-origin (often *helpful*). If operators later add `Access-Control-Allow-Origin: *` without auth, browser-based CSRF-style abuse of the local API becomes easy. |
| **Recommended fix (describe only)** | Keep deny-by-default; if CORS is ever enabled, tie it to auth and explicit origins. |

### L-02 — CLI accepts arbitrary local model / adapter paths (no containment)

| | |
| --- | --- |
| **Severity** | Low |
| **Location** | `src/edge0/cli.py` `_resolve_model`; `src/edge0/models/base.py` `artifact` / `resolve_lora` |
| **Evidence** | Any filesystem path may be passed as the model argument; adapters resolve as `Path(model_dir) / name` with fallback under repo `artifacts/`. HTTP cannot change paths, but a confused-deputy script could. |
| **Exploit scenario** | Local attacker tricks an operator/automation into pointing `EDGE0_*_MODEL` at a malicious directory (symlink farm), combining with C-02/H-01. |
| **Recommended fix (describe only)** | Resolve/`os.path.realpath` and require paths under an allowlisted models root; refuse world-writable dirs. |

### L-03 — `runpy.run_path` for adapter conversion CLI

| | |
| --- | --- |
| **Severity** | Low |
| **Location** | `src/edge0/cli.py` `cmd_convert` |
| **Evidence** | Executes fixed relative `scripts/convert_adapters_legacy.py` via `runpy.run_path` after inserting `scripts` on `sys.path`. Path is not user-controlled. |
| **Exploit scenario** | If an attacker can write that script path in an editable install, `edge0 convert-adapters` runs their code. Requires prior filesystem write. |
| **Recommended fix (describe only)** | Import a package module instead of `runpy` on a filesystem path. |

### L-04 — Flask debug not enabled, but Flask is optional and threaded

| | |
| --- | --- |
| **Severity** | Low |
| **Location** | `src/edge0/server/app.py` `app.run(host=..., port=..., threaded=True)` |
| **Evidence** | `debug` not passed (defaults False — good). CLI passes `use_flask=args.flask` (default False). Library `run_server(..., use_flask=None)` auto-selects Flask if importable. |
| **Exploit scenario** | Mis-integrated callers enabling debug later would expose Werkzeug consoles; today residual risk is mainly threaded request handling (see M-05). |
| **Recommended fix (describe only)** | Keep debug off permanently; make stdlib the only supported production transport; avoid auto-selecting Flask. |

### L-05 — Undeclared direct dependency on `transformers` / `jinja2`

| | |
| --- | --- |
| **Severity** | Low |
| **Location** | `src/edge0/backends/mlx/io.py`; `src/edge0/engine/ling.py`; `pyproject.toml` |
| **Evidence** | Runtime imports `transformers.AutoTokenizer` and `jinja2`, but `pyproject.toml` only lists mlx/mlx-lm/numpy/safetensors/tokenizers/psutil (+ optional huggingface_hub). They arrive transitively today (`transformers` via mlx-lm). |
| **Exploit scenario** | Version drift / alternate backends can break or silently change security-sensitive defaults (`trust_remote_code` behavior across transformers majors). |
| **Recommended fix (describe only)** | Declare and pin direct dependencies with security-reviewed floors. |

### I-01 — Default bind `127.0.0.1:8000` is a sound localhost default

| | |
| --- | --- |
| **Severity** | Info |
| **Location** | `src/edge0/cli.py` `--host` / `--port` defaults; `run_server` defaults |
| **Evidence** | Defaults are loopback. README curl examples use `127.0.0.1`. |
| **Exploit scenario** | N/A (positive control). |
| **Recommended fix (describe only)** | Preserve default; add loud warnings for non-loopback (see H-03). |

### I-02 — Weight path prefers safetensors / mmap (avoids `torch.load` / pickle in hot path)

| | |
| --- | --- |
| **Severity** | Info |
| **Location** | `src/edge0/backends/mlx/io.py`; `src/edge0/streaming/mmap.py`; adapters via `load_safetensors` |
| **Evidence** | No `pickle`/`torch.load` in `src/` serve path; experts streamed from safetensors byte ranges. |
| **Exploit scenario** | N/A (positive control). Residual risks are header DoS (M-03) and trusting tensor math from untrusted files. |
| **Recommended fix (describe only)** | Keep safetensors-only policy; extend to ban npz in runtime paths. |

### I-03 — No shell=`True` / `os.system` / `subprocess` in library serve path

| | |
| --- | --- |
| **Severity** | Info |
| **Location** | `src/`, `scripts/` (grep) |
| **Evidence** | No `subprocess`, `os.system`, or `shell=True` in audited Python. `mx.async_eval` / `core.eval` are MLX APIs, not Python `eval`. |
| **Exploit scenario** | N/A for classic command injection in fetch (Hub API used). Script risk is elsewhere (M-01/M-02). |
| **Recommended fix (describe only)** | Maintain ban in CI grep tests. |

### I-04 — CORS absent; OpenAI surface is intentionally minimal

| | |
| --- | --- |
| **Severity** | Info |
| **Location** | Server + docs |
| **Evidence** | Only health/models/chat; `/v1/completions` returns 400. |
| **Exploit scenario** | Smaller attack surface than a full OpenAI gateway, but chat alone is enough for C-01/H-02. |
| **Recommended fix (describe only)** | Keep surface minimal; add auth before any expansion. |

---

## Checklist coverage

| # | Topic | Result |
| --- | --- | --- |
| 1 | Trust boundaries — default host/bind, auth on `/v1/*`, CORS | Default `127.0.0.1`; **no auth**; **no CORS** (C-01, H-03, L-01, I-01) |
| 2 | Path traversal loading models/adapters | No HTTP path params; CLI paths unconstrained (L-02); adapter names fixed strings under `model_dir` |
| 3 | Unsafe deserialization / weight loading | Safetensors-first (I-02); Jinja + `trust_remote_code` (C-02, H-01); npz converter (M-06); unbounded headers (M-03) |
| 4 | Command injection in scripts | No shell invocation in `fetch_models` (I-03); Hub `repo_id` env override (M-02) |
| 5 | Dependency risks | **Yanked** `mlx-lm==0.31.0` (H-04); undeclared transformers/jinja2 (L-05) |
| 6 | Secrets (HF token, logging) | Token via env; redirect header re-attach (M-01); no token print observed in upload script |
| 7 | SSRF / fetch abuse | Upload redirect credential leak (M-01); fetch repo override (M-02) |
| 8 | Exposure if serve binds `0.0.0.0` | Full unauthenticated API exposure (H-03 + C-01) |
| 9 | Resource exhaustion | Unbounded `max_tokens`/body/prompt; thread fan-out (H-02, M-05) |
| 10 | eval/exec/pickle/subprocess | No Python `eval`/`exec`/`subprocess` in serve path; Jinja RCE equivalent (C-02); `runpy` (L-03); `np.load` (M-06) |

---

## Out of scope / non-findings

- No remediation or package code changes were made in this audit.
- CloudAgent/GitHub org access issues are environmental, not product vulns.
- Functional bug: `scripts/fetch_models.py` success print uses `.replace` on a **tuple** (`TIER_REPOS[tier]`) and would throw after download — quality issue, not scored as a security finding.
- Docs claim streaming “requires Flask”; stdlib path also implements SSE — documentation drift only.

---

## Suggested verification (for humans; not run as exploits here)

1. Confirm `edge0 serve --help` shows `--host` default `127.0.0.1`.
2. Confirm no auth headers required against a running server (already covered by unit tests).
3. On a disposable VM only: place a canary Jinja template under a fake model dir and observe whether `encode_chat` evaluates expressions (validates C-02).
4. `pip index versions mlx-lm` / PyPI page to reconfirm yank status before changing pins.

---

*End of report.*


---

## Remediation status (local clone, 2026-09-10 America/New_York)

Private local hardening only — **do not PR upstream** from this pass.

| ID | Status | Notes |
| --- | --- | --- |
| **C-01** | **Local mitigation** | No auth added. Mitigated by keeping bind on `127.0.0.1` (CLI default + wrapper enforce + non-loopback warning). Documented in `docs/HARDENING.md`. |
| **C-02** | **Documented only** | Jinja sandbox **not** implemented. Mitigate by loading only known-good Edge0 HF checkpoints. |
| **H-01** | **Documented only** | `trust_remote_code` **not** flipped. Mitigate via known-good checkpoints only. |
| **H-02** | **Local mitigation** | Request limits: max body 1 MiB; max messages/prompt chars; `max_tokens` hard ceiling 2048 (`server/chat.py`, `server/app.py`). |
| **H-03** | **Local mitigation** | Default `127.0.0.1`; loud warning on non-loopback; `local-fallback-agent/bin/serve-edge0` forces loopback. |
| **H-04** | **Deferred** | Yanked `mlx-lm==0.31.0` not upgraded in this pass (not trivial/safe without revalidation). |
| Other M/L/I | **Deferred / documented** | See original findings; not in Greg’s local-hardening scope this pass. |

See also: `docs/HARDENING.md`.

