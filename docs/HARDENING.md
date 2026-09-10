# Edge0 local hardening notes

Local clone: `/Users/first/github/edge0` (private; not for upstream PR).
Date: 2026-09-10 (America/New_York).

This document records **local** mitigations and **documented-only** residual risks from `docs/SECURITY_AUDIT.md`.

## Do this (operator posture)

1. **Keep bind on localhost.** Prefer `edge0 serve … --host 127.0.0.1` (CLI default). Do **not** set `--host 0.0.0.0` or other non-loopback addresses unless you fully understand that the OpenAI-compatible API has **no authentication**.
2. **Wrapper path:** Greg’s `local-fallback-agent/bin/serve-edge0` **forces** loopback (`127.0.0.1` / `localhost`) and rejects other `EDGE0_HOST` values.
3. **Treat checkpoints as trusted code.** Model directories (safetensors, tokenizer files, `chat_template.jinja`, optional HF `auto_map` Python) run at process privilege. Only load **known-good Edge0 HF checkpoints** you fetched intentionally.
4. **Do not point `EDGE0_*_MODEL` / fetch env overrides at unknown Hub repos.**

## Mitigations applied in this local pass

| Area | Change |
| --- | --- |
| Bind / H-03 | CLI default remains `127.0.0.1`; non-loopback `--host` prints a loud stderr warning. Wrapper `serve-edge0` hard-allowlists loopback. |
| Resource limits / H-02 | OpenAI-compatible API enforces: max POST body **1 MiB**; max **64** messages; max **32 768** chars per message; max **131 072** total prompt chars; `max_tokens` clamped to **≤ 2048**. |
| C-01 (auth) | **Local mitigation only via localhost bind** — no bearer auth added. Network exposure still means full unauthenticated inference. |

## Documented only (out of scope this pass)

| Finding | Why documented only |
| --- | --- |
| **C-02** — Non-sandboxed Jinja2 `chat_template.jinja` | Upstream design. **Mitigate by loading only known-good Edge0 checkpoints.** Do **not** implement a Jinja sandbox in this pass. |
| **H-01** — `trust_remote_code=True` on tokenizer load | Upstream load path. **Do not flip `trust_remote_code` in this pass.** Mitigate with known-good checkpoints only. |
| **H-04** — yanked `mlx-lm==0.31.0` | Deferred unless a trivial safe pin bump is revalidated; document only for now. |

## Request limit constants (code)

Defined in `src/edge0/server/chat.py` and `src/edge0/server/app.py`:

- `MAX_BODY_BYTES = 1_048_576`
- `MAX_MESSAGES = 64`
- `MAX_MESSAGE_CHARS = 32_768`
- `MAX_PROMPT_CHARS = 131_072`
- `MAX_MAX_TOKENS = 2048`

## Related

- Full findings: `docs/SECURITY_AUDIT.md`
- Consumer wrapper: `/Users/first/github/local-fallback-agent` (`bin/ask`, `bin/serve-edge0`)
