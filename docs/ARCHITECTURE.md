# Architecture

## Request path

```
LLM client (DSH / SDK)
    POST /v1/responses  or  /v1/chat/completions
        → privacy-gateway :8317
            1. parse JSON
            2. Layer 0 regex over the whole tree
            3. Layer 1 residual classifier on leftover candidates
            4. forward redacted JSON
        → OpenAI-compatible proxy :8316
        → internet
```

GET `/v1/models` and other non-LLM JSON are proxied untouched.

## What is scanned

Recursive walk of the request JSON, including:

- `instructions`
- `tools[]`
- `messages[].content` / `tool_calls[].function.arguments`
- `input[]` including **`function_call_output.output`** (tool results: file reads, shell)

Skipped keys (protocol identity): `id`, `call_id`, `tool_call_id`, `model`, `object`, `type`, `role`, `name`, `status`, `stream`, `previous_response_id`, `response_id`, `conversation_id`.

Skipped strings: `data:*;base64,` blobs.

## Layer 0

Deterministic patterns, in order:

1. PEM / OpenSSH private keys
2. URI passwords (`postgres://user:pass@host`, also redis / mysql / `https://user:pass@`)
3. JWT
4. Vendor prefixes: `sk-`, `xai-`, `gsk_`, `ghp_` / `github_pat_`, `glpat-`, `AKIA` / `ASIA`, `hf_`, `npm_`, Stripe `sk_live_` / `sk_test_`, Slack `xox*`, Telegram bot, `AIza`, SendGrid, `whsec_`, …
5. `Bearer <token>` (value only)

Existing `<PRIV_…>` placeholders are frozen so they are not nested.

Each distinct secret maps to one placeholder:

```text
<PRIV_{blake2b-8hex}_{TYPE}_{n}>
```

Vault is process memory, TTL 2h from last access.

## Layer 1

After Layer 0, extract up to 8 candidates:

1. assignment values: `password=` / `api_key:` / `token:` / `secret=`
2. remaining Bearer values
3. mixed-class high-entropy tokens (Shannon ≥ 3.3), max 4 per string

Drop hostnames, UUIDs, git SHAs, paths, alphabetic words.

Each candidate is classified by the local 0.5B with the training prompt, `n_predict=1`, `temperature=0`.  
`SECRET*` → vault type `LLM_SECRET`.  
`SAFE`, timeout, or llama down → leave text as-is (fail-open).

Results cached ~1h.

**N100 note:** Q4_K_M GGUF + generation collapsed to SAFE on obvious `sk-` keys. F16 GGUF with the Chinese prompt works. Transformers last-token logits (`SECRET=65310`, `SAFE=83788`) is the original training objective and remains the most faithful scoring path.

## Response restore

- Non-stream / non-SSE: recursive string replace via the vault.
- SSE: one DFA per JSON path so a placeholder split across chunks (`<PR` + `IV_…>`) is reassembled before lookup.

The client UI is supposed to see plaintext again. If the gateway restarts, old placeholders in chat history stay tokenized.

## Operations

| Endpoint | Purpose |
|---|---|
| `GET /privacy/health` | vault + layer1 stats |
| `POST /privacy/dry-run` | redact JSON, do not forward |

Logs: `Vault Intercept: Redacted API_KEY -> <PRIV_…>` (type + placeholder only, never the secret).
