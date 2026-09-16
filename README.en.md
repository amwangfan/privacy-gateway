# Privacy Gateway

**English** | [简体中文](README.md)

A lightweight local reverse proxy: **automatically redacts sensitive credentials (API keys, tokens, private keys, database passwords, etc.) before leaving the intranet, and seamlessly restores them on the return path via a DFA stream engine**.

Designed for LLM coding agents and development environments (DeepSeek Harness, Claude Code, Cursor, CLIProxyAPI, OpenAI SDK, etc.), keeping internal code and conversation secrets safe from WAN leaks.

---

## 🎯 Key Features

- **🛡️ Defense-in-Depth Architecture**:
  - **Layer 0 (Deterministic Rule Engine)**: Millisecond-level pattern matching for cloud platform keys (OpenAI / Anthropic / GitHub / AWS / Hugging Face / Stripe / Slack / Telegram, etc.), PEM private key blocks, 3-part JWTs, database connection URIs (PostgreSQL / MySQL / Redis / MongoDB), and Bearer tokens.
  - **Layer 1 (Qwen2.5-0.5B Residual Semantic Classifier)**: A dedicated lightweight model [Qwen2.5-0.5B](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct) fine-tuned for credential classification, evaluating leftover high-entropy tokens and hardcoded script variables with single-step `SECRET` vs `SAFE` forward passes.
- **🔑 Flexible User-Defined Keys and Rules**:
  - **Custom Master Password**: Define `VAULT_PASSWORD` via environment variables to derive an AES-256 master key using PBKDF2-HMAC-SHA256, removing reliance on single-host random key files.
  - **Custom Secret Token Allowlist/Denylist**: Define `CUSTOM_SECRETS` or `/etc/privacy-gateway/custom_secrets.txt` to enforce Layer 0 immediate redaction on proprietary corporate tokens and internal passwords.
- **⚡ High Concurrency & Batch Optimization**:
  - Supports `llama-server` multi-slot parallel inference (`--parallel 2`).
  - Batch evaluation reduces prompt eval latency from seconds down to ~200-400ms.
  - Intelligent filtering of known code identifiers and LLM model names (`claude-sonnet`, `grok-4`, etc.), prioritizing newest turns in reverse traversal.
- **💾 AES-GCM-256 Encrypted Persistent Storage (SQLite WAL)**:
  - Local encrypted persistence for placeholder mappings and classification cache. Plaintext never hits the disk unencrypted. Historical placeholders (`<SECRET_...>`) remain restorable even after gateway reboots.
- **🔄 Zero-Latency DFA Stream Restoration (DFA Stream Restorer)**:
  - Built-in multi-channel Deterministic Finite Automaton (DFA) accurately reassembles placeholders split across streaming SSE chunks (e.g. `<SEC` + `RET_API_KEY_1>`), ensuring the client UI always displays the original plaintext.

---

## 📦 Ecosystem Repositories & Weights

| Component | Role | Repository |
|---|---|---|
| **`privacy-gateway`** (This Repo) | Standalone core reverse proxy (Python / FastAPI / DFA) | [GitHub: amwangfan/privacy-gateway](https://github.com/amwangfan/privacy-gateway) |
| **`dsh-privacy-guard`** | DeepSeek Harness Web plugin & dashboard | [GitHub: amwangfan/dsh-privacy-guard](https://github.com/amwangfan/dsh-privacy-guard) |
| **`qwen2.5-0.5b-privacy-v4`** | Fine-tuned residual credential classifier (LoRA + GGUF) | [HuggingFace: amwangfan/<SECRET_LLM_SECRET_89>.5-0.5b](https://huggingface.co/amwangfan/<SECRET_LLM_SECRET_89>.5-0.5b) |
| **`qwen2.5-0.5b-privacy-v3`** | Baseline model (LoRA / GGUF) | [HuggingFace: amwangfan/Qwen2.5-0.<SECRET_LLM_SECRET_60>](https://huggingface.co/amwangfan/Qwen2.5-0.<SECRET_LLM_SECRET_60>) |

---

## 🚀 Architecture & Request Flow

```
Client (DSH / SDK / Cursor)
    │  POST /v1/chat/completions or /v1/responses
    ▼
:8317 privacy-gateway (Local Proxy)
    ├─ 1. Recursive JSON traversal (User message, history, tool arguments & outputs)
    ├─ 2. Layer 0: High-precision regex (OpenAI / GitHub / PEM / JWT / DB password / Custom secrets)
    ├─ 3. Layer 1: Reverse candidate collection -> Batch classification via :8319 0.5B model (SECRET vs SAFE)
    ├─ 4. Encrypted Local Vault: Plaintext <-> <SECRET_TYPE_N>
    ▼ (Egress payload containing only placeholders)
:8316 Upstream Proxy (e.g. cliproxyapi) / Official API
    ▼
Upstream Cloud LLM (Cloud model never sees real credentials)
    │
    ▼ (Streaming SSE / JSON response)
:8317 privacy-gateway (DFA Stream Restorer)
    └─ Reassembles chunked placeholders and restores to original plaintext
    ▼
Client UI displays restored plaintext seamlessly
```

---

## 🛠️ Quick Start

### Mode A: Rule-Only Mode (Ultra-lightweight, < 50MB RAM, zero GPU/model overhead)

Covers > 90% of standard cloud platform keys, certificates, and database strings:

```bash
git clone https://github.com/amwangfan/privacy-gateway.git
cd privacy-gateway

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure your upstream LLM endpoint
export BACKEND_URL=http://127.0.0.1:8316
export LAYER1_ENABLED=0  # Disable local 0.5B model

python gateway.py        # Listens on 0.0.0.0:8317
```

Set your client tool's `base_url` to `http://127.0.0.1:8317/v1`.

---

### Mode B: Full Mode (Layer 0 Rules + Layer 1 Qwen 0.5B AI Residual Classification)

Adds full semantic detection for custom un-prefixed tokens and code variable passwords:

#### 1. Download Model Weights
```bash
bash scripts/download-models.sh ./models
# Or download directly from Hugging Face:
# https://huggingface.co/amwangfan/<SECRET_LLM_SECRET_89>.5-0.5b
```

#### 2. Start llama-server (Recommended: F16 or Q8_0 GGUF with 2 parallel slots)
```bash
./llama-server \
  -m ./models/qwen2.5-0.5b-privacy-v4-f16.gguf \
  --host 127.0.0.1 \
  --port 8319 \
  -t 2 \
  -c 1024 \
  --parallel 2 \
  --temp 0 \
  --repeat-penalty 1.0 \
  --no-webui
```

#### 3. Start Privacy Gateway
```bash
export BACKEND_URL=http://127.0.0.1:8316
export LAYER1_ENABLED=1
export LAYER1_URL=http://127.0.0.1:8319
export LAYER1_CONCURRENCY=2

python gateway.py
```

---

## ⚙️ Environment Variables & Configuration

| Variable | Default | Description |
|---|---|---|
| `GATEWAY_PORT` | `8317` | Gateway listening port |
| `BACKEND_URL` | `http://127.0.0.1:8316` | Upstream model/proxy URL |
| `VAULT_PERSIST` | `1` | Enable encrypted SQLite WAL persistence (1: on, 0: in-memory only) |
| `VAULT_DB_PATH` | `/var/lib/privacy-gateway/store.sqlite` | Path to persistent encrypted database |
| `VAULT_PASSWORD` | *(empty)* | **Custom master encryption passphrase** (derives AES-256 key via PBKDF2) |
| `VAULT_KEY_FILE` | `/etc/privacy-gateway/master.key` | Key file path (auto-generated if password is not set) |
| `CUSTOM_SECRETS` | *(empty)* | Comma-separated custom secrets/tokens to always redact in Layer 0 |
| `CUSTOM_SECRETS_FILE`| `/etc/privacy-gateway/custom_secrets.txt` | Path to file with custom secrets (one per line) |
| `RESTORE_OUTBOUND` | `1` | Restore placeholders back to plaintext on return path |
| `LAYER1_ENABLED` | `1` | Enable 0.5B residual classifier |
| `LAYER1_URL` | `http://127.0.0.1:8319` | llama-server endpoint URL |
| `LAYER1_CONCURRENCY` | `2` | Number of parallel evaluation slots |
| `LAYER1_MAX_CANDIDATES`| `8` | Maximum unknown tokens evaluated per request |
| `LAYER1_TIMEOUT` | `3.8` | Timeout per model inference batch (seconds, fail-open on timeout) |

---

## 🧪 Testing & Validation

Run the offline unit test suite (12/12 passing, zero external dependencies):

```bash
python tests/test_unit.py
```

Dry-run simulation test (100% local, no egress):
```bash
curl -s http://127.0.0.1:8317/privacy/dry-run \
  -H 'Content-Type: application/json' \
  -d '{"text": "test key: <SECRET_API_KEY_17>, db: my_pass_123"}'
```

Query gateway health and persistence status:
```bash
curl -s http://127.0.0.1:8317/privacy/health | python3 -m json.tool
```

---

## 📄 License

Licensed under the [Apache-2.0 License](LICENSE).
