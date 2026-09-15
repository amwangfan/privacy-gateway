# Privacy Gateway

Local reverse proxy that **redacts credentials before they leave the intranet**, then **restores them on the way back**.

Layer 0 is high-precision regex (API keys, PEM, JWT, DB URI passwords, …).  
Layer 1 is a residual `SECRET` / `SAFE` classifier: [Qwen2.5-0.5B](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct) LoRA, only on leftover secret-shaped spans.

Weights live on Hugging Face. This repository is the **runnable workflow** (gateway, merge, systemd, tests) so it can keep evolving.

| Artifact | Where |
|---|---|
| Gateway + deploy + tests | **this repo** |
| **v4 LoRA + GGUF (current N100)** | [amwangfan/privacy-gateway-v4-qwen2.5-0.5b](https://huggingface.co/amwangfan/privacy-gateway-v4-qwen2.5-0.5b) |
| v3 LoRA (previous) | [amwangfan/Qwen2.5-0.5B-Privacy-Gateway-v3-LoRA](https://huggingface.co/amwangfan/Qwen2.5-0.5B-Privacy-Gateway-v3-LoRA) |
| v3 GGUF (previous) | [amwangfan/Qwen2.5-0.5B-Privacy-Gateway-v3-GGUF](https://huggingface.co/amwangfan/Qwen2.5-0.5B-Privacy-Gateway-v3-GGUF) |

v4 eval vs v3: [docs/V4.md](docs/V4.md). Serve prompt: `Secret? k={key} v={span} c={ctx} ->` (empty ctx → SAFE).

License: Apache-2.0.

---

## 它做什么

把 LLM 客户端（DeepSeek Harness / OpenAI SDK / CLIProxy）指到本机网关，而不是直接出网：

```
client  →  :8317 privacy-gateway  →  :8316 your OpenAI-compatible proxy  →  internet
                 ↑
            :8319 llama-server   (optional Layer 1)
```

- 入站：在 `messages` / `input` / `instructions` / `tools` / **`function_call_output.output`** 整棵 JSON 上替换密钥为 `<PRIV_{blake2}_{TYPE}_{n}>`，明文只留在本机内存 Vault。
- 出站：非流式整棵还原；SSE 按字段 DFA 拼接被切开的占位符。
- 本地 UI 设计上仍看到明文；云端只看到占位符。

详见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。后续优化方向见 [docs/ROADMAP.md](docs/ROADMAP.md)。

---

## 快速跑通（仅 Layer 0）

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export BACKEND_URL=http://127.0.0.1:8316   # 你的 OpenAI 兼容上游
export LAYER1_ENABLED=0                    # 先不加载 0.5B
python gateway.py                          # 0.0.0.0:8317
```

客户端 `base_url` 改成 `http://127.0.0.1:8317/v1`。

不打上游的脱密自测：

```bash
python tests/test_unit.py
curl -s http://127.0.0.1:8317/privacy/dry-run \
  -H 'Content-Type: application/json' \
  -d '{"input":[{"type":"function_call_output","call_id":"c1","output":"key=sk-abcdefghijklmnopqrstuvwxyz012345"}]}'
curl -s http://127.0.0.1:8317/privacy/health
```

---

## 启用 Layer 1（0.5B 残差分类）

1. 下载权重：

```bash
bash scripts/download-models.sh ./models
```

2. 合并 LoRA（可选；GGUF 仓库已提供量化文件）：

```bash
pip install -r requirements-merge.txt
python merge_lora.py \
  --lora-path ./models/privacy-gateway-v3-lora \
  --base-model Qwen/Qwen2.5-0.5B-Instruct \
  --output-dir ./qwen2.5-0.5b-privacy-merged
```

3. 用 llama.cpp 提供分类服务（**Intel N100 上请用 F16 GGUF**；仓库里的 Q4_K_M 在 `n_predict=1` 生成路径上会把 `sk-…` 判成 SAFE。Transformers 末位 logits 仍可用）：

```bash
# build llama.cpp yourself, then:
llama-server -m ./qwen2.5-0.5b-privacy-f16.gguf \
  --host 127.0.0.1 --port 8319 -t 2 -c 1024 --temp 0 --repeat-penalty 1.0 --no-webui
```

分类 prompt（必须与训练一致）：

```text
判断以下词或短语是否为需要保密的隐私敏感信息（包括密码、API密钥、访问令牌、私钥等），仅回答 SECRET 或 SAFE：
<candidate>
答案：
```

4. 打开网关残差：

```bash
export LAYER1_ENABLED=1
export LAYER1_URL=http://127.0.0.1:8319
python gateway.py
```

systemd 模板在 [`deploy/`](deploy/)。

---

## 生产注意

- Vault 在内存，网关重启后旧 `<PRIV_…>` 无法还原。
- 不改写 `call_id` / `model` / `name` 等协议字段；不扫描 `data:image…;base64`。
- `Authorization` 头不脱密（通常只打到本机代理）。
- Layer 1 失败/超时 **fail-open**（Layer 0 结果仍有效），单请求最多约 2.5s、8 个候选。
- 绕过 8317 的客户端（例如直连官方 API）不会被保护。

---

## 仓库结构

```
gateway.py              # 运行时网关
merge_lora.py           # LoRA 合并 + lm_head 解绑校验
tests/test_unit.py      # 不连上游、不连 llama
deploy/*.service        # systemd
scripts/download-models.sh
docs/ARCHITECTURE.md
docs/ROADMAP.md
docs/huggingface/       # 可粘贴回 HF 模型卡（补 GitHub 链接）
```
