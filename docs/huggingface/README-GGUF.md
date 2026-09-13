---
base_model: Qwen/Qwen2.5-0.5B-Instruct
tags:
- privacy
- security
- credential-detection
- text-classification
- gguf
- qwen
- llama-cpp
- ollama
license: apache-2.0
language:
- zh
- en
pipeline_tag: text-classification
---

# Qwen2.5-0.5B-Privacy-Gateway-v3 (GGUF)

**Runnable gateway (code, systemd, tests):** https://github.com/amwangfan/privacy-gateway

本仓库提供合并 LoRA 并解绑 `lm_head` 后的 GGUF，供 **llama.cpp** 在边缘设备上做残差 `SECRET` / `SAFE` 分类。

---

## 📦 文件

| 文件 | 体积 | 说明 |
|---|---|---|
| `qwen2.5-0.5b-privacy-q4_k_m.gguf` | ~469 MB | 体积小。llama.cpp `n_predict=1` 生成路径在 N100 上可能把明显的 `sk-…` 判成 SAFE。 |
| `qwen2.5-0.5b-privacy-f16.gguf` | ~1.2 GB | N100 生产网关当前使用。中文训练 prompt + `temperature=0` 可用。 |

训练目标是 **末位 logits**（`SECRET=65310` vs `SAFE=83788`），不是自回归生成。优先用 Transformers 读 logits，或 llama.cpp `n_probs`。

---

## 🚀 llama-server

```bash
./llama-server -m qwen2.5-0.5b-privacy-f16.gguf \
  --host 127.0.0.1 --port 8319 \
  -t 2 -c 1024 --temp 0 --repeat-penalty 1.0 --no-webui
```

```bash
curl -X POST http://127.0.0.1:8319/completion \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "判断以下词或短语是否为需要保密的隐私敏感信息（包括密码、API密钥、访问令牌、私钥等），仅回答 SECRET 或 SAFE：\nsk-abcdef1234567890abcdef\n答案：",
    "n_predict": 1,
    "temperature": 0.0,
    "repeat_penalty": 1.0
  }'
```

完整分层网关：[amwangfan/privacy-gateway](https://github.com/amwangfan/privacy-gateway)

---

## 🔗 关联

- **GitHub 工作流**: [amwangfan/privacy-gateway](https://github.com/amwangfan/privacy-gateway)
- **PEFT LoRA**: [venti1888/Qwen2.5-0.5B-Privacy-Gateway-v3-LoRA](https://huggingface.co/venti1888/Qwen2.5-0.5B-Privacy-Gateway-v3-LoRA)
- **基座**: [Qwen/Qwen2.5-0.5B-Instruct](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct)

Apache-2.0
