---
base_model: Qwen/Qwen2.5-0.5B-Instruct
library_name: peft
tags:
- privacy
- security
- credential-detection
- text-classification
- lora
- qwen
- edge-ai
license: apache-2.0
language:
- zh
- en
pipeline_tag: text-classification
---

# Qwen2.5-0.5B-Privacy-Gateway-v3 (PEFT LoRA)

**Runnable gateway (code, systemd, tests):** https://github.com/amwangfan/privacy-gateway

**Qwen2.5-0.5B-Privacy-Gateway-v3-LoRA** 是专为**本地隐私脱敏网关（Local Privacy Gateway）**微调的轻量级凭据判别模型。

针对大模型在处理含有 API Key、访问令牌、密码、数据库连接串等敏感凭据时的隐私泄漏风险，本模型用于在网关层执行**单步 Logits 二分类判别（`SECRET` vs `SAFE`）**，结合确定性规则与本地占位符映射，实现**敏感数据在离开本地网络前透明脱敏、流式回包时本地透明还原**。

---

## 🎯 核心特性与技术亮点

1. **零自回归采样，直接读取末位 Logits**：
   - 彻底摒弃传统 `generate()` 方式，直接提取最后一个 Token 对应 `SECRET` (ID: 65310) 与 `SAFE` (ID: 83788) 的 Logits 分数进行相对概率比较。
   - **格式异常归零**：杜绝小模型在长文本或分类输出中生成随机字符或 INVALID 格式的现象。
   - **单步前向超低延迟**：仅需单次前向（Forward Pass），边缘设备（如 Intel N100）上 Transformers 推理约 **20–40ms**。
2. **全线性层微调与输出层解绑**：
   - 采用 LoRA 微调所有线性层，并专门微调了输出投影层 `lm_head`（rank=16, alpha=32）。
   - 在合并时解绑 `lm_head`（`tie_word_embeddings = False`），增强对分类目标 Token 的区分度。
3. **真实基准评测表现（Empirical Metrics）**：
   - **IID 测试集** (250 docs, 880 candidates): Recall 100.0% / Precision 100.0% / F1 1.0000 / INVALID 0
   - **OOD 域外泛化测试集** (250 docs, 848 candidates): Recall 89.27% / Precision 99.57% / F1 0.9414 / INVALID 0

---

## 📦 关联资源

- **网关工作流 (GitHub)**: [amwangfan/privacy-gateway](https://github.com/amwangfan/privacy-gateway)
- **开箱即用 GGUF**: [amwangfan/Qwen2.5-0.5B-Privacy-Gateway-v3-GGUF](https://huggingface.co/amwangfan/Qwen2.5-0.5B-Privacy-Gateway-v3-GGUF)
- **基座模型**: [Qwen/Qwen2.5-0.5B-Instruct](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct)

---

## 🚀 快速上手 (Quick Start)

```python
import torch
import torch.nn.functional as F
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

base_model_name = "Qwen/Qwen2.5-0.5B-Instruct"
lora_model_name = "amwangfan/Qwen2.5-0.5B-Privacy-Gateway-v3-LoRA"

tokenizer = AutoTokenizer.from_pretrained(base_model_name)
base_model = AutoModelForCausalLM.from_pretrained(base_model_name, torch_dtype=torch.float16, device_map="auto")
model = PeftModel.from_pretrained(base_model, lora_model_name)
model.eval()

TOKEN_ID_SECRET = 65310  # 'SECRET'
TOKEN_ID_SAFE = 83788    # 'SAFE'

def classify_credential(candidate_text: str, threshold: float = 0.5):
    prompt = (
        "判断以下词或短语是否为需要保密的隐私敏感信息"
        "（包括密码、API密钥、访问令牌、私钥等），"
        f"仅回答 SECRET 或 SAFE：\n{candidate_text}\n答案："
    )
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    with torch.inference_mode():
        outputs = model(**inputs)
        next_logits = outputs.logits[0, -1, :].float()
        score_secret = next_logits[TOKEN_ID_SECRET]
        score_safe = next_logits[TOKEN_ID_SAFE]
        pair_probs = F.softmax(torch.stack([score_secret, score_safe]), dim=0)
        p_secret = pair_probs[0].item()
    return {
        "candidate": candidate_text,
        "is_sensitive": p_secret >= threshold,
        "p_secret": p_secret,
        "diff": (score_secret - score_safe).item()
    }

print(classify_credential("sk-example-not-a-real-key-1234567890"))
print(classify_credential("今天天气晴朗适合散步"))
```

完整网关（正则 Layer 0 + 本模型残差 + Vault 还原）见 GitHub，不要把整段对话丢进 0.5B。

---

## 🛡️ 隐私网关分层落地

- **Layer 0**：PEM、已知前缀 Key、JWT、数据库 URI 密码，纯正则拦截。
- **Layer 1**：未命中 Layer 0 的赋值 / Bearer / 高熵串。无候选则 0ms。
- **Layer 2**：仅对未知候选做单步 Logits 判定。
- **Vault + 流式还原**：`<PRIV_{hash8}_{TYPE}_{N}>`，出站 DFA 还原。

Apache-2.0
