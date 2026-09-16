# Privacy Gateway (隐私脱密网关)

[English](README.en.md) | **简体中文**

本地轻量级反向代理：**在敏感凭据（API Key、Token、私钥、数据库密码等）离开内网前自动脱敏替换为占位符，流式回显时通过 DFA 状态机无感还原回明文**。

面向大模型编程工具（DeepSeek Harness、Claude Code、Cursor、CLIProxyAPI、OpenAI SDK 等），保护核心代码与对话数据出网安全。

---

## 🎯 核心特性

- **🛡️ 双层纵深防御 (Defense-in-Depth)**：
  - **Layer 0（确定性规则引擎）**：毫秒级精准匹配并拦截主流云厂商 Key（OpenAI / Anthropic / GitHub / AWS / Hugging Face / Stripe / Slack / Telegram 等）、PEM 私钥块、三段式 JWT、数据库连接串密码（PostgreSQL / MySQL / Redis / MongoDB 等）及 Bearer 令牌。
  - **Layer 1（千问 0.5B 语义残差分类）**：专为凭据判别微调的轻量模型 [Qwen2.5-0.5B](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct)，仅对 Layer 0 漏网的高熵自定义字符串、脚本变量口令执行单步 `SECRET` vs `SAFE` 判定。
- **🔑 灵活的自定义密钥与规则**：
  - **自定义主加密密码**：支持通过环境变量 `VAULT_PASSWORD` 设置自定义口令，采用 PBKDF2-HMAC-SHA256 派生 AES-256 主密钥，无需依赖单机随机密钥文件。
  - **自定义业务凭据词表**：支持通过 `CUSTOM_SECRETS` 或 `custom_secrets.txt` 载入企业/内部敏感词表，享 Layer 0 最高优先级强制脱密。
- **⚡ 高并发与批处理优化**：
  - 支持 `llama-server` 多槽位并发推理（默认 2 槽位并行）。
  - 支持候选词批量（Batch）一次性提交模型判别，耗时从秒级降低至 200~400ms。
  - 智能过滤已知代码标识符、模型名称（`claude-sonnet`、`grok-4` 等），优先倒序扫描最新输入。
- **💾 AES-GCM-256 加密持久化存储 (SQLite WAL)**：
  - 本地加密落盘保存占位符映射与模型判定结果，明文永不直接落地。网关重启后历史会话的 `<SECRET_...>` 依然可无感还原。
- **🔄 零延迟出网流式还原 (DFA Stream Restorer)**：
  - 针对 SSE 流式切片可能截断占位符（如 `<SEC` + `RET_API_KEY_1>`）的问题，内置多通道确定性有限状态自动机（DFA），流式拼接还原，客户端 UI 看到的始终是原始明文。

---

## 📦 关联生态与模型产物

| 组件 | 角色与定位 | 仓库地址 |
|---|---|---|
| **`privacy-gateway`** (本仓库) | 独立反向代理网关核心（Python / FastAPI / DFA） | [GitHub: amwangfan/privacy-gateway](https://github.com/amwangfan/privacy-gateway) |
| **`dsh-privacy-guard`** | DeepSeek Harness Web 专属监控看板与沙箱插件 | [GitHub: amwangfan/dsh-privacy-guard](https://github.com/amwangfan/dsh-privacy-guard) |
| **`qwen2.5-0.5b-privacy-v4`** | 专为凭据判别微调的模型权重 (LoRA + GGUF) | [HuggingFace: amwangfan/privacy-gateway-v4-qwen2.5-0.5b](https://huggingface.co/amwangfan/privacy-gateway-v4-qwen2.5-0.5b) |
| **`qwen2.5-0.5b-privacy-v3`** | 早期基线模型 (LoRA / GGUF) | [HuggingFace: amwangfan/Qwen2.5-0.5B-Privacy-Gateway-v3-LoRA](https://huggingface.co/amwangfan/Qwen2.5-0.5B-Privacy-Gateway-v3-LoRA) |

---

## 🚀 架构原理与请求流向

```
客户端 (DSH / SDK / Cursor)
    │  POST /v1/chat/completions 或 /v1/responses
    ▼
:8317 privacy-gateway (本地脱密网关)
    ├─ 1. JSON 递归解析 (涵盖用户输入、历史记录、工具调用参数与输出正文)
    ├─ 2. Layer 0: 正则高精识别 (OpenAI/GitHub/PEM/JWT/DB 密码/自定义凭据)
    ├─ 3. Layer 1: 倒序过滤高熵词 -> 批量送入 :8319 0.5B 模型分类 (SECRET vs SAFE)
    ├─ 4. 本地 Vault 加密记录映射: 明文 <-> <SECRET_TYPE_N>
    ▼ (请求体中的真实凭据已被全面占位符化)
:8316 聚合中转站 (如 cliproxyapi) / 官方 API
    ▼
公网上游大模型服务 (云端模型只接收和处理占位符，绝不触碰真实凭据)
    │
    ▼ (流式 SSE / JSON 回复出网流向客户端)
:8317 privacy-gateway (DFA 流式还原引擎)
    └─ 按字段 DFA 拼合分片占位符，查本地 Vault 还原回明文
    ▼
客户端看到还原后的完整代码与对话
```

---

## 🛠️ 快速跑通

### 方式 A：纯规则模式（极轻量，无需本地 GPU/模型，内存占用 < 50MB）

纯规则层可覆盖 90% 以上的标准云平台 Key 与私钥凭据：

```bash
git clone https://github.com/amwangfan/privacy-gateway.git
cd privacy-gateway

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 设置上游地址（如本地的 cliproxyapi 或其他 OpenAI 兼容网关）
export BACKEND_URL=http://127.0.0.1:8316
export LAYER1_ENABLED=0  # 关闭模型残差分类

python gateway.py        # 默认监听 0.0.0.0:8317
```

将你的客户端（如 DSH、Cursor、OpenAI SDK）的 `base_url` 改为 `http://127.0.0.1:8317/v1` 即可享受保护。

---

### 方式 B：全功能模式（Layer 0 规则 + Layer 1 千问 0.5B AI 残差分类）

具备针对无前缀自定义 Token、代码变量硬编码口令的完整语义判别能力：

#### 1. 下载模型权重
```bash
bash scripts/download-models.sh ./models
# 或直接从 Hugging Face 获取 GGUF 文件：
# https://huggingface.co/amwangfan/privacy-gateway-v4-qwen2.5-0.5b
```

#### 2. 启动 llama-server 推理后台（推荐使用 F16 或 Q8_0 版本，开启 2 槽位并行）
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

#### 3. 启动脱密网关
```bash
export BACKEND_URL=http://127.0.0.1:8316
export LAYER1_ENABLED=1
export LAYER1_URL=http://127.0.0.1:8319
export LAYER1_CONCURRENCY=2

python gateway.py
```

---

## ⚙️ 环境变量与配置清单

| 环境变量 | 默认值 | 作用说明 |
|---|---|---|
| `GATEWAY_PORT` | `8317` | 脱密网关监听端口 |
| `BACKEND_URL` | `http://127.0.0.1:8316` | 上游真实大模型/中转代理服务地址 |
| `VAULT_PERSIST` | `1` | 是否开启本地加密 SQLite WAL 持久化存储 (1: 开启, 0: 纯内存) |
| `VAULT_DB_PATH` | `/var/lib/privacy-gateway/store.sqlite` | 加密数据库文件存储路径 |
| `VAULT_PASSWORD` | *(空)* | **用户自定义主加密密码**（若设置，自动采用 PBKDF2 派生 AES-256 密钥） |
| `VAULT_KEY_FILE` | `/etc/privacy-gateway/master.key` | 主密钥文件路径（未设置密码时自动生成 0600 权限文件） |
| `CUSTOM_SECRETS` | *(空)* | 逗号分隔的自定义敏感词/密码列表（Layer 0 最高优先级脱密） |
| `CUSTOM_SECRETS_FILE`| `/etc/privacy-gateway/custom_secrets.txt` | 自定义敏感凭据词表文本文件路径（每行一条） |
| `RESTORE_OUTBOUND` | `1` | 是否在回流时自动将占位符还原回明文显示 |
| `LAYER1_ENABLED` | `1` | 是否启用千问 0.5B 本地模型做残差判别 |
| `LAYER1_URL` | `http://127.0.0.1:8319` | llama-server 推理端点地址 |
| `LAYER1_CONCURRENCY` | `2` | 模型判别并发数 |
| `LAYER1_MAX_CANDIDATES`| `8` | 单次请求允许评估的最大生词候选数 |
| `LAYER1_TIMEOUT` | `3.8` | 单批次模型推理超时时间 (秒，超时自动 fail-open 放行) |

---

## 🧪 验证与自测

项目提供完整的离线单元测试套件，不依赖外部大模型与网络：

```bash
# 运行全部 12 项脱密与还原测试
python tests/test_unit.py
```

本地快速仿真测试接口（Dry-Run，不出网）：
```bash
curl -s http://127.0.0.1:8317/privacy/dry-run \
  -H 'Content-Type: application/json' \
  -d '{"text": "测试凭据: sk-proj-1234567890abcdef123456, db_pass: my_password_999"}'
```

查看系统脱密与持久化大盘状态：
```bash
curl -s http://127.0.0.1:8317/privacy/health | python3 -m json.tool
```

---

## 📄 开源许可证

本项目基于 [Apache-2.0 License](LICENSE) 协议开源。
