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
- **🔓 豁免名单（按词放行，长期有效）**：
  - 某些必须原样出现在外发内容里的词（例如要贴到公开工单上的主机名或链接片段）可以按词放行，**默认姿态仍是全量过滤**。
  - 豁免用命令行或 HTTP 设置，一条命令即可；AI 申请时必须写明理由，人工设置可以不写。
  - 豁免长期有效，直到被撤销；全部操作写入审计日志，且只允许本机 loopback 管理。

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
| `EXEMPTIONS_FILE` | `/etc/privacy-gateway/exemptions.json` | 豁免名单持久化文件（热加载，改文件即生效） |
| `EXEMPTION_AUDIT_FILE` | `/var/log/privacy-gateway/exemptions.jsonl` | 豁免审计日志（add / revoke / expire / hit 追加写入） |
| `EXEMPTION_MIN_TERM` | `4` | 命名字面量的最小长度 |
| `EXEMPTION_MAX_TERM` | `256` | 命名字面量的最大长度 |
| `EXEMPT_TERMS` | *(空)* | 逗号分隔的临时豁免词种子，仅本进程有效、不落盘 |
| `GATEWAY_UPSTREAMS` | *(空)* | 额外上游，按路径前缀寻址：`/前缀=URL`，逗号分隔。例如 `/deepseek=https://api.deepseek.com` |

---

## 🔓 豁免机制（Allowlist）

**默认姿态是全量过滤**：网关对每一段出网文本都执行 Layer 0 正则 + Layer 1 小模型判定。豁免只是「对某一个确切的词暂停脱敏」，不是全局开关，且由代码强制约束：

- **默认长期有效**：豁免写入后一直生效，直到被显式撤销；如需临时豁免可显式传 `expires_at`；
- **理由**：AI 入口（CLI）强制要求非空理由；网关层的 HTTP 接口不强制，人工设置可以不写；
- **可用代号操作**：`--term` 既可以是字面量，也可以是 vault 里的占位符代号（如 `<SECRET_AWS_AKIA_1>`），网关自行解析到对应凭据，Agent 不必接触明文；
- **精确匹配**：对完整候选词做边界匹配（`(?<![A-Za-z0-9_])term(?![A-Za-z0-9_])`），因此放行一个短词不会让包含它的真实密钥漏出；
- **审计留痕**：`add` / `revoke` / `expire` / `hit` 全部写入 `exemptions.jsonl`；
- **仅本机可管理**：豁免接口只接受 loopback 来源，经局域网/Tailscale 访问返回 403。

实现方式：被豁免的词在冻结占位符之前被替换成惰性的 `__VAULT_EXEMPT_*` 令牌，该令牌对 Layer 0（已冻结占位符守卫）与 Layer 1（`__VAULT_` 前缀视为 boring token）都是透明的，走完两层后原样还原。这样豁免只影响被点名的那个词，其余凭据照常脱敏。

### 命令行入口（供 AI 使用）

```bash
# 按字面量放行（长期有效）
scripts/privacy-exempt.sh allow --term "office-N100" \
  --reason "办公机主机名，需原样贴在公开工单里，本身不敏感"

# 或按 vault 代号放行，Agent 无需接触明文
scripts/privacy-exempt.sh allow --term "<SECRET_AWS_AKIA_1>" \
  --reason "示例 key 已在公开 issue 里出现过"

scripts/privacy-exempt.sh revoke --term "office-N100" --reason "工单已关闭，恢复过滤"
scripts/privacy-exempt.sh list
scripts/privacy-exempt.sh audit
scripts/privacy-exempt.sh health
```

### HTTP 接口（loopback only）

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/privacy/exemptions` | 当前生效的豁免列表 + 统计 |
| `POST` | `/privacy/exemptions` | 新增，body 必含 `term`（字面量或 `<SECRET_...>` 代号），可选 `scope` / `reason` / `expires_at` / `actor` |
| `DELETE` | `/privacy/exemptions?term=&reason=&actor=` | 撤销，`term` 可用字面量或 vault 代号，`reason` 可选 |
| `GET` | `/privacy/exemptions/audit?since=&limit=` | 审计日志 |
| `GET` | `/privacy/health` | 健康总览，含 `exemptions` 摘要块 |

`POST /privacy/dry-run` 的返回值会多出 `exempt_spans` 与 `exempt_terms` 两个字段，可直接验证「豁免生效但其它凭据仍被脱密」。

---

### 多上游（同一实例保护多条链路）

网关默认把所有请求转发给 `BACKEND_URL`。加 `GATEWAY_UPSTREAMS` 后，带指定前缀的请求会被转发到另一个上游，**前缀本身被吃掉**：

```bash
GATEWAY_UPSTREAMS="/deepseek=https://api.deepseek.com"
# POST /deepseek/v1/chat/completions  ->  https://api.deepseek.com/v1/chat/completions
```

所以客户端 provider 的 `baseURL` 写成 `http://127.0.0.1:8317/deepseek/v1` 即可。无前缀的请求仍走 `BACKEND_URL`，互不影响；额外上游的健康探测仍在本机（`/privacy/*` 不会被路由出去）。

---

## 🚀 部署（源码为唯一来源）

`/root/privacy-gateway` 是唯一的 git 源码；`/opt/privacy-gateway` 只是**部署目录**（放 venv、llama.cpp 构建与 GGUF 权重）。不要手改 `/opt` 下的 `gateway.py`：

```bash
./scripts/deploy-local.sh --dry-run   # 预览差异
./scripts/deploy-local.sh             # 备份 → 同步 → systemctl restart privacy-gateway → 健康校验
```

---

## 🧪 验证与自测

项目提供完整的离线单元测试套件，不依赖外部大模型与网络：

```bash
# 运行全部 13 项脱密与还原测试
/opt/privacy-gateway/venv/bin/python -m pytest tests/test_unit.py -q
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

### 查看已保存的脱密凭据（vault 映射）

脱敏时写入 vault 的「占位符 ↔ 明文」映射可以直接查看，工具全程只读：

```bash
scripts/vault-inspect.py status                       # 密钥来源、条目数、按类型统计
scripts/vault-inspect.py list                         # 列出映射，默认只给长度+指纹，不显示明文
scripts/vault-inspect.py list --sort accessed --json  # 按最近使用排序 / 机器可读
scripts/vault-inspect.py show '<SECRET_API_KEY_1>'    # 只揭示这一条
```

- **只读**：连接以 `mode=ro` 打开，并通过 `VACUUM INTO` 取一致性快照后读取，因此 WAL 里尚未 checkpoint 的记录也能看到，且不修改任何一行（连 `last_accessed_at` 都不碰，实测默认快照模式下 db/-wal/-shm 的 mtime 均不变）；`--live` 为就地读取，同样只读，但会让 SQLite 刷新 WAL 索引；
- **默认不泄露明文**：列表只显示占位符、类型、长度与摘要指纹，足够区分不同条目；
- **不会自建密钥**：密钥文件缺失时报错退出，不像网关那样自动生成。

---

## 📄 开源许可证

本项目基于 [Apache-2.0 License](LICENSE) 协议开源。
