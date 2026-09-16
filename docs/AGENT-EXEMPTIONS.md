# 给 AI Agent 的操作须知：出网脱密与豁免

出网流量会经过本地脱密网关（`privacy-gateway.service`，`127.0.0.1:8317`）：`API Key / 私钥 / JWT / 数据库密码 / 高熵口令` 会被替换成 `<SECRET_xxx_n>` 占位符再出网，回来的内容再还原。**默认对全部流量过滤**，没有全局关闭开关。

## 什么时候申请豁免

只有一种情况：**某个词本身不是敏感信息，但必须原样出现在外发内容里**。例如要贴到公开工单/文档里的主机名、路径段，或公开的示例值。

**不要**放行真实密钥。

## 怎么申请

```bash
/root/privacy-gateway/scripts/privacy-exempt.sh allow \
  --term "<字面量，或 vault 代号如 <SECRET_AWS_AKIA_1>>" \
  --reason "<为什么可以放行，必填>"
```

- `--term` 用 **vault 代号**时无需接触明文：网关自己把代号解析成对应凭据（`<SECRET_...>` 在 `list` / `health` / 状态接口里都能看到）。
- `--reason` **必填且不能为空**。网关本身不强制理由（人工可以不带理由地设置），但这条命令是 AI 的入口，会拦住空理由。
- **没有期限要求**：豁免一直生效，直到你 `revoke`。需要临时豁免时才用 `--expires-at <epoch>`。
- 可选 `--scope all|layer0|layer1`（默认 `all`）。

```bash
privacy-exempt.sh list                  # 当前豁免（词 / 范围 / 理由 / 操作者 / 命中）
privacy-exempt.sh revoke --term "<词或代号>" --reason "<为什么可以恢复过滤>"
privacy-exempt.sh audit                 # 审计日志
privacy-exempt.sh health                # 网关状态
```

## 申请之后必须做的

1. **在回复里明确告诉用户**：放行了哪个词、为什么。不能默默放行。
2. **任务做完就撤销**（`revoke`），除非用户要求保留。
3. 插件的页内横幅会同步弹出提醒，但你的回复仍需说明理由。

## 退出码

| 码 | 含义 | 处理 |
|---|---|---|
| 2 | 缺 `--reason` 或为空 | 补上理由 |
| 3 | 网关不可达 | `systemctl status privacy-gateway` |
| 4 | 网关拒绝（代号不存在、scope 非法等） | 按 stderr 提示修正 |

`list` 报「接口不可用」= 网关仍是旧版本，需要 `systemctl restart privacy-gateway`。

## 位置

| 东西 | 路径 |
|---|---|
| 网关源码（唯一来源） | `/root/privacy-gateway/` |
| 网关部署目录（systemd 运行） | `/opt/privacy-gateway/` |
| 豁免名单 | `/etc/privacy-gateway/exemptions.json` |
| 审计日志 | `/var/log/privacy-gateway/exemptions.jsonl` |
| 部署脚本 | `/root/privacy-gateway/scripts/deploy-local.sh` |
| DSH 插件（面板 + 横幅） | `/root/dsh-privacy-guard/` |
