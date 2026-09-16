# 给 AI Agent 的操作须知：出网脱密与豁免

这份文件面向**在 DSH 里工作的 AI**。你不需要读源码，只需要按下面三步走。

## 0. 背景（一句话）

从本机出去到外部模型的流量会经过本地脱密网关（`privacy-gateway.service`，`127.0.0.1:8317`）：
`API Key / 私钥 / JWT / 数据库密码 / Bearer / 高熵口令` 等会被替换成 `<SECRET_xxx_n>` 占位符再出网，
回来的内容再还原。**默认对全部流量过滤**，没有全局关闭开关。

## 1. 什么时候需要申请豁免

只有一种情况：**某个词本身不是敏感信息，但必须原样出现在外发内容里**。典型例子：

- 要贴到公开工单 / 文档 / 网站的链接片段里带的主机名或路径段（`office-N100`、`portal.example.org`）；
- 对外的示例值、公开的测试 ID（不是真实凭据）。

**不要**为了「看起来方便」而放行真实密钥。放行真实凭据等于关掉这项保护。

## 2. 怎么申请（唯一入口）

```bash
/root/privacy-gateway/scripts/privacy-exempt.sh allow \
  --term "<要原样放行的确切字面量>" \
  --reason "<为什么它不敏感，一句话说清楚>" \
  --ttl 1800          # 可选，秒；默认 24h，硬上限 7 天
                      # 可选 --scope all|layer0|layer1（默认 all）
```

规则（由网关在代码层强制，绕不过去）：

| 规则 | 后果 |
|---|---|
| `--reason` 缺失或 < 8 字符 | 请求被拒（退出码 2），什么都没发生 |
| `--ttl` > 7 天 | 请求被拒 |
| 想放行真实密钥 | 不要做；豁免只针对「本来就不敏感、只是形状像密钥」的词 |
| 到期 | 过滤自动恢复，无需你处理 |

其它命令：

```bash
privacy-exempt.sh list    # 看当前生效的豁免（词 / 范围 / 理由 / 剩余时间 / 命中次数）
privacy-exempt.sh audit   # 看审计日志（谁在什么时候放了什么、为什么）
privacy-exempt.sh revoke --term "<词>" --reason "<为什么可以恢复过滤>"
privacy-exempt.sh health  # 网关整体状态
```

## 3. 申请之后你必须做的事

1. **在回复里明确告诉用户**：放行了哪个词、为什么、多久后失效。这是硬性要求，不能默默放行。
2. **任务做完就撤销**（`revoke`），除非用户要求保留。
3. 插件的**页内横幅**会在你放行/撤销时弹出提醒，用户无需你额外通知也知道发生了什么；但你的回复仍需说明理由。

## 4. 出错时

- 退出码 `2`：参数或理由不合规，按提示补 `--reason` / 调小 `--ttl`。
- 退出码 `3`：网关不可达 → `systemctl status privacy-gateway`。
- 退出码 `4`：网关拒绝（例如词不存在、reason 被判定不合格）。
- `list` 返回「网关豁免接口不可用」：网关还是旧版本，需要 `systemctl restart privacy-gateway`。

## 5. 相关位置

| 东西 | 路径 |
|---|---|
| 网关源码（唯一来源） | `/root/privacy-gateway/` |
| 网关部署目录（systemd 实际运行） | `/opt/privacy-gateway/` |
| 豁免名单 | `/etc/privacy-gateway/exemptions.json` |
| 豁免审计日志 | `/var/log/privacy-gateway/exemptions.jsonl` |
| 部署脚本 | `/root/privacy-gateway/scripts/deploy-local.sh` |
| DSH 插件（面板 + 横幅） | `/root/dsh-privacy-guard/` |
