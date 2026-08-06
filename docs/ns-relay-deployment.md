# 递归 NS 监测：目录账本、同网段 Relay 与邮件告警

## 1. 采集机的 dump 目录处理方式

将 BIND 的所有历史与新增 dump 都放在同一个根目录（可以有多级子目录），例如
`/data/bind-cache/dumps`。监测器会递归寻找 `.db` 文件，**只读**源文件，不会复制、
移动或删除它们。

处理账本应放在输入目录之外，例如 `/data/bind-cache/state/dump-ledger.json`。账本按
相对路径保存文件的 `size + mtime`，并包含两种状态：

- `pending`：已经发现，但尚未确认写入完成；
- `processed`：已经成功导入或确认 ClickHouse 中已有相同快照，不再读取。

一个文件必须同时满足以下条件才解析：

1. 连续两轮扫描观测到完全相同的大小和修改时间；
2. 文件最后修改时间早于 `stability_window`；
3. 第一次观察到相同签名的时间也已跨过 `stability_window`。

因此服务第一次启动会先登记全部存量文件，经过稳定窗口后逐个分析；正在写入的
文件会一直留在 `pending`。若已经处理过的同一路径又被改写，系统只告警日志而不会
自动重读，防止把同一快照重复解释；应改名为新的 dump 文件后再由监测器处理。

## 2. Relay 协议

无外网采集机以 HTTP(S) JSON 连接同网段 relay，relay 才执行外部 DNS 查询和 SMTP
投递。采集机不保存 SMTP 凭据，也不会对外发送 DNS 包。

| 端点 | 请求 | 行为 |
| --- | --- | --- |
| `POST /v1/dns-probe` | `domain`、`resolver`、`recursive`、`types`、`timeout_ms` | relay 按显式类型拨测，先 UDP、截断时 TCP 回退，返回结构化 `DNSProbeAnswer`。 |
| `POST /v1/email` | `to`、`subject`、`text` | relay 按服务器端 SMTP 配置投递纯文本告警邮件。 |
| `GET /healthz` | 无 | 返回 relay 存活状态。 |

两个 POST 均需 `Authorization: Bearer <token>`。relay 还会验证客户端 CIDR、DNS 目标
必须为 IP 且端口必须为 53、请求大小、DNS 超时、邮件收件人白名单。建议使用 HTTPS
并在采集机设置 `relay_client.tls_ca`；无 TLS 的 HTTP 仅适合受隔离的同网段管理网络。
`types` 当前只允许 `A`、`AAAA`、`CNAME`、`NS`、`SOA`、`TXT`、`MX`、`DS`、`DNSKEY`，
不接受 AXFR/IXFR。采集机和 relay 必须部署同一版本二进制，旧 relay 不具备显式类型能力。

## 3. 配置

复制 `config.json.example` 为两份独立配置：采集机一份、relay 主机一份。密码和令牌
不能写进 JSON，统一通过环境变量名引用。

采集机重点配置：

```json
{
  "dump_monitor": {
    "directory": "/data/bind-cache/dumps",
    "ledger_path": "/data/bind-cache/state/dump-ledger.json",
    "poll_interval": "30s",
    "stability_window": "90s"
  },
  "probe": { "enabled": true, "backend": "relay" },
  "relay_client": {
    "url": "https://dns-relay.example.internal:18787",
    "token_env": "NS_RELAY_TOKEN"
  },
  "alerts": {
    "enabled": true,
    "severities": ["critical"],
    "recipients": ["security@example.com"],
    "cooldown": "24h"
  }
}
```

relay 主机重点配置：

```json
{
  "relay_server": {
    "enabled": true,
    "listen": "0.0.0.0:18787",
    "token_env": "NS_RELAY_TOKEN",
    "allowed_client_cidrs": ["10.0.0.0/8"],
    "allowed_recipients": ["security@example.com"],
    "tls_cert": "/etc/bind-cache-relay/tls.crt",
    "tls_key": "/etc/bind-cache-relay/tls.key",
    "smtp": {
      "host": "smtp.example.com",
      "port": 587,
      "username_env": "SMTP_USERNAME",
      "password_env": "SMTP_PASSWORD",
      "from": "dns-alert@example.com",
      "starttls": true
    }
  }
}
```

采集机和 relay 必须拥有相同但足够随机的 `NS_RELAY_TOKEN` 值。relay 的 SMTP 用户名、
密码只在 relay 主机设置。

## 4. 启动

在 relay 主机：

```bash
export NS_RELAY_TOKEN='replace-with-random-token'
export SMTP_USERNAME='smtp-user'
export SMTP_PASSWORD='smtp-password'
./bindCacheAnalyze -relay -config /etc/bind-cache-relay/config.json
```

在无外网采集机：

```bash
export NS_RELAY_TOKEN='same-random-token'
export CLICKHOUSE_DSN='clickhouse://default:URL_ENCODED_PASSWORD@127.0.0.1:19000/bind_cache_analyze'
./bindCacheAnalyze -web-db -config /etc/bind-cache-analyze/config.json
```

DSN 中的用户名和密码属于 URL userinfo，保留字符必须百分号编码。例如密码中的 `@`
写成 `%40`；推荐通过 `CLICKHOUSE_DSN` 环境变量提供，避免把凭据提交到配置仓库。

`-web-db` 会启动页面和目录监测器。首次启动仅登记存量 dump，达到稳定窗口后依次入库；
新 dump 同样经过双观察后入库。使用 `-dump-dir`、`-dump-ledger`、`-probe-*` 参数时可
临时覆盖配置文件，但生产环境应以配置文件为准。

为避免一批 NS 异常占满下一个 10 分钟周期，`probe.max_events_per_import` 默认是 `3`：
每份快照在全部四类场景之间共享一个拨测预算，只自动拨测风险最高的 3 个未恢复事件；
其余事件照常入库、可在页面中手动补测。
单事件仍受 `probe.event_timeout`（默认 `60s`）限制。运行日志会逐阶段记录文件解析、NS
观测提取、写库、事件拨测及每个事件的耗时；可据此判断瓶颈在磁盘、ClickHouse 还是 relay。

### 基线确认与滚动更新

系统不会再把首次缓存观察直接当作基线。每个域名只有在 **连续 12 次有效 NS 指纹一致**
后才写入正式基线；10 分钟一个 dump 时约为两小时。缓存中未出现该域名不计入、不重置
该计数。已确认基线出现新结果后，仍会先生成风险事件；新结果再次连续出现 12 次时，
系统会保留并关闭该事件、记录“基线滚动更新”时间线节点，再替换正式基线。

升级已有首次观测基线的环境时，不要清空表：程序会将旧基线自动降级为第 1 次候选观察，
后续再补足 11 次一致结果后确认。

## 5. 告警交付与去重

每次新快照导致严重事件写入时，采集机通过 relay 发送邮件。投递记录写入 ClickHouse
的 `ns_alert_notifications`：成功、失败及失败原因均可审计。同一域名、同一等级、同一变化
摘要与变化类型会归并为同一个告警簇；相同告警簇、相同收件人在 `alerts.cooldown` 内不会
重复邮件。恢复事件使用独立告警簇发送一次恢复通知，不会被活动事件的冷却键抑制；
失败不会抑制后续重试。邮件会说明事件 ID、风险等级、
NS 基线/当前状态、变化类型与拨测结论，但不会将缓存观测误表述为已确认投毒。

## 6. Web 认证、角色与写操作

生产环境建议启用 HTTP Basic 认证。密码只从环境变量读取，不写入配置文件：

```json
{
  "web": {
    "listen": "127.0.0.1",
    "port": "8888",
    "auth_enabled": true,
    "users": [
      {"username": "observer", "password_env": "NS_WEB_OBSERVER_PASSWORD", "role": "observer"},
      {"username": "dnsops", "password_env": "NS_WEB_OPERATOR_PASSWORD", "role": "operator"},
      {"username": "security-admin", "password_env": "NS_WEB_ADMIN_PASSWORD", "role": "admin"}
    ]
  }
}
```

启动前设置密码：

```bash
export NS_WEB_OBSERVER_PASSWORD='replace-with-strong-random-password'
export NS_WEB_OPERATOR_PASSWORD='replace-with-another-strong-random-password'
export NS_WEB_ADMIN_PASSWORD='replace-with-a-third-strong-random-password'
```

- `observer`：只读查看。
- `operator`：确认、忽略、限期白名单、人工补测、离线名单导入。
- `admin`：包含 operator 权限，并可原子写入配置文件。
- 未启用认证时所有查询仍可使用，但写操作会明确拒绝，系统保持只读。
- 配置保存返回 `restartRequired=true`；应由 systemd 重启服务，避免同一进程内不同组件使用新旧配置。

建议 Web 仍只监听 `127.0.0.1`，由内部反向代理提供 TLS。`/healthz` 不要求认证，供
systemd 或本机探针使用。

## 7. 离线黑名单

配置目录：

```json
{
  "blacklist": {
    "directory": "/data/bind-cache/blacklists",
    "max_file_bytes": 67108864,
    "max_entries": 2000000
  }
}
```

每个 CSV 使用固定表头：

```csv
object_type,object,source,version,confidence,category,effective_at,expires_at,description
ns,ns.bad.example,internal-watch,v3,high,malicious-ns,2026-07-01,2026-08-31,confirmed malicious infrastructure
ip,192.0.2.66,internal-watch,v3,medium,suspicious-ip,2026-07-01,2026-08-31,suspicious address
asn,AS64500,internal-watch,v3,high,malicious-asn,2026-07-01,2026-08-31,known malicious network
```

`object_type` 支持 `ns`、`ip`、`asn`；可信度支持 `high`、`medium`、`low`。导入时会
校验大小、条数、字段、对象格式、生效/过期时间并计算 SHA-256。同名文件不会覆盖，发布
使用同目录临时文件加原子重命名。过期条目保留版本展示，但不产生新的风险事件。
