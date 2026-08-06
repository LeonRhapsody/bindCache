# bindCacheAnalyze 正式环境部署手册

本文适用于以下部署场景：

- 操作系统：openEuler 22.03 LTS SP4；
- ClickHouse 已安装在采集机，原生 TCP 端口为 `127.0.0.1:19000`；
- BIND 缓存快照位于 `/data/bind-cache/dumps/`，程序只读原文件，不复制、不移动、不删除；
- 程序数据、账本、GeoLite 和黑名单统一放在 `/data/bind-cache-analyze/`；
- 采集机不能访问外网，通过同网段 relay 主机执行 DNS 拨测和邮件发送；
- Web、历史快照导入和新增文件监测由同一个 `bindCacheAnalyze` 进程负责。

## 1. 部署拓扑

```text
/data/bind-cache/dumps/*.db
          │ 只读、递归扫描
          ▼
bindCacheAnalyze（采集机）
  ├─ ClickHouse 127.0.0.1:19000
  ├─ Web 127.0.0.1:8888
  ├─ 处理账本 /data/bind-cache-analyze/state/
  ├─ GeoLite /data/bind-cache-analyze/geoip/
  ├─ 黑名单 /data/bind-cache-analyze/blacklists/
  └─ HTTPS → relay:18787
                  ├─ 外部 DNS 拨测
                  └─ SMTP 邮件告警
```

生产环境建议 Web 只监听 `127.0.0.1`，通过 Nginx 等内部反向代理发布 HTTPS。若必须直接
在内网访问，应监听采集机的指定管理 IP，并通过防火墙限制来源，不建议监听
`0.0.0.0`。

## 2. 需要上传的文件

### 2.1 采集机

必须上传：

| 本地文件 | 服务器目标位置 | 说明 |
| --- | --- | --- |
| `bindCacheAnalyze` | `/opt/bind-cache-analyze/bindCacheAnalyze` | Linux amd64 正式二进制，已内嵌前端 |
| 生产 `config.json` | `/data/bind-cache-analyze/config/config.json` | 可由 Web 管理员原子保存的非敏感运行配置 |
| `ns-monitor.env` | `/etc/bind-cache-analyze/ns-monitor.env` | ClickHouse 密码、Web 密码、relay token |
| systemd unit | `/etc/systemd/system/bind-cache-analyze.service` | 主服务启动文件 |
| relay CA 证书 | `/etc/bind-cache-analyze/relay-ca.pem` | relay 使用 HTTPS 时必需 |
| GeoLite CSV 目录 | `/data/bind-cache-analyze/geoip/` | ASN、Country、Location 离线库 |
| 黑名单 CSV | `/data/bind-cache-analyze/blacklists/` | 可为空，后续可从 Web 导入 |

不需要上传：

- `frontend/`、`node_modules/`、`frontend/dist/`：前端已嵌入二进制；
- Go 源码：服务器只运行编译后的二进制；
- `schema_clickhouse.sql`：正式 NS 表由程序按当前结构自动检查和创建；
- dump 副本：程序直接只读 `/data/bind-cache/dumps/`；
- SMTP 用户名和密码：只配置在 relay 主机。

### 2.2 relay 主机

必须上传：

| 文件 | 服务器目标位置 |
| --- | --- |
| 与采集机相同版本的 `bindCacheAnalyze` | `/opt/bind-cache-relay/bindCacheAnalyze` |
| relay 配置 | `/etc/bind-cache-relay/config.json` |
| relay 环境变量 | `/etc/bind-cache-relay/relay.env` |
| HTTPS 证书 | `/etc/bind-cache-relay/tls.crt` |
| HTTPS 私钥 | `/etc/bind-cache-relay/tls.key` |
| relay systemd unit | `/etc/systemd/system/bind-cache-relay.service` |

采集机和 relay 必须使用同一版本二进制，否则显式 RR 类型拨测协议可能不兼容。

## 3. 推荐目录结构

### 3.1 采集机

```text
/opt/bind-cache-analyze/
└── bindCacheAnalyze

/etc/bind-cache-analyze/
├── ns-monitor.env
└── relay-ca.pem

/data/bind-cache-analyze/
├── config/
│   └── config.json
├── state/
│   └── dump-ledger.json
├── geoip/
│   ├── GeoLite2-ASN-CSV_*/
│   ├── GeoLite2-Country-CSV_*/
│   └── GeoLite2-City-CSV_*/
└── blacklists/
    └── *.csv

/data/bind-cache/dumps/
├── cache_dump_2026-07-29_00-00-01.db
├── cache_dump_2026-07-29_00-10-01.db
└── ...
```

`dump-ledger.json` 必须放在 dump 目录之外。它记录 `pending` 和 `processed` 文件，防止
重启后重复导入。

### 3.2 relay 主机

```text
/opt/bind-cache-relay/
└── bindCacheAnalyze

/etc/bind-cache-relay/
├── config.json
├── relay.env
├── tls.crt
└── tls.key
```

## 4. 构建正式 Linux 二进制

在开发机项目根目录执行：

```bash
cd frontend
corepack enable
pnpm install --frozen-lockfile
pnpm lint
pnpm build

cd ..
GOCACHE=/private/tmp/bind-cache-go-cache go test ./...
GOCACHE=/private/tmp/bind-cache-go-cache go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-w -s" -o bindCacheAnalyze .

file bindCacheAnalyze
sha256sum bindCacheAnalyze
```

上传前应保存 SHA-256，上传后在服务器再次执行 `sha256sum`，两端结果必须一致。

## 5. 创建采集机运行用户和目录

```bash
sudo groupadd --system bindcache
sudo useradd --system \
  --gid bindcache \
  --home-dir /var/lib/bind-cache-analyze \
  --create-home \
  --shell /sbin/nologin \
  bindcache

sudo install -d -o root -g bindcache -m 0750 /opt/bind-cache-analyze
sudo install -d -o root -g bindcache -m 0750 /etc/bind-cache-analyze
sudo install -d -o bindcache -g bindcache -m 0750 /data/bind-cache-analyze/config
sudo install -d -o bindcache -g bindcache -m 0750 /data/bind-cache-analyze/state
sudo install -d -o root -g bindcache -m 0750 /data/bind-cache-analyze/geoip
sudo install -d -o bindcache -g bindcache -m 0750 /data/bind-cache-analyze/blacklists

sudo install -o root -g bindcache -m 0750 \
  bindCacheAnalyze /opt/bind-cache-analyze/bindCacheAnalyze
```

快照当前属于 `binddump:binddump` 且通常为 `0640`。推荐给服务进程增加 `binddump` 补充组，
不要将 dump 改成全局可读：

```bash
sudo usermod -aG binddump bindcache
sudo -u bindcache test -r /data/bind-cache/dumps/cache_dump_2026-07-29_00-00-01.db
```

如果最后一条命令失败，应继续检查 `/home/binddump`、`/data/bind-cache/dumps` 的目录执行权限
以及文件组权限，直到 `bindcache` 用户可以只读打开 dump。

## 6. 采集机生产配置

保存为 `/data/bind-cache-analyze/config/config.json`。运行配置不包含密码，但管理员需要
通过 Web 原子保存它，因此与只读的环境变量文件分开：

```json
{
  "clickhouse_dsn": "clickhouse://default@127.0.0.1:19000/bind_cache_analyze?dial_timeout=10s",
  "web": {
    "listen": "127.0.0.1",
    "port": "8888",
    "auth_enabled": true,
    "users": [
      {
        "username": "observer",
        "password_env": "NS_WEB_OBSERVER_PASSWORD",
        "role": "observer"
      },
      {
        "username": "dnsops",
        "password_env": "NS_WEB_OPERATOR_PASSWORD",
        "role": "operator"
      },
      {
        "username": "security-admin",
        "password_env": "NS_WEB_ADMIN_PASSWORD",
        "role": "admin"
      }
    ]
  },
  "dump_monitor": {
    "directory": "/data/bind-cache/dumps",
    "ledger_path": "/data/bind-cache-analyze/state/dump-ledger.json",
    "poll_interval": "30s",
    "stability_window": "90s"
  },
  "geoip": {
    "directory": "/data/bind-cache-analyze/geoip"
  },
  "probe": {
    "enabled": false,
    "backend": "relay",
    "recursive_resolver": "192.0.2.53:53",
    "trusted_resolvers": [
      "198.51.100.53:53",
      "203.0.113.53:53"
    ],
    "timeout": "2s",
    "event_timeout": "60s",
    "max_domains": 20,
    "max_parallel": 12,
    "max_events_per_import": 3,
    "direct_port": 53
  },
  "relay_client": {
    "url": "https://RELAY_IP:18787",
    "token_env": "NS_RELAY_TOKEN",
    "timeout": "5s",
    "tls_ca": "/etc/bind-cache-analyze/relay-ca.pem"
  },
  "alerts": {
    "enabled": false,
    "severities": [
      "critical"
    ],
    "recipients": [
      "security@example.com"
    ],
    "subject_prefix": "[DNS NS 严重告警]",
    "cooldown": "24h",
    "timeout": "10s"
  },
  "blacklist": {
    "directory": "/data/bind-cache-analyze/blacklists",
    "max_file_bytes": 67108864,
    "max_entries": 2000000
  },
  "relay_server": {
    "enabled": false
  }
}
```

首次回灌历史数据时，`probe.enabled` 和 `alerts.enabled` 应保持 `false`。历史文件完成、
实时新增文件已追上，并建立足够基线后，再将两项改为 `true` 并重启服务。

### 6.1 配置字段说明

#### ClickHouse

| 字段 | 说明 |
| --- | --- |
| `clickhouse_dsn` | 非敏感默认连接；生产密码由 `CLICKHOUSE_DSN` 环境变量覆盖 |
| `dial_timeout` | 建立数据库连接的超时 |

ClickHouse 密码中的保留字符必须 URL 编码，例如 `@` 写成 `%40`。不要把真实密码写入
JSON、命令行历史或代码仓库。

#### Web

| 字段 | 建议值 | 说明 |
| --- | --- | --- |
| `web.listen` | `127.0.0.1` | 只允许本机反向代理访问 |
| `web.port` | `8888` | Web 监听端口 |
| `web.auth_enabled` | `true` | 正式环境必须启用 |
| `web.users[].password_env` | 环境变量名 | JSON 只记录变量名，不记录密码 |
| `web.users[].role` | `observer/operator/admin` | 只读、操作、管理三个角色 |

未启用认证时，查询接口仍可访问，但所有写操作都会被拒绝。

#### dump 监测

| 字段 | 建议值 | 说明 |
| --- | --- | --- |
| `directory` | `/data/bind-cache/dumps` | 递归扫描全部 `.db` 文件 |
| `ledger_path` | `/data/.../state/dump-ledger.json` | 已处理文件账本，不能放进 dump 目录 |
| `poll_interval` | `30s` | 目录轮询周期 |
| `stability_window` | `90s` | 文件大小和 mtime 稳定后才允许读取 |

程序不会复制、移动或删除源文件。文件需要连续两轮签名一致、修改时间超过稳定窗口，
并且稳定观察持续超过窗口后才会解析。

#### GeoLite

`geoip.directory` 是 GeoLite2 CSV 解压目录的父目录。至少需要 ASN 和 Country CSV；
Location CSV 完整时可提供更详细地理位置。缺失网络元数据时系统保留事件，但不会仅凭
缺失数据提升风险等级。

#### 拨测

| 字段 | 说明 |
| --- | --- |
| `enabled` | 是否对新增或更新风险事件执行自动拨测 |
| `backend` | 无外网采集机使用 `relay` |
| `recursive_resolver` | 被监控递归 DNS：`192.0.2.53:53` |
| `trusted_resolvers` | 两个可信递归 DNS，用于交叉验证 |
| `timeout` | 单次 DNS 请求超时 |
| `event_timeout` | 单个事件整体拨测上限 |
| `max_domains` | 单事件最多验证的受影响名称 |
| `max_parallel` | 单事件最大 DNS 并发 |
| `max_events_per_import` | 每份快照最多自动拨测的高优先级事件数 |

拨测会对异常 NS、同组其他 NS、受监控递归 DNS 和可信 DNS 进行对比。异常 NS 返回了
错误业务 IP，并产生实际解析影响时，证据等级可提升为严重。

#### relay 客户端

| 字段 | 说明 |
| --- | --- |
| `url` | relay HTTPS 地址 |
| `token_env` | 共享 token 的环境变量名 |
| `timeout` | relay HTTP 请求超时 |
| `tls_ca` | 用于验证 relay 证书的 CA 或自签名证书 |

#### 邮件告警

| 字段 | 说明 |
| --- | --- |
| `enabled` | 历史回灌结束后再启用 |
| `severities` | 建议仅自动发送 `critical` |
| `recipients` | 告警收件人，必须同时在 relay 白名单中 |
| `cooldown` | 相同告警簇、相同收件人的去重时间 |
| `timeout` | 单次告警调用超时 |

恢复事件使用独立去重键，可单独发送一次恢复通知。

#### 黑名单

| 字段 | 说明 |
| --- | --- |
| `directory` | 离线黑名单目录 |
| `max_file_bytes` | 单文件最大字节数 |
| `max_entries` | 单次加载最大条目数 |

支持 `ns`、`ip`、`asn` 三种对象类型。过期条目可以展示，但不产生新的风险事件。

## 7. 采集机敏感环境变量

保存为 `/etc/bind-cache-analyze/ns-monitor.env`：

```ini
CLICKHOUSE_DSN=clickhouse://default:URL_ENCODED_PASSWORD@127.0.0.1:19000/bind_cache_analyze?dial_timeout=10s
NS_RELAY_TOKEN=REPLACE_WITH_LONG_RANDOM_TOKEN
NS_WEB_OBSERVER_PASSWORD=REPLACE_WITH_STRONG_PASSWORD
NS_WEB_OPERATOR_PASSWORD=REPLACE_WITH_ANOTHER_STRONG_PASSWORD
NS_WEB_ADMIN_PASSWORD=REPLACE_WITH_THIRD_STRONG_PASSWORD
```

设置权限：

```bash
sudo chown bindcache:bindcache /data/bind-cache-analyze/config/config.json
sudo chmod 0640 /data/bind-cache-analyze/config/config.json
sudo chown root:bindcache /etc/bind-cache-analyze/ns-monitor.env
sudo chmod 0640 /etc/bind-cache-analyze/ns-monitor.env
sudo chown root:bindcache /etc/bind-cache-analyze/relay-ca.pem
sudo chmod 0644 /etc/bind-cache-analyze/relay-ca.pem
```

`CLICKHOUSE_DSN` 会覆盖 JSON 中的同名配置。环境文件中填写 `%40`，不要填写原始 `@`。

## 8. 采集机 systemd 服务

保存为 `/etc/systemd/system/bind-cache-analyze.service`：

```ini
[Unit]
Description=BIND cache NS persistent monitor and Web
After=network-online.target clickhouse-server.service
Wants=network-online.target

[Service]
Type=simple
User=bindcache
Group=bindcache
SupplementaryGroups=binddump
EnvironmentFile=/etc/bind-cache-analyze/ns-monitor.env
ExecStart=/opt/bind-cache-analyze/bindCacheAnalyze \
  -web-db -config /data/bind-cache-analyze/config/config.json
Restart=on-failure
RestartSec=10
TimeoutStopSec=60
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=full
ReadOnlyPaths=/data/bind-cache/dumps /data/bind-cache-analyze/geoip /etc/bind-cache-analyze
ReadWritePaths=/data/bind-cache-analyze/config /data/bind-cache-analyze/state /data/bind-cache-analyze/blacklists

[Install]
WantedBy=multi-user.target
```

加载并检查：

```bash
sudo systemd-analyze verify /etc/systemd/system/bind-cache-analyze.service
sudo systemctl daemon-reload
sudo systemctl enable bind-cache-analyze
```

## 9. 清库后的首次历史回灌

当前正式 NS 表已清空，因此旧账本不能继续使用。否则账本中的 `processed` 会导致历史
文件被跳过。

先停止服务并备份旧账本：

```bash
sudo systemctl stop bind-cache-analyze
sudo install -d -o bindcache -g bindcache -m 0750 /data/bind-cache-analyze/state

if [ -f /data/bind-cache-analyze/state/dump-ledger.json ]; then
  sudo mv \
    /data/bind-cache-analyze/state/dump-ledger.json \
    /data/bind-cache-analyze/state/dump-ledger.before-reimport.json
fi
```

确认生产配置中以下两项为 `false`：

```json
"probe":  { "enabled": false },
"alerts": { "enabled": false }
```

然后启动：

```bash
sudo systemctl start bind-cache-analyze
sudo systemctl --no-pager --full status bind-cache-analyze
sudo journalctl -u bind-cache-analyze -f
```

首次启动会先登记存量文件。文件达到稳定窗口后按时间顺序处理；每个文件应看到发现、
稳定性判断、解析、NS 提取、ClickHouse 写入和完成统计日志。

连续 12 次有效 NS 指纹一致后才确认权威基线。10 分钟一份快照时，单个持续出现的域名
最快约两小时建立基线；缓存中未出现该域名不计入，也不会重置已有连续次数。

## 10. relay 主机配置

保存为 `/etc/bind-cache-relay/config.json`：

```json
{
  "relay_server": {
    "enabled": true,
    "listen": "0.0.0.0:18787",
    "token_env": "NS_RELAY_TOKEN",
    "allowed_client_cidrs": [
      "COLLECTOR_IP/32"
    ],
    "max_request_bytes": 1048576,
    "max_dns_duration": "5s",
    "allowed_recipients": [
      "security@example.com"
    ],
    "tls_cert": "/etc/bind-cache-relay/tls.crt",
    "tls_key": "/etc/bind-cache-relay/tls.key",
    "smtp": {
      "host": "SMTP_HOST",
      "port": 587,
      "username_env": "SMTP_USERNAME",
      "password_env": "SMTP_PASSWORD",
      "from": "DNS_ALERT_SENDER",
      "starttls": true,
      "implicit_tls": false,
      "insecure_skip_verify": false
    }
  }
}
```

保存 `/etc/bind-cache-relay/relay.env`：

```ini
NS_RELAY_TOKEN=SAME_LONG_RANDOM_TOKEN_AS_COLLECTOR
SMTP_USERNAME=SMTP_USER
SMTP_PASSWORD=REPLACE_WITH_SMTP_PASSWORD
```

relay token 必须与采集机完全一致。SMTP 凭据只能出现在 relay 主机环境文件中。

### 10.1 relay 证书

必须把示例中的 IP 替换为 relay 的真实 IP，不能直接使用字符串 `RELAY_IP`：

```bash
RELAY_IP=192.0.2.10

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
  -keyout tls.key \
  -out tls.crt \
  -subj "/CN=${RELAY_IP}" \
  -addext "subjectAltName=IP:${RELAY_IP}"
```

将 `tls.crt` 和 `tls.key` 放到 relay 主机。再把 `tls.crt` 复制到采集机并命名为
`/etc/bind-cache-analyze/relay-ca.pem`。

假设 relay 服务用户为 `alipms`：

```bash
sudo install -d -o root -g alipms -m 0750 /opt/bind-cache-relay
sudo install -d -o root -g alipms -m 0750 /etc/bind-cache-relay
sudo chown root:alipms /etc/bind-cache-relay/config.json
sudo chmod 0640 /etc/bind-cache-relay/config.json
sudo chown root:alipms /etc/bind-cache-relay/tls.key
sudo chmod 0640 /etc/bind-cache-relay/tls.key
sudo chown root:alipms /etc/bind-cache-relay/tls.crt
sudo chmod 0644 /etc/bind-cache-relay/tls.crt
sudo chown root:alipms /etc/bind-cache-relay/relay.env
sudo chmod 0640 /etc/bind-cache-relay/relay.env
sudo chown root:alipms /opt/bind-cache-relay/bindCacheAnalyze
sudo chmod 0750 /opt/bind-cache-relay/bindCacheAnalyze
```

### 10.2 relay systemd 服务

保存为 `/etc/systemd/system/bind-cache-relay.service`：

```ini
[Unit]
Description=DNS probe and email relay for bindCacheAnalyze
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=alipms
Group=alipms
EnvironmentFile=/etc/bind-cache-relay/relay.env
ExecStart=/opt/bind-cache-relay/bindCacheAnalyze \
  -relay -config /etc/bind-cache-relay/config.json
Restart=on-failure
RestartSec=10
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadOnlyPaths=/etc/bind-cache-relay

[Install]
WantedBy=multi-user.target
```

如果 relay 主机不存在 `alipms` 用户，应改成实际的非 root 服务用户。

启动并验证：

```bash
sudo systemd-analyze verify /etc/systemd/system/bind-cache-relay.service
sudo systemctl daemon-reload
sudo systemctl enable --now bind-cache-relay
sudo systemctl --no-pager --full status bind-cache-relay

RELAY_IP=192.0.2.10
curl --cacert /etc/bind-cache-relay/tls.crt \
  "https://${RELAY_IP}:18787/healthz"
```

`RELAY_IP` 必须与证书 SAN 中的实际 IP 一致。

## 11. 上线验收

### 11.1 服务和端口

```bash
sudo systemctl is-active clickhouse-server
sudo systemctl is-active bind-cache-analyze
ss -lntp | grep -E '(:19000|:8888)'
curl -sS http://127.0.0.1:8888/healthz
```

预期：

- ClickHouse 只监听 `127.0.0.1:19000`；
- Web 只监听配置指定地址；
- `/healthz` 返回 `{"status":"ok"}`；
- 8123、9000 等不需要的端口不应暴露到外网。

### 11.2 数据库

```bash
clickhouse-client \
  --host 127.0.0.1 \
  --port 19000 \
  --user default \
  --password \
  --database bind_cache_analyze \
  --query "
    SELECT name, total_rows
    FROM system.tables
    WHERE database = 'bind_cache_analyze'
      AND startsWith(name, 'ns_')
    ORDER BY name
  "
```

正式结构包含以下 11 张表：

```text
ns_alert_notifications
ns_audit_log
ns_change_events
ns_domain_baseline
ns_domain_baseline_state
ns_domain_observations
ns_domain_timeline
ns_event_actions
ns_event_probes
ns_risk_events
ns_snapshot_catalog
```

### 11.3 日志

```bash
sudo journalctl -u bind-cache-analyze --since "30 min ago" --no-pager
```

重点确认：

- 可以发现 `/data/bind-cache/dumps/` 下的文件；
- 文件未稳定时明确记录等待原因；
- 稳定后出现解析、NS 观察、时间线、事件和写库统计；
- 没有 ClickHouse 认证、SQL、权限、GeoLite 或 ledger 写入错误；
- 历史回灌阶段没有执行拨测或发送邮件。

### 11.4 页面

检查：

1. 监测总览可以读取快照和组件状态；
2. 风险事件、四类检测场景、域名追溯均可打开；
3. 浏览器返回上一级仍留在系统内；
4. 普通 observer 不能执行事件操作；
5. operator 可以确认、忽略、白名单和人工补测；
6. admin 保存配置后页面提示需要重启；
7. 告警和拨测页面能看到持久化记录。

## 12. 历史追平后的正式启用顺序

1. 确认所有存量 dump 均已进入账本 `processed`；
2. 确认最新快照时间已追上当前周期；
3. 确认主要域名逐步达到连续 12 次基线；
4. 在采集机到 relay 之间验证 HTTPS `/healthz`；
5. 手工执行一条 DNS 拨测，确认 relay 返回正常；
6. 发送测试邮件，确认发件人、收件人和 SMTP TLS；
7. 将 `probe.enabled` 改为 `true`，重启并观察一个周期；
8. 将 `alerts.enabled` 改为 `true`，重启服务；
9. 观察至少两个 10 分钟快照周期后再结束上线值守。

修改配置后执行：

```bash
sudo systemctl restart bind-cache-analyze
sudo systemctl --no-pager --full status bind-cache-analyze
sudo journalctl -u bind-cache-analyze -n 200 --no-pager
```

## 13. 回滚

### 13.1 程序回滚

每次替换二进制前保留上一版本：

```bash
sudo cp -a \
  /opt/bind-cache-analyze/bindCacheAnalyze \
  /opt/bind-cache-analyze/bindCacheAnalyze.previous
```

出现问题时停止服务、恢复上一版本，再启动：

```bash
sudo systemctl stop bind-cache-analyze
sudo cp -a \
  /opt/bind-cache-analyze/bindCacheAnalyze.previous \
  /opt/bind-cache-analyze/bindCacheAnalyze
sudo systemctl start bind-cache-analyze
```

### 13.2 数据回滚

本次清理前的数据库备份为：

```text
bind_cache_analyze_backup_20260731_075535
```

不要直接在服务运行期间把备份数据覆盖回正式库。恢复前应停止服务，按表核对正式库和
备份库结构、行数及恢复范围，再执行恢复。

### 13.3 账本回滚

账本只决定哪些源文件需要再次读取，不是业务数据备份。恢复旧数据库时，应同时评估是否
恢复对应的旧账本；仅恢复其中一项可能导致重复读取或跳过文件。

## 14. 常用运维命令

```bash
# 服务状态
sudo systemctl --no-pager --full status bind-cache-analyze

# 实时日志
sudo journalctl -u bind-cache-analyze -f

# 最近 500 行日志
sudo journalctl -u bind-cache-analyze -n 500 --no-pager

# 健康检查
curl -sS http://127.0.0.1:8888/healthz

# 验证配置文件是合法 JSON
python3 -m json.tool /data/bind-cache-analyze/config/config.json >/dev/null

# 验证服务用户可读取 dump
sudo -u bindcache find /data/bind-cache/dumps -type f -name '*.db' -readable | head

# 查看账本状态数量
python3 -m json.tool /data/bind-cache-analyze/state/dump-ledger.json | less
```

正式上线完成的判断标准不是“进程已经启动”，而是：

- 服务持续健康；
- 新 dump 在稳定窗口后能够自动入库；
- ClickHouse 最新快照时间持续推进；
- 基线计数按快照滚动；
- relay 拨测和邮件测试成功；
- 页面无查询错误；
- observer、operator、admin 权限符合预期；
- 连续至少两个采集周期无重复导入、无积压和无异常告警风暴。
