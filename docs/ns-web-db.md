# 正式 NS 数据 Web 与 dump 目录

正式服务读取 ClickHouse 中的 `ns_*` 时序表。`-dump-dir` 同时承担两项职责：

- 新增且写入完成的 `.db` 文件会被自动追加分析。
- 用户点击时间线节点时，服务从同名原始 dump 按需读取全部 RR；NS 永远排在详情首位。

建议目录结构：

```text
/data/bind-cache/
  snapshots/   # 服务递归只读扫描的全部历史与新增 .db 原始快照
  state/       # 处理账本，必须位于输入目录之外
  geoip/       # GeoLite2 ASN/Country CSV 父目录
```

推荐文件名为 `cache_dump_YYYY-MM-DD_HH-MM-SS.db`，例如
`cache_dump_2026-07-28_12-10-01.db`。时间戳代表本地采集时间；BIND 的 `$DATE`
仍作为最终入库时间（UTC）。文件一旦被监测器登记即应视为不可变。

服务不会复制、移动或删除源文件。它要求文件大小和修改时间连续两轮一致，且稳定时间
超过 `dump_monitor.stability_window` 后才解析。`dump_monitor.ledger_path` 按相对路径、
大小和修改时间记录 pending/processed 状态，防止重启后重复读取；账本不得放在快照目录内。

启动示例：

```bash
export CLICKHOUSE_DSN='clickhouse://<user>:<URL_ENCODED_PASSWORD>@127.0.0.1:19000/bind_cache_analyze'
/opt/bind-cache-analyze/bindCacheAnalyze \
  -web-db -config /etc/bind-cache-analyze/config.json
```

DSN 密码中的 `@` 必须写成 `%40`，其余 URL 保留字符同样需要百分号编码。

监听地址默认是 `127.0.0.1`。对外发布应由 Nginx、SLB 或企业 SSO 反向代理完成；
不要直接把该端口暴露到公网。

首次启动会登记并处理目录内全部存量文件；之后持续发现新增文件。ClickHouse 的快照 ID
和本地账本共同保证幂等，历史文件无需移动到单独目录。若已处理文件被原地改写，服务只
记录告警并拒绝自动重读；需要更正时请生成具有新路径和新快照时间的文件。

当前自动监测仅处理未压缩 `.db`。压缩、归档和删除由独立保留策略处理；应保留原始
dump 至少覆盖告警复核周期，否则正式页面仍可展示 NS 证据，但无法再展开完整 RR。
