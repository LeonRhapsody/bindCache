# 正式部署文件包

## 采集机首次历史回灌

上传：

```text
bindCacheAnalyze
collector/config.backfill.json
collector/ns-monitor.env.example
collector/bind-cache-analyze.service
geoip_data/GeoLite2-ASN-CSV_*/
geoip_data/GeoLite2-Country-CSV_*/
```

服务器对应位置：

```text
/opt/bind-cache-analyze/bindCacheAnalyze
/data/bind-cache-analyze/config/config.json
/etc/bind-cache-analyze/ns-monitor.env
/etc/systemd/system/bind-cache-analyze.service
/data/bind-cache-analyze/geoip/GeoLite2-*/
```

`config.backfill.json` 上传后改名为 `config.json`。历史回灌阶段保持自动拨测和邮件关闭。

## 历史追平后

将 `collector/config.live.json` 中的 `REPLACE_RELAY_IP` 替换为真实 relay IP，再覆盖：

```text
/data/bind-cache-analyze/config/config.json
```

重启服务后启用自动拨测和严重告警。

## relay 主机

上传：

```text
bindCacheAnalyze
relay/config.json
relay/relay.env.example
relay/bind-cache-relay.service
tls.crt
tls.key
```

替换 `REPLACE_COLLECTOR_IP`、SMTP 主机、发件人、用户名、密码及共享 token。

完整步骤见：

```text
docs/production-deployment-openeuler.md
```
