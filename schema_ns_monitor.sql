-- 递归 DNS 风险监测正式时序库（ClickHouse）
-- 与 EnsureNSClickHouseSchema 保持一致；应用启动时也会幂等执行这些 DDL。

CREATE TABLE IF NOT EXISTS ns_snapshot_catalog (
    snapshot_id String, captured_at DateTime64(3, 'UTC'), source_name String,
    view LowCardinality(String), total_domains UInt64, ns_observations UInt64,
    imported_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(imported_at) ORDER BY snapshot_id;

CREATE TABLE IF NOT EXISTS ns_domain_observations (
    snapshot_id String, captured_at DateTime64(3, 'UTC'), domain String,
    ns_count UInt16, fingerprint String, nameservers_json String,
    imported_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(imported_at)
PARTITION BY toYYYYMM(captured_at) ORDER BY (snapshot_id, domain);

CREATE TABLE IF NOT EXISTS ns_domain_timeline (
    snapshot_id String, captured_at DateTime64(3, 'UTC'), domain String,
    ns_count UInt16, fingerprint String, state LowCardinality(String),
    severity LowCardinality(String), event_id String, summary String,
    imported_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(imported_at)
PARTITION BY toYYYYMM(captured_at) ORDER BY (domain, captured_at, snapshot_id);

CREATE TABLE IF NOT EXISTS ns_change_events (
    event_id String, domain String, severity LowCardinality(String),
    evidence LowCardinality(String), status LowCardinality(String), summary String,
    change_types Array(String), first_seen DateTime64(3, 'UTC'),
    last_seen DateTime64(3, 'UTC'), resolved_at Nullable(DateTime64(3, 'UTC')),
    occurrences UInt32, baseline_json String, current_json String, signature String,
    imported_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(imported_at)
PARTITION BY toYYYYMM(first_seen) ORDER BY event_id;

CREATE TABLE IF NOT EXISTS ns_risk_events (
    event_id String, risk_type LowCardinality(String), domain String,
    severity LowCardinality(String), evidence LowCardinality(String),
    status LowCardinality(String), summary String, change_fields Array(String),
    first_seen DateTime64(3, 'UTC'), last_seen DateTime64(3, 'UTC'),
    resolved_at Nullable(DateTime64(3, 'UTC')), occurrences UInt32,
    snapshot_id String, current_json String, extra_json String, signature String,
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(first_seen) ORDER BY event_id;

CREATE TABLE IF NOT EXISTS ns_adb_endpoint_state (
    view LowCardinality(String), ns_name String, ip String,
    last_snapshot_id String, last_seen DateTime64(3, 'UTC'), srtt UInt32,
    flags String, edns_success UInt32, edns_timeout_4096 UInt32,
    edns_timeout_1432 UInt32, edns_timeout_1232 UInt32,
    edns_timeout_512 UInt32, plain_success UInt32, plain_timeout UInt32,
    udp_size UInt16, adb_ttl Int32, health LowCardinality(String),
    consecutive_suspect UInt16, detail String,
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (view, ns_name, ip);

CREATE TABLE IF NOT EXISTS ns_adb_endpoint_history (
    snapshot_id String, captured_at DateTime64(3, 'UTC'),
    view LowCardinality(String), ns_name String, ip String,
    previous_health LowCardinality(String), health LowCardinality(String),
    consecutive_suspect UInt16, srtt UInt32, plain_success UInt32,
    plain_timeout UInt32, edns_success UInt32, edns_timeout UInt32,
    detail String
) ENGINE = MergeTree
PARTITION BY toYYYYMM(captured_at)
ORDER BY (ns_name, ip, captured_at, snapshot_id);

CREATE TABLE IF NOT EXISTS ns_domain_baseline (
    domain String, baseline_snapshot_id String, captured_at DateTime64(3, 'UTC'),
    fingerprint String, observation_json String,
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(updated_at) ORDER BY domain;

CREATE TABLE IF NOT EXISTS ns_domain_baseline_state (
    domain String, confirmed UInt8, candidate_fingerprint String,
    candidate_observation_json String, consecutive_count UInt16,
    candidate_first_seen Nullable(DateTime64(3, 'UTC')),
    candidate_last_seen Nullable(DateTime64(3, 'UTC')),
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(updated_at) ORDER BY domain;

CREATE TABLE IF NOT EXISTS ns_event_probes (
    event_id String, snapshot_id String, probed_at DateTime64(3, 'UTC'),
    verdict LowCardinality(String), summary String, result_json String,
    imported_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(imported_at)
PARTITION BY toYYYYMM(probed_at) ORDER BY event_id;

CREATE TABLE IF NOT EXISTS ns_alert_notifications (
    event_id String, alert_type LowCardinality(String), recipient String,
    status LowCardinality(String), attempted_at DateTime64(3, 'UTC'),
    message String, imported_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = MergeTree
PARTITION BY toYYYYMM(attempted_at)
ORDER BY (event_id, alert_type, recipient, attempted_at);

CREATE TABLE IF NOT EXISTS ns_event_actions (
    event_id String, action LowCardinality(String), reason String,
    actor String, actor_role LowCardinality(String),
    acted_at DateTime64(3, 'UTC'),
    expires_at Nullable(DateTime64(3, 'UTC')), details_json String
) ENGINE = MergeTree
PARTITION BY toYYYYMM(acted_at) ORDER BY (event_id, acted_at);

CREATE TABLE IF NOT EXISTS dns_campaign_events (
    event_id String, campaign_type LowCardinality(String), target String,
    severity LowCardinality(String), evidence LowCardinality(String),
    status LowCardinality(String), previous_snapshot_id String,
    current_snapshot_id String, first_seen DateTime64(3, 'UTC'),
    last_seen DateTime64(3, 'UTC'), zone_count UInt32, ns_host_count UInt32,
    record_count UInt32, zones_json String, changes_json String DEFAULT '[]', summary String, signature String,
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(first_seen) ORDER BY event_id;

CREATE TABLE IF NOT EXISTS ns_campaign_holds (
    zone String, campaign_id String, target_fingerprint String, active UInt8,
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(updated_at) ORDER BY (zone, campaign_id);

CREATE TABLE IF NOT EXISTS ns_audit_log (
    action LowCardinality(String), actor String,
    actor_role LowCardinality(String), target String,
    acted_at DateTime64(3, 'UTC'), details_json String
) ENGINE = MergeTree
PARTITION BY toYYYYMM(acted_at) ORDER BY (acted_at, actor, action);
