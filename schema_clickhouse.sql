-- ClickHouse 数据库初始化建表脚本
-- 适用于 bindCacheAnalyze 项目的数据存储与分析

CREATE DATABASE IF NOT EXISTS bind_cache_analyze;
USE bind_cache_analyze;

-- 1. 全量 DNS 缓存扁平记录表
CREATE TABLE IF NOT EXISTS dns_cache_flat
(
    snapshot_date Date COMMENT '快照标准化日期 (YYYY-MM-DD)',
    view LowCardinality(String) COMMENT 'DNS View 视图名称',
    domain String COMMENT '查询的域名',
    record_type LowCardinality(String) COMMENT '记录类型',
    record_data String COMMENT '记录的真实内容',
    ttl Int32 COMMENT 'TTL',
    trust_code LowCardinality(String) COMMENT '信誉属性文本',
    trust_level UInt8 COMMENT '数字化信任等级',
    rcode LowCardinality(String) COMMENT '状态码'
)
ENGINE = MergeTree()
PARTITION BY snapshot_date
ORDER BY (snapshot_date, domain, record_type)
SETTINGS index_granularity = 8192;

-- 2. 权威 NS 服务器网络遥测数据表
CREATE TABLE IF NOT EXISTS dns_adb_telemetry
(
    snapshot_date Date COMMENT '快照标准化日期 (YYYY-MM-DD)',
    view LowCardinality(String) COMMENT 'DNS View 视图名称',
    ns_name String COMMENT '权威 NS 主机名',
    ip String COMMENT '权威 IP',
    srtt UInt32 COMMENT '往返时延 (RTT)',
    flags String COMMENT '特征标志',
    edns_success UInt32 COMMENT 'EDNS 解析成功次数',
    edns_timeout UInt32 COMMENT 'EDNS 超时次数',
    plain_success UInt32 COMMENT '普通 DNS 成功次数',
    plain_timeout UInt32 COMMENT '普通 DNS 超时次数',
    udpsize UInt16 COMMENT 'UDP 数据包大小限制',
    cookie String COMMENT 'DNS Cookie',
    ttl Int32 COMMENT '缓存 TTL'
)
ENGINE = MergeTree()
PARTITION BY snapshot_date
ORDER BY (snapshot_date, ns_name, ip)
SETTINGS index_granularity = 8192;

-- 3. 快照元数据摘要表
CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_date Date COMMENT '快照生成日期',
    total_domains Int32 COMMENT '本快照包含的域名总数',
    view String COMMENT '所属 DNS View 视图',
    imported_at DateTime DEFAULT now() COMMENT '导入系统的时间'
) ENGINE = MergeTree()
PARTITION BY snapshot_date
ORDER BY snapshot_date;

-- 4. 每日隐患分析明细表 (用于 Web 端报表展示)
CREATE TABLE IF NOT EXISTS analysis_results (
    snapshot_date Date COMMENT '扫描快照日期',
    domain String COMMENT '隐患域名',
    issue_type LowCardinality(String) COMMENT '隐患类型 (single-ns, parent-child, ns-diff, hijack 等)',
    risk_level LowCardinality(String) COMMENT '风险等级 (high, medium, low)',
    details String COMMENT '隐患细节描述',
    detected_at DateTime DEFAULT now() COMMENT '检测时间'
) ENGINE = MergeTree()
PARTITION BY snapshot_date
ORDER BY (snapshot_date, issue_type, risk_level);

-- 5. 长期状态流转追踪表 (Tracker)
CREATE TABLE IF NOT EXISTS analysis_results_tracker (
    domain String COMMENT '隐患域名',
    issue_type LowCardinality(String) COMMENT '隐患类型',
    risk_level LowCardinality(String) COMMENT '风险等级',
    first_detected DateTime COMMENT '首次发现时间',
    last_active DateTime COMMENT '最近一次处于活跃状态的时间',
    status LowCardinality(String) COMMENT '状态 (active / resolved)',
    resolved_at Nullable(DateTime) COMMENT '消除时间',
    details String COMMENT '最新的细节描述'
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(first_detected)
ORDER BY (status, issue_type, domain, first_detected)
SETTINGS index_granularity = 8192;

-- 6. 共识基线数据表 (Baseline)
CREATE TABLE IF NOT EXISTS dns_cache_baseline (
    view LowCardinality(String) COMMENT 'DNS View 视图',
    domain String COMMENT '域名',
    record_type LowCardinality(String) COMMENT '记录类型',
    baseline_data String COMMENT '基线内容',
    confidence_score UInt8 COMMENT '共识置信度评分 (0-100)',
    last_updated DateTime COMMENT '最后更新时间'
) ENGINE = MergeTree()
ORDER BY (view, domain, record_type)
SETTINGS index_granularity = 8192;
