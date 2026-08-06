package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// DomainTag 表示域名被打上的安全与配置特征标签
type DomainTag struct {
	SnapshotDate string `json:"snapshot_date"`
	View         string `json:"view"`
	Domain       string `json:"domain"`
	Tag          string `json:"tag"`
	Category     string `json:"category"`
	RuleID       string `json:"rule_id"`
	RiskScore    int    `json:"risk_score"`
	Details      string `json:"details"`
}

// TagRule 标签生成规则的通用接口
type TagRule interface {
	ID() string            // 规则唯一标识
	Category() string      // 标签分类 (security, config, routing, business)
	Tag() string           // 对应生成的标签名称
	DefaultRiskScore() int // 规则默认的风险分值贡献
	Execute(db *sql.DB, snapshotDate string, view string) ([]DomainTag, error)
}

// TaggingEngine 标签评估引擎，管理所有分析规则并执行打标
type TaggingEngine struct {
	db    *sql.DB
	rules []TagRule
}

// NewTaggingEngine 实例化标签引擎并注册默认规则
func NewTaggingEngine(db *sql.DB) *TaggingEngine {
	engine := &TaggingEngine{db: db}

	// 注册内置规则
	engine.RegisterRule(&SingleNSRule{})
	engine.RegisterRule(&ParentChildDiffRule{})
	engine.RegisterRule(&ShadowServerHijackRule{})
	engine.RegisterRule(&CountryJumpRule{})
	engine.RegisterRule(&ASNChangeRule{})
	engine.RegisterRule(&RFC1918LeakRule{})
	engine.RegisterRule(&TTLAnomalyRule{})

	return engine
}

// RegisterRule 注册一条新标签规则
func (te *TaggingEngine) RegisterRule(rule TagRule) {
	te.rules = append(te.rules, rule)
}

// InitializeTable 初始化标签关系表
func (te *TaggingEngine) InitializeTable() error {
	_, err := te.db.Exec(`
	CREATE TABLE IF NOT EXISTS analysis_domain_tags
	(
		snapshot_date Date COMMENT '快照日期 (YYYY-MM-DD)',
		view LowCardinality(String) COMMENT 'DNS 视图视图名称',
		domain String COMMENT '被标识的域名',
		tag LowCardinality(String) COMMENT '标签名称，例如 single_ns, country_jump, rfc1918_leak 等',
		category LowCardinality(String) COMMENT '标签大类 (security, config, routing, business)',
		rule_id LowCardinality(String) COMMENT '触发标签的规则 ID',
		risk_score UInt8 COMMENT '该特征标签的风险权值',
		details String COMMENT '触发规则时的结构化上下文数据 (JSON 格式)',
		created_at DateTime DEFAULT now() COMMENT '记录入库时间'
	)
	ENGINE = ReplacingMergeTree()
	ORDER BY (snapshot_date, view, domain, tag)
	SETTINGS index_granularity = 8192;`)
	return err
}

// Run 执行注册的全部规则，并将打标结果写入 ClickHouse
func (te *TaggingEngine) Run(snapshotDate string, view string) ([]DomainTag, error) {
	if err := te.InitializeTable(); err != nil {
		return nil, fmt.Errorf("初始化标签表失败: %v", err)
	}

	// 1. 清空当天的已有标签记录（防止因重复运行产生数据堆积，由 ReplacingMergeTree 也可以去重，但为了确定性先 Drop 分区或在事务中删除）
	// ClickHouse 并不支持细粒度事务 DELETE，我们将通过 ReplacingMergeTree 自动去重。

	var allTags []DomainTag
	fmt.Printf("标签引擎开始运行，共加载 %d 个标签规则...\n", len(te.rules))

	for _, rule := range te.rules {
		fmt.Printf("└─ 正在执行规则 [%s] -> 生成标签: %s...\n", rule.ID(), rule.Tag())
		tags, err := rule.Execute(te.db, snapshotDate, view)
		if err != nil {
			fmt.Printf("规则 [%s] 执行失败: %v\n", rule.ID(), err)
			continue
		}
		fmt.Printf("   已识别出 %d 条匹配记录。\n", len(tags))
		allTags = append(allTags, tags...)
	}

	if len(allTags) == 0 {
		return allTags, nil
	}

	// 2. 批量将标签数据写入 ClickHouse
	tx, err := te.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("开启标签写入事务失败: %v", err)
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	stmt, err := tx.Prepare(`
		INSERT INTO analysis_domain_tags
		(snapshot_date, view, domain, tag, category, rule_id, risk_score, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return nil, fmt.Errorf("准备标签 INSERT 语句失败: %v", err)
	}
	defer stmt.Close()

	for _, t := range allTags {
		_, err := stmt.Exec(
			t.SnapshotDate,
			t.View,
			t.Domain,
			t.Tag,
			t.Category,
			t.RuleID,
			t.RiskScore,
			t.Details,
		)
		if err != nil {
			fmt.Printf("写入标签数据错误 (%s): %v\n", t.Domain, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("提交标签事务失败: %v", err)
	}

	tx = nil // 释放以防触发 rollback defer
	fmt.Printf("标签数据写入完成，共计 [%d] 条标签落库。\n", len(allTags))
	return allTags, nil
}

// ==========================================
// 1. 内置规则：单一 NS 规则 (SingleNSRule)
// ==========================================
type SingleNSRule struct{}

func (r *SingleNSRule) ID() string            { return "RULE_001_SINGLE_NS" }
func (r *SingleNSRule) Category() string      { return "config" }
func (r *SingleNSRule) Tag() string           { return "single_ns" }
func (r *SingleNSRule) DefaultRiskScore() int { return 2 } // 单一 NS 风险偏低

func (r *SingleNSRule) Execute(db *sql.DB, snapshotDate string, view string) ([]DomainTag, error) {
	rows, err := db.Query(`
		SELECT domain, any(record_data) AS ns
		FROM dns_cache_flat
		WHERE snapshot_date = ? AND view = ? AND record_type = 'NS' AND trust_level >= 8
		GROUP BY domain
		HAVING count(DISTINCT record_data) = 1`, snapshotDate, view)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []DomainTag
	for rows.Next() {
		var dom, ns string
		if err := rows.Scan(&dom, &ns); err == nil {
			js, _ := json.Marshal(map[string]string{"ns": ns})
			tags = append(tags, DomainTag{
				SnapshotDate: snapshotDate,
				View:         view,
				Domain:       dom,
				Tag:          r.Tag(),
				Category:     r.Category(),
				RuleID:       r.ID(),
				RiskScore:    r.DefaultRiskScore(),
				Details:      string(js),
			})
		}
	}
	return tags, nil
}

// ==========================================
// 2. 内置规则：父子一致性规则 (ParentChildDiffRule)
// ==========================================
type ParentChildDiffRule struct{}

func (r *ParentChildDiffRule) ID() string            { return "RULE_002_PARENT_CHILD_DIFF" }
func (r *ParentChildDiffRule) Category() string      { return "config" }
func (r *ParentChildDiffRule) Tag() string           { return "parent_child" }
func (r *ParentChildDiffRule) DefaultRiskScore() int { return 5 } // 中高风险，配置不一致

func (r *ParentChildDiffRule) Execute(db *sql.DB, snapshotDate string, view string) ([]DomainTag, error) {
	rows, err := db.Query(`
		SELECT domain, parent_ns_list, child_ns_list
		FROM (
			SELECT
				domain,
				arraySort(groupUniqArrayIf(record_data, trust_level <= 4)) AS parent_ns_list,
				arraySort(groupUniqArrayIf(record_data, trust_level >= 8)) AS child_ns_list
			FROM dns_cache_flat
			WHERE snapshot_date = ? AND view = ? AND record_type = 'NS'
			GROUP BY domain
		)
		WHERE length(parent_ns_list) > 0
		  AND length(child_ns_list) > 0
		  AND parent_ns_list != child_ns_list`, snapshotDate, view)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []DomainTag
	for rows.Next() {
		var dom string
		var parentNS, childNS []string
		if err := rows.Scan(&dom, &parentNS, &childNS); err == nil {
			js, _ := json.Marshal(map[string][]string{
				"parent_ns": parentNS,
				"child_ns":  childNS,
			})
			tags = append(tags, DomainTag{
				SnapshotDate: snapshotDate,
				View:         view,
				Domain:       dom,
				Tag:          r.Tag(),
				Category:     r.Category(),
				RuleID:       r.ID(),
				RiskScore:    r.DefaultRiskScore(),
				Details:      string(js),
			})
		}
	}
	return tags, nil
}

// ==========================================
// 3. 内置规则：安全黑洞劫持规则 (ShadowServerHijackRule)
// ==========================================
type ShadowServerHijackRule struct{}

func (r *ShadowServerHijackRule) ID() string            { return "RULE_003_SHADOW_SERVER_HIJACK" }
func (r *ShadowServerHijackRule) Category() string      { return "security" }
func (r *ShadowServerHijackRule) Tag() string           { return "hijack" }
func (r *ShadowServerHijackRule) DefaultRiskScore() int { return 10 } // 危机：域名被安全机构黑洞接管

func (r *ShadowServerHijackRule) Execute(db *sql.DB, snapshotDate string, view string) ([]DomainTag, error) {
	rows, err := db.Query(`
		SELECT domain, record_data
		FROM dns_cache_flat
		WHERE snapshot_date = ? AND view = ? AND record_type = 'NS' AND record_data LIKE '%shadowserver.org%'`, snapshotDate, view)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []DomainTag
	for rows.Next() {
		var dom, ns string
		if err := rows.Scan(&dom, &ns); err == nil {
			js, _ := json.Marshal(map[string]string{"ns": ns})
			tags = append(tags, DomainTag{
				SnapshotDate: snapshotDate,
				View:         view,
				Domain:       dom,
				Tag:          r.Tag(),
				Category:     r.Category(),
				RuleID:       r.ID(),
				RiskScore:    r.DefaultRiskScore(),
				Details:      string(js),
			})
		}
	}
	return tags, nil
}

// ==========================================
// 4. 内置规则：国家跳变规则 (CountryJumpRule - 包含私网IP排除优化)
// ==========================================
type CountryJumpRule struct{}

func (r *CountryJumpRule) ID() string            { return "RULE_004_COUNTRY_JUMP" }
func (r *CountryJumpRule) Category() string      { return "routing" }
func (r *CountryJumpRule) Tag() string           { return "country_jump" }
func (r *CountryJumpRule) DefaultRiskScore() int { return 6 } // 较大异常

func (r *CountryJumpRule) Execute(db *sql.DB, snapshotDate string, view string) ([]DomainTag, error) {
	var hasCountryDict int
	_ = db.QueryRow("SELECT count() FROM system.dictionaries WHERE name = 'geoip_country_dict' AND status = 'LOADED'").Scan(&hasCountryDict)
	if hasCountryDict == 0 {
		return nil, nil // 字典未装载则跳过
	}

	rows, err := db.Query(`
		SELECT
			f.domain,
			f.record_data AS current_ip,
			dictGet('geoip_country_dict', 'country_iso_code', tuple(toIPv4(current_ip))) AS current_country,
			b.baseline_data AS baseline_ip,
			dictGet('geoip_country_dict', 'country_iso_code', tuple(toIPv4(baseline_ip))) AS baseline_country
		FROM dns_cache_flat f
		INNER JOIN dns_cache_baseline b
		   ON f.view = b.view AND f.domain = b.domain AND f.record_type = b.record_type
		WHERE f.snapshot_date = ? AND f.view = ?
		  AND f.record_type = 'A'
		  AND current_ip != baseline_ip
		  AND current_country != baseline_country
		  AND current_country != 'XX' AND baseline_country != 'XX'
		  -- 排除私有地址（由 RFC1918 规则处理，降低本规则国家判定误报）
		  AND NOT (
			isIPAddressInRange(current_ip, '10.0.0.0/8') OR
			isIPAddressInRange(current_ip, '172.16.0.0/12') OR
			isIPAddressInRange(current_ip, '192.168.0.0/16') OR
			isIPAddressInRange(baseline_ip, '10.0.0.0/8') OR
			isIPAddressInRange(baseline_ip, '172.16.0.0/12') OR
			isIPAddressInRange(baseline_ip, '192.168.0.0/16')
		  )`, snapshotDate, view)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []DomainTag
	for rows.Next() {
		var dom, curIP, curC, baseIP, baseC string
		if err := rows.Scan(&dom, &curIP, &curC, &baseIP, &baseC); err == nil {
			js, _ := json.Marshal(map[string]string{
				"current_ip":       curIP,
				"current_country":  curC,
				"baseline_ip":      baseIP,
				"baseline_country": baseC,
			})
			tags = append(tags, DomainTag{
				SnapshotDate: snapshotDate,
				View:         view,
				Domain:       dom,
				Tag:          r.Tag(),
				Category:     r.Category(),
				RuleID:       r.ID(),
				RiskScore:    r.DefaultRiskScore(),
				Details:      string(js),
			})
		}
	}
	return tags, nil
}

// ==========================================
// 5. 内置规则：ASN 自治系统改变规则 (ASNChangeRule)
// ==========================================
type ASNChangeRule struct{}

func (r *ASNChangeRule) ID() string            { return "RULE_005_ASN_CHANGE" }
func (r *ASNChangeRule) Category() string      { return "routing" }
func (r *ASNChangeRule) Tag() string           { return "asn_change" }
func (r *ASNChangeRule) DefaultRiskScore() int { return 5 } // 中等偏高异常

func (r *ASNChangeRule) Execute(db *sql.DB, snapshotDate string, view string) ([]DomainTag, error) {
	var hasASNDict int
	_ = db.QueryRow("SELECT count() FROM system.dictionaries WHERE name = 'geoip_asn_dict' AND status = 'LOADED'").Scan(&hasASNDict)
	if hasASNDict == 0 {
		return nil, nil // 字典未装载则跳过
	}

	rows, err := db.Query(`
		SELECT
			f.domain,
			f.record_data AS current_ip,
			dictGet('geoip_asn_dict', 'autonomous_system_number', tuple(toIPv4(current_ip))) AS current_asn,
			dictGet('geoip_asn_dict', 'autonomous_system_organization', tuple(toIPv4(current_ip))) AS current_as_org,
			b.baseline_data AS baseline_ip,
			dictGet('geoip_asn_dict', 'autonomous_system_number', tuple(toIPv4(baseline_ip))) AS baseline_asn,
			dictGet('geoip_asn_dict', 'autonomous_system_organization', tuple(toIPv4(baseline_ip))) AS baseline_as_org
		FROM dns_cache_flat f
		INNER JOIN dns_cache_baseline b
		   ON f.view = b.view AND f.domain = b.domain AND f.record_type = b.record_type
		WHERE f.snapshot_date = ? AND f.view = ?
		  AND f.record_type = 'A'
		  AND current_ip != baseline_ip
		  AND current_asn != baseline_asn
		  AND current_asn != 0 AND baseline_asn != 0`, snapshotDate, view)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []DomainTag
	for rows.Next() {
		var dom, curIP, curOrg, baseIP, baseOrg string
		var curASN, baseASN uint32
		if err := rows.Scan(&dom, &curIP, &curASN, &curOrg, &baseIP, &baseASN, &baseOrg); err == nil {
			js, _ := json.Marshal(map[string]any{
				"current_ip":      curIP,
				"current_asn":     curASN,
				"current_as_org":  curOrg,
				"baseline_ip":     baseIP,
				"baseline_asn":    baseASN,
				"baseline_as_org": baseOrg,
			})
			tags = append(tags, DomainTag{
				SnapshotDate: snapshotDate,
				View:         view,
				Domain:       dom,
				Tag:          r.Tag(),
				Category:     r.Category(),
				RuleID:       r.ID(),
				RiskScore:    r.DefaultRiskScore(),
				Details:      string(js),
			})
		}
	}
	return tags, nil
}

// ==========================================
// 6. 新增规则：公网解析泄露为私网 IP 规则 (RFC1918LeakRule)
// ==========================================
type RFC1918LeakRule struct{}

func (r *RFC1918LeakRule) ID() string            { return "RULE_006_RFC1918_LEAK" }
func (r *RFC1918LeakRule) Category() string      { return "security" }
func (r *RFC1918LeakRule) Tag() string           { return "rfc1918_leak" }
func (r *RFC1918LeakRule) DefaultRiskScore() int { return 8 } // 高风险：公网域名指向私有 IP

func (r *RFC1918LeakRule) Execute(db *sql.DB, snapshotDate string, view string) ([]DomainTag, error) {
	rows, err := db.Query(`
		SELECT domain, record_data
		FROM dns_cache_flat
		WHERE snapshot_date = ? AND view = ?
		  AND record_type = 'A'
		  AND domain NOT LIKE '%.local' AND domain NOT LIKE '%.lan' AND domain NOT LIKE '%.localdomain'
		  AND (
			isIPAddressInRange(record_data, '10.0.0.0/8') OR
			isIPAddressInRange(record_data, '172.16.0.0/12') OR
			isIPAddressInRange(record_data, '192.168.0.0/16')
		  )`, snapshotDate, view)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []DomainTag
	for rows.Next() {
		var dom, ip string
		if err := rows.Scan(&dom, &ip); err == nil {
			js, _ := json.Marshal(map[string]string{"leaked_private_ip": ip})
			tags = append(tags, DomainTag{
				SnapshotDate: snapshotDate,
				View:         view,
				Domain:       dom,
				Tag:          r.Tag(),
				Category:     r.Category(),
				RuleID:       r.ID(),
				RiskScore:    r.DefaultRiskScore(),
				Details:      string(js),
			})
		}
	}
	return tags, nil
}

// ==========================================
// 7. 新增规则：TTL 突变判定规则 (TTLAnomalyRule)
// ==========================================
type TTLAnomalyRule struct{}

func (r *TTLAnomalyRule) ID() string            { return "RULE_007_TTL_ANOMALY" }
func (r *TTLAnomalyRule) Category() string      { return "routing" }
func (r *TTLAnomalyRule) Tag() string           { return "ttl_anomaly" }
func (r *TTLAnomalyRule) DefaultRiskScore() int { return 3 } // 辅助评估标志

func (r *TTLAnomalyRule) Execute(db *sql.DB, snapshotDate string, view string) ([]DomainTag, error) {
	// 针对有历史基线且当前 TTL 异常极小的情况进行打标检测
	rows, err := db.Query(`
		SELECT f.domain, f.ttl
		FROM dns_cache_flat f
		INNER JOIN dns_cache_baseline b
		   ON f.view = b.view AND f.domain = b.domain AND f.record_type = b.record_type
		WHERE f.snapshot_date = ? AND f.view = ?
		  AND f.record_type = 'A'
		  AND f.ttl > 0 AND f.ttl <= 5`, snapshotDate, view)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []DomainTag
	for rows.Next() {
		var dom string
		var ttl int32
		if err := rows.Scan(&dom, &ttl); err == nil {
			js, _ := json.Marshal(map[string]any{"abnormal_ttl": ttl})
			tags = append(tags, DomainTag{
				SnapshotDate: snapshotDate,
				View:         view,
				Domain:       dom,
				Tag:          r.Tag(),
				Category:     r.Category(),
				RuleID:       r.ID(),
				RiskScore:    r.DefaultRiskScore(),
				Details:      string(js),
			})
		}
	}
	return tags, nil
}
