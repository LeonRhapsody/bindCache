# 标签系统 (Tagging System) 设计与规则维护指南

为了能够应对后续大量的规则迭代并提供细粒度的网络隐患特征标注，本项目引入了模块化的**标签评估引擎 (Tagging Engine)**。本指南将详细介绍标签系统的设计架构、ClickHouse 表结构以及如何快速新增自定义标签规则。

---

## 1. 核心设计思想

原有的隐患扫描直接基于硬编码的 SQL 查询在数据库内比对，扩展性极差，且无法沉淀多维度的特征分析结果。

重构后的标签系统遵循以下理念：
1. **解耦评估与追踪**：标签规则引擎只负责评估快照并为域名附着多维度标签（如国家地理跳变、TTL突变等）；而时序追踪器 (Tracker) 仅关注这些高风险标签的生命周期（发现、持续、恢复）。
2. **规则接口化**：每一条打标逻辑都是一个独立的 `TagRule` 接口实现，添加、移除或修改规则仅需操作对应规则文件，不会对主干业务流程造成任何侵入。
3. **加权风险评分**：每个标签自带风险得分，当域名在单次快照中被评估出多个标签时，风险分值会进行累加，最终基于累计风险分数对域名做出安全级别评定（Crisis, High, Medium, Low）。

---

## 2. 数据库表结构 (ClickHouse)

标签系统对应的关系表为 `analysis_domain_tags`。该表采用 `ReplacingMergeTree` 引擎，以 `(snapshot_date, view, domain, tag)` 为排序列，防止因快照重复导入而产生冗余打标数据。

```sql
CREATE TABLE IF NOT EXISTS analysis_domain_tags
(
    snapshot_date Date COMMENT '快照标准化日期 (YYYY-MM-DD)',
    view LowCardinality(String) COMMENT 'DNS View 视图名称',
    domain String COMMENT '被标识的域名',
    tag LowCardinality(String) COMMENT '标签名称 (例如 rfc1918_leak, ttl_anomaly 等)',
    category LowCardinality(String) COMMENT '分类 (security, config, routing, business)',
    rule_id LowCardinality(String) COMMENT '触发标签的规则 ID',
    risk_score UInt8 COMMENT '该特征标签的风险权重值',
    details String COMMENT '触发规则时的结构化上下文数据 (JSON 格式)',
    created_at DateTime DEFAULT now() COMMENT '入库时间'
)
ENGINE = ReplacingMergeTree()
ORDER BY (snapshot_date, view, domain, tag)
SETTINGS index_granularity = 8192;
```

---

## 3. 现已支持的标签规则

目前系统已内置了 7 种打标规则，涵盖了原有安全指标的优化及全新指标的引入：

| 规则 ID | 生成标签 | 分类 | 默认权重 | 检测逻辑概述 |
| :--- | :--- | :--- | :--- | :--- |
| `RULE_001_SINGLE_NS` | `single_ns` | `config` | 2 | 快照中仅配置了单一权威名服务器 (NS) 的域名。 |
| `RULE_002_PARENT_CHILD_DIFF` | `parent_child` | `config` | 5 | 父域（NS trust <=4）与子域（NS trust >=8）授权 NS 记录不一致。 |
| `RULE_003_SHADOW_SERVER_HIJACK` | `hijack` | `security` | 10 | 权威 NS 记录指向已知的安全机构黑洞服务器（`shadowserver.org`）。 |
| `RULE_004_COUNTRY_JUMP` | `country_jump` | `routing` | 6 | 当前解析国家与历史基线不同，**已优化排除 RFC1918 私网 IP 干扰**。 |
| `RULE_005_ASN_CHANGE` | `asn_change` | `routing` | 5 | 当前解析 ASN 自治域与历史基线发生跳变。 |
| `RULE_006_RFC1918_LEAK` | `rfc1918_leak` | `security` | 8 | **[新增]** 公网域名（非 `.local` / `.lan` 等）在缓存中解析为 RFC1918 私网 IP。 |
| `RULE_007_TTL_ANOMALY` | `ttl_anomaly` | `routing` | 3 | **[新增]** 相比历史基线，当前 A 记录缓存 TTL 缩短为极低值 (<= 5s) 的突变。 |

---

## 4. 后续开发：如何新增自定义规则

要在系统中加入新的打标规则，只需在 [tagging.go](tagging.go) 中执行以下 3 步：

### 第一步：实现 `TagRule` 接口
在 [tagging.go](tagging.go) 中定义一个结构体，并实现全部接口方法。
例如，需要添加一条检测 “TXT记录包含恶意Shell命令” 的标签规则：

```go
type MaliciousTXTRule struct{}

func (r *MaliciousTXTRule) ID() string               { return "RULE_008_MALICIOUS_TXT" }
func (r *MaliciousTXTRule) Category() string         { return "security" }
func (r *MaliciousTXTRule) Tag() string              { return "malicious_txt" }
func (r *MaliciousTXTRule) DefaultRiskScore() int    { return 9 }

func (r *MaliciousTXTRule) Execute(db *sql.DB, snapshotDate string, view string) ([]DomainTag, error) {
	rows, err := db.Query(`
		SELECT domain, record_data
		FROM dns_cache_flat
		WHERE snapshot_date = ? AND view = ? AND record_type = 'TXT'
		  AND (record_data LIKE '%wget%' OR record_data LIKE '%curl%')`, snapshotDate, view)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []DomainTag
	for rows.Next() {
		var dom, txtContent string
		if err := rows.Scan(&dom, &txtContent); err == nil {
			js, _ := json.Marshal(map[string]string{"malicious_payload": txtContent})
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
```

### 第二步：在引擎中注册规则
找到 [tagging.go](tagging.go) 中的 `NewTaggingEngine` 函数，注册您刚刚实现的规则实例：

```go
func NewTaggingEngine(db *sql.DB) *TaggingEngine {
	engine := &TaggingEngine{db: db}

	// 注册默认规则
	engine.RegisterRule(&SingleNSRule{})
	// ...

	// 注册您新加的规则
	engine.RegisterRule(&MaliciousTXTRule{})

	return engine
}
```

### 第三步：编译与验证
在终端运行项目测试以验证代码兼容性：
```bash
go test ./...
```
项目编译正常通过后，当重新导入快照数据时，新规则就会自动开始运作，并将匹配结果落入 `analysis_domain_tags` 中，高危域名还会被自动同步推送给 `analysis_results_tracker` 隐患追踪列表。
